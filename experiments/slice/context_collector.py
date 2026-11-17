#!/usr/bin/env python3
"""Pod context collector -> context.cluster.v0 and source.completeness.v0.

Watches Pods with UID, resourceVersion, stream ID and sequence. Coverage
(SourceCompleteness NO_KNOWN_GAP and the heartbeat low watermark) advances only
while a watch stream is connected. On restart it resumes from the checkpointed
resourceVersion; a 410 (HTTP status or in-stream ERROR event) yields a relist
(RELIST_SNAPSHOT observations), a WatchGap, and an INCOMPLETE completeness
record with WATCH_RELIST_GAP covering [last coverage end, relist time].
Intermediate changes are never synthesized.

WatchGap has no object UID but context.cluster.v0 is keyed by OBJECT_UID; the
slice broadcasts it to every partition with the producer-instance key (see
README, contract note).
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.environ.get("MT_REPO", "/repo"), "experiments", "cluster", "audit-context"))
import mtk8s  # noqa: E402
import mtslice as M  # noqa: E402

TOPIC = "context.cluster.v0"
CT = M.context_pb2.ChangeType.Value


class PodCollector:
    def __init__(self, args):
        self.args = args
        self.params = M.load_params()
        self.bus = M.Bus(args.bootstrap, args.instance)
        self.run_ctx = M.Run(args.run_id, args.descriptor_sha256, self.params)
        self.kc = mtk8s.KubeConfig(args.kubeconfig_json, args.private)
        self.api = mtk8s.Api(self.kc)
        self.scope = f"pods;context-collector={args.instance}"
        self.state_path = os.path.join(args.out, "context-state.json")
        self.log = M.JsonLog(os.path.join(args.out, "slice-context.jsonl"))
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.connected = False
        self.rv = None
        self.cov_end = None
        self.stream_no = 0
        self.seq = 0
        if args.resume and os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                st = json.load(fh)
            self.rv, self.cov_end, self.stream_no = st["rv"], st["cov_end"], st["stream_no"]

    def stream_id(self):
        return f"{self.args.instance}/pods/{self.stream_no}"

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"rv": self.rv, "cov_end": self.cov_end, "stream_no": self.stream_no}, fh)
        os.replace(tmp, self.state_path)

    def observe(self, obj, change):
        meta, spec, status = obj.get("metadata") or {}, obj.get("spec") or {}, obj.get("status") or {}
        self.seq += 1
        o = M.context_pb2.ObjectObservation(api_group="", kind="Pod", namespace=meta.get("namespace", ""),
                                            name=meta.get("name", ""), uid=meta.get("uid", ""),
                                            resource_version=meta.get("resourceVersion", ""),
                                            change_type=CT(change), watch_stream_id=self.stream_id(),
                                            watch_stream_seq=self.seq)
        o.observed_time.CopyFrom(M.ts(M.now()))
        o.pod.node_name = spec.get("nodeName", "")
        o.pod.pod_ips.extend(x.get("ip") for x in status.get("podIPs") or [] if x.get("ip"))
        o.pod.service_account = spec.get("serviceAccountName", "")
        for c in status.get("containerStatuses") or []:
            cs = o.pod.containers.add(name=c.get("name", ""), container_id=c.get("containerID", ""),
                                      restart_count=int(c.get("restartCount") or 0), image_id=c.get("imageID", ""))
            del cs
        eid = M.event_id("CLUSTER_CONTEXT", f"{o.uid}/{o.resource_version}/{change}", "watch")
        env = M.envelope(self.run_ctx, "context-collector", "CONTEXT_OBSERVATION", "CLUSTER_CONTEXT",
                         "context_observation", o, logical_id=eid)
        self.bus.send(TOPIC, M.key_for(TOPIC, {"OBJECT_UID": o.uid}), env)

    def relist(self, reason):
        self.stream_no += 1
        self.seq = 0
        r = self.api.request("GET", "/api/v1/pods?limit=500")
        if r.status != 200:
            raise RuntimeError(f"pod list failed: HTTP {r.status}")
        body = r.json()
        if body["metadata"].get("continue"):
            raise RuntimeError("pod list exceeded one page; slice bound violated")
        for it in body.get("items") or []:
            self.observe(it, "RELIST_SNAPSHOT")
        self.rv = body["metadata"]["resourceVersion"]
        self.log.write({"relist": reason, "items": len(body.get("items") or []), "rv": self.rv})
        return M.now()

    def on_gone(self, how):
        last_rv, gap_start = self.rv, self.cov_end
        t = self.relist("after-410")
        wg = M.context_pb2.WatchGap(api_group="", resource="pods", last_resource_version=last_rv or "",
                                    relist_resource_version=self.rv, reason=M.context_pb2.GONE_410,
                                    watch_stream_id=self.stream_id())
        wg.gap_start.CopyFrom(M.ts(gap_start))
        wg.gap_end.CopyFrom(M.ts(t))
        self.bus.broadcast(TOPIC, M.envelope(self.run_ctx, "context-collector", "CONTEXT_WATCH_GAP",
                                             "CLUSTER_CONTEXT", "context_watch_gap", wg))
        sc = M.completeness_msg("CLUSTER_CONTEXT", self.scope, gap_start, t, "INCOMPLETE",
                                [M.gap("WATCH_RELIST_GAP", "pods", how, gap_start, t)])
        self.bus.send("source.completeness.v0",
                      M.key_for("source.completeness.v0", {"SOURCE_NAME": "CLUSTER_CONTEXT", "SCOPE": self.scope}),
                      M.envelope(self.run_ctx, "context-collector", "SOURCE_COMPLETENESS", "CLUSTER_CONTEXT",
                                 "source_completeness", sc))
        self.log.write({"watch_gap": how, "gap_start": M.rfc3339(gap_start), "gap_end": M.rfc3339(t)})
        with self.lock:
            self.cov_end = t

    def watch_once(self):
        q = urllib.parse.urlencode({"watch": "1", "resourceVersion": self.rv, "allowWatchBookmarks": "true",
                                    "timeoutSeconds": "30"})
        conn, resp = self.api.stream("/api/v1/pods?" + q, timeout=45)
        try:
            if resp.status == 410:
                self.connected = False
                self.on_gone("HTTP 410 on watch request")
                return
            if resp.status != 200:
                self.connected = False
                time.sleep(1)
                return
            self.connected = True
            while not self.stop.is_set():
                line = resp.readline()
                if not line:
                    return
                ev = json.loads(line)
                typ, obj = ev.get("type"), ev.get("object") or {}
                if typ == "ERROR":
                    self.connected = False
                    if obj.get("code") == 410:
                        self.on_gone("watch ERROR event code 410")
                    return
                if typ == "BOOKMARK":
                    self.rv = (obj.get("metadata") or {}).get("resourceVersion", self.rv)
                    continue
                self.observe(obj, typ)
                self.rv = (obj.get("metadata") or {}).get("resourceVersion", self.rv)
        except (OSError, ValueError):
            time.sleep(0.5)
        finally:
            self.connected = False
            conn.close()

    def coverage_loop(self):
        while not self.stop.is_set():
            time.sleep(self.params["heartbeat_s"])
            with self.lock:
                if not self.connected or self.cov_end is None:
                    continue
                end = M.now() - self.params["context_coverage_lag_s"]
                if end > self.cov_end:
                    sc = M.completeness_msg("CLUSTER_CONTEXT", self.scope, self.cov_end, end, "NO_KNOWN_GAP")
                    self.bus.send("source.completeness.v0",
                                  M.key_for("source.completeness.v0",
                                            {"SOURCE_NAME": "CLUSTER_CONTEXT", "SCOPE": self.scope}),
                                  M.envelope(self.run_ctx, "context-collector", "SOURCE_COMPLETENESS",
                                             "CLUSTER_CONTEXT", "source_completeness", sc))
                    self.cov_end = end
                self.bus.heartbeat(self.run_ctx, "context-collector", TOPIC, self.cov_end, "CLUSTER_CONTEXT")
                self.save()

    def run(self):
        if self.rv is None:
            self.cov_end = self.relist("initial")
        else:
            self.stream_no += 1
            self.log.write({"resume": True, "from_rv": self.rv})
        t = threading.Thread(target=self.coverage_loop, daemon=True)
        t.start()
        while not self.stop.is_set():
            self.watch_once()
        t.join(timeout=5)
        with self.lock:
            self.save()
        self.bus.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kubeconfig-json", required=True)
    ap.add_argument("--private", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--descriptor-sha256", required=True)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()
    os.umask(0o022)
    pc = PodCollector(args)
    signal.signal(signal.SIGTERM, lambda *_: pc.stop.set())
    signal.signal(signal.SIGINT, lambda *_: pc.stop.set())
    pc.run()


if __name__ == "__main__":
    main()
