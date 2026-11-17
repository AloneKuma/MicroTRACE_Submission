#!/usr/bin/env python3
"""Record RBAC and Pod watch history with UID, resourceVersion and stream order.

Each resource gets its own watch stream. A list is recorded as a relist
boundary (snapshot items are marked `relist_item`, never as watch events). An
HTTP 410 or a watch ERROR event with code 410 produces an explicit
`watch_gap`: state between the last observed resourceVersion and the relist is
UNKNOWN and is not reconstructed from the snapshot.

Usage:
  context-watch.py --kubeconfig-json K --private DIR --out OUT.jsonl
      [--resources roles,clusterroles,rolebindings,clusterrolebindings,pods]
      [--namespace NS] [--checkpoint CK] [--resume] [--stop-after-list]
      [--max-seconds N] [--stream-name NAME]
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtk8s import Api, JsonlWriter, KubeConfig, utc_now, write_json_atomic  # noqa: E402

RESOURCES = {
    "roles": ("/apis/rbac.authorization.k8s.io/v1", "roles", True),
    "clusterroles": ("/apis/rbac.authorization.k8s.io/v1", "clusterroles", False),
    "rolebindings": ("/apis/rbac.authorization.k8s.io/v1", "rolebindings", True),
    "clusterrolebindings": ("/apis/rbac.authorization.k8s.io/v1", "clusterrolebindings", False),
    "pods": ("/api/v1", "pods", True),
}


def base_path(resource, namespace):
    prefix, plural, namespaced = RESOURCES[resource]
    if namespace and namespaced:
        return f"{prefix}/namespaces/{namespace}/{plural}"
    return f"{prefix}/{plural}"


def obs_fields(obj):
    meta = obj.get("metadata") or {}
    out = {"uid": meta.get("uid"), "rv": meta.get("resourceVersion"), "namespace": meta.get("namespace"),
           "name": meta.get("name"), "creation_ts": meta.get("creationTimestamp"),
           "deletion_ts": meta.get("deletionTimestamp")}
    if obj.get("kind") == "Pod" or "podIP" in (obj.get("status") or {}):
        st = obj.get("status") or {}
        spec = obj.get("spec") or {}
        out["pod"] = {"ip": st.get("podIP"), "ips": [x.get("ip") for x in st.get("podIPs") or []],
                      "phase": st.get("phase"), "node": spec.get("nodeName"),
                      "host_network": bool(spec.get("hostNetwork")),
                      "restart_counts": [c.get("restartCount") for c in st.get("containerStatuses") or []]}
    return out


class ResourceWatcher(threading.Thread):
    def __init__(self, resource, api, out, lock, stop, namespace, stream_name, start_rv, stop_after_list):
        super().__init__(daemon=True)
        self.resource = resource
        self.api = api
        self.out = out
        self.lock = lock
        self.stop = stop
        self.path = base_path(resource, namespace)
        self.stream_name = stream_name
        self.rv = start_rv
        self.stop_after_list = stop_after_list
        self.stream_no = 0
        self.last_event_utc = None
        self.error = None

    def emit(self, rec):
        rec.setdefault("resource", self.resource)
        rec.setdefault("observed_utc", utc_now())
        with self.lock:
            self.out.write(rec)

    def stream_id(self):
        return f"{self.stream_name}/{self.resource}/{self.stream_no}"

    def relist(self, reason):
        self.stream_no += 1
        items, cont, list_rv = [], None, None
        while True:
            q = {"limit": "500"}
            if cont:
                q["continue"] = cont
            r = self.api.request("GET", self.path + "?" + urllib.parse.urlencode(q))
            if r.status != 200:
                raise RuntimeError(f"list {self.resource} failed: HTTP {r.status}")
            body = r.json()
            list_rv = list_rv or body["metadata"]["resourceVersion"]
            items.extend(body.get("items") or [])
            cont = body["metadata"].get("continue")
            if not cont:
                break
        self.emit({"kind": "relist", "stream_id": self.stream_id(), "reason": reason,
                   "list_rv": list_rv, "item_count": len(items)})
        for it in items:
            self.emit({"kind": "relist_item", "stream_id": self.stream_id(), **obs_fields(it)})
        self.rv = list_rv
        return list_rv

    def gap(self, last_rv, how):
        detected = utc_now()
        relist_rv = self.relist("after-410")
        self.emit({"kind": "watch_gap", "stream_id": self.stream_id(), "last_rv": last_rv,
                   "last_event_utc": self.last_event_utc, "detected_utc": detected, "cause": how,
                   "relist_rv": relist_rv, "state_between": "UNKNOWN"})

    def run(self):
        try:
            if self.rv is None:
                self.relist("initial")
            else:
                self.stream_no += 1
                self.emit({"kind": "resume", "stream_id": self.stream_id(), "from_rv": self.rv})
            if self.stop_after_list:
                return
            while not self.stop.is_set():
                self.watch_once()
        except Exception as exc:  # recorded, never silent
            self.error = repr(exc)
            self.emit({"kind": "watcher_error", "stream_id": self.stream_id(), "error": repr(exc)})

    def watch_once(self):
        q = urllib.parse.urlencode({"watch": "1", "resourceVersion": self.rv,
                                    "allowWatchBookmarks": "true", "timeoutSeconds": "30"})
        conn, resp = self.api.stream(self.path + "?" + q, timeout=45)
        try:
            if resp.status == 410:
                self.emit({"kind": "http_410", "stream_id": self.stream_id(), "requested_rv": self.rv})
                self.gap(self.rv, "HTTP 410 on watch request")
                return
            if resp.status != 200:
                self.emit({"kind": "watch_http_error", "stream_id": self.stream_id(), "status": resp.status})
                time.sleep(1)
                return
            seq = 0
            while not self.stop.is_set():
                line = resp.readline()
                if not line:
                    return  # server timeout: resume from self.rv
                ev = json.loads(line)
                typ, obj = ev.get("type"), ev.get("object") or {}
                if typ == "ERROR":
                    code = obj.get("code")
                    self.emit({"kind": "watch_error_event", "stream_id": self.stream_id(), "code": code,
                               "reason": obj.get("reason"), "requested_rv": self.rv})
                    if code == 410:
                        self.gap(self.rv, "watch ERROR event code 410")
                    return
                if typ == "BOOKMARK":
                    self.rv = (obj.get("metadata") or {}).get("resourceVersion", self.rv)
                    continue
                seq += 1
                fields = obs_fields(obj)
                self.emit({"kind": "watch_event", "stream_id": self.stream_id(), "seq": seq,
                           "type": typ, **fields})
                self.last_event_utc = utc_now()
                self.rv = fields["rv"] or self.rv
        except (OSError, ValueError) as exc:
            self.emit({"kind": "watch_disconnect", "stream_id": self.stream_id(), "error": type(exc).__name__})
            time.sleep(0.5)
        finally:
            conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kubeconfig-json", required=True)
    ap.add_argument("--private", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--resources", default="roles,clusterroles,rolebindings,clusterrolebindings,pods")
    ap.add_argument("--namespace", default=None)
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--stop-after-list", action="store_true")
    ap.add_argument("--max-seconds", type=float, default=None)
    ap.add_argument("--stream-name", default="main")
    args = ap.parse_args()
    os.umask(0o077)

    kc = KubeConfig(args.kubeconfig_json, args.private)
    out = JsonlWriter(args.out)
    lock = threading.Lock()
    stop = threading.Event()
    start_rv = {}
    if args.resume and args.checkpoint and os.path.exists(args.checkpoint):
        with open(args.checkpoint, encoding="utf-8") as fh:
            start_rv = json.load(fh)["rv"]
    watchers = [ResourceWatcher(r, Api(kc), out, lock, stop, args.namespace, args.stream_name,
                                start_rv.get(r), args.stop_after_list)
                for r in args.resources.split(",")]

    def on_term(signum, frame):
        stop.set()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    with lock:
        out.write({"kind": "watcher_start", "observed_utc": utc_now(), "stream_name": args.stream_name,
                   "resources": args.resources.split(","), "namespace": args.namespace,
                   "resume": bool(start_rv)})
    for w in watchers:
        w.start()
    deadline = time.time() + args.max_seconds if args.max_seconds else None
    while not stop.is_set() and any(w.is_alive() for w in watchers):
        if deadline and time.time() >= deadline:
            stop.set()
        time.sleep(0.2)
    stop.set()
    for w in watchers:
        w.join(timeout=50)
    if args.checkpoint:
        write_json_atomic(args.checkpoint, {"rv": {w.resource: w.rv for w in watchers}, "utc": utc_now()})
    with lock:
        out.write({"kind": "watcher_stop", "observed_utc": utc_now(), "stream_name": args.stream_name,
                   "errors": {w.resource: w.error for w in watchers if w.error}})
    out.close()
    sys.exit(1 if any(w.error for w in watchers) else 0)


if __name__ == "__main__":
    main()
