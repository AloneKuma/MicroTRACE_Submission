#!/usr/bin/env python3
"""Audit collector -> raw.audit.v0 (keyed by audit ID) and source.completeness.v0.

Reuses the Gap 2 collector's tailing logic unchanged: (dev, ino, offset) with a
content fingerprint, inode-following rotation, (auditID, stage) dedup,
checkpoint/resume, and DROPPED_BEFORE detection when a checkpointed file was
deleted by rotation. Instead of redacted JSONL it produces AuditEvent
envelopes, per-partition heartbeats, and contiguous SourceCompleteness
intervals. Coverage is claimed only up to the start of the last read that
reached EOF, minus collector_skew_s.

Request/response bodies are not embedded; the envelope carries an EvidenceRef
with the body's SHA-256 and archive_id "not-archived-slice".
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.environ.get("MT_REPO", "/repo"), "experiments", "cluster", "audit-context"))
import collector as gap2  # noqa: E402
import mtslice as M  # noqa: E402

EXTRA = "authentication.kubernetes.io/"


def audit_event(ev, policy_sha, cur, offset):
    a = M.audit_pb2.AuditEvent(audit_id=ev.get("auditID", ""), stage=ev.get("stage", ""),
                               level=ev.get("level", ""), request_uri=ev.get("requestURI", ""),
                               verb=ev.get("verb", ""), user_agent=ev.get("userAgent", ""),
                               policy_version=policy_sha)
    u = ev.get("user") or {}
    a.user.username = u.get("username", "")
    a.user.uid = u.get("uid", "")
    a.user.groups.extend(u.get("groups") or [])
    for k, v in (u.get("extra") or {}).items():
        a.user.extra[k].values.extend(v if isinstance(v, list) else [v])
    imp = ev.get("impersonatedUser")
    if imp:
        a.impersonated_user.username = imp.get("username", "")
        a.impersonated_user.groups.extend(imp.get("groups") or [])
    a.source_ips.extend(ev.get("sourceIPs") or [])
    ref = ev.get("objectRef") or {}
    for f, k in (("api_group", "apiGroup"), ("api_version", "apiVersion"), ("resource", "resource"),
                 ("subresource", "subresource"), ("namespace", "namespace"), ("name", "name"),
                 ("uid", "uid"), ("resource_version", "resourceVersion")):
        setattr(a.object_ref, f, ref.get(k) or "")
    rs = ev.get("responseStatus") or {}
    a.response_code = int(rs.get("code") or 0)
    a.response_reason = rs.get("reason") or ""
    for k, v in (ev.get("annotations") or {}).items():
        a.annotations[k] = str(v)
    for field, key in (("request_received_timestamp", "requestReceivedTimestamp"),
                       ("stage_timestamp", "stageTimestamp")):
        e = M.parse_rfc3339(ev.get(key))
        if e is not None:
            getattr(a, field).CopyFrom(M.ts(e))
    for field, key in (("request_object", "requestObject"), ("response_object", "responseObject")):
        obj = ev.get(key)
        if obj is not None:
            body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
            r = getattr(a, field)
            r.archive_id = "not-archived-slice"
            r.object_key = f"{a.audit_id}/{a.stage}/{key}"
            r.sha256_hex = hashlib.sha256(body).hexdigest()
            r.protection = M.common_pb2.PROTECTED_RBAC_BODY
    a.position.route = M.audit_pb2.LOG_FILE_TAIL
    a.position.file_dev, a.position.file_ino, a.position.file_offset = cur["dev"], cur["ino"], offset
    return a


class KafkaCollector(gap2.Collector):
    def __init__(self, args, bus, run, params):
        self.bus, self.run_ctx, self.params = bus, run, params
        self.policy_sha = args.policy_sha256
        self.scope = f"audit-collector={bus.instance}"
        self.state_path = os.path.join(args.out, "slice-state.json")
        self.cov_end = None
        if args.resume and os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                self.cov_end = json.load(fh).get("cov_end")
        self.eof_time = None
        self.log = M.JsonLog(os.path.join(args.out, "slice-collector.jsonl"))
        super().__init__(args)

    # --- produce records instead of redacted JSONL
    def _process_line(self, line, offset):
        try:
            ev = json.loads(line)
        except ValueError:
            self.stats["parse_errors"] += 1
            self.events.write({"event": "parse_error", "utc": gap2.utc_now(), "ino": self.cur["ino"],
                               "offset": offset, "length": len(line)})
            return
        key = (ev.get("auditID"), ev.get("stage"))
        if key in self.seen:
            self.stats["duplicates"] += 1
            return
        self.seen.add(key)
        st = M.parse_rfc3339(ev.get("stageTimestamp"))
        if self.pending_gap is not None:
            self._emit_gap(st)
        a = audit_event(ev, self.policy_sha, self.cur, offset)
        env = M.envelope(self.run_ctx, "audit-collector", "RAW_AUDIT", "AUDIT", "raw_audit", a,
                         logical_id=M.event_id("AUDIT", a.audit_id, a.stage))
        self.bus.send("raw.audit.v0", M.key_for("raw.audit.v0", {"AUDIT_ID": a.audit_id}), env)
        self.stats["records"] += 1
        if self.cov_end is None and st is not None:
            self.cov_end = st  # fresh start: coverage begins at the first record read
        self.last_stage_ts = ev.get("stageTimestamp")

    def _emit_gap(self, first_after):
        g = self.pending_gap
        start = self.cov_end if self.cov_end is not None else M.parse_rfc3339(g.get("from_stage_ts"))
        end = first_after
        sc = M.completeness_msg("AUDIT", self.scope, start, end, "INCOMPLETE",
                                [M.gap("DROPPED_BEFORE", "raw.audit.v0", g["reason"], start, end)])
        self.bus.send("source.completeness.v0",
                      M.key_for("source.completeness.v0", {"SOURCE_NAME": "AUDIT", "SCOPE": self.scope}),
                      M.envelope(self.run_ctx, "audit-collector", "SOURCE_COMPLETENESS", "AUDIT",
                                 "source_completeness", sc))
        g["to_stage_ts"] = M.rfc3339(end)
        self.events.write(g)
        self.log.write({"emit": "completeness", "status": "INCOMPLETE", "start": M.rfc3339(start),
                        "end": M.rfc3339(end), "reason": "DROPPED_BEFORE"})
        self.cov_end = end
        self.pending_gap = None

    def _read_available(self):
        t = M.now()
        got = super()._read_available()
        self.eof_time = t  # everything written before t has now been read
        return got

    def checkpoint(self, final=False):
        super().checkpoint(final)
        # Coverage and heartbeats only when caught up and no unresolved gap.
        if self.eof_time is None or self.pending_gap is not None or self.cov_end is None:
            return
        end = self.eof_time - self.params["collector_skew_s"]
        if end > self.cov_end:
            sc = M.completeness_msg("AUDIT", self.scope, self.cov_end, end, "NO_KNOWN_GAP",
                                    counters={"records": self.stats["records"],
                                              "parse_errors": self.stats["parse_errors"],
                                              "rotations": self.stats["rotations"]})
            self.bus.send("source.completeness.v0",
                          M.key_for("source.completeness.v0", {"SOURCE_NAME": "AUDIT", "SCOPE": self.scope}),
                          M.envelope(self.run_ctx, "audit-collector", "SOURCE_COMPLETENESS", "AUDIT",
                                     "source_completeness", sc))
            self.cov_end = end
        self.bus.heartbeat(self.run_ctx, "audit-collector", "raw.audit.v0", self.cov_end, "AUDIT")
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"cov_end": self.cov_end}, fh)
        os.replace(tmp, self.state_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--base", default="audit.log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--key", required=True, help="pseudonym key required by the reused Gap 2 class")
    ap.add_argument("--poll", type=float, default=0.1)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--instance", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--descriptor-sha256", required=True)
    ap.add_argument("--policy-sha256", required=True)
    ap.add_argument("--chown", default=None)
    args = ap.parse_args()
    os.umask(0o022)
    params = M.load_params()
    bus = M.Bus(args.bootstrap, args.instance)
    c = KafkaCollector(args, bus, M.Run(args.run_id, args.descriptor_sha256, params), params)
    import signal

    def on_term(signum, frame):
        c.stop_signal = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        c.run(os.path.join(args.out, "collector.stop"))
    finally:
        bus.flush()
        c.records.close()
        c.events.close()
        if args.chown:
            uid, gid = (int(x) for x in args.chown.split(":"))
            for name in os.listdir(args.out):
                try:
                    os.chown(os.path.join(args.out, name), uid, gid)
                except OSError:
                    pass


if __name__ == "__main__":
    main()
