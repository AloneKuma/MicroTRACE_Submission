#!/usr/bin/env python3
"""Tail a kube-apiserver JSON audit log and emit redacted field-presence records.

File identity is (st_dev, st_ino, byte offset). The collector follows the
inode it has open until EOF, so a rename-based rotation (lumberjack) is drained
before the new file is opened. Records are deduplicated by (auditID, stage) within
one collector session; a resume continues from the checkpointed byte offset,
so it does not re-read records.
Raw requestObject/responseObject, tokens and identities never leave this
process: only presence, sizes, kinds, classes and run-local pseudonyms.

Usage:
  collector.py --dir /var/log/kubernetes/audit --base audit.log --out OUT --key KEY [--resume]
Stop cleanly by creating OUT/collector.stop: the live file's size at that
moment is recorded as the drain target and read to, then the end offset is
recorded (the API server keeps writing; later bytes are outside the run).
SIGTERM stops without draining (used for the stopped-reader fault).
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtk8s import (Pseudonymizer, JsonlWriter, credential_id_format, parse_ts,  # noqa: E402
                   utc_now, write_json_atomic)

BUILTIN_GROUPS = {"system:authenticated", "system:unauthenticated", "system:serviceaccounts",
                  "system:masters", "system:nodes", "system:bootstrappers", "kubeadm:cluster-admins",
                  "system:monitoring"}
URI_KEEP = {"command", "container", "stdin", "stdout", "stderr", "tty", "watch", "resourceVersion",
            "resourceVersionMatch", "allowWatchBookmarks", "timeoutSeconds", "limit", "dryRun",
            "fieldManager", "gracePeriodSeconds", "propagationPolicy", "sendInitialEvents"}
EXTRA = "authentication.kubernetes.io/"
FP_BYTES = 1024


# ------------------------------------------------------------------ redaction

def user_class(name):
    if not name:
        return "empty"
    if name == "system:anonymous":
        return "anonymous"
    if name.startswith("system:serviceaccount:"):
        return "serviceaccount"
    if name.startswith("system:node:"):
        return "node"
    if name.startswith("system:"):
        return "system-component"
    return "other-user"


def group_class(g):
    if g in BUILTIN_GROUPS:
        return g
    if g.startswith("system:serviceaccounts:"):
        return "system:serviceaccounts:<namespace>"
    return "other-group"


def ip_class(ip):
    if not ip:
        return None
    if ip.startswith("127.") or ip == "::1":
        return "loopback"
    parts = ip.split(".")
    if len(parts) == 4 and all(x.isdigit() for x in parts):
        a, b = int(parts[0]), int(parts[1])
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            return "private-v4"
        return "public-v4"
    return "v6"


def sanitize_uri(uri):
    if not uri:
        return None
    path, _, query = uri.partition("?")
    if not query:
        return path
    kept = []
    for part in query.split("&"):
        k, _, v = part.partition("=")
        kept.append(f"{k}={v}" if k in URI_KEEP else f"{k}=<redacted>")
    return path + "?" + "&".join(kept)


def extra_value(extra, key):
    v = (extra or {}).get(EXTRA + key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def object_summary(obj, p):
    if obj is None:
        return {"present": False}
    if not isinstance(obj, dict):
        return {"present": True, "bytes": len(json.dumps(obj)), "kind": None, "uid_p": None}
    meta = obj.get("metadata") or {}
    details = obj.get("details") or {}
    out = {"present": True,
           "bytes": len(json.dumps(obj, separators=(",", ":"))),
           "kind": obj.get("kind"),
           "uid_p": p(meta.get("uid") or details.get("uid")),
           "resource_version": meta.get("resourceVersion")}
    if "rules" in obj:
        out["rules_count"] = len(obj.get("rules") or [])
    if "subjects" in obj:
        out["subjects_count"] = len(obj.get("subjects") or [])
    if "roleRef" in obj:
        out["role_ref_present"] = True
    # Credential-bearing shapes are flagged, never copied.
    status, spec = obj.get("status"), obj.get("spec")
    out["contains_token_field"] = bool(isinstance(status, dict) and status.get("token")) or         (isinstance(spec, dict) and "token" in spec)
    out["contains_data_field"] = "data" in obj or "stringData" in obj
    return out


def redact(ev, p):
    user = ev.get("user") or {}
    extra = user.get("extra") or {}
    ann = ev.get("annotations") or {}
    ref = ev.get("objectRef") or {}
    src = ev.get("sourceIPs") or []
    cred = extra_value(extra, "credential-id")
    issued = ann.get(EXTRA + "issued-credential-id")
    imp = ev.get("impersonatedUser")
    ua = ev.get("userAgent") or ""
    return {
        "auditID": ev.get("auditID"),
        "stage": ev.get("stage"),
        "level": ev.get("level"),
        "verb": ev.get("verb"),
        "requestURI": sanitize_uri(ev.get("requestURI")),
        "requestReceivedTimestamp": ev.get("requestReceivedTimestamp"),
        "stageTimestamp": ev.get("stageTimestamp"),
        "objectRef": {k: ref.get(k) for k in ("resource", "subresource", "apiGroup", "apiVersion",
                                              "namespace", "name")} | {"uid_p": p(ref.get("uid"))}
        if ref else None,
        "responseStatus": {"code": (ev.get("responseStatus") or {}).get("code"),
                           "reason": (ev.get("responseStatus") or {}).get("reason"),
                           "status": (ev.get("responseStatus") or {}).get("status")}
        if ev.get("responseStatus") is not None else None,
        "user": {
            "class": user_class(user.get("username")),
            "username_p": p(user.get("username")),
            "uid_present": bool(user.get("uid")),
            "groups": sorted({group_class(g) for g in user.get("groups") or []}),
            "extra_keys": sorted(extra.keys()),
            "credential_id": {"present": cred is not None, "format": credential_id_format(cred),
                              "value_p": p(cred)},
            "pod_uid_p": p(extra_value(extra, "pod-uid")),
            "pod_name_p": p(extra_value(extra, "pod-name")),
            "node_name_present": extra_value(extra, "node-name") is not None,
            "node_uid_present": extra_value(extra, "node-uid") is not None,
        },
        "impersonated": {"present": imp is not None,
                         "class": user_class((imp or {}).get("username")) if imp else None},
        "sourceIPs": {"count": len(src), "last_p": p(src[-1]) if src else None,
                      "last_class": ip_class(src[-1]) if src else None},
        "userAgent_product": ua.split("/")[0][:40] if ua else None,
        "annotations": {
            "keys": sorted(ann.keys()),
            "issued_credential_id": {"present": issued is not None,
                                     "format": credential_id_format(issued), "value_p": p(issued)},
            "truncated": ann.get("audit.k8s.io/truncated"),
            "authz_decision": ann.get("authorization.k8s.io/decision"),
        },
        "requestObject": object_summary(ev.get("requestObject"), p),
        "responseObject": object_summary(ev.get("responseObject"), p),
    }


# ------------------------------------------------------------------ tailing

class Collector:
    def __init__(self, args):
        self.dir = args.dir
        self.base = os.path.join(args.dir, args.base)
        self.prefix = os.path.splitext(args.base)[0] + "-"
        self.out = args.out
        self.poll = args.poll
        self.p = Pseudonymizer(args.key)
        self.records = JsonlWriter(os.path.join(args.out, "audit-records.jsonl"))
        self.events = JsonlWriter(os.path.join(args.out, "collector-events.jsonl"))
        self.ck_path = os.path.join(args.out, "checkpoint.json")
        self.seen = set()
        self.stats = {"records": 0, "duplicates": 0, "parse_errors": 0, "missing_audit_id": 0,
                      "bytes_read": 0, "rotations": 0, "gaps": 0}
        self.fh = None
        self.cur = None           # {"dev","ino","path","offset"}
        self.partial = b""
        self.last_stage_ts = None
        self.pending_gap = None
        self.queue = []           # static backup files to read before tailing base
        self.done_inodes = set()  # (dev, ino) read to EOF after rotation
        self.stop_signal = False
        self.max_lag = 0.0
        self.lags = []
        self.last_ck = 0.0
        if args.resume and os.path.exists(self.ck_path):
            with open(self.ck_path, encoding="utf-8") as fh:
                ck = json.load(fh)
            self.stats.update({k: ck["stats"][k] for k in self.stats if k in ck.get("stats", {})})
            self.last_stage_ts = ck.get("last_stage_ts")
            self._resume(ck)
        else:
            self.events.write({"event": "start", "utc": utc_now(), "mode": "fresh"})

    # --- file helpers
    def _files(self):
        """Rotated backups (lumberjack name order == time order) then the live file."""
        backups = sorted(f for f in os.listdir(self.dir)
                         if f.startswith(self.prefix) and f.endswith(".log"))
        out = []
        for name in backups + [os.path.basename(self.base)]:
            path = os.path.join(self.dir, name)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            out.append({"path": path, "dev": st.st_dev, "ino": st.st_ino, "size": st.st_size})
        return out

    def _open(self, entry, offset):
        self.fh = open(entry["path"], "rb")
        st = os.fstat(self.fh.fileno())
        if (st.st_dev, st.st_ino) != (entry["dev"], entry["ino"]):
            # Replaced between stat and open; retry from the listing.
            self.fh.close()
            self.fh = None
            return False
        self.fh.seek(offset)
        self.cur = {"dev": st.st_dev, "ino": st.st_ino, "path": entry["path"], "offset": offset}
        self.partial = b""
        self.events.write({"event": "open", "utc": utc_now(), "dev": st.st_dev, "ino": st.st_ino,
                           "file": os.path.basename(entry["path"]), "offset": offset, "size": st.st_size})
        return True

    @staticmethod
    def _fingerprint(path_or_fd, length):
        """SHA-256 of the first `length` bytes: guards against inode-number reuse
        after lumberjack deletes a backup and creates a new file."""
        if length <= 0:
            return None
        if isinstance(path_or_fd, int):
            data = os.pread(path_or_fd, length, 0)
        else:
            with open(path_or_fd, "rb") as fh:
                data = fh.read(length)
        return hashlib.sha256(data).hexdigest() if len(data) == length else None

    def _same_file(self, f, ck):
        if (f["dev"], f["ino"]) != (ck["dev"], ck["ino"]):
            return False
        if not ck.get("fp_len"):
            return True
        try:
            return self._fingerprint(f["path"], ck["fp_len"]) == ck.get("fp")
        except OSError:
            return False

    def _resume(self, ck):
        files = self._files()
        idx = next((i for i, f in enumerate(files) if self._same_file(f, ck)), None)
        self.events.write({"event": "start", "utc": utc_now(), "mode": "resume",
                           "checkpoint": {"dev": ck["dev"], "ino": ck["ino"], "offset": ck["offset"]},
                           "files_present": [{"file": os.path.basename(f["path"]), "dev": f["dev"],
                                              "ino": f["ino"], "size": f["size"]} for f in files]})
        if idx is None:
            # The inode we were reading is gone: its unread tail and any file
            # rotated away entirely while we were stopped cannot be recovered.
            self.pending_gap = {"event": "gap", "status": "DROPPED_BEFORE",
                                "reason": "checkpoint file (inode + content fingerprint) no longer present: "
                                          "deleted by rotation before it was fully read",
                                "lost_inode": ck["ino"], "lost_from_offset": ck["offset"],
                                "from_stage_ts": ck.get("last_stage_ts"), "detected_utc": utc_now()}
            self.stats["gaps"] += 1
            self.queue = files[:-1]
            live = files[-1] if files else None
            start = self.queue.pop(0) if self.queue else live
            if start:
                self._open(start, 0)
        else:
            f = files[idx]
            if f["size"] < ck["offset"]:
                self.events.write({"event": "anomaly", "utc": utc_now(), "reason": "inode shorter than checkpoint"})
            # Later backups are read in order; the live file is picked up by
            # _advance() when the base path's inode differs from the current one.
            self.queue = files[idx + 1:-1] if idx < len(files) - 1 else []
            self._open(f, ck["offset"])

    # --- processing
    def _process_line(self, line, offset):
        try:
            ev = json.loads(line)
        except ValueError:
            self.stats["parse_errors"] += 1
            self.events.write({"event": "parse_error", "utc": utc_now(), "ino": self.cur["ino"],
                               "offset": offset, "length": len(line)})
            return
        aid, stage = ev.get("auditID"), ev.get("stage")
        if not aid:
            self.stats["missing_audit_id"] += 1
        key = (aid, stage)
        if key in self.seen:
            self.stats["duplicates"] += 1
            return
        self.seen.add(key)
        now = time.time()
        st = parse_ts(ev.get("stageTimestamp"))
        lag = (now - st) if st is not None else None
        try:
            rec = redact(ev, self.p)
        except Exception as exc:  # an unexpected shape is a recorded gap, never a crash
            self.stats["redact_errors"] = self.stats.get("redact_errors", 0) + 1
            self.events.write({"event": "redact_error", "utc": utc_now(), "ino": self.cur["ino"],
                               "offset": offset, "stage": stage, "error": type(exc).__name__})
            return
        rec["_src"] = {"dev": self.cur["dev"], "ino": self.cur["ino"], "offset": offset,
                       "length": len(line), "read_utc": utc_now(),
                       "collector_lag_s": round(lag, 6) if lag is not None else None}
        if self.pending_gap is not None:
            self.pending_gap["to_stage_ts"] = ev.get("stageTimestamp")
            self.events.write(self.pending_gap)
            self.pending_gap = None
        self.records.write(rec)
        self.stats["records"] += 1
        if lag is not None:
            self.lags.append(lag)
        self.last_stage_ts = ev.get("stageTimestamp")

    def _read_available(self):
        got = False
        while True:
            chunk = self.fh.read(1 << 16)
            if not chunk:
                return got
            got = True
            self.stats["bytes_read"] += len(chunk)
            buf = self.partial + chunk
            start_off = self.cur["offset"] - len(self.partial)
            lines = buf.split(b"\n")
            self.partial = lines.pop()
            pos = start_off
            for ln in lines:
                if ln.strip():
                    self._process_line(ln, pos)
                pos += len(ln) + 1
            self.cur["offset"] += len(chunk)

    def _finish_current(self, reason):
        self._read_available()
        size = os.fstat(self.fh.fileno()).st_size
        if self.partial:
            self.stats["parse_errors"] += 1
            self.events.write({"event": "parse_error", "utc": utc_now(), "ino": self.cur["ino"],
                               "offset": self.cur["offset"] - len(self.partial),
                               "length": len(self.partial), "reason": "partial line at end of file"})
        self.events.write({"event": "file_done", "utc": utc_now(), "reason": reason,
                           "dev": self.cur["dev"], "ino": self.cur["ino"],
                           "end_offset": self.cur["offset"], "size": size,
                           "fully_read": self.cur["offset"] == size})
        self.done_inodes.add((self.cur["dev"], self.cur["ino"]))
        self.fh.close()
        self.fh = None

    def checkpoint(self, final=False):
        if not self.cur:
            return
        fp_len = min(self.cur["offset"], FP_BYTES)
        write_json_atomic(self.ck_path, {
            "dev": self.cur["dev"], "ino": self.cur["ino"], "offset": self.cur["offset"],
            "fp_len": fp_len, "fp": self._fingerprint(self.fh.fileno(), fp_len) if self.fh else None,
            "last_stage_ts": self.last_stage_ts, "utc": utc_now(), "final": final,
            "stats": self.stats})
        self.last_ck = time.time()

    def _advance(self):
        """At EOF: move to the next queued backup, or detect rotation of the live file."""
        if self.queue:
            self._finish_current("backup read to EOF")
            nxt = self.queue.pop(0)
            if not self._open(nxt, 0):
                self.queue.insert(0, nxt)
            return
        try:
            st = os.stat(self.base)
        except FileNotFoundError:
            return  # between rename and create; keep draining current inode
        if (st.st_dev, st.st_ino) != (self.cur["dev"], self.cur["ino"]):
            self._finish_current("rotated")
            self.stats["rotations"] += 1
            self.events.write({"event": "rotation", "utc": utc_now(), "new_dev": st.st_dev,
                               "new_ino": st.st_ino})
            self._open({"path": self.base, "dev": st.st_dev, "ino": st.st_ino}, 0)
        elif st.st_size < self.cur["offset"]:
            self.events.write({"event": "anomaly", "utc": utc_now(),
                               "reason": "live file truncated in place", "offset": self.cur["offset"],
                               "size": st.st_size})

    def _drain_target(self):
        """End offset recorded when the stop is requested: the live file's size then."""
        try:
            st = os.stat(self.base)
            t = {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size}
        except FileNotFoundError:
            t = {"dev": self.cur["dev"], "ino": self.cur["ino"], "size": os.fstat(self.fh.fileno()).st_size}
        self.events.write({"event": "drain_target", "utc": utc_now(), **t})
        return t

    def _reached(self, t):
        if (t["dev"], t["ino"]) in self.done_inodes:
            return True
        return (self.cur["dev"], self.cur["ino"]) == (t["dev"], t["ino"]) and self.cur["offset"] >= t["size"]

    def run(self, stop_path):
        while self.fh is None:
            files = self._files()
            if files and self._open(files[-1] if not self.queue else self.queue.pop(0), 0):
                break
            time.sleep(self.poll)
        target = None
        while True:
            if self.stop_signal:
                self.checkpoint(final=False)
                self.events.write({"event": "stop", "utc": utc_now(), "mode": "signal", "stats": self.stats})
                return
            got = self._read_available()
            if not got:
                self._advance()
            if target is None and os.path.exists(stop_path):
                target = self._drain_target()
            if target is not None and not self.queue and self._reached(target):
                size = os.fstat(self.fh.fileno()).st_size
                self.checkpoint(final=True)
                lags = sorted(self.lags)
                # The API server keeps writing after the target; bytes past it
                # are simply outside this run's collection interval.
                self.events.write({"event": "stop", "utc": utc_now(), "mode": "drained",
                                   "target": target,
                                   "end": {"dev": self.cur["dev"], "ino": self.cur["ino"],
                                           "offset": self.cur["offset"], "size_at_stop": size,
                                           "reached_target": True,
                                           "fully_read": self.cur["offset"] >= target["size"]
                                           if (self.cur["dev"], self.cur["ino"]) == (target["dev"], target["ino"])
                                           else True},
                                   "stats": self.stats, "lag_s": summarize_lags(lags)})
                return
            if not got:
                time.sleep(self.poll)
            if time.time() - self.last_ck > 1.0:
                self.checkpoint()


def summarize_lags(lags):
    if not lags:
        return None

    def q(p):
        return round(lags[min(len(lags) - 1, int(p * len(lags)))], 6)
    return {"n": len(lags), "p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "max": round(lags[-1], 6)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--base", default="audit.log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--poll", type=float, default=0.1)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--chown", default=None, help="uid:gid to own output files (container runs as root)")
    args = ap.parse_args()
    # Output files are world-readable by mode but live in the run's mode-0700
    # private directory, so the unprivileged host user can read checkpoints
    # while this root container is still running.
    os.umask(0o022)
    c = Collector(args)

    def on_term(signum, frame):
        c.stop_signal = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        c.run(os.path.join(args.out, "collector.stop"))
    except Exception:
        import traceback
        c.events.write({"event": "crash", "utc": utc_now(), "traceback": traceback.format_exc()})
        traceback.print_exc()
        raise
    finally:
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
