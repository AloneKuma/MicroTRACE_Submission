"""Offline fixture tests for the Gap 2 audit/context harness.

These exercise harness logic only (parsing, (auditID, stage) dedup,
redaction, inode-following rotation, stopped-reader gap detection, a
simulated watch 410, Pod IP interval resolution, and a review of the
candidate policy against the probe matrix). They are not cluster validation.

Run from experiments/cluster/audit-context:  python3 -m unittest -v tests.test_harness
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

import collector  # noqa: E402
import probe  # noqa: E402
import summarize  # noqa: E402
from mtk8s import LEVELS, Pseudonymizer  # noqa: E402

spec = importlib.util.spec_from_file_location("context_watch", os.path.join(HERE, "context-watch.py"))
context_watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context_watch)

JTI = "0f3c1a2b-4d5e-4f60-8a71-92b3c4d5e6f7"
POD_UID = "11111111-2222-4333-8444-555555555555"
TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJqdGkiOiJ4In0.sig"


def event(aid, stage="ResponseComplete", ts="2026-09-27T10:00:00.000000Z", **kw):
    ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": aid,
          "stage": stage, "requestURI": "/api/v1/namespaces/n/pods/p?secretparam=abc", "verb": "get",
          "user": {"username": "system:serviceaccount:n:sa", "uid": "x",
                   "groups": ["system:serviceaccounts", "system:serviceaccounts:n", "system:authenticated"],
                   "extra": {"authentication.kubernetes.io/credential-id": ["JTI=" + JTI],
                             "authentication.kubernetes.io/pod-uid": [POD_UID],
                             "authentication.kubernetes.io/pod-name": ["p"],
                             "authentication.kubernetes.io/node-name": ["worker"]}},
          "sourceIPs": ["172.18.0.1"], "userAgent": "curl/8",
          "objectRef": {"resource": "pods", "namespace": "n", "name": "p", "apiVersion": "v1"},
          "responseStatus": {"metadata": {}, "code": 200},
          "requestReceivedTimestamp": ts, "stageTimestamp": ts,
          "annotations": {"authorization.k8s.io/decision": "allow",
                          "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"x\""}}
    ev.update(kw)
    return ev


class Tmp:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="mt-harness-")
        self.audit = os.path.join(self.root, "audit")
        self.out = os.path.join(self.root, "out")
        os.makedirs(self.audit)
        os.makedirs(self.out)
        self.key = os.path.join(self.root, "key")
        with open(self.key, "wb") as fh:
            fh.write(os.urandom(32))

    def args(self, resume=False):
        return argparse.Namespace(dir=self.audit, base="audit.log", out=self.out, key=self.key, poll=0.02,
                                  resume=resume)

    def append(self, name, *lines):
        with open(os.path.join(self.audit, name), "a", encoding="utf-8") as fh:
            for ln in lines:
                fh.write((ln if isinstance(ln, str) else json.dumps(ln)) + "\n")

    def records(self):
        return [json.loads(x) for x in open(os.path.join(self.out, "audit-records.jsonl"), encoding="utf-8")]

    def events(self):
        return [json.loads(x) for x in open(os.path.join(self.out, "collector-events.jsonl"), encoding="utf-8")]

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def run_collector(t, resume=False):
    c = collector.Collector(t.args(resume))
    th = threading.Thread(target=c.run, args=(os.path.join(t.out, "collector.stop"),), daemon=True)
    th.start()
    return c, th


def wait_for(pred, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def finish(c, th, t):
    open(os.path.join(t.out, "collector.stop"), "w").close()
    th.join(timeout=20)
    c.records.close()
    c.events.close()
    os.remove(os.path.join(t.out, "collector.stop"))


class RedactionTests(unittest.TestCase):
    def test_redact_hides_values_keeps_presence(self):
        p = Pseudonymizer_from_bytes()
        ev = event("a1", responseObject={"kind": "TokenRequest", "status": {"token": TOKEN}},
                   requestObject={"kind": "Secret", "metadata": {"uid": POD_UID}, "data": {"k": "c2VjcmV0"}},
                   annotations={"authentication.kubernetes.io/issued-credential-id": "JTI=" + JTI})
        r = collector.redact(ev, p)
        text = json.dumps(r)
        for raw in (JTI, POD_UID, TOKEN, "system:serviceaccount:n:sa", "c2VjcmV0", "abc", "172.18.0.1",
                    "RBAC: allowed"):
            self.assertNotIn(raw, text)
        self.assertEqual(r["user"]["credential_id"]["format"], "JTI=<uuid>")
        self.assertEqual(r["user"]["credential_id"]["value_p"], p("JTI=" + JTI))
        self.assertEqual(r["user"]["pod_uid_p"], p(POD_UID))
        self.assertTrue(r["user"]["node_name_present"])
        self.assertEqual(r["user"]["class"], "serviceaccount")
        self.assertIn("system:serviceaccounts:<namespace>", r["user"]["groups"])
        self.assertTrue(r["annotations"]["issued_credential_id"]["present"])
        self.assertTrue(r["responseObject"]["contains_token_field"])
        self.assertTrue(r["requestObject"]["contains_data_field"])
        self.assertIn("secretparam=<redacted>", r["requestURI"])

    def test_status_response_object(self):
        p = Pseudonymizer_from_bytes()
        ev = event("a3", level="RequestResponse", verb="delete",
                   responseObject={"kind": "Status", "apiVersion": "v1", "status": "Success",
                                   "details": {"name": "r", "kind": "roles", "uid": POD_UID}},
                   requestObject={"kind": "DeleteOptions", "spec": "odd-string"})
        r = collector.redact(ev, p)
        self.assertEqual(r["responseObject"]["kind"], "Status")
        self.assertEqual(r["responseObject"]["uid_p"], p(POD_UID))
        self.assertFalse(r["responseObject"]["contains_token_field"])
        self.assertTrue(collector.redact(event("a4", responseObject="scalar"), p)["responseObject"]["present"])

    def test_failed_authn_shape(self):
        p = Pseudonymizer_from_bytes()
        ev = event("a2", stage="ResponseStarted", user={}, responseStatus={"code": 401})
        r = collector.redact(ev, p)
        self.assertEqual(r["user"]["class"], "empty")
        self.assertFalse(r["user"]["credential_id"]["present"])
        self.assertEqual(r["sourceIPs"]["last_class"], "private-v4")

    def test_summary_redaction_scan(self):
        self.assertTrue(summarize.redaction_scan('{"x": "%s"}' % TOKEN))
        self.assertTrue(summarize.redaction_scan('{"u": "%s"}' % POD_UID))
        self.assertTrue(summarize.redaction_scan("JTI=" + JTI))
        self.assertFalse(summarize.redaction_scan('{"format": "JTI=<uuid>", "ok": true}'))


def Pseudonymizer_from_bytes():
    fd, path = tempfile.mkstemp()
    os.write(fd, os.urandom(32))
    os.close(fd)
    p = Pseudonymizer(path)
    os.remove(path)
    return p


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.t = Tmp()

    def tearDown(self):
        self.t.cleanup()

    def test_parse_dedup_rotation(self):
        t = self.t
        t.append("audit.log", event("a1"), event("a2"), event("a1"), "not json {", event("a3"))
        c, th = run_collector(t)
        self.assertTrue(wait_for(lambda: c.stats["records"] == 3))
        # Rotation: a write lands in the renamed inode after the rename, then a new file appears.
        t.append("audit.log", event("a4"))
        os.rename(os.path.join(t.audit, "audit.log"), os.path.join(t.audit, "audit-2026-09-27T10-00-00.000.log"))
        t.append("audit-2026-09-27T10-00-00.000.log", event("a5"))
        t.append("audit.log", event("a6"), event("a6", stage="ResponseStarted"))
        self.assertTrue(wait_for(lambda: c.stats["records"] == 7))
        finish(c, th, t)
        ids = [(r["auditID"], r["stage"]) for r in t.records()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(c.stats["duplicates"], 1)
        self.assertEqual(c.stats["parse_errors"], 1)
        self.assertEqual(c.stats["rotations"], 1)
        ev = t.events()
        done = [e for e in ev if e["event"] == "file_done"]
        self.assertTrue(done and all(e["fully_read"] for e in done))
        stop = [e for e in ev if e["event"] == "stop"][-1]
        self.assertEqual(stop["mode"], "drained")
        self.assertTrue(stop["end"]["fully_read"])
        srcs = {(r["_src"]["ino"]) for r in t.records()}
        self.assertEqual(len(srcs), 2)  # records attributed to two distinct inodes

    def test_drain_terminates_under_continuous_writes(self):
        t = self.t
        t.append("audit.log", event("d0"))
        c, th = run_collector(t)
        self.assertTrue(wait_for(lambda: c.stats["records"] == 1))
        stop = threading.Event()

        def writer():
            i = 1
            while not stop.is_set():
                t.append("audit.log", event(f"d{i}"))
                i += 1
                time.sleep(0.005)
        w = threading.Thread(target=writer, daemon=True)
        w.start()
        time.sleep(0.3)
        open(os.path.join(t.out, "collector.stop"), "w").close()
        th.join(timeout=10)
        stop.set()
        w.join()
        self.assertFalse(th.is_alive(), "drain did not terminate while the writer kept writing")
        c.records.close()
        c.events.close()
        end = [e for e in t.events() if e["event"] == "stop"][-1]
        self.assertEqual(end["mode"], "drained")
        self.assertGreaterEqual(end["end"]["offset"], end["target"]["size"])

    def test_stopped_reader_overrun_is_a_gap(self):
        t = self.t
        t.append("audit.log", event("b1", ts="2026-09-27T10:00:01.000000Z"),
                 event("b2", ts="2026-09-27T10:00:02.000000Z"))
        c, th = run_collector(t)
        self.assertTrue(wait_for(lambda: c.stats["records"] == 2))
        c.stop_signal = True
        th.join(timeout=10)
        c.records.close()
        c.events.close()
        # While stopped: unread tail, two rotations, oldest backup deleted (maxbackup=1).
        t.append("audit.log", event("b3", ts="2026-09-27T10:00:03.000000Z"))
        os.rename(os.path.join(t.audit, "audit.log"), os.path.join(t.audit, "audit-2026-09-27T10-00-03.000.log"))
        t.append("audit.log", event("b4", ts="2026-09-27T10:00:04.000000Z"),
                 event("b5", ts="2026-09-27T10:00:05.000000Z"))
        os.rename(os.path.join(t.audit, "audit.log"), os.path.join(t.audit, "audit-2026-09-27T10-00-05.000.log"))
        os.remove(os.path.join(t.audit, "audit-2026-09-27T10-00-03.000.log"))
        t.append("audit.log", event("b6", ts="2026-09-27T10:00:06.000000Z"))
        c2, th2 = run_collector(t, resume=True)
        self.assertTrue(wait_for(lambda: c2.stats["records"] == 5))
        finish(c2, th2, t)
        got = {r["auditID"] for r in t.records()}
        self.assertEqual(got, {"b1", "b2", "b4", "b5", "b6"})
        gaps = [e for e in t.events() if e["event"] == "gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["status"], "DROPPED_BEFORE")
        self.assertEqual(gaps[0]["from_stage_ts"], "2026-09-27T10:00:02.000000Z")
        self.assertEqual(gaps[0]["to_stage_ts"], "2026-09-27T10:00:04.000000Z")

    def test_resume_without_loss_has_no_gap(self):
        t = self.t
        t.append("audit.log", event("c1"))
        c, th = run_collector(t)
        self.assertTrue(wait_for(lambda: c.stats["records"] == 1))
        c.stop_signal = True
        th.join(timeout=10)
        c.records.close()
        c.events.close()
        t.append("audit.log", event("c2"))
        os.rename(os.path.join(t.audit, "audit.log"), os.path.join(t.audit, "audit-2026-09-27T11-00-00.000.log"))
        t.append("audit.log", event("c3"))
        c2, th2 = run_collector(t, resume=True)
        self.assertTrue(wait_for(lambda: c2.stats["records"] == 3))
        finish(c2, th2, t)
        self.assertEqual({r["auditID"] for r in t.records()}, {"c1", "c2", "c3"})
        self.assertFalse([e for e in t.events() if e["event"] == "gap"])


class FakeResp:
    def __init__(self, status, lines):
        self.status, self.lines = status, list(lines)

    def readline(self):
        return self.lines.pop(0) if self.lines else b""

    def getheaders(self):
        return []


class FakeConn:
    def close(self):
        pass


class FakeApi:
    def __init__(self, stop):
        self.stop, self.streams, self.lists = stop, 0, 0

    def request(self, method, path, **kw):
        self.lists += 1
        body = {"metadata": {"resourceVersion": str(100 * self.lists)},
                "items": [{"metadata": {"uid": "u1", "resourceVersion": "90", "name": "r", "namespace": "n"}}]}
        return types.SimpleNamespace(status=200, json=lambda: body)

    def stream(self, path, timeout):
        self.streams += 1
        if self.streams == 1:
            return FakeConn(), FakeResp(410, [])
        if self.streams == 2:
            err = {"type": "ERROR", "object": {"kind": "Status", "code": 410, "reason": "Expired"}}
            return FakeConn(), FakeResp(200, [json.dumps(err).encode() + b"\n"])
        self.stop.set()
        return FakeConn(), FakeResp(200, [])


class WatchTests(unittest.TestCase):
    def test_simulated_410_records_gap_not_state(self):
        out = []
        writer = types.SimpleNamespace(write=out.append)
        stop = threading.Event()
        api = FakeApi(stop)
        w = context_watch.ResourceWatcher("roles", api, writer, threading.Lock(), stop, "n", "fixture", "50", False)
        w.run()
        kinds = [r["kind"] for r in out]
        self.assertIn("http_410", kinds)
        self.assertIn("watch_error_event", kinds)
        gaps = [r for r in out if r["kind"] == "watch_gap"]
        self.assertEqual(len(gaps), 2)
        self.assertEqual(gaps[0]["last_rv"], "50")
        self.assertEqual(gaps[0]["state_between"], "UNKNOWN")
        self.assertNotIn("watch_event", kinds)  # snapshot never replayed as events
        self.assertTrue(all(r["kind"] != "relist_item" or r["stream_id"] for r in out))
        self.assertIsNone(w.error)


class IpReuseTests(unittest.TestCase):
    def ctx(self, overlap):
        def ev(t, uid, typ, ip):
            return {"kind": "watch_event", "resource": "pods", "type": typ, "uid": uid,
                    "observed_utc": f"2026-09-27T10:00:{t:02d}.000000Z", "pod": {"ip": ip, "host_network": False}}
        old_end = 30 if overlap else 20
        return [ev(10, "old", "MODIFIED", "10.244.1.5"), ev(old_end, "old", "DELETED", "10.244.1.5"),
                ev(25, "new", "MODIFIED", "10.244.1.5"), ev(40, "new", "MODIFIED", "10.244.1.5"),
                ev(12, "host", "MODIFIED", "172.18.0.3"),
                {"kind": "watch_event", "resource": "pods", "type": "MODIFIED", "uid": "host2",
                 "observed_utc": "2026-09-27T10:00:13.000000Z", "pod": {"ip": "172.18.0.3", "host_network": True}}]

    def test_interval_resolution(self):
        g = types.SimpleNamespace(context=self.ctx(False), state={"ip_reuse": {"created": 2}})
        v = summarize.t_ipreuse(g, None)
        self.assertEqual(v["verdict"], "pass")
        iv = summarize.pod_intervals(g)
        self.assertIsNone(summarize.resolve(iv, "10.244.1.5", summarize.parse_ts("2026-09-27T10:00:22Z")))
        self.assertNotIn("host2", iv)

    def test_overlap_is_uncertain(self):
        g = types.SimpleNamespace(context=self.ctx(True), state={})
        iv = summarize.pod_intervals(g)
        self.assertEqual(summarize.resolve(iv, "10.244.1.5", summarize.parse_ts("2026-09-27T10:00:27Z")),
                         "JOIN_UNCERTAIN")


def rule_matches(rule, req):
    if rule.get("verbs") and req["verb"] not in rule["verbs"]:
        return False
    if rule.get("resources"):
        if req.get("non_resource_url"):
            return False
        name = req["resource"] + ("/" + req["subresource"] if req["subresource"] else "")
        return any(g.get("group", "") == req["group"] and (name in g.get("resources", []) or
                                                            not g.get("resources"))
                   for g in rule["resources"])
    return True


class PolicyReviewTests(unittest.TestCase):
    """Review the exact candidate policy against the emitted probe matrix."""

    @classmethod
    def setUpClass(cls):
        import yaml
        with open(os.path.join(REPO, "spec", "audit", "audit-policy.v0.yaml"), encoding="utf-8") as fh:
            cls.policy = yaml.safe_load(fh)
        with open(os.path.join(REPO, "spec", "rules", "rulebook.v0.yaml"), encoding="utf-8") as fh:
            cls.rulebook = yaml.safe_load(fh)

    def evaluate(self, req):
        for i, rule in enumerate(self.policy["rules"]):
            if rule_matches(rule, req):
                return i, rule["level"], set(rule.get("omitStages", [])) | set(self.policy.get("omitStages", []))
        return None, "None", set()

    def test_probe_matrix_covers_every_requirement(self):
        cells = {(v, g, r, s, a, n) for v, g, r, s, a, n in probe.PROBE_COVERAGE}
        missing = []
        for rule in self.rulebook["findings"]:
            for q in rule.get("audit_requirements") or []:
                for verb in q["verbs"]:
                    cell = (verb, q["group"], q["resource"], q["subresource"], q["authenticated"],
                            q.get("non_resource_url"))
                    if cell not in cells:
                        missing.append((rule["id"], cell))
        self.assertEqual(missing, [])

    def test_candidate_policy_predicts_required_levels(self):
        bad = []
        for rule in self.rulebook["findings"]:
            for q in rule.get("audit_requirements") or []:
                for verb in q["verbs"]:
                    idx, level, omit = self.evaluate({"verb": verb, "group": q["group"], "resource": q["resource"],
                                                      "subresource": q["subresource"],
                                                      "non_resource_url": q.get("non_resource_url")})
                    if LEVELS[level] < LEVELS[q["min_level"]] or set(q["stages"]) & omit:
                        bad.append((rule["id"], verb, q["resource"], level, idx))
        self.assertEqual(bad, [])

    def test_credential_probes_capped_at_metadata(self):
        for v, g, r, s, a, n in probe.PROBE_COVERAGE:
            if (g, r, s) in summarize.CRED_RESOURCES:
                _, level, _ = self.evaluate({"verb": v, "group": g, "resource": r, "subresource": s,
                                             "non_resource_url": n})
                self.assertLessEqual(LEVELS[level], LEVELS["Metadata"], (v, r, s))


if __name__ == "__main__":
    unittest.main()
