"""End to end (build step 4): shipper -> receiver -> norm.events.v0 ->
restreamer -> agents A-H -> findings.v0 / rule.evaluations.v0, on the dev
Kafka. The online result equals the offline engine on the same events; with
transit loss the run only loses findings (never gains one) and abstains on
the lost intervals. Skipped when Kafka is not reachable."""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid

import pytest
from google.protobuf import json_format

import agent_fixtures as F
import test_agent_c as C
import test_agent_e as E
import test_agent_g as G
import test_agent_h as H
from agent_testlib import params
from mtcore import REPO
from mtcore.agents.engine import run_offline
from mtcore.agents.rules import ALL
from mtcore.kafka_topics import DEV_CONFIG, ensure_topics
from shipping_rig import (RUNNING, KafkaWindow, Receiver, Shipper, build_binaries, make_certs, stop_all,
                          write_lines, write_plan)
from test_faults import BOOTSTRAP, _kafka_up

pytestmark = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")
PYDIR = os.path.join(REPO, "src", "python")
OUT = ["findings.v0", "rule.evaluations.v0"]


@pytest.fixture(scope="module")
def binaries():
    build_binaries()
    _, _, _, problems = ensure_topics(BOOTSTRAP, DEV_CONFIG)
    assert not problems, problems


@pytest.fixture
def certs(binaries, world, tmp_path_factory):
    return make_certs(str(tmp_path_factory.mktemp("certs")), [F.NODE])


@pytest.fixture(autouse=True)
def cleanup():
    yield
    stop_all()


@pytest.fixture
def world(monkeypatch):
    """Events on a time base no earlier run used: 1000 s of event time per
    real second, so two runs are always further apart than any window, and
    closed gaps or context left in the shared Kafka by an earlier run cannot
    overlap. Each run also ships as its own node: an earlier run's receiver
    may have left an open SOURCE_IDLE gap on its node, which the agents
    re-read from the side topics and which this run's first eBPF event of
    that node would close, so it would cover this run's first windows."""
    monkeypatch.setattr(F, "T0", 1_924_992_000 + (int(time.time()) - 1_791_460_800) * 1000)
    monkeypatch.setattr(F, "NODE", f"node-{uuid.uuid4().hex[:8]}")
    pods = [F.pod(-50, uid=E.POD, owner="checkout", containers=(("checkout", 0, "containerd://c1", -40),)),
            F.pod(-50, uid="pod-payments-1", owner="payments"), F.pod(-50, uid="pod-db-1", owner="orders-db")]
    events = [F.gateway(1, matches=[("sqli-union", "QUERY")], indicators=["row-dump"]),
              *[F.audit(2 + i * 0.1, verb="list", resource=f"r{i}") for i in range(6)],
              C.ns_change(3, op="NS_SAMPLE", family="ns.sample", before=None, after=C.CONT), C.ns_change(4),
              E.write(5, seq=10), E.exec_(9, ino=777, seq=12), E.exec_(12, seq=13),
              G.exec_request(14), G.target_exec(14.5), G.connect(15, "pod-db-1", 5432),
              H.data_read(16, seq=200), H.ext_connect(17, seq=201), H.flow_bytes(18, 5000, seq=202),
              F.db_read(19), F.path_flow(20, 40, octets=900)]
    return pods, events


def lines(pods, events, end_s):
    out = []
    for _topic, env in pods:
        out.append({"lane": "NORMAL", "topic": "context.cluster.v0", "key_type": "KEY_OBJECT_UID",
                    "key_components": [env.context_observation.uid], "envelope": json_format.MessageToDict(env)})
    for env in sorted(events, key=lambda e: (e.normalized_event.time.event_time.ToNanoseconds(), e.logical_id)):
        t = env.normalized_event.time.event_time
        out.append({"lane": "NORMAL", "topic": "norm.events.v0", "key_type": "KEY_PRIMARY_ENTITY",
                    "key_components": ["EVENT", env.logical_id], "envelope": json_format.MessageToDict(env)})
        out.append({"lane": "NORMAL", "watermark": t.ToJsonString()})
    out.append({"lane": "NORMAL", "watermark": F.ts(end_s).ToJsonString()})
    return out


class Proc:
    """A Python CLI subprocess; waits for its "ready" line on stderr."""

    def __init__(self, workdir, name, args, env=None):
        self.log = []
        self.proc = subprocess.Popen([sys.executable, "-m", *args], cwd=PYDIR, stderr=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL, text=True, env=dict(os.environ, **(env or {})))
        RUNNING.append(self.proc)
        self.path = os.path.join(workdir, f"{name}.log")
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        with open(self.path, "w") as fh:
            for line in self.proc.stderr:
                self.log.append(line)
                fh.write(line)

    def wait_ready(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            if any(line.strip() == "ready" for line in self.log):
                return
            assert self.proc.poll() is None, "".join(self.log)
            time.sleep(0.2)
        raise TimeoutError("".join(self.log))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(30)


def run_pipeline(tmp_path, certs, pods, events, extra_shipper=()):
    tag = uuid.uuid4().hex[:8]
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP, extra=["-heartbeat", "500ms"]).start()
    win = KafkaWindow(BOOTSTRAP, OUT)
    rs = Proc(str(tmp_path), "restreamer", ["mtcore.restream", "--bootstrap", BOOTSTRAP, "--group", f"rs-{tag}",
                                            "--instance", f"rs-{tag}", "--from-latest", "--heartbeat-ms", "500"])
    ag = Proc(str(tmp_path), "agents", ["mtcore.agents.run", "--bootstrap", BOOTSTRAP, "--group", f"ag-{tag}",
                                        "--instance", f"ag-{tag}", "--from-latest", "--heartbeat-ms", "500"])
    rs.wait_ready()
    ag.wait_ready()
    inp = write_lines(str(tmp_path / "input.jsonl"), lines(pods, events, 5000))
    sh = Shipper(str(tmp_path), certs, rx.port, F.NODE, extra=list(extra_shipper)).start(inp)
    assert sh.wait(120) == 0, sh.log()
    ids = {e.logical_id for e in events}
    # Results are complete once the evaluation count stops growing.
    last, stable_since, recs = -1, time.time(), []
    deadline = time.time() + 120
    while time.time() < deadline:
        time.sleep(2)
        recs = win.read()
        n = sum(1 for r in recs if r["env"].HasField("rule_evaluation"))
        if n != last:
            last, stable_since = n, time.time()
        elif n > 0 and time.time() - stable_since > 6:
            break
    ag.stop()
    rs.stop()
    rx.stop()
    win.close()
    findings = {r["env"].finding.finding_id: r["env"].finding for r in recs if r["env"].HasField("finding")
                and set(r["env"].finding.input_event_ids) <= ids}
    evals = {r["env"].rule_evaluation.evaluation_id: r["env"].rule_evaluation for r in recs
             if r["env"].HasField("rule_evaluation") and set(r["env"].rule_evaluation.input_event_ids) <= ids}
    beats = [r for r in recs if r["env"].HasField("heartbeat") and r["env"].heartbeat.producer_instance == f"ag-{tag}"]
    return findings, evals, beats


def test_online_pipeline_equals_offline_engine(tmp_path, certs, world):
    pods, events = world
    want_f, want_e, _ = run_offline(ALL, params(), F.stream(*pods, *events))
    findings, evals, beats = run_pipeline(tmp_path, certs, pods, events)
    assert len(want_f) >= 8
    assert sorted(findings) == sorted(f.finding_id for f in want_f)
    assert sorted(evals) == sorted(e.evaluation_id for e in want_e)
    assert {(e.evaluation_id, e.outcome) for e in evals.values()} == {(e.evaluation_id, e.outcome) for e in want_e}
    assert beats and {b["partition"] for b in beats if b["topic"] == "findings.v0"}   # promises on findings.v0


def test_transit_loss_only_removes_findings_and_abstains(tmp_path, certs, world):
    pods, events = world
    want_f, _, _ = run_offline(ALL, params(), F.stream(*pods, *events))
    plan = write_plan(str(tmp_path / "plan.yaml"), 11, [{"id": "loss", "kind": "loss", "stage": "transit", "rate": 0.3}])
    flog = str(tmp_path / "transit.jsonl")
    findings, evals, _ = run_pipeline(tmp_path, certs, pods, events, extra_shipper=["-faults", plan, "-fault-log", flog])
    dropped = [json.loads(x) for x in open(flog) if x.strip() and "header" not in x]
    assert dropped, "the plan dropped nothing; choose another seed"
    assert set(findings) <= {f.finding_id for f in want_f}
    assert len(findings) < len(want_f)
    assert any(r == 2 for e in evals.values() for r in e.abstain_reasons)   # DROPPED_BEFORE
