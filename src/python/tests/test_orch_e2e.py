"""End to end (build step 5e): findings.v0 + norm.events.v0 on the dev Kafka
-> orchestrator runner -> witness.decisions.v0 / incidents.v0. The online
decisions equal the offline engine's on the same records, and the runner
heartbeats every output partition. Skipped when confluent_kafka or Kafka is
not available."""
import io
import json
import os
import socket
import time
import uuid

import pytest

pytest.importorskip("confluent_kafka")
BOOTSTRAP = os.environ.get("MT_KAFKA", "127.0.0.1:9092")


def _kafka_up():
    host, port = BOOTSTRAP.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")

from confluent_kafka import Producer  # noqa: E402
from google.protobuf import json_format  # noqa: E402

import agent_fixtures as F  # noqa: E402
import orch_fixtures as O  # noqa: E402
import test_orch_witness as TW  # noqa: E402
from microtrace.v0 import incident_pb2, witness_pb2  # noqa: E402
from mtcore.kafka_topics import DEV_CONFIG, ensure_topics  # noqa: E402
from mtcore.orchestrator import emit  # noqa: E402
from mtcore.orchestrator.run import run_file  # noqa: E402
from shipping_rig import KafkaWindow, stop_all  # noqa: E402
from test_agents_e2e import Proc  # noqa: E402

FND, NORM = "findings.v0", "norm.events.v0"
END = 5000


@pytest.fixture(autouse=True)
def cleanup():
    yield
    stop_all()


@pytest.fixture
def world(monkeypatch):
    """Records on a time base no earlier run used, from a node of their own
    (see test_agents_e2e.world): loss records and open SOURCE_IDLE gaps left
    in source.completeness.v0, read from the start, cannot overlap them."""
    monkeypatch.setattr(F, "T0", 1_924_992_000 + (int(time.time()) - 1_791_460_800) * 1000)
    tag = uuid.uuid4().hex[:8]
    monkeypatch.setattr(F, "NODE", f"node-{tag}")
    e1, e2 = TW.proc(1, 10, lineage=f"ln-{tag}"), TW.proc(5, 11, lineage=f"ln-{tag}")
    e3, e4 = TW.proc(20, 30, lineage=f"lx-{tag}"), TW.proc(24, 31, lineage=f"lx-{tag}", host=True)
    recs = [(NORM, e) for e in (e1, e2, e3, e4)]
    recs += [(FND, TW.fnd(f"f1-{tag}", e1)), (FND, TW.fnd(f"f2-{tag}", e2)),
             (FND, TW.fnd(f"f3-{tag}", e3)), (FND, TW.fnd(f"f4-{tag}", e4))]
    return tag, recs


def heartbeats(partitions, instance):
    """Promises to END, stamped with the wall clock as a real producer stamps
    them: the orchestrator advances only once its clock has passed the
    emitted_at behind the watermark (knowledge time, step 7g), and END lies
    years ahead on this test's time base."""
    now = time.time() - F.T0                  # fixture seconds
    return [(t, O.hb(t, p, END, now, instance=instance)) for t in (FND, NORM) for p in range(partitions[t])]


def latest_incidents(incs):
    """Latest record per incident ID (Kafka keeps per-key order)."""
    out = {}
    for inc in incs:
        out[inc.incident_id] = inc
    return {k: (v.status, v.version, list(v.finding_ids)) for k, v in out.items()}


def test_online_runner_equals_offline_engine(tmp_path, world):
    tag, recs = world
    _, _, _, problems = ensure_topics(BOOTSTRAP, DEV_CONFIG)
    assert not problems, problems
    win = KafkaWindow(BOOTSTRAP, emit.OUT_TOPICS)
    md = win.c.list_topics(timeout=10).topics
    parts = {t: len(md[t].partitions) for t in (FND, NORM, *emit.OUT_TOPICS)}
    beats = heartbeats(parts, f"in-{tag}")

    path = tmp_path / "records.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for topic, env in recs + beats:
            fh.write(json.dumps({"topic": topic, "envelope": json_format.MessageToDict(env)}) + "\n")
    buf = io.StringIO()
    run_file(O.oparams(), str(path), out=buf)
    offline = [json.loads(x) for x in buf.getvalue().splitlines()]
    want_w = {(r["record"]["witnessId"], r["record"]["status"]) for r in offline if r["topic"] == emit.WITNESS_TOPIC}
    assert len(want_w) >= 2

    orch = Proc(str(tmp_path), "orchestrator", ["mtcore.orchestrator.run", "--bootstrap", BOOTSTRAP,
                                                "--group", f"orch-{tag}", "--instance", f"orch-{tag}",
                                                "--from-latest"])
    orch.wait_ready()
    prod = Producer({"bootstrap.servers": BOOTSTRAP})
    for topic, env in recs:
        prod.produce(topic, value=env.SerializeToString(), key=env.logical_id.encode())
    prod.flush(30)
    for topic, env in beats:                  # after the records: the promise covers them
        prod.produce(topic, value=env.SerializeToString(), partition=env.heartbeat.partition,
                     key=emit.instance_key(f"in-{tag}"))
    prod.flush(30)

    ours = lambda w: tag in w.source_finding_id  # noqa: E731
    got, last, stable_since, deadline = [], -1, time.time(), time.time() + 120
    while time.time() < deadline:
        time.sleep(2)
        got = win.read()
        n = sum(1 for r in got if r["env"].HasField("witness") and ours(r["env"].witness))
        if n != last:
            last, stable_since = n, time.time()
        elif n > 0 and time.time() - stable_since > 6:
            break
    orch.stop()
    win.close()
    online_w = {(r["env"].witness.witness_id, r["env"].witness.status) for r in got
                if r["env"].HasField("witness") and ours(r["env"].witness)}
    assert {(w, witness_pb2.WitnessStatus.Name(st)) for w, st in online_w} == want_w

    want_i = latest_incidents(json_format.ParseDict(r["record"], incident_pb2.Incident()) for r in offline
                              if r["topic"] == emit.INCIDENT_TOPIC and tag in r["record"]["anchorFindingId"])
    online_i = latest_incidents(r["env"].incident for r in got
                                if r["env"].HasField("incident") and tag in r["env"].incident.anchor_finding_id)
    assert online_i == want_i                 # empty until groups (5d) wire IncidentBook into the engine

    hb = {(r["topic"], r["partition"]) for r in got
          if r["env"].HasField("heartbeat") and r["env"].heartbeat.producer_instance == f"orch-{tag}"}
    assert hb == {(t, p) for t in emit.OUT_TOPICS for p in range(parts[t])}
