"""Build step 8f: the Exp. 5 part A failpoints in the receiver, the agents
and the TGS, each killing the real process (exit 137) where the plan puts
it, then restarted, and the component's guarantee checked
(evaluation-plan.md section 4: "The receiver follows the ship contract,
the agents already commit at the oldest record an open window needs, and
the TGS is atomic; those are tested for correctness only"). The GO's
points are tested in test_orch_restart.py.

- receiver: no record lost; duplicates only where the ship contract allows
  them (a crash between the Kafka write and the state write), and then
  byte-identical, so consumers remove them by logical_id;
- agents: after the restart, findings and evaluations equal the offline
  engine's (a re-emitted record has the same ID);
- TGS: a batch killed mid-transaction leaves no row and no offset, and
  applying it again gives the graph a clean run gives; the Kafka runner
  killed in its second batch resumes from its last commit to the offline
  graph.

Needs the dev Kafka (receiver, agents) and Postgres (TGS)."""
import json
import os
import subprocess
import sys
import time
import uuid

import pytest
from google.protobuf import json_format

import agent_fixtures as F
import test_agents_e2e as AE
import test_tgs_e2e as TE
import test_tgs_ingest as T
import test_tgs_snapshot as TS
from agent_testlib import params
from mtcore import failpoint
from mtcore.agents.engine import run_offline
from mtcore.agents.rules import ALL
from mtcore.tgs.hashes import graph_hash
from mtcore.tgs.store import MemoryStore
from mtcore.tgs import apply as A
from shipping_rig import KafkaWindow, Receiver, Shipper, make_certs, stop_all, write_lines
from test_agents_e2e import binaries, certs, world  # noqa: F401  (fixtures: one node per run)
from test_shipping import BOOTSTRAP, WATCH, _kafka_up, by_logical_id, data_records, gen

PYDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
kafka = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")


@pytest.fixture
def rx_certs(binaries, tmp_path_factory):
    return make_certs(str(tmp_path_factory.mktemp("rx-certs")), ["node-2"])


@pytest.fixture(autouse=True)
def _stop_processes():
    yield
    stop_all()


def wait_exit(proc, timeout=120):
    end = time.time() + timeout
    while proc.poll() is None and time.time() < end:
        time.sleep(0.2)
    return proc.poll()


def armed(point, log, nth=1):
    return {"MT_FAILPOINT": point, "MT_FAILPOINT_LOG": str(log), "MT_FAILPOINT_NTH": str(nth)}


# --- receiver -------------------------------------------------------------------------------
def stored_next(rx, node, boot, lane="NORMAL"):
    """The next expected sequence the receiver has durably stored (1 when
    its replier has not written the stream's state yet)."""
    path = os.path.join(rx.state, node, f"{boot}.json")
    if not os.path.exists(path):
        return 1
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["next"].get(lane, 1)


@kafka
@pytest.mark.parametrize("point", ["receiver.after_kafka_ack_before_seq_store",   # in Kafka, next not stored
                                   "receiver.mid_batch",                          # half the batch in Kafka
                                   "receiver.after_store_before_ack"])            # stored, not acknowledged
def test_receiver_killed_at_a_point_loses_nothing(rx_certs, tmp_path, point):
    """The receiver is pipelined: while one batch's state is stored, later
    batches are already being written to Kafka, so a kill at any point may
    leave records in Kafka above the stored next sequence, which the
    shipper resends (the duplicates ship-contract.md allows). Below it,
    nothing is ever written twice."""
    certs = rx_certs
    log = tmp_path / "fp.log"
    window = KafkaWindow(BOOTSTRAP, WATCH)
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP, env=armed(point, log, nth=3)).start()
    boot, n = uuid.uuid4().hex, 3000
    path = write_lines(str(tmp_path / "in.jsonl"), gen("node-2", boot, n))
    sh = Shipper(str(tmp_path), certs, rx.port, "node-2", boot=boot,
                 extra=["-window", "500", "-batch-max", "100"]).start(path)
    try:
        assert wait_exit(rx.proc, 60) == failpoint.EXIT_CODE, rx.log()
        [fired] = failpoint.read_log(str(log))
        assert fired["failpoint"] == point and fired["hit"] == 3
        if point == "receiver.after_store_before_ack":
            assert fired["state"]["acks"] > 0
        else:
            assert fired["state"]["records"] > 0 and fired["state"]["node"] == "node-2"
        if point == "receiver.mid_batch":
            assert 0 < fired["state"]["written"] < fired["state"]["records"]
        stored = stored_next(rx, "node-2", boot)
        if point == "receiver.after_store_before_ack":
            assert stored > 1                                       # the state write has just happened
        rx.env = {}
        rx.start()                                                  # same port, same state directory
        assert sh.wait(300) == 0, sh.log()
    finally:
        rx.stop()
    recs = data_records(window.read(timeout=120), "node-2", boot)
    window.close()
    counts = by_logical_id(recs)
    assert set(counts) == {f"ev-node-2-{boot}-{i}" for i in range(1, n + 1)}, "records lost"
    dups = {lid: c for lid, c in counts.items() if c > 1}
    below = sorted(int(lid.rsplit("-", 1)[1]) for lid in dups if int(lid.rsplit("-", 1)[1]) < stored)
    assert below == [], f"records below the stored next sequence {stored} written twice"
    values = {}
    for r in recs:
        values.setdefault(r["env"].logical_id, set()).add(r["value"])
    assert all(len(v) == 1 for v in values.values()), "a duplicate differs from its original"
    print(f"{point}: {n} records, stored next {stored} at the kill, {sum(c - 1 for c in dups.values())} duplicates")


# --- agents ---------------------------------------------------------------------------------
def run_with_agent_crash(tmp_path, certs, pods, events, point):
    """run_pipeline (test_agents_e2e) with the agents killed at point and
    restarted from their committed offsets; returns the failpoint entry
    and the run's findings and evaluations."""
    tag = uuid.uuid4().hex[:8]
    log = tmp_path / "fp.log"
    rx = Receiver(str(tmp_path), certs, BOOTSTRAP, extra=["-heartbeat", "500ms"]).start()
    win = KafkaWindow(BOOTSTRAP, AE.OUT)
    rs = AE.Proc(str(tmp_path), "restreamer", ["mtcore.restream", "--bootstrap", BOOTSTRAP, "--group", f"rs-{tag}",
                                               "--instance", f"rs-{tag}", "--from-latest", "--heartbeat-ms", "500"])
    agent_args = ["mtcore.agents.run", "--bootstrap", BOOTSTRAP, "--group", f"ag-{tag}", "--instance", f"ag-{tag}",
                  "--heartbeat-ms", "500"]
    ag = AE.Proc(str(tmp_path), "agents-1", agent_args + ["--from-latest"], env=armed(point, log))
    rs.wait_ready()
    ag.wait_ready()
    inp = write_lines(str(tmp_path / "input.jsonl"), AE.lines(pods, events, 5000))
    sh = Shipper(str(tmp_path), certs, rx.port, F.NODE).start(inp)
    assert sh.wait(120) == 0, sh.log()
    assert wait_exit(ag.proc, 180) == failpoint.EXIT_CODE, "".join(ag.log)
    [fired] = failpoint.read_log(str(log))
    ag2 = AE.Proc(str(tmp_path), "agents-2", agent_args)        # resumes from the committed offsets
    ag2.wait_ready()
    ids = {e.logical_id for e in events}
    last, stable_since, recs, deadline = -1, time.time(), [], time.time() + 180
    while time.time() < deadline:
        time.sleep(2)
        recs = win.read()
        n = sum(1 for r in recs if r["env"].HasField("rule_evaluation"))
        if n != last:
            last, stable_since = n, time.time()
        elif n > 0 and time.time() - stable_since > 8:
            break
    for p in (ag2, rs, rx):
        p.stop()
    win.close()
    findings = {r["env"].finding.finding_id for r in recs if r["env"].HasField("finding")
                and set(r["env"].finding.input_event_ids) <= ids}
    evals = {(r["env"].rule_evaluation.evaluation_id, r["env"].rule_evaluation.outcome) for r in recs
             if r["env"].HasField("rule_evaluation") and set(r["env"].rule_evaluation.input_event_ids) <= ids}
    return fired, findings, evals


@kafka
@pytest.mark.parametrize("point", ["agent.window_open", "agent.after_finding_before_commit"])
def test_agents_killed_at_a_point_restart_to_the_offline_result(tmp_path, certs, world, point):
    pods, events = world
    want_f, want_e, _ = run_offline(ALL, params(), F.stream(*pods, *events))
    fired, findings, evals = run_with_agent_crash(tmp_path, certs, pods, events, point)
    assert fired["failpoint"] == point
    if point == "agent.window_open":
        assert fired["state"]["pending_windows"] > 0
    else:
        assert fired["state"]["findings"] > 0
    assert findings == {f.finding_id for f in want_f}
    assert evals == {(e.evaluation_id, e.outcome) for e in want_e}


# --- TGS ------------------------------------------------------------------------------------
def tgs_records():
    envs = [T.witness("w12", "f1", "f2"), T.witness("w23", "f2", "f3"),
            TS.inc("in-1", members=("f1", "f2", "f3"), witnesses=("w12", "w23"))]
    topics = [T.WIT, T.WIT, T.INC]
    return [(t, 0, i, e) for i, (t, e) in enumerate(zip(topics, envs))]


def test_tgs_killed_mid_transaction_keeps_nothing_and_reapplies_cleanly(tmp_path):
    recs = tgs_records()
    path = tmp_path / "recs.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for topic, part, off, env in recs:
            fh.write(json.dumps({"topic": topic, "partition": part, "offset": off,
                                 "envelope": json_format.MessageToDict(env)}) + "\n")
    clean = MemoryStore()
    A.apply_batch(clean, recs)
    want = graph_hash(clean)
    with T.pg_store() as store:
        schema = store.conn.execute("SELECT current_schema()").fetchone()[0]
        store.conn.commit()
        dsn = f"{T.TEST_DSN} options='-c search_path={schema}'"
        log = tmp_path / "fp.log"
        cmd = [sys.executable, "-m", "mtcore.tgs.run", "--offline", str(path), "--dsn", dsn]
        out = subprocess.run(cmd, cwd=PYDIR, env=dict(os.environ, **armed("tgs.mid_transaction", log)),
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == failpoint.EXIT_CODE, out.stderr
        [fired] = failpoint.read_log(str(log))
        assert fired["state"]["applied"] > 0 and fired["state"]["records"] == len(recs)
        assert store.offsets() == {} and graph_hash(store) == graph_hash(MemoryStore())
        store.conn.rollback()                       # end the read: the run's schema setup waits for it
        out = subprocess.run(cmd, cwd=PYDIR, capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
        assert graph_hash(store) == want and store.offsets() == clean.offsets()


@kafka
def test_tgs_runner_killed_mid_batch_resumes_to_the_offline_graph(tmp_path):
    """The Kafka runner, killed in its second batch: the first batch is
    committed with its offsets, nothing of the second is kept, and the
    restarted runner ends with the offline graph."""
    with T.pg_store() as pg:
        schema = pg.conn.execute("SELECT current_schema()").fetchone()[0]
        dsn = f"{T.TEST_DSN} options='-c search_path={schema}'"
        tag = uuid.uuid4().hex[:8]
        recs = TE._records(tag, 1, 12)
        TE._start_at_topic_ends(pg)
        before = pg.offsets()
        TE._produce(recs)
        log = tmp_path / "fp.log"

        def tgs(env=None):
            return subprocess.Popen([sys.executable, "-m", "mtcore.tgs.run", "--dsn", dsn, "--bootstrap", BOOTSTRAP,
                                     "--group", f"tgs-crash-{tag}", "--batch-size", "4"], cwd=PYDIR,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=dict(os.environ, **(env or {})))

        assert wait_exit(tgs(armed("tgs.mid_transaction", log, nth=2))) == failpoint.EXIT_CODE
        [fired] = failpoint.read_log(str(log))
        assert fired["hit"] == 2 and fired["state"]["applied"] > 0
        pg.conn.rollback()                          # a fresh snapshot of the killed process's commits
        offs = pg.offsets()
        rows = []
        for table in ("events", "findings", "witnesses", "incident_records"):
            rows += [(r["topic"], r["kafka_partition"], r["kafka_offset"]) for r in pg.rows(table)]
        assert all(o <= offs[(t, part)] for t, part, o in rows), "rows beyond the applied offsets"
        assert sum(offs[k] - before[k] for k in offs) < len(recs), "the interrupted batch was kept"

        p = tgs()
        deadline = time.time() + 60
        while time.time() < deadline and sum(pg.offsets()[k] - before[k] for k in before) < len(recs):
            pg.conn.rollback()
            time.sleep(0.5)
        p.terminate()
        p.wait(30)
        pg.conn.rollback()
        offline = MemoryStore()
        for topic, e in recs:
            A.apply_batch(offline, [(topic, 0, 0, e)])
        assert T._shape(pg) == T._shape(offline)
        assert len(pg.rows("events")) == len(offline.rows("events"))


def test_cells_modes_filter_keeps_draws():
    """--modes C keeps exactly the full matrix's A, A', C and X cells, with the same nth."""
    from mtcore.harness import crashrun as CR
    pts = ["go.after_flush_before_commit", "go.mid_group_records", "agent.window_open"]
    full = CR.cells(pts, reps=3, max_nth=5, seed=7)
    only_c = CR.cells(pts, reps=3, max_nth=5, seed=7, modes=["C"])
    assert only_c == [c for c in full if c["run"] in ("A", "A2", "C", "X")]
    assert CR.cells(pts, reps=3, max_nth=5, seed=7, modes=None) == full


def test_drain_waits_max_idle_plus_settle_after_the_shippers_drained():
    """A run (A included) may not end before max_idle + settle_s after the last
    shipper drained, even when the outputs went quiet earlier (shakedown 2026-11-16)."""
    from mtcore.harness import crashrun as CR

    class P:
        def __init__(self, alive):
            self.a = alive

        def alive(self):
            return self.a

    class St:
        max_idle = "10s"

        def __init__(self, ps):
            self.ps = ps

        def shippers(self):
            return self.ps

    class W:
        last = 0.0

    ship = P(True)
    d = CR._Drain(St([ship]), W(), settle_s=5.0)
    assert d.wait_s == 15.0 and not d.done(now=100.0)        # still shipping
    ship.a = False
    assert not d.done(now=100.0)                             # drained at 100
    assert not d.done(now=114.9)                             # quiet long ago, but < max_idle + settle
    assert d.done(now=115.0)
    W.last = 112.0                                           # a late (idle-released) record
    assert not d.done(now=115.0) and d.done(now=117.0)
    assert CR._idle_s(type("S", (), {"max_idle": "500ms"})()) == 0.5
