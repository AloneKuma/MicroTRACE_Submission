"""Step 7g GO restart, offline: OrchRunner over an in-memory broker, killed at
several points and restarted from its checkpoint (oldest-needed), must give
the projection of an uninterrupted run (Exp. 5 run C against A). Restarting
from the read position (run D) must not. The commit point never passes a
record still held, and heartbeats never move back."""
import sys
import types

import pytest

import agent_fixtures as F
import orch_fixtures as O
import test_orch_admission as A
from microtrace.v0 import envelope_pb2, witness_pb2
from test_orch_knowledge import idle

from mtcore.orchestrator import emit
from mtcore.orchestrator.run import OrchRunner

FND, NORM, COMP, CTX = "findings.v0", "norm.events.v0", "source.completeness.v0", "context.cluster.v0"
PARTS = {FND: 2, NORM: 1, COMP: 1, CTX: 1, emit.WITNESS_TOPIC: 2, emit.INCIDENT_TOPIC: 2}
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
END = 420
GROUPS = 20
# Short windows and path span, so postings, evidence and incidents expire within the run.
WINDOWS = {"NETWORK_FLOW": 30, "REQUEST_IDENTITY": 30, "PROCESS_ANCESTRY": 60, "HOST_TRANSITION": 60,
           "CREDENTIAL_READ_TO_USE": 30, "ADMISSION_INSTANCE": 30, "CONTROL_PLANE_CAUSALITY_INSTANCE": 30,
           "HOST_CONTEXT": 30, "CONTROL_PLANE_CAUSALITY_CLASS": 30, "IMAGE_CLASS": 30}


def oparams():
    return O.oparams(T_s=60, W_w_s=WINDOWS)


class TP:
    def __init__(self, topic, partition, offset=-1001):
        self.topic, self.partition, self.offset = topic, partition, offset


def _fake(mp, tmp):
    mod = types.ModuleType("confluent_kafka")
    mod.TopicPartition, mod.OFFSET_BEGINNING, mod.OFFSET_STORED = TP, -2, -1000
    mp.setitem(sys.modules, "confluent_kafka", mod)
    mp.setenv("MT_POSITIONS_LOG", str(tmp / "positions.jsonl"))


@pytest.fixture(autouse=True)
def fake_kafka(monkeypatch, tmp_path):
    _fake(monkeypatch, tmp_path)


class Msg:
    def __init__(self, topic, part, off, value, seq, ts_ms):
        self._t, self._p, self._o, self._v, self.seq, self._ts = topic, part, off, value, seq, ts_ms

    def topic(self):
        return self._t

    def partition(self):
        return self._p

    def offset(self):
        return self._o

    def key(self):
        return None

    def value(self):
        return self._v

    def error(self):
        return None

    def timestamp(self):
        return (2, self._ts)                  # LogAppendTime


class Broker:
    def __init__(self):
        self.log = {(t, p): [] for t, n in PARTS.items() for p in range(n)}
        self.committed, self.seq = {}, 0

    def append(self, topic, part, env, t):
        lst = self.log[(topic, part)]
        self.seq += 1
        lst.append(Msg(topic, part, len(lst), env.SerializeToString(), self.seq, F.ns(t) // 1_000_000))


class Consumer:
    def __init__(self, broker):
        self.b, self.pos = broker, {}

    def list_topics(self, timeout):
        return types.SimpleNamespace(topics={t: types.SimpleNamespace(partitions=dict.fromkeys(range(n)))
                                             for t, n in PARTS.items()})

    def assign(self, tps):
        for tp in tps:
            k = (tp.topic, tp.partition)
            self.pos[k] = 0 if tp.offset == -2 else self.b.committed.get(k, 0) if tp.offset < 0 else tp.offset

    def consume(self, n, timeout):
        cand = sorted((m for k, off in self.pos.items() for m in self.b.log[k][off:]), key=lambda m: m.seq)[:n]
        for m in cand:
            self.pos[(m.topic(), m.partition())] = m.offset() + 1
        return cand

    def commit(self, offsets, asynchronous):
        for tp in offsets:
            self.b.committed[(tp.topic, tp.partition)] = tp.offset

    def get_watermark_offsets(self, tp, timeout, cached):
        return 0, len(self.b.log[(tp.topic, tp.partition)])

    def close(self):
        pass


class Producer:
    def __init__(self, sent):
        self.sent = sent

    def produce(self, topic, value, key=None, partition=None):
        env = envelope_pb2.Envelope()
        env.ParseFromString(value)
        self.sent.append((topic, partition, env))

    def flush(self, timeout):
        return 0


# --- the scenario ---------------------------------------------------------------------
_SCENARIO = []


def scenario():
    """Built once: fixture event IDs come from a counter, and witness IDs cite them."""
    if not _SCENARIO:
        _SCENARIO.extend(_build())
    return _SCENARIO


def _build():
    """[(arrival s, topic, partition, Envelope)]: twenty linked pairs 15 s apart on two
    findings partitions, heartbeats every 5 s, a late idle record after group 0
    sealed, an idle record known before group 3 sealed, and a late eBPF loss in
    group 10's interval (a witness re-decided)."""
    recs = []
    for i in range(GROUPS):
        b = 15 * i
        e1, e2 = A.proc(b + 1, 100 + 2 * i, lineage=f"ln-{i}"), A.proc(b + 5, 101 + 2 * i, lineage=f"ln-{i}")
        recs += [(b + 1.2, NORM, 0, e1), (b + 5.2, NORM, 0, e2),
                 (b + 7, FND, i % 2, A.fnd(f"g{i}a", e1)), (b + 7.5, FND, i % 2, A.fnd(f"g{i}b", e2))]
    for t in range(0, END, 5):
        recs += [(t, topic, p, O.hb(topic, p, t - 8, t, instance=f"{topic}-{p}"))
                 for topic, n in ((FND, 2), (NORM, 1)) for p in range(n)]
    recs += [(100, COMP, 0, idle("AUDIT", 2, 10, "sc-late")), (60, COMP, 0, idle("GATEWAY", 50, 55, "sc-early")),
             (200, COMP, 0, F.loss(151.5, 153)[1])]
    return sorted(recs, key=lambda r: (r[0], r[1], r[2]))


def runner(broker, sent, path, mode):
    r = OrchRunner(oparams(), None, "orch-test", commit_mode=mode, checkpoint=str(path),
                   consumer=Consumer(broker), producer=Producer(sent))
    r.heartbeat_s = float("inf")          # checkpoints only where the driver says
    return r


def drive(tmp_path, mode="oldest-needed", crash=None, probe=None, recs=None, end=END):
    """Arrive records second by second, one step per second, a checkpoint every
    4 s; at crash, drop the runner unflushed and start another. Returns all
    records produced, in order."""
    broker, sent = Broker(), []
    recs, i = recs or scenario(), 0
    path = tmp_path / f"{mode}-{crash}.ckpt"
    r = runner(broker, sent, path, mode)
    for tick in range(end + 40):
        while i < len(recs) and recs[i][0] <= tick:
            broker.append(recs[i][1], recs[i][2], recs[i][3], recs[i][0])
            i += 1
        if tick == crash:
            r = runner(broker, sent, path, mode)
        r.step()
        if tick % 4 == 0:
            r.checkpoint_now()
            if probe:
                probe(r)
    r.checkpoint_now()
    return sent


def projection(sent):
    wit, inc = {}, {}
    for _topic, _p, env in sent:
        if env.HasField("witness"):
            wit[env.witness.witness_id] = env.witness.status
        elif env.HasField("incident"):
            i = env.incident
            assert i.version >= inc.get(i.incident_id, (0,))[0], "an incident version moved back"
            sc = i.source_completeness
            inc[i.incident_id] = (i.version, i.anchor_finding_id, tuple(i.finding_ids), tuple(i.aliases),
                                  tuple(sc.at_seal_excluded_sources), tuple(sc.current_excluded_sources),
                                  i.status != 0)
    groups = {k: v[1:] for k, v in inc.items()}
    return {"findings": sorted({f for v in groups.values() for f in v[1]}),
            "confirmed": sorted(w for w, s in wit.items() if s == CONFIRMED), "incidents": groups}


@pytest.fixture(scope="module")
def reference(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ref")
    with pytest.MonkeyPatch.context() as mp:
        _fake(mp, tmp)
        return projection(drive(tmp))


def test_the_scenario_exercises_seals_amendments_and_exclusions(reference):
    inc = reference["incidents"]
    assert len(inc) == GROUPS and len(reference["confirmed"]) == GROUPS - 1   # group 10's link retracted by a late loss
    sc = {v[0]: (v[3], v[4]) for v in inc.values()}       # anchor -> (at seal, current)
    assert sc["g0a"] == (("GATEWAY",), ("AUDIT", "GATEWAY"))   # AUDIT learned after seal: an amendment only
    assert sc["g3a"] == (("GATEWAY",), ("GATEWAY",))      # known at seal
    assert sc["g5a"] == ((), ())


@pytest.mark.parametrize("crash", [9, 23, 50, 77, 81, 118, 150, 205, 262, 333, 401])
def test_restart_from_the_oldest_needed_offset_matches_the_uninterrupted_run(tmp_path, reference, crash):
    assert projection(drive(tmp_path, crash=crash)) == reference


def test_restart_from_the_read_position_loses_open_state(tmp_path, reference):
    got = projection(drive(tmp_path, mode="read-position", crash=50))
    assert got != reference
    assert set(got["confirmed"]) < set(reference["confirmed"])


def test_full_replay_matches_the_uninterrupted_run(tmp_path, reference):
    assert projection(drive(tmp_path, mode="full-replay", crash=77)) == reference


def test_the_commit_point_never_passes_a_record_still_held(tmp_path):
    seen = []

    def probe(r):
        eng, committed = r.engine, r.committed
        for fid in eng.held():
            tp, off = eng.pos[fid]
            topic, part = tp.rsplit("/", 1)
            assert off >= committed[(topic, int(part))], fid
        for ev in eng.evidence.events.values():
            assert ev.offset >= committed[(ev.topic, ev.partition)]
        seen.append(len(eng.held()))
    drive(tmp_path, probe=probe)
    assert max(seen) > 0


def test_heartbeats_never_move_back_and_wait_for_the_replay(tmp_path):
    sent = drive(tmp_path, crash=81)
    last = {}
    for topic, p, env in sent:
        if env.HasField("heartbeat"):
            low = env.heartbeat.low_watermark.ToNanoseconds()
            assert low >= last.get((topic, p), low), (topic, p)
            last[(topic, p)] = low
    assert set(last) == {(t, p) for t in emit.OUT_TOPICS for p in range(PARTS[t])}


def test_failpoints_and_positions_follow_the_crash_harness_contract(tmp_path, monkeypatch):
    import json
    from mtcore.orchestrator import run
    hits = []
    monkeypatch.setattr(run, "failpoint", types.SimpleNamespace(
        hit=lambda name, state, require: hits.append((name, dict(state), require()))))
    drive(tmp_path, crash=118)
    names = {h[0] for h in hits}
    assert names <= {"go.after_feed_before_advance", "go.after_produce_before_flush", "go.after_flush_before_commit",
                     "go.mid_group_records", "go.sealing_pairs_pending"}
    assert {"go.after_feed_before_advance", "go.after_flush_before_commit", "go.mid_group_records"} <= names
    assert any(req for _n, _s, req in hits) and any(not req for _n, _s, req in hits)
    assert set(hits[0][1]) == {"pending_findings", "pending_pairs", "open_groups", "unretired_incidents"}
    lines = [json.loads(x) for x in (tmp_path / "positions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines and set(lines[-1]) == {"t", "positions", "committed"}
    last = lines[-1]
    assert all(last["committed"][k] <= last["positions"][k] for k in last["committed"])
    assert any(last["committed"][k] < last["positions"][k] for k in last["committed"])   # held back by open state


# --- bounded side state ---------------------------------------------------------------
def history(seconds):
    """Pairs every 15 s, and every 5 s a closed eBPF loss on another node and a
    new observation of one Pod: side history that grows with the run."""
    recs = []
    for i in range(seconds // 15):
        b = 15 * i
        e1, e2 = A.proc(b + 1, 1000 + 2 * i, lineage=f"h-{i}"), A.proc(b + 5, 1001 + 2 * i, lineage=f"h-{i}")
        recs += [(b + 1.2, NORM, 0, e1), (b + 5.2, NORM, 0, e2),
                 (b + 7, FND, i % 2, A.fnd(f"h{i}a", e1)), (b + 7.5, FND, i % 2, A.fnd(f"h{i}b", e2))]
    for t in range(0, seconds, 5):
        recs += [(t, topic, p, O.hb(topic, p, t - 8, t, instance=f"{topic}-{p}"))
                 for topic, n in ((FND, 2), (NORM, 1)) for p in range(n)]
        recs += [(t + 1, COMP, 0, F.loss(t - 3, t - 2, node="node-9")[1]), (t + 1, CTX, 0, F.pod(t)[1])]
    return sorted(recs, key=lambda r: (r[0], r[1], r[2]))


def _final_log(tmp_path, seconds):
    import pickle
    drive(tmp_path, recs=history(seconds), end=seconds)
    ck = pickle.loads((tmp_path / "oldest-needed-None.ckpt").read_bytes())
    return len(ck["side_log"]), (tmp_path / "oldest-needed-None.ckpt").stat().st_size


def test_the_checkpoints_side_log_stays_bounded_as_history_grows(tmp_path):
    short, long_ = tmp_path / "short", tmp_path / "long"
    short.mkdir()
    long_.mkdir()
    n1, size1 = _final_log(short, 400)
    n10, size10 = _final_log(long_, 4000)
    print(f"side records 400 s: {n1} ({size1} B); 4000 s: {n10} ({size10} B)")
    assert n1 > 0 and n10 <= 1.5 * n1 and size10 <= 1.5 * size1
    assert n10 < 4000 // 5                     # far below the records read


def _sealed_engine():
    from mtcore.orchestrator.engine import Engine
    evs = [A.proc(1, 10), A.proc(5, 11)]
    eng = Engine(oparams(), {FND: 1})
    for env in evs:
        eng.feed(env, NORM)
    for env in (A.fnd("f1", evs[0]), A.fnd("f2", evs[1])):
        eng.feed(env, FND)
    return eng


def _log(*recs):
    return [(COMP, 0, i, receipt, env.SerializeToString()) for i, (receipt, env) in enumerate(recs)]


def _advance(eng, t):
    eng.feed(O.hb(FND, 0, t, t), FND)
    eng.advance()
    eng.incidents_hook(F.ns(t))


def test_a_gap_overlapping_an_unretired_sealed_incident_is_never_pruned():
    eng = _sealed_engine()
    gap = idle("AUDIT", 2, 4, "sc-old")
    eng.feed(gap, COMP, receipt_ns=F.ns(3))
    _advance(eng, 120)                         # sealed at 61 s, retired only after seal + max horizon
    assert eng.book.live and all(st.sealed for st in eng.book.live.values())
    bound = eng.side_bound()
    assert bound[0] < F.ns(2)                  # B lies below the incident's open period
    log = _log((F.ns(3), gap))
    eng.prune_side(bound)
    assert eng.side_keep(log, bound) == log and eng.idle


def test_an_open_ended_idle_gap_survives_pruning_until_closed():
    eng = _sealed_engine()
    open_ = idle("AUDIT", 2, 4, "sc-open")
    open_.source_completeness.ClearField("interval_end")
    for g in open_.source_completeness.gaps:
        g.ClearField("to")
    eng.feed(open_, COMP, receipt_ns=F.ns(3))
    later = A.proc(1000, 50, lineage="ln-later")
    eng.feed(later, NORM)
    eng.feed(A.fnd("f9", later), FND)          # moves the frontier: f1, f2 expire and the incident retires
    for t in range(150, 1200, 50):
        _advance(eng, t)
    assert not eng.book.live
    bound = eng.side_bound()
    log = _log((F.ns(3), open_))
    eng.prune_side(bound)
    assert eng.side_keep(log, bound) == log and eng.idle and eng.gaps.gaps
    close = idle("AUDIT", 2, 4, "sc-close")
    eng.feed(close, COMP, receipt_ns=F.ns(1200))
    # A seal before 1200 s could still see the gap as ongoing: it stays until every
    # decision still to be made is known after the closing record.
    last = A.proc(1400, 51, lineage="ln-last")
    eng.feed(last, NORM)
    eng.feed(A.fnd("f10", last), FND)
    for t in range(1250, 1600, 50):
        _advance(eng, t)
    bound = eng.side_bound()
    log = _log((F.ns(3), open_), (F.ns(1200), close))
    eng.prune_side(bound)
    assert eng.side_keep(log, bound) == [] and not eng.idle and not eng.gaps.gaps
