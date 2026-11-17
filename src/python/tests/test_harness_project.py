"""Exp. 5 equality projection: repeated deliveries collapse by ID, the sealed
and latest views, report-only detail, JSONL round trip, the Kafka dump (fake
consumer), and two offline GO runs projecting identically."""
import io
import json

from google.protobuf import json_format

import orch_fixtures as O
import test_orch_witness as TW
from microtrace.v0 import envelope_pb2, incident_pb2, witness_pb2
from mtcore.harness import dump as D
from mtcore.harness import project as P
from mtcore.orchestrator.run import run_file

IS = incident_pb2.IncidentStatus
WI, IN = P.WITNESS_TOPIC, P.INCIDENT_TOPIC


# --- fixtures shared by the harness tests --------------------------------------
def inc(iid, members, status="INCIDENT_SEALED", version=1, links=(), aliases=(), at_seal=(), current=(),
        paths=(), start=100, anchor=None):
    m = incident_pb2.Incident(incident_id=iid, anchor_finding_id=anchor or members[0], version=version,
                              status=IS.Value(status))
    m.finding_ids.extend(members)
    m.link_witness_ids.extend(links)
    m.aliases.extend(aliases)
    m.source_completeness.at_seal_excluded_sources.extend(at_seal)
    m.source_completeness.current_excluded_sources.extend(current)
    for fids in paths:
        p = m.ranked_paths.add(finding_ids=list(fids))
        p.path_id = "p-" + "-".join(fids)
    m.event_start.FromSeconds(start)
    m.event_end.FromSeconds(start + 10)
    if status != "INCIDENT_OPEN":
        m.watermark_time.FromSeconds(start + 40)
    return m


def wit(wid, status="CONFIRMED"):
    return witness_pb2.Witness(witness_id=wid, status=witness_pb2.WitnessStatus.Value(status))


def run_a():
    """Reference: two incidents, two confirmed links and one rejected."""
    return [(WI, wit("w1")), (WI, wit("w2")), (WI, wit("w3", "REJECTED")),
            (IN, inc("i1", ["f1", "f2"], "INCIDENT_OPEN")),
            (IN, inc("i1", ["f1", "f2", "f3"], "INCIDENT_OPEN")),
            (IN, inc("i1", ["f1", "f2", "f3"], links=["w1", "w2"], paths=[("f1", "f2", "f3")])),
            (IN, inc("i2", ["f7", "f8"], links=[], start=500))]


def proj(items, tgs=None):
    return P.project(P.from_messages(items), tgs)


def jsonl(items):
    return "".join(json.dumps({"topic": t, "record": json_format.MessageToDict(m)}) + "\n" for t, m in items)


# --- projection ----------------------------------------------------------------
def test_reference_projection():
    p = proj(run_a(), tgs={"integrity": "abc"})
    s = p.sealed
    assert s["finding_ids"] == {"f1", "f2", "f3", "f7", "f8"}
    assert s["confirmed_witness_ids"] == {"w1", "w2"}
    assert s["groups"] == {"i1|anchor|f1", "i1|member|f1", "i1|member|f2", "i1|member|f3",
                           "i2|anchor|f7", "i2|member|f7", "i2|member|f8"}
    assert s["links"] == {"i1|w1", "i1|w2"}
    assert s["tgs"] == {"integrity=abc"}
    assert p.latest == s
    assert p.report["open_records"] == 2
    assert p.report["paths"] == ["i1|ranked|p-f1-f2-f3"]
    assert p.report["timestamps"]["i2"]["event_start"] == 500 * 10**9


def test_repeated_deliveries_collapse():
    items = run_a()
    replayed = items + items[3:] + [items[0]]
    assert proj(replayed).sealed == proj(items).sealed
    assert proj(replayed).latest == proj(items).latest


def test_last_witness_record_wins():
    items = run_a() + [(WI, wit("w2", "UNPROVEN")), (WI, wit("w3"))]
    assert proj(items).sealed["confirmed_witness_ids"] == {"w1", "w3"}


def test_sealed_keeps_the_at_seal_record_and_latest_the_amendment():
    items = run_a() + [(IN, inc("i2", ["f7", "f8", "f9"], "INCIDENT_AMENDED", version=2, at_seal=[],
                                current=["EBPF"], start=500))]
    p = proj(items)
    assert "i2|member|f9" not in p.sealed["groups"] and "i2|member|f9" in p.latest["groups"]
    assert p.latest["current_excluded_sources"] == {"i2|EBPF"}
    assert p.sealed_records["i2"].version == 1 and p.latest_records["i2"].version == 2


def test_an_older_version_delivered_late_does_not_replace_the_latest():
    items = run_a() + [(IN, inc("i2", ["f7", "f8", "f9"], "INCIDENT_AMENDED", version=2, start=500)),
                       (IN, inc("i2", ["f7", "f8"], start=500))]
    assert "i2|member|f9" in proj(items).latest["groups"]


def test_merged_away_incident_leaves_latest_but_keeps_its_sealed_record():
    items = run_a() + [(IN, inc("i1", ["f1", "f2", "f3", "f7", "f8"], "INCIDENT_AMENDED", version=2,
                                aliases=["i2"], links=["w1", "w2"]))]
    p = proj(items)
    assert "i2" in p.sealed_records and "i2" not in p.latest_records
    assert p.latest["aliases"] == {"i1|i2"} and p.sealed["aliases"] == frozenset()


def test_jsonl_round_trip_equals_in_process():
    items = run_a()
    p = P.project(P.parse_lines(io.StringIO(jsonl(items) + '{"topic": "incidents.v0", "heartbeat": {}}\n\n')))
    assert p.to_json() == proj(items).to_json()


def test_seal_times_take_the_first_sealed_record():
    lines = [json.dumps({"topic": IN, "record": json_format.MessageToDict(m), "timestamp_ms": ts})
             for (_, m), ts in zip(run_a()[3:] + run_a()[5:6], [1, 2, 3, 4, 9])]
    assert P.seal_times_ms(P.parse_lines(lines)) == {"i1": 3, "i2": 4}


# --- offline GO runs -------------------------------------------------------------
def go_records(tmp_path):
    e1, e2 = TW.proc(1, 10, lineage="ln-h"), TW.proc(5, 11, lineage="ln-h")
    e3, e4 = TW.proc(20, 30, lineage="lx-h"), TW.proc(24, 31, lineage="lx-h", host=True)
    recs = [(TW.NORM, e) for e in (e1, e2, e3, e4)]
    recs += [(TW.FND, TW.fnd("f1", e1)), (TW.FND, TW.fnd("f2", e2)), (TW.FND, TW.fnd("f3", e3)),
             (TW.FND, TW.fnd("f4", e4))]
    recs += [(t, O.hb(t, 0, 5000, 5000)) for t in (TW.FND, TW.NORM)]
    path = tmp_path / "records.jsonl"
    path.write_text("".join(json.dumps({"topic": t, "envelope": json_format.MessageToDict(e)}) + "\n"
                            for t, e in recs), encoding="utf-8")
    return path


def offline_run(path, out):
    with open(out, "w", encoding="utf-8") as fh:
        run_file(O.oparams(), str(path), out=fh)
    return P.project_file(str(out))


def test_two_offline_go_runs_project_identically(tmp_path):
    path = go_records(tmp_path)
    a, a2 = offline_run(path, tmp_path / "a.jsonl"), offline_run(path, tmp_path / "a2.jsonl")
    assert a.sealed["confirmed_witness_ids"] and a.sealed["groups"]
    assert a.to_json() == a2.to_json()


# --- dump (fake consumer) ----------------------------------------------------------
class TP:
    def __init__(self, topic, partition, offset=None):
        self.topic, self.partition, self.offset = topic, partition, offset


class Msg:
    def __init__(self, topic, partition, offset, env, ts):
        self._k, self._o, self._v, self._ts = (topic, partition), offset, env.SerializeToString(), ts

    def topic(self):
        return self._k[0]

    def partition(self):
        return self._k[1]

    def offset(self):
        return self._o

    def value(self):
        return self._v

    def timestamp(self):
        return (2, self._ts)

    def error(self):
        return None


class FakeConsumer:
    """Two partitions per topic; partitions arrive interleaved (each in offset
    order) and one record lies beyond the start-time end."""

    def __init__(self, logs):
        self.logs, self.assigned = logs, None

    def list_topics(self, timeout=None):
        class M:
            pass
        md = M()
        md.topics = {}
        for t in D.TOPICS:
            md.topics[t] = M()
            md.topics[t].partitions = {0: None, 1: None}
        return md

    def get_watermark_offsets(self, tp, timeout=None, cached=False):
        return 0, len(self.logs.get((tp.topic, tp.partition), []))

    def assign(self, tps):
        self.assigned = tps
        per = [[Msg(t, p, o, env, 1000 + o) for o, env in enumerate(log)] for (t, p), log in self.logs.items()]
        msgs = [m for i in range(max(map(len, per))) for log in reversed(per) for m in log[i:i + 1]]
        late = self.logs.get((IN, 0), [])
        if late:
            msgs.append(Msg(IN, 0, len(late), late[0], 0))      # written after the start: ignored
        self.queue = msgs

    def consume(self, n, timeout=None):
        out, self.queue = self.queue[:2], self.queue[2:]
        return out


def env_of(m):
    env = envelope_pb2.Envelope()
    (env.witness if isinstance(m, witness_pb2.Witness) else env.incident).CopyFrom(m)
    return env


def test_dump_writes_projection_lines_in_partition_order():
    a = run_a()
    hb = O.hb(IN, 0, 10, 10)
    logs = {(WI, 0): [env_of(m) for _, m in a[:3]], (IN, 0): [env_of(m) for _, m in a[3:6]] + [hb],
            (IN, 1): [env_of(a[6][1])]}
    buf = io.StringIO()
    n = D.dump(FakeConsumer(logs), buf, tp=TP)
    lines = [json.loads(x) for x in buf.getvalue().splitlines()]
    assert n == len(lines) == 7
    assert [(x["topic"], x["partition"], x["offset"]) for x in lines][3:] == [(IN, 0, 0), (IN, 0, 1), (IN, 0, 2),
                                                                             (IN, 1, 0)]
    assert lines[3]["timestamp_ms"] == 1000
    assert P.project(P.parse_lines(buf.getvalue().splitlines())).to_json() == proj(a).to_json()
    buf2 = io.StringIO()
    assert D.dump(FakeConsumer(logs), buf2, tp=TP, heartbeats=True) == 8
    assert sum("heartbeat" in json.loads(x) for x in buf2.getvalue().splitlines()) == 1


def test_dump_fails_cleanly_without_kafka(tmp_path):
    rc = D.main(["--bootstrap", "127.0.0.1:1", "--out", str(tmp_path / "x.jsonl"), "--timeout", "2"])
    assert rc == 2
