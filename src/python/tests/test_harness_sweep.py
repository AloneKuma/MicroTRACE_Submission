"""Step 8g sweep plumbing without Kafka: the settings plan, the history cut
and input span, read lag from the positions log and sampled ends, the GO's
re-read backlog, the longest open-incident span, and run_setting's timeout
and prefill handling (the matrix itself is stubbed)."""
import json

from google.protobuf import json_format

from mtcore.harness import crashrun as CR
from mtcore.harness import project as P
from mtcore.harness import recovery as R
from mtcore.harness import sweep as SW
from microtrace.v0 import incident_pb2  # noqa: I100 (after mtcore: it sets up gen/)

T0 = 1_700_000_000


def line(t=None, lid="x"):
    env = {"logicalId": lid}
    if t is not None:
        env["normalizedEvent"] = {"eventId": lid, "time": {"eventTime": f"2023-11-14T22:{t // 60:02d}:{t % 60:02d}Z"}}
    return json.dumps({"topic": "raw.ebpf.v0", "envelope": env})


def test_one_factor_at_a_time_around_the_base():
    plan = SW.settings([1, 2, 4], [3, 60, 600], [600, 3600, 14400], (1, 3, 600))
    names = [n for n, _ in plan]
    assert names == ["base", "pace-2", "pace-4", "outage-60", "outage-600", "history-3600", "history-14400"]
    assert dict(plan)["outage-60"] == {"pace": 1, "outage_s": 60, "history_s": 600}
    assert len(SW.settings([1, 2, 4], [3, 60, 600], [600, 3600, 14400], (1, 3, 600), factorial=True)) == 27


def test_without_a_prefill_there_is_no_history_factor():
    plan = SW.settings([1, 2], [3], [], (1, 3, 600))
    assert plan == [("base", {"pace": 1, "outage_s": 3, "history_s": 0}),
                    ("pace-2", {"pace": 2, "outage_s": 3, "history_s": 0})]


def test_dry_run_prints_the_plan(capsys):
    assert SW.main(["--input", "n=x", "--out", "o", "--prefill", "n=h", "--dry-run"]) == 0
    assert [n for n, _ in json.loads(capsys.readouterr().out)][0] == "base"


def test_history_cut_keeps_the_last_seconds_and_untimed_lines(tmp_path):
    src = tmp_path / "h.jsonl"
    src.write_text("\n".join([line(None, "ctx"), line(0, "a"), line(100, "b"), line(250, "c"),
                              line(300, "d")]) + "\n")
    dst = tmp_path / "cut.jsonl"
    assert CR.cut_history(str(src), str(dst), 60) == 3
    kept = [json.loads(x)["envelope"]["logicalId"] for x in dst.read_text().splitlines()]
    assert kept == ["ctx", "c", "d"]
    assert CR.input_span_s([str(src)]) == 300
    assert CR._event_time_s(json.loads(line(None))) is None


def test_read_lag_follows_each_components_latest_positions(tmp_path):
    pos, ends = tmp_path / "positions.jsonl", tmp_path / "ends.jsonl"
    pos.write_text("\n".join(json.dumps(x) for x in [
        {"t": 10_000_000_000, "positions": {"findings.v0/0": 5, "norm.events.v0/0": 50,
                                            "source.completeness.v0/0": 9}, "committed": {}},
        {"t": 11_000_000_000, "positions": {"agent.b.v0/0": 40}, "committed": {}},
        {"t": 12_000_000_000, "positions": {"findings.v0/0": 8, "norm.events.v0/0": 60}, "committed": {}},
    ]) + "\n")
    ends.write_text("\n".join(json.dumps(x) for x in [
        {"t": 9.0, "ends": {"findings.v0/0": 10, "norm.events.v0/0": 70, "agent.b.v0/0": 45}},
        {"t": 11.5, "ends": {"findings.v0/0": 10, "norm.events.v0/0": 70, "agent.b.v0/0": 45}},
        {"t": 12.5, "ends": {"findings.v0/0": 12, "norm.events.v0/0": 70, "agent.b.v0/0": 45}},
    ]) + "\n")
    s = R.read_lag_series(str(pos), str(ends), {"go": ["findings.v0", "norm.events.v0"], "agents": ["agent.b.v0"]})
    assert s["go"] == [(11.5, 5 + 20), (12.5, 4 + 10)]               # before t=10 the GO had no positions
    assert s["agents"] == [(11.5, 5), (12.5, 5)]
    assert R.read_lag_series(str(tmp_path / "none"), str(ends), {"go": ["findings.v0"]}) == {"go": []}


def test_go_backlog_is_read_minus_committed_before_the_kill(tmp_path):
    pos = tmp_path / "positions.jsonl"
    pos.write_text("\n".join(json.dumps(x) for x in [
        {"t": 1_000_000_000, "positions": {"findings.v0/0": 10, "norm.events.v0/0": 100},
         "committed": {"findings.v0/0": 4, "norm.events.v0/0": 60}},
        {"t": 2_000_000_000, "positions": {"agent.b.v0/0": 7}, "committed": {"agent.b.v0/0": 1}},
        {"t": 5_000_000_000, "positions": {"findings.v0/0": 99}, "committed": {"findings.v0/0": 0}},
    ]) + "\n")
    assert CR.go_backlog(str(pos), kill_t=3.0) == 6 + 40
    assert CR.go_backlog(str(pos), kill_t=0.5) is None


def test_longest_open_span_uses_each_incidents_latest_record_before_the_kill():
    def inc(iid, status, start, end):
        m = incident_pb2.Incident(incident_id=iid, status=incident_pb2.IncidentStatus.Value(status))
        m.event_start.FromSeconds(start)
        m.event_end.FromSeconds(end)
        return json_format.MessageToDict(m)
    lines = [{"topic": P.INCIDENT_TOPIC, "record": inc("i1", "INCIDENT_OPEN", 0, 50), "timestamp_ms": 1000},
             {"topic": P.INCIDENT_TOPIC, "record": inc("i2", "INCIDENT_OPEN", 0, 120), "timestamp_ms": 1000},
             {"topic": P.INCIDENT_TOPIC, "record": inc("i2", "INCIDENT_SEALED", 0, 120), "timestamp_ms": 2000},
             {"topic": P.INCIDENT_TOPIC, "record": inc("i3", "INCIDENT_OPEN", 0, 999), "timestamp_ms": 9000}]
    recs = P.parse_lines(json.dumps(x) for x in lines)
    assert CR.longest_open_span_s(recs, at_ms=1500) == 120
    assert CR.longest_open_span_s(recs, at_ms=2500) == 50            # i2 sealed; i3 not yet seen
    assert CR.longest_open_span_s(recs, at_ms=500) is None


def test_run_setting_cuts_the_prefill_and_sizes_the_timeout(tmp_path, monkeypatch):
    got = {}

    def fake_matrix(matrix, inputs, out_dir, parallel, **kw):
        got.update(kw, matrix=matrix, inputs=inputs)
        return {"ok": True}
    monkeypatch.setattr(CR, "run_matrix", fake_matrix)
    inp, hist = tmp_path / "in.jsonl", tmp_path / "hist.jsonl"
    inp.write_text("\n".join([line(0, "a"), line(1200, "b")]) + "\n")              # 20 min of event time
    hist.write_text("\n".join([line(0, "h1"), line(3000, "h2")]) + "\n")
    out = tmp_path / "s"
    assert CR.run_setting({"n": str(inp)}, str(out), ["go.after_flush_before_commit"], reps=1, pace=2.0,
                          outage_s=60, prefill={"n": str(hist)}, history_s=600, hold_s=30) == {"ok": True}
    assert got["timeout_s"] == 1200 / 2 + 60 + 30 + 900
    assert got["pace"] == 2.0 and got["outage_s"] == 60 and got["hold_s"] == 30
    cut = got["prefill"]["n"]
    assert [json.loads(x)["envelope"]["logicalId"] for x in open(cut)] == ["h2"]
    assert json.loads((out / "setting.json").read_text())["history_s"] == 600
    assert [c["run"] for c in got["matrix"]][:2] == ["A", "A2"]
