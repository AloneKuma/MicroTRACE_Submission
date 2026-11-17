"""Exp. 5 recovery metrics from synthetic samples, and the lag sampler with a
fake consumer."""
import json

import pytest

from test_harness_project import TP, run_a
from mtcore.harness import project as P
from mtcore.harness import recovery as R


def series(points):
    return [(float(t), lag) for t, lag in points]


REF = series((t, 5 + t % 3) for t in range(100))             # steady lag 5..7


def test_percentile_and_band():
    assert R.percentile(range(1, 101), 0.99) == 99
    assert R.percentile([3], 0.99) == 3
    assert R.steady_band(REF) == 7
    assert R.steady_band(REF + [(200.0, 1000)], end=100) == 7
    with pytest.raises(ValueError):
        R.percentile([], 0.5)


def test_recovery_needs_a_full_hold_within_the_band():
    restart = 10.0
    run = series([(t, 900) for t in range(0, 10)] + [(t, 500 - 40 * (t - 10)) for t in range(10, 22)]
                 + [(t, 6) for t in range(22, 40)] + [(40, 50)] + [(t, 6) for t in range(41, 80)])
    # within the band from t=22 but broken at 40; held from 41 to 71
    assert R.recovered_at(run, restart, 7, hold_s=30) == 41
    assert R.recovered_at(run, restart, 7, hold_s=10) == 22
    assert R.recovered_at(run, restart, 7, hold_s=60) is None
    got = R.recovery_times({"go": run}, {"go": REF}, restart, hold_s=30)
    assert got == {"go": {"threshold": 7, "recovered_at": 41.0, "recovery_s": 31.0}}


def test_samples_before_the_restart_do_not_count():
    run = series([(t, 0) for t in range(0, 50)])
    assert R.recovered_at(run, 15.0, 7, hold_s=30) == 15


def test_added_seal_delay_matches_by_incident_relative_to_run_start():
    ref = {"i1": 10_000, "i2": 20_000, "i3": 30_000}
    run = {"i1": 1_000_010_000, "i2": 1_000_026_000, "i4": 1_000_040_000}
    d = R.added_seal_delay(ref, run, ref_start_ms=0, run_start_ms=1_000_000_000)
    assert d["per_incident_s"] == {"i1": 0.0, "i2": 6.0}
    assert d["missing"] == ["i3"] and d["extra"] == ["i4"] and d["max_s"] == 6.0


def test_seal_delay_from_dump_lines():
    from google.protobuf import json_format
    a = run_a()
    lines = [json.dumps({"topic": t, "record": json_format.MessageToDict(m), "timestamp_ms": 1000 * i})
             for i, (t, m) in enumerate(a)]
    seals = P.seal_times_ms(P.parse_lines(lines))
    assert seals == {"i1": 5000, "i2": 6000}
    assert R.added_seal_delay(seals, {"i1": 7000, "i2": 6000})["per_incident_s"] == {"i1": 2.0, "i2": 0.0}


def test_peak_usage_over_the_window():
    s = [(0, 90.0, 900), (10, 40.0, 300), (12, 85.0, 500), (20, 30.0, 700), (31, 99.0, 999)]
    assert R.peak_usage(s, 10, 30) == {"cpu_peak": 85.0, "mem_peak": 700, "samples": 3}
    assert R.peak_usage(s, 100, 200) == {"cpu_peak": None, "mem_peak": None, "samples": 0}


def test_outage_is_kill_to_the_first_heartbeat_after_it():
    hb = lambda ms, inst="orch-1": {"topic": "incidents.v0", "timestamp_ms": ms,  # noqa: E731
                                    "heartbeat": {"producerInstance": inst}}
    lines = [hb(1000), hb(9000), hb(4000, "other"), hb(7000), {"topic": "incidents.v0", "record": {}}]
    assert R.outage_s(2_000_000_000, lines) == 2.0
    assert R.outage_s(2_000_000_000, lines, instance="orch-1") == 5.0
    assert R.outage_s(10_000_000_000, lines) is None


def test_lag_from_positions():
    ends = {("a", 0): (0, 100), ("a", 1): (40, 50), ("b", 0): (0, 10)}
    total, per = R.lag_from_positions({("a", 0): 90, ("a", 1): None, ("b", 0): 12}, ends)
    assert per == {("a", 0): 10, ("a", 1): 10, ("b", 0): 0} and total == 20


class LagConsumer:
    def __init__(self, committed, ends):
        self.c, self.e = committed, ends

    def list_topics(self, timeout=None):
        class M:
            pass
        md = M()
        md.topics = {}
        for t, p in self.e:
            md.topics.setdefault(t, M()).__dict__.setdefault("partitions", {})[p] = None
        return md

    def committed(self, parts, timeout=None):
        return [TP(x.topic, x.partition, self.c.get((x.topic, x.partition), -1001)) for x in parts]

    def get_watermark_offsets(self, tp, timeout=None, cached=False):
        return self.e[(tp.topic, tp.partition)]


def test_sample_group_with_a_fake_consumer():
    c = LagConsumer({("findings.v0", 0): 70}, {("findings.v0", 0): (0, 100), ("findings.v0", 1): (5, 25)})
    total, per = R.sample_group(c, ["findings.v0"], tp=TP)
    assert per == {("findings.v0", 0): 30, ("findings.v0", 1): 20} and total == 50


def test_load_series(tmp_path):
    p = tmp_path / "lag.jsonl"
    p.write_text("".join(json.dumps({"t": t, "component": c, "lag": t, "partitions": {}}) + "\n"
                         for t, c in ((1, "go"), (2, "agents"), (3, "go"))))
    assert R.load_series(str(p)) == {"go": [(1, 1), (3, 3)], "agents": [(2, 2)]}


def test_sampler_cli_fails_cleanly_without_kafka(tmp_path):
    rc = R.main(["sample", "--bootstrap", "127.0.0.1:1", "--group", "g", "--component", "go",
                 "--topics", "findings.v0", "--out", str(tmp_path / "lag.jsonl"), "--duration", "3"])
    assert rc == 2
