"""Step 8f crash runner smoke test: A, A' and one crash per component kind on
isolated stacks (own Kafka and Postgres each), over the agents e2e world
without its namespace changes (a C1b finding opens a node-trust epoch, which
leaves every witness POST_COMPROMISE and no incident to compare).
Every fired crash run must score identical to A within A' noise. Slow and
heavy (one Kafka, one Postgres and the pipeline per stack): runs only with
MT_CRASHRUN=1 and the dev toolchain on PATH."""
import json
import os
import shutil

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("MT_CRASHRUN") != "1" or not shutil.which("kafka-storage.sh"),
                                reason="set MT_CRASHRUN=1 (needs the dev toolchain)")

from mtcore.harness import crashrun as CR  # noqa: E402
from mtcore.harness import project as P  # noqa: E402
from shipping_rig import build_binaries, write_lines  # noqa: E402
from test_agents_e2e import lines, world  # noqa: E402,F401

POINTS = ["go.after_flush_before_commit", "agent.after_finding_before_commit", "receiver.after_store_before_ack",
          "tgs.mid_transaction", CR.PG_CRASH]


def test_matrix_on_isolated_stacks(tmp_path, world):
    build_binaries()
    pods, events = world
    events = [e for e in events if not (e.normalized_event.HasField("ebpf")
                                        and e.normalized_event.ebpf.event_family.startswith("ns."))]
    inp = write_lines(str(tmp_path / "node-1.jsonl"), lines(pods, events, 5000))
    matrix = [c for c in CR.cells(POINTS, reps=1, max_nth=1, seed=1) if c["run"] in ("A", "A2", "C", "X")]
    summary = CR.run_matrix(matrix, {"node-1": inp}, str(tmp_path / "runs"), parallel=3, outage_s=1.0,
                            settle_s=10.0, timeout_s=600.0)
    print(json.dumps(summary, indent=2, sort_keys=True))
    for name in ("A", "A2"):
        meta = json.load(open(tmp_path / "runs" / name / "meta.json"))
        assert meta["status"] == "ok", meta.get("error")
        assert meta["output_lines"] > 0
    ref = P.project_file(str(tmp_path / "runs" / "A" / "output.jsonl"))
    assert ref.sealed["finding_ids"] and ref.sealed["confirmed_witness_ids"], "A has nothing to compare"
    for key, g in summary.items():
        assert not g["errors"], (key, g["errors"])
        if g["tally"]:
            assert g["tally"]["failures"] == 0, (key, g)
    fired = sum(g["tally"]["runs"] for g in summary.values() if g["tally"])
    assert fired >= 3, summary


def test_paced_run_after_a_prefill_reports_recovery(tmp_path, world):
    """Step 8g: the first half of the world is a history prefill, the second
    half is shipped at pace 4; the GO is killed in the measured part only
    (MT_FAILPOINT_AFTER), run C still equals A, and the recovery block is
    filled in (read-lag recovery, seal delay, the GO backlog)."""
    import agent_fixtures as F
    build_binaries()
    pods, events = world
    events = sorted((e for e in events if not (e.normalized_event.HasField("ebpf")
                                               and e.normalized_event.ebpf.event_family.startswith("ns."))),
                    key=lambda e: (e.normalized_event.time.event_time.ToNanoseconds(), e.logical_id))
    half = len(events) // 2
    first, second = events[:half], events[half:]
    split_s = second[0].normalized_event.time.event_time.ToNanoseconds() / F.NS - F.T0
    pre = write_lines(str(tmp_path / "prefill.jsonl"), lines(pods, first, split_s - 0.001))
    inp = write_lines(str(tmp_path / "node-1.jsonl"), lines(pods, second, 5000))
    out = tmp_path / "runs"
    summary = CR.run_setting({"node-1": inp}, str(out), ["go.after_flush_before_commit"], reps=1, max_nth=1,
                             parallel=3, outage_s=1.0, settle_s=10.0, pace=4.0, prefill={"node-1": pre},
                             hold_s=5.0)
    print(json.dumps(summary, indent=2, sort_keys=True))
    a = json.load(open(out / "A" / "meta.json"))
    assert a["status"] == "ok", a.get("error")
    runs = [d for d in os.listdir(out) if d.startswith("C-")]
    assert runs, os.listdir(out)
    meta = json.load(open(out / runs[0] / "meta.json"))
    if meta["status"] == "not_fired":
        pytest.skip("the GO point did not fire in the measured part")
    assert meta["status"] == "ok", meta.get("error")
    assert meta["kills"][0]["t"] > meta["prefill_done_ns"], "killed during the prefill"
    res = json.load(open(out / runs[0] / "compare.json"))
    assert res["identical"], res
    rec = res["recovery"]
    assert set(rec["components"]) == {"agents", "go"}
    assert rec["go_backlog_records"] is not None and rec["restart_t"] is not None
    assert "max_s" in rec["seal_delay"]
