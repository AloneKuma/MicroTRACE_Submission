"""score_pilot.py stages for sealed held-out truth: detect never opens restricted/,
score reads truth from --truth-root, all keeps the old one-pass behaviour, and stale,
failed or broken outputs are never reused."""
import gzip
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "pilot"))
import score_pilot as SP  # noqa: E402


@pytest.fixture
def fake(monkeypatch, tmp_path):
    calls = []

    def run(cmd, cwd=None, stdout=None, stderr=None, **kw):
        calls.append(cmd)
        if "mtcore.harness.offline" in cmd:
            Path(cmd[cmd.index("--out") + 1]).write_text('{"topic": "findings.v0"}\n')
        if "mtcore.harness.score" in cmd:
            Path(cmd[cmd.index("--out") + 1]).write_text('{"ok": 1}')
        return subprocess.CompletedProcess(cmd, 0, stdout="")
    monkeypatch.setattr(SP.subprocess, "run", run)
    monkeypatch.setattr(SP, "TIME", str(tmp_path / "no-time"))      # no /usr/bin/time in the test
    return calls


def _params(tmp_path, name="p.yaml", version="T"):
    p = tmp_path / name
    if not p.exists():
        p.write_text(f"parameter_set_version: {version}\n")
    return str(p)


def _args(tmp_path, stage, truth_root=None, params=None):
    return SimpleNamespace(out_dir=str(tmp_path / "out"), pilot=str(tmp_path / "runs"),
                           params=params or _params(tmp_path), no_ml=False, stage=stage, truth_root=truth_root)


def _truth_paths(calls):
    return [c[c.index("--truth") + 1] for c in calls if "--truth" in c]


def _pipeline_calls(calls):
    return [c for c in calls if "mtcore.harness.offline" in c or "mtcore.harness.score" in c]


def test_detect_then_score_from_sealed_root(fake, tmp_path):
    r, status = SP.run_one("r1", _args(tmp_path, "detect"))
    assert status == "ok" and not _truth_paths(fake)
    out = tmp_path / "out" / "runs" / "r1"
    assert gzip.open(out / "output.jsonl.gz", "rt").read() and not (out / "score.json").exists()
    t = json.loads((out / "time.json").read_text())
    assert t["exit"] == 0 and t["wall_s"] >= 0 and t["peak_rss_mb"] is None and t["params_sha256"]
    assert SP.run_one("r1", _args(tmp_path, "detect"))[1] == "cached"
    fake.clear()
    r, status = SP.run_one("r1", _args(tmp_path, "score", truth_root=str(tmp_path / "sealed")))
    assert status == "ok" and (out / "score.json").exists()
    assert _truth_paths(fake) == [str(tmp_path / "sealed" / "r1" / "restricted")]
    assert not any("mtcore.harness.offline" in c for c in fake)
    assert not (out / "output.jsonl").exists() and (out / "output.jsonl.gz").exists()


def test_score_without_detect_output_fails(fake, tmp_path):
    assert SP.run_one("r2", _args(tmp_path, "score"))[1].startswith("FAILED")


def test_all_stage_scores_against_the_run_folder(fake, tmp_path):
    r, status = SP.run_one("r3", _args(tmp_path, "all"))
    assert status == "ok" and _truth_paths(fake) == [str(tmp_path / "runs" / "r3" / "restricted")]
    assert len(_pipeline_calls(fake)) == 2
    assert (tmp_path / "out" / "runs" / "r3" / "score.json").exists()


def test_stale_or_broken_outputs_are_not_reused(fake, tmp_path):
    SP.run_one("r4", _args(tmp_path, "detect"))
    out = tmp_path / "out" / "runs" / "r4"
    # Other params: scoring refuses the old output.
    other = _args(tmp_path, "score", params=_params(tmp_path, "q.yaml", "Q"))
    assert SP.run_one("r4", other)[1].startswith("FAILED")
    # A failed detection is not cached.
    t = json.loads((out / "time.json").read_text())
    (out / "time.json").write_text(json.dumps(dict(t, exit=1)))
    assert SP.run_one("r4", _args(tmp_path, "detect"))[1] == "ok"
    # A truncated gz fails that run only, with a message.
    (out / "output.jsonl.gz").write_bytes(b"\x1f\x8b\x08\x00broken")
    assert SP.run_one("r4", _args(tmp_path, "score"))[1].startswith("FAILED (unreadable")
    assert not (out / "output.jsonl.gz.tmp").exists()


def test_failed_sage_run_is_redone(monkeypatch, tmp_path):
    sage = tmp_path / "out" / "sage"
    sage.mkdir(parents=True)
    (sage / "run.json").write_text(json.dumps({"sage_status": "failed"}))
    called = []
    monkeypatch.setattr(SP.subprocess, "run",
                        lambda *a, **k: called.append(a) or subprocess.CompletedProcess(a, 0))
    a = SimpleNamespace(out_dir=str(tmp_path / "out"), findings_from=str(tmp_path / "f"), sage_params="s.yaml")
    (tmp_path / "f" / "runs" / "r").mkdir(parents=True)
    (tmp_path / "f" / "runs" / "r" / "output.jsonl.gz").write_bytes(b"")
    assert SP.run_sage(a, ["r"]) == 0 and called and not (sage / "run.json").exists()
    sage.mkdir(exist_ok=True)
    (sage / "run.json").write_text(json.dumps({"sage_status": "ok"}))
    called.clear()
    assert SP.run_sage(a, ["r"]) == 0 and not called


def test_drop_source_detect_keeps_fault_log_and_score_passes_it(fake, tmp_path):
    def run(cmd, cwd=None, stdout=None, stderr=None, **kw):
        fake.append(cmd)
        if "mtcore.harness.offline" in cmd:
            Path(cmd[cmd.index("--out") + 1]).write_text('{"topic": "findings.v0"}\n')
            Path(cmd[cmd.index("--fault-log") + 1]).write_text('{"header": {}}\n')
        if "mtcore.harness.score" in cmd:
            Path(cmd[cmd.index("--out") + 1]).write_text('{"ok": 1}')
        return subprocess.CompletedProcess(cmd, 0, stdout="")
    SP.subprocess.run = run
    a = _args(tmp_path, "detect")
    a.drop_source = "AUDIT"
    assert SP.run_one("r5", a)[1] == "ok"
    off = [c for c in fake if "mtcore.harness.offline" in c][0]
    assert off[off.index("--drop-source") + 1] == "AUDIT"
    out = tmp_path / "out" / "runs" / "r5"
    assert (out / "dropped.jsonl.gz").exists() and not (out / "dropped.jsonl").exists()
    assert json.loads((out / "time.json").read_text())["drop_source"] == "AUDIT"
    # The plain (no-drop) score stage refuses the ablation's output, and the reverse.
    assert SP.run_one("r5", _args(tmp_path, "score"))[1].startswith("FAILED")
    fake.clear()
    s = _args(tmp_path, "score")
    s.drop_source = "AUDIT"
    assert SP.run_one("r5", s)[1] == "ok"
    plain, adjusted = [c for c in fake if "mtcore.harness.score" in c]
    assert "--fault-log" not in plain and plain[plain.index("--out") + 1].endswith(SP.NOFAULT + ".tmp")
    assert adjusted[adjusted.index("--fault-log") + 1] == str(out / "dropped.jsonl")
    assert (out / "score.json").exists() and (out / SP.NOFAULT).exists()
    assert not (out / "dropped.jsonl").exists() and (out / "dropped.jsonl.gz").exists()
    assert SP.run_one("r5", s)[1] == "cached"
    (out / SP.NOFAULT).unlink()                    # a drop pass without its plain score is redone
    assert SP.run_one("r5", s)[1] == "ok"


def test_drop_summary_reports_end_to_end_recall_and_unresolved(tmp_path):
    runs = tmp_path / "runs"
    (runs / "r").mkdir(parents=True)
    (runs / "r" / "manifest.json").write_text(json.dumps({"observability_profile": "full"}))
    row = lambda tp, fn, fp: {"present": tp + fn, "tp": tp, "fn": fn, "fp": fp, "fp_absent": fp,
                              "fp_background": 0, "on_unobservable": 0}
    out = tmp_path / "out" / "runs" / "r"
    out.mkdir(parents=True)
    # With the fault log: B1 lost all its opportunities (UNOBSERVABLE), H1 kept 2 of 5.
    adj = {"overall": row(2, 0, 1), "per_type": {"H1": row(2, 0, 1)}}
    # Without it: the same output against the Full row's opportunities (B1 4, H1 5).
    nf = {"overall": row(4, 5, 1), "per_type": {"B1": row(1, 3, 0), "H1": row(3, 2, 1)}}
    (out / "score.json").write_text(json.dumps({"findings": adj, "links": {}, "paths": {}, "incidents": {}}))
    (out / SP.NOFAULT).write_text(json.dumps({"findings": nf, "links": {}, "paths": {}, "incidents": {}}))
    a = SimpleNamespace(out_dir=str(tmp_path / "out"), pilot=str(runs), params="p", split="s", half="h",
                        correlator="go", drop_source="AUDIT")
    s = SP.summarize(a, ["r"])
    e = s["end_to_end"]["findings"]
    assert e["present"] == 9 and e["tp"] == 4 and round(e["recall"], 4) == 0.4444
    assert (e["unresolved"], e["unresolved_detected"], e["unresolved_missed"]) == (7, 2, 5)
    b = s["end_to_end"]["per_agent"]["B"]           # B only exists before the adjustment
    assert (b["present"], b["tp"], b["unresolved"], b["unresolved_detected"]) == (4, 1, 4, 1)
    h = s["end_to_end"]["per_agent"]["H"]
    assert (h["present"], h["unresolved"], h["unresolved_detected"], h["unresolved_missed"]) == (5, 3, 1, 2)
    assert s["findings"]["recall"] == 1.0           # the adjusted number stays as it was


def test_summary_has_per_agent_and_host_rows(tmp_path):
    runs = tmp_path / "runs"
    (runs / "r").mkdir(parents=True)
    (runs / "r" / "manifest.json").write_text(json.dumps({"observability_profile": "full"}))
    row = lambda tp, fn, fp: {"present": tp + fn, "tp": tp, "fn": fn, "fp": fp, "fp_absent": fp,
                              "fp_background": 0, "on_unobservable": 0}
    score = {"findings": {"overall": row(6, 3, 2), "per_type": {"A1": row(1, 1, 0), "C1a": row(2, 0, 1),
                                                                "H1": row(3, 2, 1)}},
             "links": {}, "paths": {}, "incidents": {}}
    out = tmp_path / "out" / "runs" / "r"
    out.mkdir(parents=True)
    (out / "score.json").write_text(json.dumps(score))
    a = SimpleNamespace(out_dir=str(tmp_path / "out"), pilot=str(runs), params="p", split="s", half="h",
                        correlator="go")
    s = SP.summarize(a, ["r"])
    assert s["per_agent"]["A"]["tp"] == 1 and s["per_agent"]["A"]["recall"] == 0.5
    assert s["per_agent"]["H"]["types"] == ["H1"]
    assert s["host_steps"]["types"] == ["C1a", "H1"] and s["host_steps"]["tp"] == 5
    assert s["host_steps"]["present"] == 7 and s["drop_source"] is None


def test_time_output_gives_memory_and_cpu_seconds():
    assert SP.parse_time("204800 12.50 1.25\n") == {"peak_rss_mb": 200.0, "cpu_user_s": 12.5, "cpu_sys_s": 1.25}
    assert SP.parse_time("Command exited with non-zero status 1\n1024 0.01 0.00\n")["peak_rss_mb"] == 1.0
    assert SP.parse_time("") == {"peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None}
    assert SP.parse_time("garbage line\n")["cpu_user_s"] is None
