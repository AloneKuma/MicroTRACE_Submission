"""mtcore.harness.seal: the readable part of a run holds no truth, the two parts hold the
whole run, and the pipeline's output on the readable part equals its output on the full
run (apart from publishTime, which is wall-clock)."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mtcore.harness import seal as SEAL

PY = Path(__file__).resolve().parents[1]
PARAMS = str(PY.parent / "params" / "frozen" / "pilot-multistep-fit.K10.yaml")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("seal")
    env = dict(os.environ, PYTHONHASHSEED="1")
    subprocess.run([sys.executable, "-m", "mtgen", "build", "--scenarios", "chain_container_escape",
                    "--duration-s", "120", "--world", "Small", "--seed", "7", "--out", str(tmp / "run")],
                   check=True, cwd=PY, env=env, capture_output=True)
    SEAL.split(str(tmp / "run"), str(tmp / "r"), str(tmp / "t"))
    return tmp


def test_readable_part_holds_no_truth(run):
    assert SEAL.verify(str(run / "r")) == []
    assert not (run / "r" / "restricted").exists() and not (run / "r" / "base.pb").exists()
    m = json.load(open(run / "r" / "manifest.json"))
    assert not set(SEAL.TRUTH_FIELDS) & set(m) and m["run_id"] and m["observability_profile"]
    assert (run / "t" / "restricted" / "truth_actions.pb").exists() and (run / "t" / "base.pb").exists()


def test_parts_hold_every_shipper_line(run):
    for n in os.listdir(run / "run" / "shipper"):
        full = open(run / "run" / "shipper" / n, encoding="utf-8").readlines()
        kept = open(run / "r" / "shipper" / n, encoding="utf-8").readlines()
        gone_p = run / "t" / "shipper-truth" / n
        gone = open(gone_p, encoding="utf-8").readlines() if gone_p.exists() else []
        assert sorted(full) == sorted(kept + gone)
        assert all(json.loads(x)["topic"] == SEAL.TRUTH_TOPIC for x in gone)


def test_pipeline_output_is_unchanged_by_the_seal(run):
    env = dict(os.environ, PYTHONHASHSEED="1")
    outs = {}
    for side in ("run", "r"):
        o = run / f"{side}.jsonl"
        subprocess.run([sys.executable, "-m", "mtcore.harness.offline", str(run / side), "--out", str(o),
                        "--params", PARAMS, "--orch-params", PARAMS], check=True, cwd=PY, env=env,
                       capture_output=True)
        outs[side] = re.sub(r'"publishTime": ?"[^"]*"', "", o.read_text())
    assert outs["run"] == outs["r"] and outs["run"]


def test_refuses_unknown_entries_and_symlinks(run, tmp_path):
    odd = tmp_path / "odd"
    (odd / "shipper").mkdir(parents=True)
    (odd / "manifest.json").write_text("{}")
    (odd / "notes.txt").write_text("x")
    with pytest.raises(SystemExit):
        SEAL.split(str(odd), str(tmp_path / "r1"), str(tmp_path / "t1"))
    (odd / "notes.txt").unlink()
    try:
        os.symlink(run / "run" / "restricted", odd / "shipper" / "link")
    except (OSError, NotImplementedError):
        pytest.skip("no symlinks on this system")
    with pytest.raises(SystemExit):
        SEAL.split(str(odd), str(tmp_path / "r2"), str(tmp_path / "t2"))
