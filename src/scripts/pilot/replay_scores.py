"""Scores under a correlator parameter set, from cached agent findings.

    python src/scripts/pilot/replay_scores.py RUNS_DIR CACHED_DIR --params P.yaml \\
        --split SPLIT.json --out-dir DIR [--check]

The agents' findings do not depend on the GO's parameters, so a score for
Full, No-Conflict or No-Origin needs only the GO again: per SCORE run of the
split, the run's GO inputs (shipper) and then the agents' findings of an
earlier offline output (CACHED_DIR/<run_id>.output.jsonl, twin safety's) are
fed to a new GO in mtcore.harness.offline's order. The output (the cached
findings and rule evaluations, then the replayed witness decisions and
incidents) is scored by mtcore.harness.score into DIR/runs/<run_id>/, the
layout of score_pilot.py, whose summary then reads it (score_pilot.py with
the same --out-dir finds every run cached).

--check: also compare the replayed GO records with the cached ones (they
must be equal when P is the parameter set the cached output was made with).
"""
import argparse
import gzip
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PY = REPO / "src" / "python"
sys.path.insert(0, str(PY))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from google.protobuf import json_format  # noqa: E402

from mtcore.harness import offline as OFF  # noqa: E402
from mtcore.orchestrator.engine import Engine  # noqa: E402
from mtcore.orchestrator.params import OrchParams  # noqa: E402

import cached_output  # noqa: E402
from ablation_cases import _findings  # noqa: E402

GO_TOPICS = ("witness.decisions.v0", "incidents.v0")


def replay(run_dir, cached, oparams):
    """The cached agent lines and the replayed GO lines, in offline's order."""
    with cached_output.open_text(cached) as fh:
        agent_lines = [ln for ln in fh if json.loads(ln)["topic"] not in GO_TOPICS]
    go = Engine(oparams)
    offsets = Counter()
    for topic, env in OFF.read_shipper(str(run_dir)):
        if topic in OFF.GO_INPUTS:
            go.feed(env, topic, 0, offsets[topic])
            offsets[topic] += 1
    for env in _findings(cached):
        go.feed(env, OFF.FINDINGS, 0, offsets[OFF.FINDINGS])
        offsets[OFF.FINDINGS] += 1
    go.finish()
    OFF._hook(go, OFF._now(go, 0))
    go_lines = []
    for topic, _key, env in go.drain():
        msg = env.witness if env.HasField("witness") else env.incident
        go_lines.append(json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n")
    return agent_lines, go_lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs_dir", type=Path)
    ap.add_argument("cached_dir", type=Path)
    ap.add_argument("--params", required=True)
    ap.add_argument("--split", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    oparams = OrchParams.load(a.params)
    runs_dir, out_dir = a.runs_dir.resolve(), a.out_dir.resolve()
    ids = json.loads(a.split.read_text(encoding="utf-8"))["score"]
    bad = []
    for n, rid in enumerate(ids, 1):
        out = out_dir / "runs" / rid
        if (out / "score.json").exists():
            print(f"{n}/{len(ids)} {rid} cached", flush=True)
            continue
        out.mkdir(parents=True, exist_ok=True)
        cached = cached_output.find(a.cached_dir.resolve(), rid)
        if cached is None:
            bad.append(rid)
            print(f"{n}/{len(ids)} {rid} FAILED: no cached output in {a.cached_dir}", flush=True)
            continue
        agent_lines, go_lines = replay(runs_dir / rid, cached, oparams)
        if a.check:
            with cached_output.open_text(cached) as fh:
                old = [ln for ln in fh if json.loads(ln)["topic"] in GO_TOPICS]
            if old != go_lines:
                bad.append(rid)
                print(f"{n}/{len(ids)} {rid} CHECK FAILED: {len(old)} cached GO records, {len(go_lines)} replayed",
                      flush=True)
                continue
        jsonl = out / "output.jsonl"
        jsonl.write_text("".join(agent_lines + go_lines), encoding="utf-8")
        with open(out / "score.log", "w") as log:
            r = subprocess.run([sys.executable, "-m", "mtcore.harness.score", "--truth", str(runs_dir / rid / "restricted"),
                                "--output", str(jsonl), "--out", str(out / "score.json.tmp")],
                               cwd=PY, stdout=log, stderr=subprocess.STDOUT)
        if r.returncode:
            bad.append(rid)
            print(f"{n}/{len(ids)} {rid} FAILED (see {out / 'score.log'})", flush=True)
            continue
        with open(jsonl, "rb") as src, gzip.open(str(jsonl) + ".gz", "wb") as dst:
            shutil.copyfileobj(src, dst)
        jsonl.unlink()
        (out / "score.json.tmp").replace(out / "score.json")
        print(f"{n}/{len(ids)} {rid} ok ({len(go_lines)} GO records)", flush=True)
    print(f"replayed: {len(ids) - len(bad)} of {len(ids)}; failed: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
