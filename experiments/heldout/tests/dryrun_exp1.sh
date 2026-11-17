#!/usr/bin/env bash
# Host dry run before held-out Session A (heldout-aws-plan.md section 7; Exp. 1 checks decided
# 2026-11-15). Development PILOT SCORE runs only; nothing held-out is touched.
#
#   W=~/microtrace-dryrun2 RUNS="id1 id2 id3" nohup bash dryrun_exp1.sh > dryrun.out 2>&1 &
#
# W/code is a checkout of the commit under test (with src/python/gen). Steps, each logged to
# W/STATUS as PASS/FAIL/INFO:
#   D1 seal + detect-then-score equals one-pass scoring (go_main params), and equals the
#      2026-11-13 development v2 scores of the same runs
#   D2 determinism: a second detect with PYTHONHASHSEED=1 gives identical output (findings'
#      wall-clock publishTime left out);
#      PYTHONHASHSEED=2 is reported (INFO) to show whether results depend on the seed
#   D3 the four drop-source passes, detect then score against the sealed truth: dropped
#      records, findings, unobservable opportunities and abstentions per source
#   D4 agent independence: each agent alone gives the same records as in the full run
#   D5 summary rows: per_agent and host_steps present and adding up
# The last STATUS line is DRYRUN_DONE (all PASS) or DRYRUN_FAILED.
set -u
W=${W:?set W}; CODE=$W/code
PILOT=${PILOT:-$HOME/microtrace-pilot-multistep/pilot-multistep}
V2=${V2:-$HOME/microtrace-rescore-v2/go-v2}
VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}
WORKERS=${WORKERS:-3}
PARAMS=$CODE/src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml
read -r -a RUNS <<< "${RUNS:?set RUNS}"
. "$VENV/bin/activate"
export PYTHONPATH=$CODE/src/python:$CODE/src/python/gen PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
SP=$CODE/src/scripts/pilot/score_pilot.py
FAIL=0
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$W/STATUS"; }
check() { if [ "$1" = 0 ]; then status "PASS $2"; else status "FAIL $2"; FAIL=$((FAIL + 1)); fi; }

: > "$W/STATUS"
status "START code $(git -C "$CODE" rev-parse --short HEAD) runs ${RUNS[*]}"
python - "$W/split.json" "${RUNS[@]}" <<'PY'
import json, sys
json.dump({"dry": sys.argv[2:]}, open(sys.argv[1], "w"))
PY

# Full copies (one-pass reference) and the sealed split (readable / truth), by the real splitter.
mkdir -p "$W/full" "$W/readable" "$W/truth"
for r in "${RUNS[@]}"; do
  [ -d "$W/full/$r" ] || cp -r "$PILOT/$r" "$W/full/$r"
  if [ ! -d "$W/readable/$r" ]; then
    (cd "$CODE/src/python" && python -m mtcore.harness.seal "$W/full/$r" --readable "$W/readable/$r" \
      --truth "$W/truth/$r") >> "$W/seal.log" 2>&1 || { status "FAIL seal $r"; FAIL=$((FAIL + 1)); }
  fi
  [ -e "$W/readable/$r/restricted" ] && { status "FAIL readable part of $r holds restricted/"; FAIL=$((FAIL + 1)); }
done

sp() { python "$SP" --split "$W/split.json" --half dry --params "$PARAMS" --workers "$WORKERS" "$@"; }

# D1 -------------------------------------------------------------------------------------
sp --pilot "$W/full" --out-dir "$W/d1-all" --stage all > "$W/d1-all.log" 2>&1
check $? "D1 one-pass run"
sp --pilot "$W/readable" --out-dir "$W/d1-sealed" --stage detect > "$W/d1-detect.log" 2>&1
check $? "D1 sealed detect"
sp --pilot "$W/readable" --truth-root "$W/truth" --out-dir "$W/d1-sealed" --stage score > "$W/d1-score.log" 2>&1
check $? "D1 sealed score"
python - "$W" "$V2" "${RUNS[@]}" > "$W/d1-compare.txt" 2>&1 <<'PY'
import json, sys
w, v2, runs = sys.argv[1], sys.argv[2], sys.argv[3:]
bad = 0
for r in runs:
    a = json.load(open(f"{w}/d1-all/runs/{r}/score.json"))
    s = json.load(open(f"{w}/d1-sealed/runs/{r}/score.json"))
    try:
        old = json.load(open(f"{v2}/runs/{r}/score.json"))
    except OSError:
        old = None
    same_seal = a == s
    keys = ("findings", "links", "paths")
    same_v2 = old is not None and all(a[k] == old.get(k) for k in keys)
    print(r, "sealed==one-pass", same_seal, "one-pass==dev-v2(findings,links,paths)", same_v2)
    if old is not None and not same_v2:
        for k in keys:
            if a[k] != old.get(k):
                ka, ko = a[k], old.get(k) or {}
                diff = sorted(x for x in set(ka) | set(ko) if ka.get(x) != ko.get(x))
                print("   differs in", k, diff[:12])
    bad += not same_seal or not same_v2
sys.exit(1 if bad else 0)
PY
check $? "D1 sealed == one-pass == dev v2 (see d1-compare.txt)"

# D2 -------------------------------------------------------------------------------------
sp --pilot "$W/readable" --out-dir "$W/d2-seed1" --stage detect > "$W/d2-seed1.log" 2>&1
PYTHONHASHSEED=2 sp --pilot "$W/readable" --out-dir "$W/d2-seed2" --stage detect > "$W/d2-seed2.log" 2>&1
# Findings carry publishTime, the wall-clock time they were emitted; it differs on every run by
# design and is not scored, so it is left out of the comparison (first dry run, 2026-11-15).
same_output() {
  python - "$1" "$2" <<'PY'
import gzip, json, sys
def norm(p):
    out = []
    for line in gzip.open(p, "rt"):
        j = json.loads(line)
        j.get("record", {}).pop("publishTime", None)
        out.append(json.dumps(j, sort_keys=True))
    return out
sys.exit(0 if norm(sys.argv[1]) == norm(sys.argv[2]) else 1)
PY
}
d2=0; d2s=0
for r in "${RUNS[@]}"; do
  same_output "$W/d1-sealed/runs/$r/output.jsonl.gz" "$W/d2-seed1/runs/$r/output.jsonl.gz" || d2=1
  same_output "$W/d1-sealed/runs/$r/output.jsonl.gz" "$W/d2-seed2/runs/$r/output.jsonl.gz" || d2s=1
done
check $d2 "D2 repeated detect (seed 1) identical apart from publishTime"
status "INFO D2 seed 2 vs seed 1 (apart from publishTime): $([ $d2s = 0 ] && echo identical || echo DIFFERENT)"

# D3 -------------------------------------------------------------------------------------
for src in EBPF GATEWAY KYVERNO AUDIT; do
  o=$W/d3-$src
  sp --pilot "$W/readable" --out-dir "$o" --stage detect --drop-source "$src" > "$o.detect.log" 2>&1
  check $? "D3 $src detect"
  sp --pilot "$W/readable" --truth-root "$W/truth" --out-dir "$o" --stage score --drop-source "$src" > "$o.score.log" 2>&1
  check $? "D3 $src score"
done
python - "$W" "${RUNS[@]}" > "$W/d3-report.txt" 2>&1 <<'PY'
import glob, gzip, json, sys
w, runs = sys.argv[1], sys.argv[2:]
full = json.load(open(f"{w}/d1-sealed/summary.json"))
print("full: findings", {k: full["findings"][k] for k in ("present", "tp", "fp", "recall", "precision")},
      "unobservable", full["findings"]["unobservable_opportunities"])
bad = 0
for src in ("EBPF", "GATEWAY", "KYVERNO", "AUDIT"):
    s = json.load(open(f"{w}/d3-{src}/summary.json"))
    dropped = sum(sum(1 for l in gzip.open(f, "rt") if '"logical_id"' in l)
                  for f in glob.glob(f"{w}/d3-{src}/runs/*/dropped.jsonl.gz"))
    f = s["findings"]
    agents = {a: (c["tp"], c["fp"], c["present"]) for a, c in s["per_agent"].items()}
    print(f"{src}: dropped IDs {dropped}, present {f['present']}, tp {f['tp']}, fp {f['fp']}, "
          f"recall {f['recall']}, unobservable {f['unobservable_opportunities']}, "
          f"abstained {f['abstained_evaluations']}, per agent (tp, fp, present) {agents}")
    bad += s["drop_source"] != src or dropped == 0
sys.exit(1 if bad else 0)
PY
check $? "D3 every source dropped something and the summaries name it (see d3-report.txt)"

# D4 -------------------------------------------------------------------------------------
python "$CODE/experiments/heldout/tests/agent_independence.py" --params "$PARAMS" "$W/d4.json" \
  $(for r in "${RUNS[@]}"; do echo "$W/readable/$r"; done) > "$W/d4.log" 2>&1
check $? "D4 each agent alone == its records in the full run (see d4.json)"

# D5 -------------------------------------------------------------------------------------
python - "$W/d1-sealed/summary.json" > "$W/d5.txt" 2>&1 <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
pa, hs, f = s["per_agent"], s["host_steps"], s["findings"]
for k in ("tp", "fp", "present"):
    assert sum(c[k] for c in pa.values()) == f[k], k
print("per_agent", {a: (c["tp"], c["fp"], c["present"], c["recall"]) for a, c in pa.items()})
print("host_steps", {k: hs[k] for k in ("types", "present", "tp", "fp", "recall", "precision")})
PY
check $? "D5 per_agent adds up to the overall counts; host_steps present (see d5.txt)"

if [ "$FAIL" = 0 ]; then status DRYRUN_DONE; else status "DRYRUN_FAILED ($FAIL failed)"; fi
