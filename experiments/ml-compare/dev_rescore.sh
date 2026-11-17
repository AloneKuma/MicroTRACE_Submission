#!/usr/bin/env bash
# Development re-scores with ML setting v2 on the test host (plan approved 2026-11-12:
# GO v2 and mlB3 on PILOT SCORE, GO v2 on PILOT FIT for a SAGE refit, SAGE v1 and seeded ORTHRUS
# on the v2 SCORE findings). One job, sequential, WORKERS score_pilot workers. Resumable: each
# stage leaves done/<stage>, score_pilot skips runs with a score.json. STATUS ends RESCORE_DONE.
# Waits until the held-out build (run_all.sh) is no longer running: both need the host's RAM.
#
#   W=~/microtrace-rescore-v2 setsid nohup bash dev_rescore.sh > ~/microtrace-rescore-v2/job.out 2>&1 < /dev/null &
set -uo pipefail
W=${W:-$HOME/microtrace-rescore-v2}; CODE=${CODE:-$W/code}; S=$W/STATUS
D=${D:-$HOME/microtrace-pilot-multistep/pilot-multistep}; SPLIT=$D/_gates/pilot-multistep-split.json
VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}; WORKERS=${WORKERS:-3}
CONV=${CONV:-$HOME/microtrace-convert}
export MT_SAGE_HOME=${MT_SAGE_HOME:-$HOME/microtrace-dev/baselines/sage}
PF=$CODE/src/params/frozen
mkdir -p "$W/done" "$W/logs"
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
stop() { st "STOP $*"; exit 1; }
done_() { touch "$W/done/$1"; }
is_done() { [ -f "$W/done/$1" ]; }
disk_ok() { local g; g=$(df -BG --output=avail ~ | tail -1 | tr -dc 0-9); [ "$g" -ge "${1:-8}" ] || stop "disk ${g} GB free < ${1:-8} GB before $2"; }

# ---- preflight --------------------------------------------------------------------------------
. "$VENV/bin/activate" || stop "venv $VENV"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || stop "code $CODE"
if [ -n "${TEST_SPLIT:-}" ]; then           # test mode: a few runs, no build wait
  SPLIT=$TEST_SPLIT; NO_WAIT=1; st "TEST mode: split $SPLIT"
else
  [ "$(sha256sum "$SPLIT" | cut -c1-12)" = be0053857137 ] || stop "split hash differs"
  python3 -c "import json,sys;d=json.load(open('$SPLIT'));sys.exit(not (len(d['score'])==163 and len(d['fit'])==170))" \
    || stop "split is not 163 SCORE / 170 FIT"
fi
for f in pilot-multistep-fit.K10.mlv2.yaml pilot-multistep-fit.K10.mlB3.yaml; do
  python -c "from mtcore.agents.params import Params; from mtcore.agents.ml.scorer import Scorer; Scorer.load(Params.load('$PF/$f'))" \
    || stop "models of $f do not load"
done
[ -f "$CONV/out/config.json" ] || stop "no conversion in $CONV/out"
[ -d "$MT_SAGE_HOME/SAGE" ] || stop "no SAGE in $MT_SAGE_HOME"
for c in mtpids-postgres mtpids-app; do docker ps --format '{{.Names}}' | grep -qx "$c" || stop "container $c not running"; done
st "PREFLIGHT ok: code $(cat "$W/CODE_COMMIT" 2>/dev/null), split 163/170 be0053857137, workers $WORKERS"

if [ -n "${WAIT_FOR_TEST:-}" ]; then        # queued mode: start only after the test run passed
  st "WAIT test run ($WAIT_FOR_TEST)"
  while :; do
    grep -q " RESCORE_DONE" "$WAIT_FOR_TEST" 2>/dev/null && { st "TEST passed"; break; }
    grep -q " STOP " "$WAIT_FOR_TEST" 2>/dev/null && stop "test run failed, not started: $(grep ' STOP ' "$WAIT_FOR_TEST" | tail -1)"
    sleep 300
  done
fi
wait_build() {   # the held-out build (run_all.sh) shares RAM and disk: never run a stage beside it
  [ "${NO_WAIT:-0}" = 1 ] && return
  local said=0
  # Anchored: only the build itself ("bash run_all.sh"), never a shell whose command line merely
  # mentions it (on 2026-11-12 the launcher's own ssh command matched and held the job for 12 h).
  while pgrep -f "^bash ([^ ]*/)?run_all\.sh" > /dev/null; do
    [ $said = 1 ] || { st "WAIT held-out build (run_all.sh) running${1:+, before $1}"; said=1; }
    sleep 300
  done
  [ $said = 1 ] && st "RESUME build no longer running"
  return 0
}
wait_build
st "START $(free -g | awk '/Mem:/ {print $7}') GB available, $(df -h ~ | awk 'END{print $4}') disk free"

go() {  # name params half
  local n=$1 p=$2 h=$3
  is_done "$n" && { st "SKIP $n (done)"; return; }
  wait_build "$n"; disk_ok 8 "$n"
  st "RUN $n: $p --half $h"
  python src/scripts/pilot/score_pilot.py --pilot "$D" --split "$SPLIT" --half "$h" --params "$PF/$p" \
      --out-dir "$W/$n" --workers "$WORKERS" > "$W/logs/$n.log" 2>&1 || stop "$n score_pilot (logs/$n.log)"
  python3 -c "import json,sys;s=json.load(open('$W/$n/summary.json'));m=s['runs_missing'];print(len(m));sys.exit(bool(m))" \
      > /dev/null || stop "$n: runs missing (summary.json)"
  st "DONE $n $(python3 -c "
import json;s=json.load(open('$W/$n/summary.json'));f,l=s['findings'],s['links']
g=lambda m,k: '-' if m.get(k) is None else '%.4f' % m[k]
print('findings P/R/F1', g(f,'precision'), g(f,'recall'), g(f,'f1'), 'links P/R/F1', g(l,'precision'), g(l,'recall'), g(l,'f1'))")"
  done_ "$n"
}

go go-v2 pilot-multistep-fit.K10.mlv2.yaml score
go go-mlB3 pilot-multistep-fit.K10.mlB3.yaml score

if ! is_done subset; then   # v2 findings = mlB3 findings minus some B1/H1 (and nothing else)
  python3 - "$W" "$SPLIT" > "$W/logs/subset.log" 2>&1 <<'PY' || stop "subset check (logs/subset.log)"
import gzip, json, sys
from collections import Counter
w, split = sys.argv[1:]
gone, bad = Counter(), []
for r in json.load(open(split))["score"]:
    ids = {}
    for v in ("go-v2", "go-mlB3"):
        f = {}
        for line in gzip.open(f"{w}/{v}/runs/{r}/output.jsonl.gz", "rt"):
            if '"findings.v0"' in line:
                o = json.loads(line)
                if o["topic"] == "findings.v0":
                    f[o["record"]["findingId"]] = o["record"]["findingType"]
        ids[v] = f
    a, b = ids["go-v2"], ids["go-mlB3"]
    if set(a) - set(b):
        bad.append((r, "extra in v2"))
    for k in set(b) - set(a):
        gone[b[k]] += 1
        if b[k] not in ("B1", "H1"):
            bad.append((r, f"dropped {b[k]}"))
print(json.dumps({"dropped_by_v2": dict(gone), "bad": bad[:5], "n_bad": len(bad)}))
sys.exit(1 if bad else 0)
PY
  st "SUBSET ok $(tail -1 "$W/logs/subset.log")"
  rm -f "$W"/go-mlB3/runs/*/output.jsonl.gz; done_ subset
fi

go go-v2-fit pilot-multistep-fit.K10.mlv2.yaml fit

if ! is_done sagefit; then
  wait_build sagefit; disk_ok 5 sagefit
  sed 's/^version: sage.v0$/version: sage.v1/' "$CODE/src/params/sage.v0.yaml" > "$W/sage.v1.yaml"
  grep -q "^version: sage.v1$" "$W/sage.v1.yaml" || stop "sage.v1.yaml version line"
  st "RUN sagefit (refit t, w on v2 FIT findings, frozen grid and rule)"
  python src/scripts/pilot/fit_sage.py --pilot "$D" --split "$SPLIT" --findings-from "$W/go-v2-fit" \
      --out-dir "$W/sagefit" --params "$W/sage.v1.yaml" --write-params "$W/sage.v1.yaml" --workers "$WORKERS" \
      > "$W/logs/sagefit.log" 2>&1 || stop "fit_sage (logs/sagefit.log)"
  st "DONE sagefit $(grep -E '^(t|w|fitted):' "$W/sage.v1.yaml" | xargs) $(grep -E 'fit_link_f1' "$W/sage.v1.yaml" | xargs)"
  rm -f "$W"/go-v2-fit/runs/*/output.jsonl.gz; done_ sagefit
fi

for v in ag seq; do
  n=sage-v2-$v
  is_done "$n" && continue
  wait_build "$n"
  st "RUN $n"
  python src/scripts/pilot/score_pilot.py --pilot "$D" --split "$SPLIT" --half score --params "$PF/pilot-multistep-fit.K10.mlv2.yaml" \
      --correlator sage --findings-from "$W/go-v2" --sage-variant "$v" --sage-params "$W/sage.v1.yaml" \
      --out-dir "$W/$n" --workers "$WORKERS" > "$W/logs/$n.log" 2>&1 || stop "$n (logs/$n.log)"
  st "DONE $n $(grep -E '^(Links|Paths):' "$W/$n/summary.md" | xargs)"
  done_ "$n"
done

if ! is_done orthrus; then
  wait_build orthrus
  O=$W/orthrus; mkdir -p "$O"; ln -sfn "$CONV/out" "$O/out"
  st "RUN orthrus seeded on v2 SCORE findings (own folder $O, artifacts/rescore-v2)"
  B=$O CODE=$CODE ASUB=rescore-v2 LOAD=0 WAIT_CONV=0 WORKERS=$WORKERS \
    BGROUPS="pilot:MT_PILOT:$D:$W/go-v2:$SPLIT:$PF/pilot-multistep-fit.K10.mlv2.yaml:score" \
    bash "$CODE/experiments/baselines/pidsmaker/run_seeded_orthrus.sh" > "$W/logs/orthrus.log" 2>&1
  tail -1 "$O/ORTHRUS_STATUS" | grep -q ALL_DONE || stop "orthrus: $(tail -1 "$O/ORTHRUS_STATUS")"
  st "DONE orthrus $(grep DONE_pilot "$O/ORTHRUS_STATUS" | cut -d' ' -f2- | cut -c1-300)"
  done_ orthrus
fi

python3 - "$W" > "$W/compare.md" <<'PY' || stop "compare.md"
import json, os, sys
w = sys.argv[1]
def s(d): return json.load(open(os.path.join(w, d, "summary.json")))
L = ["# Development re-scores, ML setting v2 (PILOT SCORE, 163 runs)", ""]
L += ["| Row | Findings P / R / F1 | Links P / R / F1 | Strict path recall | FCR |", "|---|---|---|---|---|"]
for d, name in (("go-v2", "GO v2 (main)"), ("go-mlB3", "GO mlB3 (side)"), ("sage-v2-ag", "SAGE ag, sage.v1"),
                ("sage-v2-seq", "SAGE seq, sage.v1"), ("orthrus/score-pilot", "ORTHRUS seeded on v2")):
    try:
        x = s(d)
    except FileNotFoundError:
        L.append(f"| {name} | - | - | - | - |"); continue
    f, l, p = x.get("findings", {}), x.get("links", {}), x.get("paths", {})
    g = lambda m, k: "-" if m.get(k) is None else f"{m[k]:.4f}"
    L.append(f"| {name} | {g(f,'precision')} / {g(f,'recall')} / {g(f,'f1')} | {g(l,'precision')} / {g(l,'recall')} / "
             f"{g(l,'f1')} | {g(p,'top_k_path_recall')} | {g(p,'false_chain_rate')} |")
L += ["", "Recorded earlier (ROADMAP 2b, K = 10): GO rules-only PILOT links P .9241 R .8787, strict path recall",
      ".7603, FCR .0416; SAGE seq (sage.v0) .1653 / .68; ORTHRUS seeded .5950 / .56.", ""]
L += ["Per type (findings tp / fp / fn), v2 vs mlB3:", ""]
a, b = s("go-v2").get("per_type", {}), s("go-mlB3").get("per_type", {})
for t in sorted(set(a) | set(b)):
    fa, fb = a.get(t, {}), b.get(t, {})
    L.append(f"- {t}: {fa.get('tp')}/{fa.get('fp')}/{fa.get('fn')} vs {fb.get('tp')}/{fb.get('fp')}/{fb.get('fn')}")
print("\n".join(L))
PY
st "RESCORE_DONE disk $(df -h ~ | awk 'END{print $4}') free"
