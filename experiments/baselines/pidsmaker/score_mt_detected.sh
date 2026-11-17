#!/usr/bin/env bash
# KAIROS and ORTHRUS outputs -> our metrics, with the B2 rules fixed on 2026-11-01
# (src/python/mtcore/baselines/provenance/score.py):
#   KAIROS: detected kairos (kairos_run, kairos_summary) and kairos-nodes (distinct flagged
#   nodes against the steps they cover) on each test group.
#   ORTHRUS context row: its flagged nodes -> one graph per run, the union of DEPIMPACT
#   traces (detected seeds, seeded_tracing.py) -> links (seeded records) -> score_pilot.py.
#   ORTHRUS seeded row (main): its records from run_seeded_orthrus.sh -> score_pilot.py.
#
# STAGE splits the work so held-out truth is read only in the scoring step:
#   detect  context-row seeds, tracing and records (no truth; needs the graphs and the
#           mtpids-app container, so it runs where the graphs were built)
#   score   KAIROS, KAIROS nodes, context-row and seeded-row link scoring (reads truth)
#   all     both (default; development runs)
#
#   RES=~/microtrace-b3/results/<session> bash score_mt_detected.sh            # development
#   RES=<results>/ STAGE=detect A=<artifacts> ASUB=seeded CONV=<conv> BGROUPS="..." bash ...
#   RES=<results>/ STAGE=score CONV=<conv> SEEDED=<seeded dir> BGROUPS="..." bash ...
# RES holds results/<step>/flagged.csv per step (kairos_<g> or kairos_<DATASET>, the same for
# orthrus; STEPS_SUFFIX=_run2 scores the KAIROS repeat). BGROUPS lists
# group:dataset:data:truth:findings:split:params:half. Every group in BGROUPS must have its
# KAIROS and ORTHRUS outputs: a missing one is an error, never a silent skip. A failing
# group does not stop the others; the script exits non-zero if any failed.
set -uo pipefail
: "${RES:?set RES to the downloaded results directory}"
B=${B:-$HOME/microtrace-convert}; W=$HOME/microtrace-b3
ASUB=${ASUB:-}; A=${A:-$HOME/microtrace-baselines/pidsmaker/artifacts}; A=$A${ASUB:+/$ASUB}
AD=/home/artifacts${ASUB:+/$ASUB}
CONV=${CONV:-$B/out}; CODE=${CODE:-$W/code}; S=$RES/SCORE_STATUS
VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}; SUFFIX=${STEPS_SUFFIX:-}
STAGE=${STAGE:-all}; SEEDED=${SEEDED:-}
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
FAILED=0
fail() { st "FAILED $*"; FAILED=$((FAILED + 1)); }
. "$VENV/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || { st "STOP code"; exit 1; }
[ -f "$CONV/event_map.csv" ] || { st "STOP no $CONV/event_map.csv"; exit 1; }
st "START stage $STAGE suffix '$SUFFIX' code $(git rev-parse --short HEAD 2>/dev/null || echo '?')"

D=$HOME/microtrace-pilot-multistep/pilot-multistep; DC=$HOME/microtrace-pilot-cases/pilot-cases
BGROUPS=${BGROUPS:-"pilot:MT_PILOT:$D:$D:$HOME/microtrace-pilot-multistep/d23/cache-t0:$D/_gates/pilot-multistep-split.json:$D/_gates/pilot-multistep-fit.yaml:score cases:MT_CASES:$DC:$DC:$DC/_gates/twin_safety:$DC/_gates/tactic/split60.json:$DC/_gates/fit-ri-on.yaml:score"}

step_dir() {   # kind group dataset -> the existing results folder, or empty
  for c in "$RES/$1_$2$4" "$RES/$1_$3$4"; do [ -d "$c" ] && { echo "$c"; return; }; done
}

group() {
  local g=$1 n=$2 d=$3 t=$4 f=$5 sp=$6 pa=$7 h=${8:-score} k o nx
  k=$(step_dir kairos "$g" "$n" "$SUFFIX")
  if [ "$STAGE" != detect ]; then
    [ -n "$k" ] && [ -f "$k/flagged.csv" ] || { fail "kairos $g$SUFFIX: no flagged.csv under $RES"; return; }
    python -m mtcore.baselines.provenance.detected kairos --conv "$CONV" --group "$g" --data "$t" \
      --flagged "$k/flagged.csv" --out "$k/kairos-$g.json" < /dev/null >> "$RES/score.log" 2>&1 \
      || { fail "kairos $g$SUFFIX"; return; }
    st "KAIROS $g$SUFFIX $(tail -1 "$RES/score.log")"
    python -m mtcore.baselines.provenance.detected kairos-nodes --conv "$CONV" --group "$g" --data "$t" \
      --flagged "$k/flagged.csv" --out "$k/kairos-nodes-$g.json" < /dev/null >> "$RES/score.log" 2>&1 \
      || { fail "kairos nodes $g$SUFFIX"; return; }
    st "KAIROS_NODES $g$SUFFIX $(tail -1 "$RES/score.log")"
  fi
  [ -n "$SUFFIX" ] && return                   # the repeat is KAIROS only

  o=$(step_dir orthrus "$g" "$n" "")
  [ -n "$o" ] && [ -f "$o/flagged.csv" ] || { fail "orthrus $g: no flagged.csv under $RES"; return; }
  if [ "$STAGE" != score ]; then
    nx=$(cd "$A" && ls -d construction/"$n"/construction/*/nx 2>/dev/null)
    [ "$(echo "$nx" | grep -c .)" = 1 ] || { fail "$g: expected one graph directory under $A, found: $nx"; return; }
    python -m mtcore.baselines.provenance.detected seeds --conv "$CONV" --group "$g" --flagged "$o/flagged.csv" \
      --out "$o/seeds.json" < /dev/null >> "$RES/score.log" 2>&1 || { fail "context seeds $g"; return; }
    st "SEEDS $g $(tail -1 "$RES/score.log")"
    mkdir -p "$A/mt-context" && chmod 777 "$A/mt-context" && cp "$o/seeds.json" "$A/mt-context/seeds-$g.json"
    docker exec -u pids -w /home/artifacts -e PYTHONPATH=/home/artifacts/orthrus-src mtpids-app \
      /opt/conda/envs/pids/bin/python /home/artifacts/seeded_tracing.py --seeds "$AD/mt-context/seeds-$g.json" \
      --graphs "$AD/$nx" --orthrus-src /home/artifacts/orthrus-src --workers 6 \
      --out "$AD/mt-context/traced-$g.json" < /dev/null >> "$RES/score.log" 2>&1 || { fail "context tracing $g"; return; }
    cp "$A/mt-context/traced-$g.json" "$o/traced.json"
    python -m mtcore.baselines.provenance.seeded records --conv "$CONV" --group "$g" --findings-from "$f" --k 10 \
      --traced "$o/traced.json" --out-dir "$o/score" < /dev/null >> "$RES/score.log" 2>&1 \
      || { fail "context records $g"; return; }
    st "CONTEXT_RECORDS $g"
  fi
  if [ "$STAGE" != detect ]; then
    [ -f "$o/score/sage/run.json" ] || { fail "context $g: no records (run STAGE=detect first)"; return; }
    python src/scripts/pilot/score_pilot.py --correlator sage --sage-variant ag --pilot "$d" --truth-root "$t" \
      --half "$h" --split "$sp" --params "$pa" --findings-from "$f" --out-dir "$o/score" --stage score \
      --workers "${WORKERS:-4}" < /dev/null >> "$RES/score.log" 2>&1 || { fail "context score $g"; return; }
    st "CONTEXT $g $(grep '^Links:' "$o/score/summary.md"); $(grep '^Paths:' "$o/score/summary.md")"
    if [ -n "$SEEDED" ]; then
      [ -f "$SEEDED/score-$g/sage/run.json" ] || { fail "seeded $g: no records in $SEEDED/score-$g"; return; }
      python src/scripts/pilot/score_pilot.py --correlator sage --sage-variant ag --pilot "$d" --truth-root "$t" \
        --half "$h" --split "$sp" --params "$pa" --findings-from "$f" --out-dir "$SEEDED/score-$g" --stage score \
        --workers "${WORKERS:-4}" < /dev/null >> "$RES/score.log" 2>&1 || { fail "seeded score $g"; return; }
      st "SEEDED $g $(grep '^Links:' "$SEEDED/score-$g/summary.md"); $(grep '^Paths:' "$SEEDED/score-$g/summary.md")"
    fi
  fi
}

for spec in $BGROUPS; do
  IFS=: read -r g n d t f sp pa h <<< "$spec"
  group "$g" "$n" "$d" "$t" "$f" "$sp" "$pa" "$h"
done
if [ "$FAILED" -gt 0 ]; then st "FAILED_GROUPS $FAILED"; exit 1; fi
st ALL_DONE
