#!/usr/bin/env bash
# Exp. 3 local dry run on development data (worklog section 6): sender and receiver on one machine.
# DEV holds PILOT development runs (full runs from `mtgen build` of rows of
# spec/generator/run-matrix.pilot-multistep.yaml; truth is used only by the scoring step at the
# end, from DEV/<run>/restricted). Needs MT_BIN (faultinject, shipper, receiver, devcerts),
# KAFKA_HOME (+ java), and for SAGE passes MT_SAGE_HOME (otherwise give PASSES without sage rows).
#
#   DEV=~/microtrace-exp3/dev RUNS=~/microtrace-exp3/runs.json:runs OUT=~/microtrace-exp3/dry \
#     PASSES=experiments/exp3/configs/passes.tsv bash experiments/exp3/tests/dryrun_exp3.sh
#
# Steps: W1 = nofault (live), loss-transit-20, compromise-forge and nofault-fast (a no-fault fast
# replay, the lossless-transport check); W2 = loss-transit-20 again (same seed); reference offline
# outputs on the original runs; dryrun_checks.py (D1-D6); then the score role on W1 (dev truth).
set -euo pipefail
: "${DEV:?}" "${RUNS:?}" "${OUT:?}"
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
PASSES=${PASSES:-$REPO/experiments/exp3/configs/passes.tsv}
MAIN=${MAIN:-$REPO/src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml}
PY=${PY:-python}; SLOTS=${SLOTS:-3}; WORKERS=${WORKERS:-3}
mkdir -p "$OUT/cfg" "$OUT/plans" "$OUT/ref"
# The committed conditions plus one dry-run-only row: the no-fault plan at pace 0.
cp "$REPO/experiments/exp3/configs/conditions.tsv" "$OUT/cfg/conditions.tsv"
printf 'nofault-fast\tnofault.yaml\toffline\t0\t1\t-\tdry-run check: lossless transport\n' >> "$OUT/cfg/conditions.tsv"
cp "$REPO"/experiments/exp3/plans/*.yaml "$OUT/plans/"
cd "$REPO"
common=(--role local --data "$DEV" --runs "$RUNS" --conditions "$OUT/cfg/conditions.tsv" --passes "$PASSES"
        --main-params "$MAIN" --slots "$SLOTS" --workers "$WORKERS" --keep-jsonl)
$PY -m mtcore.exp3.run "${common[@]}" --work "$OUT/w1" --only nofault,nofault-fast,loss-transit-20,compromise-forge
$PY -m mtcore.exp3.run "${common[@]}" --work "$OUT/w2" --only loss-transit-20
for r in $($PY -c "import json,sys; print(' '.join(json.load(open(sys.argv[1]))['runs']))" "$OUT/w1/runs.json"); do
  [ -f "$OUT/ref/$r.jsonl" ] || (cd src/python && $PY -m mtcore.harness.offline "$DEV/$r" --out "$OUT/ref/$r.jsonl" \
       --params "$MAIN" --orch-params "$MAIN" 2> "$OUT/ref/$r.log")
done
$PY experiments/exp3/tests/dryrun_checks.py --w1 "$OUT/w1" --w2 "$OUT/w2" --reference "$OUT/ref" --out "$OUT/checks.json"
$PY -m mtcore.exp3.run --role score --work "$OUT/w1" --data "$DEV" --runs "$RUNS" --conditions "$OUT/cfg/conditions.tsv" \
  --passes "$PASSES" --main-params "$MAIN" --truth-root "$DEV" --workers "$WORKERS" \
  --only nofault,nofault-fast,loss-transit-20,compromise-forge
