#!/usr/bin/env bash
# The single scoring step, after every detection output is in S3 (docs/plans/heldout-aws-plan.md).
# Runs on a session machine started with -var scoring=true (the only role that reads truth),
# after bootstrap.sh. It fetches the held-out sets (checked against their frozen manifests) and
# their truth (checked against the upload checksums), the detection results of the analysis and
# baseline sessions, and scores: every MicroTRACE and SAGE pass (score_pilot.py --stage score),
# KAIROS run 1 and run 2, KAIROS nodes, the ORTHRUS context row and the seeded ORTHRUS row
# (score_mt_detected.sh STAGE=score). No detection is rerun here and nothing is tuned.
# Output goes to s3://$BUCKET/scored/<date>/ (readable by the scoring role and the laptop only).
# SETS lists set:go_pass:params for each held-out set (default: the two real sets). The set name
# is its S3 folder, its split file experiments/heldout/splits/<set>.json (key <set>), its manifest
# manifests/<set>.tsv, its convert group and its PIDSMaker dataset MT_<SET>; go_pass is the
# analysis pass whose findings seed ORTHRUS (and SAGE-style link scoring) for that set, params its frozen parameter file.
# The smoke test uses SETS="smoke:go_main:...". 
#
#   . ~/mt-env.sh; BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> ANALYSIS=<session A> \
#     BASELINES=<session B> CONFIGS=configs/heldout-main.tsv nohup bash score_heldout.sh > score.out 2>&1 &
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${ANALYSIS:?}" "${BASELINES:?}" "${CONFIGS:?}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; TRUTH=${TRUTH:-$HOME/truth}; OUT=${OUT:-$HOME/scored}
WORKERS=${WORKERS:-8}; VENV=${VENV:-$CODE/.venv}
CONFIGS=$(cd "$(dirname "$CONFIGS")" && pwd)/$(basename "$CONFIGS")
DEST="s3://$BUCKET/scored/${SCORED_NAME:-$(date -u +%F)}"
SETS=${SETS:-"held_out:go_main:src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml held_out_cases:cases_full:src/params/frozen/fit-ri-on.K10.yaml"}
SET_NAMES=$(for x in $SETS; do echo -n "${x%%:*} "; done)
ds() { echo "MT_$(echo "$1" | tr a-z A-Z)"; }
mkdir -p "$OUT"; S=$OUT/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
. "$VENV/bin/activate"; export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
status "START scoring, code $(git -C "$CODE" rev-parse --short HEAD), configs $(sha256sum "$CONFIGS" | cut -c1-12)"

for set in $SET_NAMES; do
  if [ ! -f "$DATA/.fetched-$set" ]; then
    aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$set" "$DATA/$set" < /dev/null \
      || { status "FAILED runs $set"; exit 1; }
    bash "$HERE/check_fetch.sh" "$DATA/$set" "$HERE/manifests/$set.tsv" "$CODE" >> "$S" 2>&1 \
      || { status "FAILED $set does not match its manifest"; exit 1; }
    touch "$DATA/.fetched-$set"
  fi
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/truth/$set" "$TRUTH/$set" < /dev/null \
    || { status "FAILED truth $set"; exit 1; }
  bad=0
  # _build/ holds the build's gate reports (build_heldout.sh), not runs: the run folders must be
  # exactly the fetched data's runs, each passing its SHA256SUMS.
  for r in $(ls "$TRUTH/$set" | grep -v '^_'); do
    (cd "$TRUTH/$set/$r" && sha256sum -c --quiet SHA256SUMS < /dev/null) || bad=$((bad + 1))
  done
  [ "$bad" = 0 ] && [ "$(ls "$TRUTH/$set" | grep -v '^_')" = "$(ls "$DATA/$set" | grep -v '^\.')" ] \
    || { status "FAILED truth $set: $bad checksum failures or run names differ from the data"; exit 1; }
  status "TRUTH $set $(ls "$TRUTH/$set" | grep -vc '^_') runs, checksums ok"
done
for s in "$ANALYSIS" "$BASELINES"; do
  aws s3 sync --only-show-errors "s3://$BUCKET/results/$s" "$OUT/$s" --exclude 'bundle/*' --exclude '*/offline.log' < /dev/null \
    || { status "FAILED results $s"; exit 1; }
done

failed=0
mapfile -t PASSES < <(grep -v '^#' "$CONFIGS" | grep .)
for line in "${PASSES[@]}"; do
  IFS=$'\t' read -r name corr params set split half from variant <<< "$line"
  args=(--pilot "$DATA/$set" --truth-root "$TRUTH/$set" --split "$CODE/$split" --half "$half"
        --params "$CODE/$params" --out-dir "$OUT/$ANALYSIS/$name" --workers "$WORKERS" --stage score)
  # A go pass may carry drop:<SOURCE> in the findings_from column: the Exp. 1 telemetry ablation
  # (score_pilot.py --drop-source; decided 2026-11-15).
  case "$from" in drop:*) [ "$corr" = go ] && args+=(--drop-source "${from#drop:}") ;; esac
  [ "$corr" = sage ] && args+=(--correlator sage --findings-from "$OUT/$ANALYSIS/$from" --sage-variant "${variant:-ag}")
  if (cd "$CODE" && python src/scripts/pilot/score_pilot.py "${args[@]}" < /dev/null) > "$OUT/score-$name.log" 2>&1; then
    status "SCORED $name $(python3 -c "import json;s=json.load(open('$OUT/$ANALYSIS/$name/summary.json'));print(s['runs_scored'],'runs',json.dumps(s['findings']))" 2>/dev/null)"
  else
    status "FAILED score $name (see score-$name.log)"; failed=$((failed + 1))
  fi
done

P=$OUT/$BASELINES
GROUPS_S=""
for x in $SETS; do
  IFS=: read -r s gp pf <<< "$x"
  GROUPS_S+="$s:$(ds "$s"):$DATA/$s:$TRUTH/$s:$OUT/$ANALYSIS/$gp:$HERE/splits/$s.json:$CODE/$pf:$s "
done
RES=$P/pidsmaker/results STAGE=score CONV=$P/conv SEEDED=$P/seeded CODE=$CODE VENV=$VENV WORKERS=$WORKERS \
  BGROUPS="$GROUPS_S" bash "$CODE/experiments/baselines/pidsmaker/score_mt_detected.sh" < /dev/null \
  && status "SCORED baselines" || { status "FAILED baselines (see $P/pidsmaker/results/SCORE_STATUS)"; failed=$((failed + 1)); }
RES=$P/pidsmaker/results STAGE=score STEPS_SUFFIX=_run2 CONV=$P/conv CODE=$CODE VENV=$VENV WORKERS=$WORKERS \
  BGROUPS="$GROUPS_S" bash "$CODE/experiments/baselines/pidsmaker/score_mt_detected.sh" < /dev/null \
  && status "SCORED KAIROS run 2" || { status "FAILED KAIROS run 2"; failed=$((failed + 1)); }

# Only scores and the files they were computed from go back (no runs, no truth copies).
aws s3 sync --only-show-errors "$OUT" "$DEST" --exclude '*/output.jsonl.gz' --exclude '*/sage/*/*.jsonl' \
  --exclude '*/conv/*' --exclude '*/seeded/out/*' < /dev/null && status "COPIED to $DEST"
[ "$failed" = 0 ] && status "ALL_DONE" || { status "FAILED $failed parts"; exit 1; }
