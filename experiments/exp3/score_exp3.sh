#!/usr/bin/env bash
# Exp. 3 scoring, in the second scoring session (heldout-aws-plan.md section 8, "Scoring order",
# Option 2), on a machine started with -var scoring=true (the only role that reads truth), after
# bootstrap.sh. No detection is rerun and nothing is tuned: the fault-log consistency check
# (mtcore.exp3.check) runs first, then every pass of the Exp. 3 session is scored with the existing
# scorer (score_pilot.py --stage score --fault-log-root: truth adjusted by what the fault log says was
# lost) and summed (mtcore.exp3.summary). Output: s3://$BUCKET/scored/<date>/exp3/.
#
#   . ~/mt-env.sh; BUCKET=... HELDOUT_BUCKET=... EXP3_SESSION=<the Exp. 3 session> SET=held_out \
#     MAIN_PARAMS=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml nohup bash experiments/exp3/score_exp3.sh > score3.out 2>&1 &
set -uo pipefail
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${EXP3_SESSION:?}" "${SET:?}" "${MAIN_PARAMS:?}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; TRUTH=${TRUTH:-$HOME/truth}; W=${W:-$HOME/exp3-scored}
FL=${FL:-$HOME/exp3-faultlogs}; WORKERS=${WORKERS:-8}
DEST="s3://$BUCKET/scored/${SCORED_NAME:-$(date -u +%F)}/exp3/$SET"
mkdir -p "$W"; S=$W/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
. "$VENV/bin/activate"; export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
status "START exp3 scoring, code $(git -C "$CODE" rev-parse --short HEAD), session $EXP3_SESSION, set $SET"
if [ ! -f "$DATA/.fetched-$SET" ]; then
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$SET" "$DATA/$SET" < /dev/null \
    || { status "FAILED runs $SET"; exit 1; }
  bash "$CODE/experiments/heldout/check_fetch.sh" "$DATA/$SET" "$CODE/experiments/heldout/manifests/$SET.tsv" "$CODE" >> "$S" 2>&1 \
    || { status "FAILED $SET does not match its manifest"; exit 1; }
  touch "$DATA/.fetched-$SET"
fi
aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/truth/$SET" "$TRUTH/$SET" < /dev/null \
  || { status "FAILED truth $SET"; exit 1; }
bad=0
for r in $(ls "$TRUTH/$SET" | grep -v '^_'); do
  (cd "$TRUTH/$SET/$r" && sha256sum -c --quiet SHA256SUMS < /dev/null) || bad=$((bad + 1))
done
[ "$bad" = 0 ] || { status "FAILED truth $SET: $bad checksum failures"; exit 1; }
aws s3 sync --only-show-errors "s3://$BUCKET/results/$EXP3_SESSION/exp3" "$W" < /dev/null || { status "FAILED results"; exit 1; }
aws s3 sync --only-show-errors "s3://$BUCKET/results/$EXP3_SESSION-faultlogs" "$FL" < /dev/null || { status "FAILED fault logs"; exit 1; }
grep -q "ALL_DONE" "$W/STATUS" || status "WARNING the Exp. 3 session did not end ALL_DONE; scoring what is there"
(cd "$CODE" && python -m mtcore.exp3.run --role score --work "$W" --data "$DATA/$SET" --runs "$W/runs.json" \
   --main-params "$CODE/$MAIN_PARAMS" --truth-root "$TRUTH/$SET" --faultlogs "$FL" --workers "$WORKERS" \
   ${MAX_TIER:+--max-tier "$MAX_TIER"} ${ONLY:+--only "$ONLY"} < /dev/null) > "$W/score.log" 2>&1
rc=$?
# Scores and checks only (no runs, no truth, no received streams).
aws s3 sync --only-show-errors "$W" "$DEST" --exclude '*' --include 'STATUS' --include 'exp3-summary.*' \
  --include 'scored/*' --include 'detect/*/summary.*' --include 'detect/*/runs/*/score*.json' --include 'timing.tsv' \
  --include 'splits/*' --include 'plans/*/meta.json' --include 'plans/*/*/meta.json' < /dev/null && status "COPIED to $DEST"
[ "$rc" = 0 ] && status "ALL_DONE" || { status "FAILED scoring (see $W/score.log)"; exit 1; }
