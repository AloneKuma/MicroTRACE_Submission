#!/usr/bin/env bash
# Exp. 3 scoring, unattended (user decision 2026-11-16): started by mt-job.service on a scoring
# machine (Terraform -var scoring=true -var autorun=true, the only role that reads truth) as ubuntu,
# with BUCKET, COMMIT and SESSION set. It waits until each Exp. 3 session has finished and copied its
# final outputs, then scores that session with score_exp3.sh, which reads its set's truth only then.
# The machine shuts down when this script exits (mt-job.service); its cost cap ends it in any case.
#
# A session is finished when its results/<session>/exp3/STATUS has, after the LAST "START exp3
# analysis" line (earlier, aborted starts leave stale lines), the line "SHUTDOWN after final copy"
# (written after ALL_DONE and one full output copy, run_exp3_aws.sh finish()). A session that ended
# FAILED is still scored, and the status says so. A session not finished when the time left on this
# machine falls below SCORE_BUDGET_S is given up (score it by hand). Output:
# s3://$BUCKET/scored/<start date>/exp3/<set>/ (score_exp3.sh) and s3://$BUCKET/results/$SESSION/.
#
# Test of the finish rule without AWS:  bash score_job_aws.sh --state <STATUS file>
set -uo pipefail

# finished-state of one STATUS text on stdin: running | done | failed
session_state() {
  awk '/ START exp3 analysis /{n=0; delete l} {l[++n]=$0}
       END{done=0; ok=0; for(i=1;i<=n;i++){ if(l[i] ~ /SHUTDOWN after final copy/) done=1;
                                            if(l[i] ~ / ALL_DONE$/) ok=1 }
           print (done ? (ok ? "done" : "failed") : "running")}'
}
if [ "${1:-}" = "--state" ]; then session_state < "$2"; exit 0; fi

: "${BUCKET:?}" "${COMMIT:?}" "${SESSION:?}"
HELDOUT_BUCKET=${HELDOUT_BUCKET:-<SEALED_BUCKET>}
CODE=${CODE:-$HOME/code}; OUT=${OUT:-$HOME/exp3-score-job}
POLL_S=${POLL_S:-300}; SCORE_BUDGET_S=${SCORE_BUDGET_S:-$((4 * 3600))}
# Output folder name: experiments/exp3/configs/scored_name when present (2026-11-17: the re-run must
# not overwrite scored/2026-11-17/, which holds the kept rows), else the start date.
SCORED_NAME=${SCORED_NAME:-$(cat "$CODE/experiments/exp3/configs/scored_name" 2>/dev/null || date -u +%F)}
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$OUT/logs"; S=$OUT/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null; }
deadline() { local d; d=$(cat /etc/mt-deadline 2>/dev/null); case "$d" in ''|*[!0-9]*) echo 0;; *) echo "$d";; esac; }

status "START exp3 score job, code ${COMMIT:0:7}, scored name $SCORED_NAME"
BUCKET=$BUCKET COMMIT=$COMMIT bash "$CODE/experiments/heldout/bootstrap.sh" > "$OUT/logs/bootstrap.log" 2>&1 \
  || { status "FAILED bootstrap (logs/bootstrap.log)"; aws s3 sync --only-show-errors "$OUT" "$R" < /dev/null; exit 1; }
. "$HOME/mt-env.sh"
status "READY $(tail -1 "$OUT/logs/bootstrap.log")"

# Session -> score_exp3.sh settings (docs/plans/exp3-runner-worklog.md section 7).
# Sessions to score: experiments/exp3/configs/score_sessions.tsv (session, set, main params, ONLY
# patterns or -), committed before the sessions start; SCORE_SESSIONS=<file> gives another one.
SESSIONS_FILE=${SCORE_SESSIONS:-$CODE/experiments/exp3/configs/score_sessions.tsv}
session_field() { awk -F'	' -v s="$1" -v f="$2" '!/^#/ && $1 == s {print $f}' "$SESSIONS_FILE"; }
score_session() {
  local sess=$1 rc SET MAIN_PARAMS ONLY
  SET=$(session_field "$sess" 2); MAIN_PARAMS=$(session_field "$sess" 3); ONLY=$(session_field "$sess" 4)
  [ "$ONLY" = "-" ] && ONLY=
  [ -n "$SET" ] && [ -n "$MAIN_PARAMS" ] || { status "SCORE $sess: not in $SESSIONS_FILE"; return 1; }
  status "SCORE $sess (set $SET) start"
  (cd "$HOME" && BUCKET=$BUCKET HELDOUT_BUCKET=$HELDOUT_BUCKET EXP3_SESSION=$sess SET=$SET MAIN_PARAMS=$MAIN_PARAMS \
     MAX_TIER=1 ONLY=$ONLY W=$HOME/score-$sess FL=$HOME/faultlogs-$sess SCORED_NAME=$SCORED_NAME \
     bash "$CODE/experiments/exp3/score_exp3.sh" < /dev/null) > "$OUT/logs/score-$sess.out" 2>&1
  rc=$?
  status "SCORE $sess exit $rc ($(tail -1 "$HOME/score-$sess/STATUS" 2>/dev/null))"
  return $rc
}

pending=$(awk -F'	' '!/^#/ && NF {print $1}' "$SESSIONS_FILE" | tr '
' ' '); failed=0; pids=""
[ -n "$pending" ] || { status "FAILED no sessions in $SESSIONS_FILE"; exit 1; }
status "SESSIONS $pending"
while [ -n "$pending" ]; do
  next=""
  for sess in $pending; do
    st=$(aws s3 cp "s3://$BUCKET/results/$sess/exp3/STATUS" - < /dev/null 2>/dev/null | session_state)
    case "$st" in
      done)   score_session "$sess" & pids="$pids $!" ;;          # sessions are scored in parallel
      failed) status "NOTE $sess ended without ALL_DONE; scoring what it wrote"
              score_session "$sess" & pids="$pids $!" ;;
      *)      next="$next $sess" ;;
    esac
  done
  pending=$(echo $next)
  [ -z "$pending" ] && break
  if [ $(( $(deadline) - $(date +%s) )) -lt "$SCORE_BUDGET_S" ]; then
    status "GAVE UP waiting for: $pending (too little machine time left to score; score by hand)"
    failed=$((failed + 1)); break
  fi
  status "WAIT $pending"
  sleep "$POLL_S"
done
for p in $pids; do wait "$p" || failed=$((failed + 1)); done
aws s3 sync --only-show-errors "$OUT" "$R" < /dev/null
[ "$failed" = 0 ] && status "ALL_SCORED" || status "FINISHED with $failed problem(s)"
