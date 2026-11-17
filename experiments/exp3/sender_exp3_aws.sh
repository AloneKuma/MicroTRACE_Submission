#!/usr/bin/env bash
# Exp. 3 sender node (docs/plans/exp3-runner-worklog.md section 7): replays the base streams of the
# jobs the analysis host posts (s3://$BUCKET/results/$SESSION/exp3-ctl/) through faultinject and the
# shipper to the analysis host's receivers, and uploads each job's fault logs to
# s3://$BUCKET/results/$SESSION-faultlogs/ (truth side: only the scoring session reads them).
# The base stream is exported here from the set's readable runs (mtcore.exp3.base: no truth lines,
# restricted/ and base.pb are not on this side at all). Run after bootstrap.sh (MT_SKIP_SAGE=1) and
# bootstrap_exp3.sh (ROLE=sender); start it before or after run_exp3_aws.sh.
#
#   . ~/mt-env.sh; BUCKET=... HELDOUT_BUCKET=... SESSION=... SET=held_out SENDER_INDEX=0 SENDERS=2 \
#     nohup bash experiments/exp3/sender_exp3_aws.sh > sender.out 2>&1 &
set -uo pipefail
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${SESSION:?}" "${SET:?}" "${SENDER_INDEX:?}" "${SENDERS:?}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; W=${W:-$HOME/exp3-sender}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
CTL="s3://$BUCKET/results/$SESSION/exp3-ctl"; FL="s3://$BUCKET/results/$SESSION-faultlogs"
LOGS="s3://$BUCKET/results/$SESSION/exp3-senders/$SENDER_INDEX"
mkdir -p "$W"; S=$W/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
. "$VENV/bin/activate" || { status "FAILED venv"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
for b in faultinject shipper devcerts; do [ -x "$MT_BIN/$b" ] || { status "FAILED $MT_BIN/$b (bootstrap_exp3.sh)"; exit 1; }; done
finish() {
  aws s3 cp --only-show-errors "$S" "$LOGS/STATUS" < /dev/null
  if [ "$AUTO_SHUTDOWN" = 1 ]; then sudo shutdown -h now; fi
}
trap finish EXIT
status "START sender $SENDER_INDEX of $SENDERS, $(nproc) cpu, code $(git -C "$CODE" rev-parse --short HEAD)," \
       "clock $(chronyc -n tracking 2>/dev/null | grep -E 'System time' | xargs)"
if [ ! -f "$DATA/.fetched-$SET" ]; then
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$SET" "$DATA/$SET" < /dev/null \
    || { status "FAILED fetch $SET"; exit 1; }
  bash "$CODE/experiments/heldout/check_fetch.sh" "$DATA/$SET" "$CODE/experiments/heldout/manifests/$SET.tsv" "$CODE" >> "$S" 2>&1 \
    || { status "FAILED $SET does not match its manifest"; exit 1; }
  touch "$DATA/.fetched-$SET"
fi
(cd "$CODE" && python -m mtcore.exp3.run --role sender --sender-index "$SENDER_INDEX" --senders "$SENDERS" \
   --work "$W" --data "$DATA/$SET" --ctl "$CTL" --faultlogs "$FL" --sender-jobs "${SENDER_JOBS:-4}" < /dev/null) \
   >> "$W/sender.log" 2>&1
rc=$?
# The sender's clock against the analysis host is the Exp. 3 cross-node clock error (heldout-aws-plan.md
# section 8, "PTP clock"): chrony's tracking report, once more at the end.
status "SENDER exit $rc, clock $(chronyc -n tracking 2>/dev/null | grep -E 'System time|Reference ID' | xargs)"
aws s3 cp --only-show-errors "$W/sender.log" "$LOGS/sender.log" < /dev/null
exit $rc
