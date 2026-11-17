#!/usr/bin/env bash
# Exp. 3 on the AWS analysis host (docs/plans/exp3-runner-worklog.md section 7). Receivers, Kafka,
# the live pipeline and every detection pass run here; the sender nodes (sender_exp3_aws.sh) replay
# the base streams through the fault injector. No truth is on this machine and none is read; the
# fault logs go from the senders straight to s3://$BUCKET/results/$SESSION-faultlogs/, which this
# script never reads. Scoring happens later, in the second scoring session (score_exp3.sh).
# Run after bootstrap.sh and bootstrap_exp3.sh (ROLE=analysis).
#
#   . ~/mt-env.sh; BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> SESSION=<name> SET=held_out \
#     MAIN_PARAMS=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml SELECT=5:exp3-2026-11 SENDERS=2 \
#     nohup bash experiments/exp3/run_exp3_aws.sh > exp3.out 2>&1 &
#
# SELECT N:SALT picks N runs per observability profile by sha256(SALT|run_id) (truth- and
# results-free); RUNS=<file>[:key] gives an explicit list instead. MAX_TIER, ONLY (condition
# patterns) narrow the conditions. Resumable: results/$SESSION/exp3/ is pulled back on start, so
# finished jobs and passes are skipped (a new epoch makes the senders ignore jobs of the old start).
# The machine shuts down when the script exits (AUTO_SHUTDOWN=0 turns that off).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${SESSION:?}" "${SET:?}" "${MAIN_PARAMS:?}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; W=${W:-$HOME/exp3}
SLOTS=${SLOTS:-8}; WORKERS=${WORKERS:-8}; SENDERS=${SENDERS:-2}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
R="s3://$BUCKET/results/$SESSION/exp3"; CTL="s3://$BUCKET/results/$SESSION/exp3-ctl"
mkdir -p "$W/logs"; S=$W/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }

. "$VENV/bin/activate" || { status "FAILED venv"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
for b in faultinject shipper receiver devcerts; do [ -x "$MT_BIN/$b" ] || { status "FAILED $MT_BIN/$b (bootstrap_exp3.sh)"; exit 1; }; done
[ -d "${KAFKA_HOME:-/nonexistent}/libs" ] || { status "FAILED KAFKA_HOME (bootstrap_exp3.sh)"; exit 1; }
[ -n "${MT_SAGE_HOME:-}" ] && [ -d "$MT_SAGE_HOME/SAGE" ] || { status "FAILED MT_SAGE_HOME (bootstrap.sh)"; exit 1; }
[ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || { status "FAILED code tree has local changes"; exit 1; }
IP=$(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token \
       -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')" http://169.254.169.254/latest/meta-data/local-ipv4)
[ -n "$IP" ] || { status "FAILED no private IP from the instance metadata"; exit 1; }

aws s3 sync --only-show-errors "$R" "$W" < /dev/null || true          # resume after an interruption
sync_up() {
  aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null
  aws s3 sync --only-show-errors --no-follow-symlinks "$W" "$R" --exclude "STATUS" --exclude "*.tmp" \
    --exclude "slots/*" --exclude "sendwork/*" --exclude "received/*/received.jsonl" \
    --exclude "*/shipper/received.jsonl" --exclude "*/output.jsonl" < /dev/null
}
( n=0; while true; do
    echo "$(date -u +%T) avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo) load=$(cut -d' ' -f1 /proc/loadavg)" \
      >> "$W/logs/memory.log"
    n=$((n + 1)); [ $((n % 40)) -eq 0 ] && sync_up; sleep 15
  done ) &
SAMPLER=$!
finish() {
  kill $SAMPLER 2>/dev/null; sync_up
  if [ "$AUTO_SHUTDOWN" = 1 ]; then status "SHUTDOWN after final copy"; sync_up; sudo shutdown -h now; fi
}
trap finish EXIT
status "START exp3 analysis $(nproc) cpu, code $(git -C "$CODE" rev-parse --short HEAD), set $SET, slots $SLOTS," \
       "senders $SENDERS, ip $IP, clock $(tail -1 /var/log/mt-clock.txt 2>/dev/null)"

# The seal: as run_analysis_aws.sh, only AccessDenied on a truth object counts.
list=$(aws s3api list-objects-v2 --bucket "$HELDOUT_BUCKET" --prefix heldout/truth/ --max-keys 1 --no-paginate \
         --query 'Contents[0].Key' --output text < /dev/null 2>&1) || { status "FAILED seal check: cannot list ($list)"; exit 1; }
[ "$list" != None ] && [ -n "$list" ] || { status "FAILED seal check: no truth objects listed"; exit 1; }
err=$(aws s3api get-object --bucket "$HELDOUT_BUCKET" --key "$list" /dev/null < /dev/null 2>&1 >/dev/null)
case "$err" in
  *AccessDenied*) status "SEAL ok: truth not readable here (AccessDenied)" ;;
  "") status "FAILED seal: this machine can read $list"; exit 1 ;;
  *) status "FAILED seal check inconclusive: $err"; exit 1 ;;
esac
if [ ! -f "$DATA/.fetched-$SET" ]; then
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$SET" "$DATA/$SET" < /dev/null \
    || { status "FAILED fetch $SET"; exit 1; }
  bash "$CODE/experiments/heldout/check_fetch.sh" "$DATA/$SET" "$CODE/experiments/heldout/manifests/$SET.tsv" "$CODE" >> "$S" 2>&1 \
    || { status "FAILED $SET does not match its manifest"; exit 1; }
  touch "$DATA/.fetched-$SET"
fi
status "DATA $SET $(find "$DATA/$SET" -mindepth 1 -maxdepth 1 -type d | wc -l) runs"
sync_up

sel=(--select "${SELECT:-5:exp3-2026-11}"); [ -n "${RUNS:-}" ] && sel=(--runs "$CODE/$RUNS")
extra=(); [ -n "${MAX_TIER:-}" ] && extra+=(--max-tier "$MAX_TIER"); [ -n "${ONLY:-}" ] && extra+=(--only "$ONLY")
(cd "$CODE" && python -m mtcore.exp3.run --role analysis --work "$W" --data "$DATA/$SET" "${sel[@]}" \
   --main-params "$CODE/$MAIN_PARAMS" --ctl "$CTL" --senders "$SENDERS" --slots "$SLOTS" --workers "$WORKERS" \
   --listen-host 0.0.0.0 --advertise-host "$IP" "${extra[@]}" < /dev/null) > "$W/logs/run.log" 2>&1
rc=$?
status "RUNNER exit $rc ($(tail -1 "$W/STATUS"))"
[ "$rc" = 0 ] && status "ALL_DONE" || { status "FAILED runner"; exit 1; }
