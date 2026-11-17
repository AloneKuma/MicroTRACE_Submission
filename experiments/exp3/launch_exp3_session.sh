#!/usr/bin/env bash
# Launch one Exp. 3 session from the laptop (docs/plans/exp3-runner-worklog.md section 7, steps 6-8),
# after `terraform apply` in its workspace. Same commands on every machine, over EC2 Instance Connect.
#
#   SESSION=exp3-c1 SET=held_out MAIN_PARAMS=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml \
#     SELECT=8:exp3-2026-11 ONLY='nofault,reorder-1s,reorder-5s' COMMIT=<40-char sha> \
#     bash experiments/exp3/launch_exp3_session.sh
#
# Reads analysis_id and sender_ids from `terraform output -json` of the current workspace (run it in
# experiments/aws/heldout with the session's workspace selected). The code bundle s3://.../code/<sha>.bundle
# must exist. Senders start first; the analysis host starts the runner (MAX_TIER=1, WORKERS).
set -euo pipefail
: "${SESSION:?}" "${SET:?}" "${MAIN_PARAMS:?}" "${SELECT:?}" "${COMMIT:?}"
ONLY=${ONLY:-}; WORKERS=${WORKERS:-16}; PROFILE=${PROFILE:-microtrace}; REGION=${REGION:-us-east-1}
BUCKET=${BUCKET:-<WORK_BUCKET>}
HELDOUT_BUCKET=${HELDOUT_BUCKET:-<SEALED_BUCKET>}
TF_DIR=${TF_DIR:-$(cd "$(dirname "$0")/../aws/heldout" && pwd)}
KEY_DIR=${KEY_DIR:-/d/MicroTRACE-scratch/keys}          # the key without spaces in its path
mkdir -p "$KEY_DIR"; cp -u ~/.ssh/mt_smoke ~/.ssh/mt_smoke.pub "$KEY_DIR/"; chmod 600 "$KEY_DIR/mt_smoke"
KEY=$KEY_DIR/mt_smoke; PUB=$(cygpath -m "$KEY_DIR/mt_smoke.pub" 2>/dev/null || echo "$KEY_DIR/mt_smoke.pub")

out=$(cd "$TF_DIR" && terraform output -json)
AN=$(echo "$out" | python -c "import json,sys; print(json.load(sys.stdin)['analysis_id']['value'])")
SENDERS_IDS=$(echo "$out" | python -c "import json,sys; print(' '.join(json.load(sys.stdin)['sender_ids']['value']))")
NS=$(echo "$SENDERS_IDS" | wc -w)
echo "session $SESSION: analysis $AN, senders $SENDERS_IDS"

port=$((40000 + RANDOM % 20000))
remote() {   # remote <instance> <command>
  local id=$1 cmd=$2 p=$((port++)) pid
  aws ec2-instance-connect open-tunnel --profile "$PROFILE" --region "$REGION" --instance-id "$id" \
    --local-port "$p" > /dev/null 2>&1 & pid=$!
  sleep 4
  aws ec2-instance-connect send-ssh-public-key --profile "$PROFILE" --region "$REGION" --instance-id "$id" \
    --instance-os-user ubuntu --ssh-public-key "file://$PUB" > /dev/null
  ssh -i "$KEY" -p "$p" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 \
    ubuntu@localhost "$cmd"
  local rc=$?
  kill "$pid" 2>/dev/null || true
  return $rc
}
boot="aws s3 cp --only-show-errors s3://$BUCKET/code/$COMMIT.bundle /tmp/c.bundle && rm -rf /tmp/c && git clone -q /tmp/c.bundle /tmp/c && git -C /tmp/c checkout -q $COMMIT && cd /tmp/c/experiments/heldout"
envs="BUCKET=$BUCKET HELDOUT_BUCKET=$HELDOUT_BUCKET SESSION=$SESSION SET=$SET"

i=0
for id in $SENDERS_IDS; do
  echo "== sender $i ($id)"
  remote "$id" "$boot && MT_SKIP_SAGE=1 BUCKET=$BUCKET COMMIT=$COMMIT bash bootstrap.sh > ~/bootstrap.log 2>&1 && . ~/mt-env.sh && ROLE=sender bash ~/code/experiments/exp3/bootstrap_exp3.sh > ~/bootstrap_exp3.log 2>&1; tail -1 ~/bootstrap_exp3.log; $envs SENDER_INDEX=$i SENDERS=$NS nohup bash ~/code/experiments/exp3/sender_exp3_aws.sh > ~/sender.out 2>&1 < /dev/null & sleep 2; echo started"
  i=$((i + 1))
done
echo "== analysis ($AN)"
remote "$AN" "$boot && BUCKET=$BUCKET COMMIT=$COMMIT bash bootstrap.sh > ~/bootstrap.log 2>&1 && . ~/mt-env.sh && ROLE=analysis bash ~/code/experiments/exp3/bootstrap_exp3.sh > ~/bootstrap_exp3.log 2>&1; tail -1 ~/bootstrap_exp3.log; . ~/mt-env.sh; $envs MAIN_PARAMS=$MAIN_PARAMS SELECT=$SELECT SENDERS=$NS MAX_TIER=1 WORKERS=$WORKERS ONLY='$ONLY' nohup bash ~/code/experiments/exp3/run_exp3_aws.sh > ~/exp3.out 2>&1 < /dev/null & sleep 2; echo started"
echo "watch: aws s3 cp --profile $PROFILE s3://$BUCKET/results/$SESSION/exp3/STATUS -"
