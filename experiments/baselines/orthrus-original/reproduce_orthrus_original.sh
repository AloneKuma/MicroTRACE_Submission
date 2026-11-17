#!/usr/bin/env bash
# Check of our THEIA-E3 data and labels with the ORIGINAL ORTHRUS code and the
# authors' pre-trained weights, using the THEIA_E3 command from their README.
# Their README expects THEIA_E3_full 22 TP / 0 FP and THEIA_E3_ano 2 TP / 0 FP.
# Background: docs/plans/kairos-reproduction-plan.md §10. Run from ~/orthrus-orig
# with this file and compose.yml next to it:
#
#   BUCKET=<bucket> RESULTS=results-orthrus-orig-<date> \
#     setsid -f bash reproduce_orthrus_original.sh > reproduce.out 2>&1 < /dev/null
#
# Copies STATUS and logs/ to s3://$BUCKET/$RESULTS/ after each step and every
# 15 min; when the script exits, for any reason, it makes a final copy and
# shuts the machine down, which terminates it (AUTO_SHUTDOWN=0 turns that off).
set -uo pipefail
cd "$(dirname "$0")"
: "${BUCKET:?set BUCKET}"
RESULTS=${RESULTS:-results-orthrus-orig}
AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
COMMIT=e7f25df   # ubc-provenance/orthrus main on 2026-10-26
C="docker compose -f compose.yml"
mkdir -p logs data
status() { echo "$(date -u +%FT%TZ) $*" | tee -a STATUS; }
sync_up() {
  aws s3 cp --only-show-errors STATUS "s3://$BUCKET/$RESULTS/STATUS"
  aws s3 sync --only-show-errors logs "s3://$BUCKET/$RESULTS/logs"
}

# Sampler, every 15 s: available memory, the app's cgroup memory, the GPU.
(
  n=0
  while true; do
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    cur=$(docker exec mtorig-pids cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)
    gpu=$(nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv,noheader 2>/dev/null)
    echo "$(date -u +%T) avail_mb=$avail app_gb=$(( ${cur:-0} / 1073741824 )) gpu=$gpu" >> logs/memory.log
    n=$((n + 1))
    [ $((n % 60)) -eq 0 ] && sync_up
    sleep 15
  done
) &
SAMPLER=$!
finish() {
  kill $SAMPLER 2>/dev/null
  sync_up
  if [ "$AUTO_SHUTDOWN" = 1 ]; then
    status "SHUTDOWN after final copy to S3"
    sync_up
    sudo shutdown -h now
  fi
}
trap finish EXIT

status "START $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB, $(nvidia-smi --query-gpu=name --format=csv,noheader | sort | uniq -c | xargs)"
if [ ! -d orthrus ]; then
  git clone --quiet --recurse-submodules https://github.com/ubc-provenance/orthrus.git > logs/clone.log 2>&1 \
    || { status "FAILED clone"; exit 1; }
  git -C orthrus checkout --quiet "$COMMIT" && git -C orthrus submodule update --quiet --init --recursive \
    || { status "FAILED checkout $COMMIT"; exit 1; }
fi
status "CLONE $(git -C orthrus rev-parse --short HEAD), ground truth $(git -C orthrus/Ground_Truth/darpa rev-parse --short HEAD 2>/dev/null || echo MISSING)"
status "WEIGHTS THEIA_E3.pkl sha256 $(sha256sum orthrus/weights/THEIA_E3.pkl | cut -c1-16)"
[ -f data/theia_e3.dump ] || aws s3 cp --only-show-errors "s3://$BUCKET/data/theia_e3.dump" data/theia_e3.dump
status "DUMP sha256 $(sha256sum data/theia_e3.dump | cut -c1-16)"

t0=$(date +%s)
$C build pids > logs/build.log 2>&1 || { status "FAILED build"; exit 1; }
status "BUILD_OK in $(( ($(date +%s) - t0) / 60 )) min"
$C up -d >> logs/up.log 2>&1 || { status "FAILED up"; exit 1; }
docker exec mtorig-pids nvidia-smi -L > logs/gpu_in_container.log 2>&1 \
  && status "GPU in container: $(cat logs/gpu_in_container.log)" \
  || { status "FAILED no GPU in container"; exit 1; }

rows=$(docker exec mtorig-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM event_table" 2>/dev/null || echo 0)
if [ "${rows:-0}" -gt 0 ]; then
  status "LOAD skipped, event_table has $rows rows"
else
  status "LOAD start"
  docker exec mtorig-postgres bash -c \
    "pg_restore -U postgres --clean --if-exists --no-owner --no-privileges -j 8 -d theia_e3 /data/theia_e3.dump" \
    > logs/load.log 2>&1
  status "LOAD exit $?"
fi
for t in event_table file_node_table netflow_node_table subject_node_table; do
  status "COUNT $t $(docker exec mtorig-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM $t" 2>&1)"
done
sync_up

# The THEIA_E3 command from the authors' README ("Reproduce results from the
# paper"), word for word. It runs graph construction, featurization,
# detection from the pre-trained weights and attack reconstruction.
status "RUN orthrus_original: THEIA_E3 --from_weights --detection.gnn_training.encoder.graph_attention.dropout=0.1 --seed=2"
t0=$(date +%s)
docker exec -w /home mtorig-pids /opt/conda/envs/pids/bin/python src/orthrus.py THEIA_E3 --from_weights \
  --detection.gnn_training.encoder.graph_attention.dropout=0.1 --seed=2 > logs/orthrus_original.log 2>&1
rc=$?
peak=$(grep -o 'app_gb=[0-9]*' logs/memory.log | cut -d= -f2 | sort -n | tail -1)
status "DONE orthrus_original exit $rc in $(( ($(date +%s) - t0) / 60 )) min, peak ${peak:-?} GB"
# Every TP/FP/precision/MCC line, in order, for the ano and full results.
grep -E "(^| - )(tp|fp|tn|fn|precision|recall|mcc): " logs/orthrus_original.log > logs/metrics.txt 2>/dev/null
sync_up
status "ALL_DONE"
