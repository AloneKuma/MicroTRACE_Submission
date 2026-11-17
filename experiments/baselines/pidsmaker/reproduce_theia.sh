#!/usr/bin/env bash
# Reproduction check of ORTHRUS and KAIROS (PIDSMaker 3.0.0) on DARPA THEIA-E3,
# CPU only, on the shared test host. Run from ~/microtrace-baselines/pidsmaker
# with nohup; progress goes to STATUS, each step's output to logs/.
#
#   nohup bash reproduce_theia.sh > reproduce.out 2>&1 &
#
# Steps: containers up, load theia_e3.dump, ORTHRUS (orthrus.yml as released),
# KAIROS (tuned THEIA_E3 settings from docs/docs/tuned_systems.md) at node
# level, then KAIROS's own time-window evaluation (kairos_idf_queue) on the same
# trained model. A guard stops the app container if the host's available memory
# falls below GUARD_MB, so other projects on the host are never starved.
set -uo pipefail
cd "$(dirname "$0")"
C="docker compose -f compose.mt.yml"
GUARD_MB=${GUARD_MB:-1500}
mkdir -p logs
status() { echo "$(date -u +%FT%TZ) $*" | tee -a STATUS; }

# Memory guard and sampler: host available memory and the app's usage, every 30 s.
(
  while true; do
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    app=$(docker stats --no-stream --format '{{.MemUsage}}' mtpids-app 2>/dev/null || echo -)
    echo "$(date -u +%T) avail_mb=$avail app=$app" >> logs/memory.log
    if [ "$avail" -lt "$GUARD_MB" ]; then
      echo "$(date -u +%FT%TZ) GUARD: available ${avail} MB < ${GUARD_MB} MB, stopping mtpids-app" | tee -a STATUS
      docker stop mtpids-app > /dev/null 2>&1
      touch GUARD_TRIPPED
      exit 0
    fi
    sleep 30
  done
) &
GUARD=$!
trap 'kill $GUARD 2>/dev/null' EXIT

status "START"
$C up -d >> logs/up.log 2>&1 || { status "FAILED up"; exit 1; }
status "UP $(docker ps --format '{{.Names}}' | grep -c '^mtpids-') mtpids containers"

# Load THEIA-E3 (skipped if its event table already has rows).
rows=$(docker exec mtpids-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM event_table" 2>/dev/null || echo 0)
if [ "${rows:-0}" -gt 0 ]; then
  status "LOAD skipped, event_table has $rows rows"
else
  status "LOAD start"
  docker exec mtpids-postgres bash -c \
    "pg_restore -U postgres --clean --if-exists --no-owner --no-privileges -d theia_e3 /data/theia_e3.dump" \
    > logs/load.log 2>&1
  status "LOAD exit $?"
fi
for t in event_table file_node_table netflow_node_table subject_node_table; do
  n=$(docker exec mtpids-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM $t" 2>&1)
  status "COUNT $t $n"
done

run() {   # name, then PIDSMaker arguments
  local name=$1; shift
  [ -f GUARD_TRIPPED ] && { status "SKIP $name (guard tripped)"; return 1; }
  status "RUN $name: $*"
  local t0=$(date +%s)
  docker exec -u pids -w /home/pids mtpids-app \
    /opt/conda/envs/pids/bin/python pidsmaker/main.py "$@" --cpu --artifact_dir /home/artifacts/ \
    > "logs/$name.log" 2>&1
  local rc=$?
  status "DONE $name exit $rc in $(( ($(date +%s) - t0) / 60 )) min"
  return $rc
}

run orthrus orthrus THEIA_E3
run kairos kairos THEIA_E3 --training.encoder.dropout=0.3 --training.lr=0.001 \
  --training.node_hid_dim=320 --training.node_out_dim=320 --training.num_epochs=12 --featurization.emb_dim=256
run kairos_queue kairos THEIA_E3 --training.encoder.dropout=0.3 --training.lr=0.001 \
  --training.node_hid_dim=320 --training.node_out_dim=320 --training.num_epochs=12 --featurization.emb_dim=256 \
  --evaluation.used_method=queue_evaluation

status "ALL_DONE"
