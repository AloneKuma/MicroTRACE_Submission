#!/usr/bin/env bash
# Reproduction check of ORTHRUS and KAIROS (PIDSMaker 3.0.0) on DARPA THEIA-E3,
# on the one-session AWS GPU machine. Same steps and settings as
# reproduce_theia.sh (the test host run, which ran out of memory in batching),
# but on the GPU and with everything set up from scratch. Plan, targets and
# pass rule: docs/plans/kairos-reproduction-plan.md. Run from ~/pidsmaker with
# this file and compose.aws.yml next to it:
#
#   BUCKET=<bucket> RESULTS=results-<date> STEPS='kairos_s0 kairos_queue_s0' \
#     nohup bash reproduce_theia_aws.sh > reproduce.out 2>&1 &
#
# After each step STATUS, summary.tsv, logs/ and the small artifact stages are
# copied to s3://$BUCKET/$RESULTS/; the memory sampler also copies every 15 min.
# When the script exits, for any reason, it makes a final copy and shuts the
# machine down, which terminates it (AUTO_SHUTDOWN=0 turns that off).
set -uo pipefail
cd "$(dirname "$0")"
: "${BUCKET:?set BUCKET}"
AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
RESULTS=${RESULTS:-results}       # S3 prefix for this session's results
MEM_STOP_GB=${MEM_STOP_GB:-325}   # 10 GB below APP_MEM (compose.aws.yml, default 335g)
C="docker compose -f compose.aws.yml"
mkdir -p logs data artifacts
rm -f STOP_MEM
status() { echo "$(date -u +%FT%TZ) $*" | tee -a STATUS; }
sync_up() {
  aws s3 cp --only-show-errors STATUS "s3://$BUCKET/$RESULTS/STATUS"
  [ -f summary.tsv ] && aws s3 cp --only-show-errors summary.tsv "s3://$BUCKET/$RESULTS/summary.tsv"
  aws s3 sync --only-show-errors logs "s3://$BUCKET/$RESULTS/logs"
  for d in training evaluation triage postprocessing; do
    [ -d "artifacts/$d" ] && aws s3 sync --only-show-errors --exclude "*edge_scores_*.pkl" \
      "artifacts/$d" "s3://$BUCKET/$RESULTS/artifacts/$d"
  done
}

# Sampler, every 15 s: available memory, the app's cgroup memory and swap
# (docker stats leaves swap out), and the GPU. Stops a step that goes past
# MEM_STOP_GB so the peak is on record before the OOM kill, and copies the
# results to S3 every 15 min.
(
  n=0
  while true; do
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    cur=$(docker exec mtpids-app cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)
    swp=$(docker exec mtpids-app cat /sys/fs/cgroup/memory.swap.current 2>/dev/null || echo 0)
    gpu=$(nvidia-smi --id=0 --query-gpu=memory.used,utilization.gpu --format=csv,noheader 2>/dev/null)
    app_gb=$(( ${cur:-0} / 1073741824 ))
    echo "$(date -u +%T) avail_mb=$avail app_gb=$app_gb swap_gb=$(( ${swp:-0} / 1073741824 )) gpu=$gpu" >> logs/memory.log
    if [ "$app_gb" -ge "$MEM_STOP_GB" ] && [ ! -f STOP_MEM ]; then
      touch STOP_MEM
      status "STOPPED memory: app at ${app_gb} GB (limit ${MEM_STOP_GB} GB)"
      docker exec mtpids-app pkill -f pidsmaker/main.py
    fi
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

status "START $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB, $(nvidia-smi --query-gpu=name --format=csv,noheader | sort | uniq -c | xargs), STEPS=${STEPS:-default}"
if [ ! -d PIDSMaker ]; then
  git clone --quiet --branch 3.0.0 --depth 1 https://github.com/ubc-provenance/PIDSMaker.git > logs/clone.log 2>&1 \
    || { status "FAILED clone"; exit 1; }
fi
status "CLONE $(git -C PIDSMaker describe --tags --always)"
# Our patches to PIDSMaker (patches/*.patch), each with a test that must pass
# before any run (see below). tgn-chunked-flush.patch: the end-of-training
# TGN memory flush in chunks, so KAIROS fits a 24 GB GPU; same result.
for p in patches/*.patch; do
  [ -f "$p" ] || continue
  if git -C PIDSMaker apply --reverse --check "$PWD/$p" 2>/dev/null; then
    status "PATCH $(basename "$p") already applied"
  else
    git -C PIDSMaker apply "$PWD/$p" || { status "FAILED patch $p"; exit 1; }
    status "PATCH $(basename "$p") applied, sha256 $(sha256sum "$p" | cut -c1-16)"
  fi
done
cp patches/test_*.py PIDSMaker/ 2>/dev/null
[ -f data/theia_e3.dump ] || aws s3 cp --only-show-errors "s3://$BUCKET/data/theia_e3.dump" data/theia_e3.dump
status "DUMP sha256 $(sha256sum data/theia_e3.dump | cut -c1-16)"

t0=$(date +%s)
$C build app > logs/build.log 2>&1 || { status "FAILED build"; exit 1; }
status "BUILD_OK in $(( ($(date +%s) - t0) / 60 )) min"
$C up -d >> logs/up.log 2>&1 || { status "FAILED up"; exit 1; }
status "UP $(docker ps --format '{{.Names}}' | grep -c '^mtpids-') mtpids containers"
docker exec mtpids-app nvidia-smi -L > logs/gpu_in_container.log 2>&1 \
  && status "GPU in container: $(cat logs/gpu_in_container.log)" \
  || { status "FAILED no GPU in container"; exit 1; }
for t in PIDSMaker/test_*.py; do
  [ -f "$t" ] || continue
  docker exec -w /home/pids mtpids-app /opt/conda/envs/pids/bin/python "/home/pids/$(basename "$t")" \
    > "logs/$(basename "$t" .py).log" 2>&1 \
    && status "TEST $(basename "$t") passed: $(tail -1 "logs/$(basename "$t" .py).log")" \
    || { status "FAILED test $(basename "$t"): $(tail -1 "logs/$(basename "$t" .py).log")"; exit 1; }
done

# Load THEIA-E3 (skipped if its event table already has rows).
rows=$(docker exec mtpids-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM event_table" 2>/dev/null || echo 0)
if [ "${rows:-0}" -gt 0 ]; then
  status "LOAD skipped, event_table has $rows rows"
else
  status "LOAD start"
  docker exec mtpids-postgres bash -c \
    "pg_restore -U postgres --clean --if-exists --no-owner --no-privileges -j 8 -d theia_e3 /data/theia_e3.dump" \
    > logs/load.log 2>&1
  status "LOAD exit $?"
fi
for t in event_table file_node_table netflow_node_table subject_node_table; do
  n=$(docker exec mtpids-postgres psql -U postgres -d theia_e3 -tAc "SELECT count(*) FROM $t" 2>&1)
  status "COUNT $t $n"
done
sync_up

# One summary line per step. Node runs: the metrics of the epoch PIDSMaker
# selects (best_adp), as in Bilot et al. Table 4. Other runs: the last value
# of each metric in the log. `trained` says whether the step trained a model
# (a time-window step should reuse the node step's model and say no).
[ -f summary.tsv ] || printf 'step\texit\tminutes\tpeak_gb\ttrained\tepoch\tprecision\trecall\ttp\tfp\ttn\tfn\tmcc\tauc\tadp_score\n' > summary.tsv
summarize() {   # name, exit code, minutes, peak GB
  local name=$1 rc=$2 mins=$3 peak=$4 log="logs/$1.log"
  local trained=no ep
  grep -q "START SUBTASK training_loop.py" "$log" && trained=yes
  ep=$(grep -o 'Best model path: .*model_epoch_[0-9]*' "$log" | tail -1 | grep -o '[0-9]*$')
  awk -v ep="$ep" -v pre="$name\t$rc\t$mins\t$peak\t$trained\t${ep:--}" '
    BEGIN { split("precision recall tp fp tn fn mcc auc adp_score", keys, " ") }
    ep != "" && index($0, "[@model_epoch_" ep "] - Stats") { inblk = 1; next }
    ep != "" && inblk && /\] - Stats/ { inblk = 0 }
    ep != "" && inblk && /scores_file:/ { inblk = 0 }
    {
      for (i in keys) if (match($0, " - " keys[i] ": [-0-9.e]+$")) {
        v = substr($0, RSTART + length(keys[i]) + 5)
        if (ep == "") last[keys[i]] = v
        else if (inblk && !(keys[i] in best)) best[keys[i]] = v
      }
    }
    END {
      line = pre
      for (i = 1; i <= 9; i++) line = line "\t" (ep != "" ? (keys[i] in best ? best[keys[i]] : "-") : (keys[i] in last ? last[keys[i]] : "-"))
      print line
    }' "$log" >> summary.tsv
}

run() {   # name, then PIDSMaker arguments
  local name=$1; shift
  status "RUN $name: $*"
  local t0=$(date +%s) m0=$(wc -l < logs/memory.log)
  docker exec -u pids -w /home/pids mtpids-app \
    /opt/conda/envs/pids/bin/python pidsmaker/main.py "$@" --artifact_dir /home/artifacts/ \
    > "logs/$name.log" 2>&1
  local rc=$? mins=$(( ($(date +%s) - t0) / 60 ))
  local peak=$(tail -n +"$((m0 + 1))" logs/memory.log | grep -o 'app_gb=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
  status "DONE $name exit $rc in $mins min, peak ${peak:-?} GB"
  summarize "$name" "$rc" "$mins" "${peak:--}"
  sync_up
  if [ -f STOP_MEM ]; then status "ABORT remaining steps after memory stop"; exit 1; fi
  return $rc
}

# STEPS picks and orders the runs; a rerun keeps the clone, image, database
# and PIDSMaker's cached stages. kairos_sN / kairos_queue_sN are the KAIROS
# plan's S1/S2 runs (tuned settings, training seed N, node level / time
# windows). KAIROS's featurization has no randomness, so seeds only change
# training, and the queue step reuses the trained model.
# orthrus_5seeds is PIDSMaker's own answer to training instability
# (docs/docs/tuned_systems.md): five runs, mean and std.
KAIROS_TUNED="--training.encoder.dropout=0.3 --training.lr=0.001 --training.node_hid_dim=320 \
  --training.node_out_dim=320 --training.num_epochs=12 --featurization.emb_dim=256"
for step in ${STEPS:-orthrus kairos kairos_queue}; do
  case $step in
    orthrus)        run orthrus orthrus THEIA_E3 ;;
    orthrus_5seeds) run orthrus_5seeds orthrus THEIA_E3 --experiment=run_n_times ;;
    kairos)         run kairos kairos THEIA_E3 $KAIROS_TUNED ;;
    kairos_queue)   run kairos_queue kairos THEIA_E3 $KAIROS_TUNED --evaluation.used_method=queue_evaluation ;;
    kairos_s[0-9])  run "$step" kairos THEIA_E3 $KAIROS_TUNED --training.seed="${step#kairos_s}" ;;
    kairos_queue_s[0-9])
                    run "$step" kairos THEIA_E3 $KAIROS_TUNED --training.seed="${step#kairos_queue_s}" \
                      --evaluation.used_method=queue_evaluation ;;
    *)              status "UNKNOWN step $step" ;;
  esac
done

status "ALL_DONE"
