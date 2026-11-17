#!/usr/bin/env bash
# KAIROS (Exp. 1) and the ORTHRUS context row (Exp. 2) on our data, on the one-session
# AWS GPU machine (B3 in docs/plans/kairos-orthrus-our-data-plan.md). Built from
# reproduce_theia_aws.sh, with these differences: our database (dump of `mt` from the
# test host), PIDSMaker's default settings (kairos.yml, orthrus.yml; no tuned values;
# deterministic algorithms on),
# node level only (no queue step), and the epoch chosen by mt_detected.py on validation
# loss. PIDSMaker's own epoch pick (best_model_selection) reads test labels and is not
# used; this script never reads its test metrics either.
#
# Run from ~/pidsmaker with this file, compose.aws.yml (+ compose.gpu.yml), mt_detected.py
# and patches/ next to it:
#
#   BUCKET=<bucket> RESULTS=mt-dev-<date> nohup bash run_mt_aws.sh > run.out 2>&1 &
#   BUCKET=<bucket> BUNDLE=data/heldout-bundle RESULTS=heldout-<date> \
#     STEPS="kairos:MT_HELD_OUT kairos:MT_HELD_OUT:run2 orthrus:MT_HELD_OUT ..." nohup bash run_mt_aws.sh ...
#
# Input, s3://$BUCKET/$BUNDLE/ (make_mt_bundle.sh; default data/mt-bundle):
#   mt.dump (pg_dump -Fc of database mt), mt_datasets.json (the registered datasets),
#   ground_truth.tar.gz (PIDSMaker's own report files; empty for sealed sets),
#   sealed.txt (datasets whose truth is sealed, may be empty), counts.tsv, SHA256SUMS.
#
# Steps: STEPS is a list of model:DATASET[:runN] (kairos or orthrus); the old names
# kairos_pilot, kairos_cases, orthrus_pilot, orthrus_cases still work. Run N > 1 uses
# its own artifact folder (artifacts/runN), so PIDSMaker builds and trains from scratch
# instead of reusing the cached stages of run 1 (the KAIROS repeat, decided 2026-11-04).
# Sealed datasets (sealed.txt): converted with convert.py --sealed, so their ground truth
# files hold a placeholder node, not truth; PIDSMaker's own metrics for them are
# meaningless and, as for every dataset, never read here.
# CPU or GPU: the GPU is used when nvidia-smi works on the machine (GPU=0 forces CPU).
# Output, s3://$BUCKET/$RESULTS/: STATUS, summary.tsv, logs/, results/<step>/
#   (val_loss.tsv, choice.json, flagged.csv), copied after each step and every 15 min.
# Scoring runs afterwards (score_mt_detected.sh; held-out: score_heldout.sh): the truth, findings
# and graphs it needs are there.
#
# When the script exits, for any reason, it makes a final copy and shuts the machine
# down, which terminates it (AUTO_SHUTDOWN=0 turns that off).
set -uo pipefail
cd "$(dirname "$0")"
: "${BUCKET:?set BUCKET}"
AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
RESULTS=${RESULTS:-mt-dev}
BUNDLE=${BUNDLE:-data/mt-bundle}
if [ -z "${GPU:-}" ]; then nvidia-smi -L > /dev/null 2>&1 && GPU=1 || GPU=0; fi
# The app gets the machine's memory less postgres (16 GB) and 12 GB for the OS.
export APP_MEM=${APP_MEM:-$(( $(free -g | awk '/Mem:/ {print $2}') - 28 ))g}
MEM_STOP_GB=${MEM_STOP_GB:-$(( ${APP_MEM%g} - 10 ))}
C="docker compose -f compose.aws.yml"
[ "$GPU" = 1 ] && C="$C -f compose.gpu.yml"
PY=/opt/conda/envs/pids/bin/python
# PIDSMaker defaults plus deterministic algorithms (decided 2026-11-01: stock KAIROS gave
# different flagged nodes on identical runs; this changes no model setting).
MT_ARGS="--training.deterministic=True"
mkdir -p logs data artifacts results
rm -f STOP_MEM
status() { echo "$(date -u +%FT%TZ) $*" | tee -a STATUS; }
sync_up() {
  aws s3 cp --only-show-errors STATUS "s3://$BUCKET/$RESULTS/STATUS"
  [ -f summary.tsv ] && aws s3 cp --only-show-errors summary.tsv "s3://$BUCKET/$RESULTS/summary.tsv"
  aws s3 sync --only-show-errors logs "s3://$BUCKET/$RESULTS/logs"
  aws s3 sync --only-show-errors results "s3://$BUCKET/$RESULTS/results"
}

# Sampler, every 15 s: available memory, the app's cgroup memory and swap, and the GPU.
# Stops a step that goes past MEM_STOP_GB so the peak is on record before the OOM kill,
# and copies the results to S3 every 15 min.
(
  n=0
  while true; do
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    # Process memory only (anon): page cache from writing edge-loss files must not stop a step.
    cur=$(docker exec mtpids-app awk '$1 == "anon" {print $2}' /sys/fs/cgroup/memory.stat 2>/dev/null || echo 0)
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

if [ "$GPU" = 1 ]; then gpus=$(nvidia-smi --query-gpu=name --format=csv,noheader | sort | uniq -c | xargs); else gpus="no GPU (CPU run)"; fi
status "START $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB, APP_MEM=$APP_MEM, $gpus, BUNDLE=$BUNDLE, STEPS=${STEPS:-default}"
if [ ! -d PIDSMaker ]; then
  git clone --quiet --branch 3.0.0 --depth 1 https://github.com/ubc-provenance/PIDSMaker.git > logs/clone.log 2>&1 \
    || { status "FAILED clone"; exit 1; }
fi
status "CLONE $(git -C PIDSMaker describe --tags --always)"
# Our patches (patches/*.patch; patches/proposed/ is not applied). mt-datasets.patch:
# registers our datasets from pidsmaker/config/mt_datasets.json. tgn-chunked-flush.patch:
# the end-of-training TGN memory flush in chunks, so KAIROS fits a 24 GB GPU; same result.
# eval-every-epoch.patch: validation (and test) inference after every epoch, not only
# epochs 0, 1, 3, ..., so the epoch rule can pick any epoch (decided 2026-11-01).
# A Windows checkout may give the patches CRLF endings, which git apply rejects: strip them.
sed -i 's/\r$//' patches/*.patch
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
cp mt_detected.py PIDSMaker/ || { status "FAILED copy mt_detected.py"; exit 1; }

# Our data: database dump, dataset registry, ground truth (PIDSMaker's own reports need it).
# The bundle is always restored to data/mt-bundle (compose mounts ./data at /data).
mkdir -p data/mt-bundle
aws s3 sync --only-show-errors "s3://$BUCKET/$BUNDLE" data/mt-bundle || { status "FAILED fetch bundle"; exit 1; }
(cd data/mt-bundle && sha256sum -c --quiet SHA256SUMS) || { status "FAILED bundle checksums"; exit 1; }
status "BUNDLE $BUNDLE $(du -sh data/mt-bundle | cut -f1), dump sha256 $(sha256sum data/mt-bundle/mt.dump | cut -c1-16)"
cp data/mt-bundle/mt_datasets.json PIDSMaker/pidsmaker/config/mt_datasets.json
mkdir -p PIDSMaker/Ground_Truth/orthrus && tar xzf data/mt-bundle/ground_truth.tar.gz -C PIDSMaker/Ground_Truth/orthrus \
  || { status "FAILED ground truth"; exit 1; }
SEALED=" $(cat data/mt-bundle/sealed.txt 2>/dev/null | xargs) "
status "SEALED datasets:${SEALED}"
status "REGISTRY $(python3 -c "import json; print({k: [len(v[x]) for x in ('train_dates', 'val_dates', 'test_dates', 'attack_to_time_window')] for k, v in json.load(open('PIDSMaker/pidsmaker/config/mt_datasets.json')).items()})")"

t0=$(date +%s)
$C build app > logs/build.log 2>&1 || { status "FAILED build"; exit 1; }
status "BUILD_OK in $(( ($(date +%s) - t0) / 60 )) min"
$C up -d >> logs/up.log 2>&1 || { status "FAILED up"; exit 1; }
status "UP $(docker ps --format '{{.Names}}' | grep -c '^mtpids-') mtpids containers"
if [ "$GPU" = 1 ]; then
  docker exec mtpids-app nvidia-smi -L > logs/gpu_in_container.log 2>&1 \
    && status "GPU in container: $(cat logs/gpu_in_container.log)" \
    || { status "FAILED no GPU in container"; exit 1; }
fi
for t in PIDSMaker/test_*.py; do
  [ -f "$t" ] || continue
  docker exec -w /home/pids mtpids-app $PY "/home/pids/$(basename "$t")" \
    > "logs/$(basename "$t" .py).log" 2>&1 \
    && status "TEST $(basename "$t") passed: $(tail -1 "logs/$(basename "$t" .py).log")" \
    || { status "FAILED test $(basename "$t"): $(tail -1 "logs/$(basename "$t" .py).log")"; exit 1; }
done

# Load database mt (skipped if its event table already has rows), then check the row
# counts against the test host's.
Q() { docker exec mtpids-postgres psql -U postgres -tA "$@"; }
rows=$(Q -d mt -c "SELECT count(*) FROM event_table" 2>/dev/null || echo 0)
if [ "${rows:-0}" -gt 0 ]; then
  status "LOAD skipped, event_table has $rows rows"
else
  status "LOAD start"
  Q -c "CREATE DATABASE mt" > logs/load.log 2>&1
  docker exec mtpids-postgres pg_restore -U postgres --no-owner --no-privileges -j 8 -d mt \
    /data/mt-bundle/mt.dump >> logs/load.log 2>&1
  status "LOAD exit $?"
fi
while read -r t want; do
  n=$(Q -d mt -c "SELECT count(*) FROM $t" 2>&1)
  [ "$n" = "$want" ] || { status "FAILED count $t: $n, test host has $want"; exit 1; }
  status "COUNT $t $n"
done < data/mt-bundle/counts.tsv
sync_up

# One summary line per step: time, memory, and the epoch choice. No test metric.
[ -f summary.tsv ] || printf 'step\texit\tminutes\tpeak_gb\tpeak_gpu_mb\tepochs_with_val\tepoch\tval_mean_loss\tflagged\tnodes_scored\n' > summary.tsv
summarize() {   # name, exit code, minutes, peak GB, peak GPU MB
  local name=$1 c="results/$1/choice.json"
  if [ -f "$c" ]; then
    python3 - "$c" "$1\t$2\t$3\t$4\t$5" >> summary.tsv <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(sys.argv[2].replace("\\t", "\t") + "\t" + "\t".join(str(x) for x in (
    ",".join(map(str, c["epochs_with_val_loss"])), c["epoch"], round(c["val_mean_loss"], 6), c["flagged"], c["nodes_scored"])))
PY
  else
    printf '%s\t%s\t%s\t%s\t%s\t-\t-\t-\t-\t-\n' "$@" >> summary.tsv
  fi
}

run() {   # name, model, dataset[, artifact subfolder]
  local name=$1 model=$2 dataset=$3 adir=/home/artifacts/${4:+$4/}
  mkdir -p "artifacts/${4:-}" && chmod 777 "artifacts/${4:-}"
  status "RUN $name: $model $dataset $MT_ARGS artifacts $adir"
  local t0=$(date +%s) m0=$(wc -l < logs/memory.log)
  docker exec -u pids -w /home/pids mtpids-app \
    $PY pidsmaker/main.py "$model" "$dataset" $MT_ARGS --artifact_dir "$adir" > "logs/$name.log" 2>&1
  local rc=$? mins=$(( ($(date +%s) - t0) / 60 ))
  local seg; seg=$(tail -n +"$((m0 + 1))" logs/memory.log)
  local peak=$(echo "$seg" | grep -o 'app_gb=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
  local gpu=$(echo "$seg" | grep -o 'gpu=[0-9]* MiB' | grep -o '[0-9]*' | sort -n | tail -1)
  status "DONE $name exit $rc in $mins min, peak ${peak:-?} GB, GPU ${gpu:-?} MiB"
  if [ $rc = 0 ]; then
    docker exec -u pids -w /home/pids -e MT_OUT="/home/artifacts/mt-results/$name" mtpids-app \
      $PY mt_detected.py "$model" "$dataset" $MT_ARGS --artifact_dir "$adir" >> "logs/$name.log" 2>&1 \
      && mkdir -p "results/$name" && cp artifacts/mt-results/"$name"/* "results/$name/" \
      && status "EPOCH $name $(grep '^EPOCH' "logs/$name.log" | tail -1)" \
      || { status "FAILED export $name"; rc=1; }
  fi
  summarize "$name" "$rc" "$mins" "${peak:--}" "${gpu:--}"
  sync_up
  if [ -f STOP_MEM ]; then status "ABORT remaining steps after memory stop"; exit 1; fi
  return $rc
}

# STEPS picks and orders the runs; a rerun keeps the clone, image, database and
# PIDSMaker's cached stages. Each test set is its own PIDSMaker dataset (same training
# and validation runs), so each step trains its own model.
FAILED_STEPS=0
run_step() { run "$@" || FAILED_STEPS=$((FAILED_STEPS + 1)); }
for step in ${STEPS:-kairos_pilot kairos_cases orthrus_pilot orthrus_cases}; do
  case $step in
    kairos_pilot)  run_step "$step" kairos MT_PILOT ;;
    kairos_cases)  run_step "$step" kairos MT_CASES ;;
    orthrus_pilot) run_step "$step" orthrus MT_PILOT ;;
    orthrus_cases) run_step "$step" orthrus MT_CASES ;;
    kairos:*|orthrus:*)
      IFS=: read -r model dataset rep <<< "$step"
      case ${rep:-run1} in
        run1) run_step "${model}_${dataset}" "$model" "$dataset" ;;
        run[2-9]) run_step "${model}_${dataset}_${rep}" "$model" "$dataset" "$rep" ;;
        *) status "UNKNOWN repeat $rep in $step"; FAILED_STEPS=$((FAILED_STEPS + 1)) ;;
      esac ;;
    *)             status "UNKNOWN step $step"; FAILED_STEPS=$((FAILED_STEPS + 1)) ;;
  esac
done

if [ "$FAILED_STEPS" -gt 0 ]; then
  status "FAILED_STEPS $FAILED_STEPS (see the DONE/FAILED lines above)"
  exit 1
fi
status "ALL_DONE"
