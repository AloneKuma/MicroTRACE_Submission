#!/usr/bin/env bash
# Scalability supplement (user decision 2026-11-17, post-freeze, disclosed as such): seeded ORTHRUS
# (the authors' DEPIMPACT tracer, as in Exp. 2) on the nested Core subsets of 41, 82, 164 and 328
# held-out runs (held_out_s<N>.json), three repeats each, seeded from the scored heldout-a/go_main
# findings, with time and memory per step. Companion of sage_job.sh; the GO side needs no run.
#
# Unattended: started by mt-job.service on an ANALYSIS machine (Terraform -var autorun=true
# -var job_script=experiments/exp4/scaling/orthrus_job.sh) as ubuntu, with BUCKET, COMMIT, SESSION.
# No truth is read: only seeds, tracing and records are run (the scoring stage is not).
#
# Inputs reused from session heldout-b1, so nothing is converted again: the database bundle
# (results/heldout-b1/bundle, restored with pg_restore) and the conversion's manifest and event map
# (results/heldout-b1/conv). The node tables, which that upload left out, are exported from the
# restored database (node_uuid and index_id, the two columns seeded.py reads).
#
# Timed per subset and repeat: seeds, tracing (6 workers, as Exp. 2) and records, each with its wall
# time; the graphs of MT_HELD_OUT are built once (all dates, as Exp. 2) and timed apart. A subset is
# selected through a copy of the manifest in which runs outside it get another group name.
# Memory: a 1 s sampler logs the machine's used memory, the mtpids-app container's cgroup
# memory.current, and the largest python RSS on the host (memsample.tsv); steps.tsv gives the
# start and end of every step, so each step's peak can be read off.
# Output: s3://$BUCKET/results/$SESSION/ (STATUS, steps.tsv, memsample.tsv, logs/, s<N>_r<k>/).
set -uo pipefail
: "${BUCKET:?}" "${COMMIT:?}" "${SESSION:?}"
CODE=${CODE:-$HOME/code}; W=${W:-$HOME/esc}; P=$HOME/pidsmaker; PM=$CODE/experiments/baselines/pidsmaker
SRC_SESSION=${SRC_SESSION:-heldout-b1}; GO=${GO:-heldout-a/go_main}; DS=MT_HELD_OUT
ASUB=esc; A=$P/artifacts/$ASUB; AD=/home/artifacts/$ASUB
ORTHRUS_REF=e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543; PIDSMAKER_SHA=438a05a7c55256f639e5b5945cf4828fe3ee078e
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$W/logs"; S=$W/STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null; }
up() { aws s3 sync --only-show-errors --no-follow-symlinks "$W" "$R" --exclude 'conv/*' --exclude 'go/*' \
         --exclude 'views/*' --exclude '*.jsonl.gz' < /dev/null; }
stop() { st "STOP $*"; up; exit 1; }
SAMPLER=""
trap '[ -n "$SAMPLER" ] && kill $SAMPLER 2>/dev/null; up' EXIT
st "START seeded ORTHRUS scaling, code ${COMMIT:0:7}"

BUCKET=$BUCKET COMMIT=$COMMIT MT_SKIP_SAGE=1 bash "$CODE/experiments/heldout/bootstrap.sh" > "$W/logs/bootstrap.log" 2>&1 \
  || stop "bootstrap (logs/bootstrap.log)"
. "$HOME/mt-env.sh"
. "$CODE/.venv/bin/activate"; export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
st "READY $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB"

# --- PIDSMaker tree, the authors' ORTHRUS source, containers (as run_baselines_aws.sh and run_mt_aws.sh).
mkdir -p "$P" && cd "$P" || stop "pidsmaker dir"
cp "$PM"/{compose.aws.yml,mt_construct.py,seeded_tracing.py} . && rm -rf patches && cp -r "$PM/patches" . || stop "copy pidsmaker files"
git clone --quiet --branch 3.0.0 --depth 1 https://github.com/ubc-provenance/PIDSMaker.git < /dev/null > "$W/logs/clone.log" 2>&1 || stop "clone PIDSMaker"
[ "$(git -C PIDSMaker rev-parse HEAD)" = "$PIDSMAKER_SHA" ] || stop "PIDSMaker is not $PIDSMAKER_SHA"
for p in patches/*.patch; do sed -i 's/\r$//' "$p"; git -C PIDSMaker apply "$PWD/$p" || stop "patch $p"; done
git clone --quiet https://github.com/ubc-provenance/orthrus.git orthrus < /dev/null >> "$W/logs/clone.log" 2>&1 \
  && git -C orthrus checkout --quiet $ORTHRUS_REF || stop "clone ORTHRUS"
mkdir -p "$A" artifacts/orthrus-src data/mt-bundle && chmod -R 777 artifacts
cp orthrus/src/attack_reconstruction/tracing_methods/*.py orthrus/src/provnet_utils.py orthrus/src/config.py artifacts/orthrus-src/ \
  || stop "ORTHRUS source files"
cp mt_construct.py seeded_tracing.py artifacts/
aws s3 sync --only-show-errors "s3://$BUCKET/results/$SRC_SESSION/bundle" data/mt-bundle < /dev/null || stop "fetch bundle"
(cd data/mt-bundle && sha256sum -c --quiet SHA256SUMS) || stop "bundle checksums"
cp data/mt-bundle/mt_datasets.json PIDSMaker/pidsmaker/config/mt_datasets.json
mkdir -p PIDSMaker/Ground_Truth/orthrus && tar xzf data/mt-bundle/ground_truth.tar.gz -C PIDSMaker/Ground_Truth/orthrus || stop "ground truth files"
export APP_MEM=$(( $(free -g | awk '/Mem:/ {print $2}') - 28 ))g
t0=$(date +%s)
docker compose -f compose.aws.yml build app > "$W/logs/build.log" 2>&1 || stop "build (logs/build.log)"
docker compose -f compose.aws.yml up -d > "$W/logs/up.log" 2>&1 || stop "up"
until docker exec mtpids-postgres pg_isready -U postgres > /dev/null 2>&1; do sleep 5; done
st "CONTAINERS in $(( $(date +%s) - t0 )) s"
Q() { docker exec mtpids-postgres psql -U postgres -tA "$@"; }
t0=$(date +%s)
Q -c "CREATE DATABASE mt" > "$W/logs/load.log" 2>&1
docker exec mtpids-postgres pg_restore -U postgres --no-owner --no-privileges -j 8 -d mt /data/mt-bundle/mt.dump >> "$W/logs/load.log" 2>&1
while read -r t want; do
  n=$(Q -d mt -c "SELECT count(*) FROM $t" 2>&1); [ "$n" = "$want" ] || stop "count $t: $n, bundle says $want"
done < data/mt-bundle/counts.tsv
st "LOADED database mt in $(( $(date +%s) - t0 )) s"

# --- Conversion files: manifest and event map from S3, node tables from the database.
C=$W/conv; mkdir -p "$C"
aws s3 sync --only-show-errors "s3://$BUCKET/results/$SRC_SESSION/conv" "$C" --exclude 'ground_truth/*' < /dev/null || stop "fetch conv"
for t in subject_node_table file_node_table netflow_node_table; do
  Q -d mt -c "COPY (SELECT node_uuid, index_id FROM $t) TO STDOUT WITH (FORMAT csv)" > "$C/$t.csv" || stop "export $t"
done
st "CONV $(du -sh "$C" | cut -f1), node tables $(cat "$C"/*_node_table.csv | wc -l) rows"

# --- GO findings (the scored main row).
aws s3 sync --only-show-errors "s3://$BUCKET/results/$GO/runs" "$W/go/runs" --exclude '*' --include '*/output.jsonl.gz' < /dev/null \
  || stop "fetch $GO"
[ "$(find "$W/go/runs" -name output.jsonl.gz | wc -l)" = 328 ] || stop "$GO: expected 328 outputs"
st "GO findings: 328 runs"

# --- Memory sampler (1 s).
APPCG=/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' mtpids-app).scope/memory.current
[ -r "$APPCG" ] || stop "no cgroup memory file $APPCG"
(
  echo -e "utc\tused_mb\tapp_cgroup_mb\tmax_python_rss_mb" > "$W/memsample.tsv"
  while true; do
    used=$(awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print int((t-a)/1024)}' /proc/meminfo)
    app=$(( $(cat "$APPCG" 2>/dev/null || echo 0) / 1048576 ))
    py=$(ps -C python,python3 -o rss= 2>/dev/null | sort -n | tail -1 | awk '{print int($1/1024)}')
    echo -e "$(date -u +%FT%T.%3NZ)\t$used\t$app\t${py:-0}" >> "$W/memsample.tsv"
    sleep 1
  done
) &
SAMPLER=$!
echo -e "step\tstart_utc\tend_utc\twall_s\texit\tnote" > "$W/steps.tsv"
timed() {  # name, note, command...
  local name=$1 note=$2; shift 2
  local s=$(date -u +%FT%T.%3NZ) t0=$(date +%s.%N) rc
  "$@"; rc=$?
  echo -e "$name\t$s\t$(date -u +%FT%T.%3NZ)\t$(python3 -c "print(round($(date +%s.%N) - $t0, 2))")\t$rc\t$note" >> "$W/steps.tsv"
  return $rc
}

# --- Graphs of MT_HELD_OUT, once (as in Exp. 2: all dates of the dataset).
timed graphs "MT_HELD_OUT, all dates" docker exec -u pids -w /home/pids -e PYTHONPATH=/home/pids mtpids-app \
  /opt/conda/envs/pids/bin/python /home/artifacts/mt_construct.py orthrus "$DS" --cpu --artifact_dir "$AD/" \
  > "$W/logs/graphs.log" 2>&1 || stop "graphs (logs/graphs.log)"
NX=$(cd "$A" && ls -d construction/"$DS"/construction/*/nx)
[ "$(echo "$NX" | wc -l)" = 1 ] || stop "expected one graph directory, found: $NX"
st "GRAPHS $(du -sh "$A/$NX" | cut -f1) in $(tail -1 "$W/steps.tsv" | cut -f4) s"
up

# --- Per subset and repeat: seeds, tracing, records.
mkdir -p "$W/views"
for n in 41 82 164 328; do
  if [ "$n" = 328 ]; then split=$CODE/experiments/heldout/splits/held_out.json; else split=$CODE/experiments/exp4/scaling/held_out_s$n.json; fi
  V=$W/views/s$n; mkdir -p "$V"
  for f in "$C"/*; do [ "$(basename "$f")" = manifest.json ] || ln -sfn "$f" "$V/"; done
  python3 - "$C/manifest.json" "$split" "$V/manifest.json" <<'PY' || stop "view s$n"
import json, sys
m = json.load(open(sys.argv[1])); keep = set(json.load(open(sys.argv[2]))["held_out"])
for r in m["runs"]:
    if r["group"] == "held_out" and r["run_id"] not in keep:
        r["group"] = "excluded"
n = sum(r["group"] == "held_out" for r in m["runs"])
assert n == len(keep), (n, len(keep))
json.dump(m, open(sys.argv[3], "w"))
PY
  for rep in 1 2 3; do
    k=s${n}_r$rep; O=$W/$k; mkdir -p "$O" "$A/$k" && chmod 777 "$A/$k"
    timed "$k.seeds" "$n runs" python -m mtcore.baselines.provenance.seeded seeds --conv "$V" --group held_out \
      --findings-from "$W/go" --out "$A/$k/seeds.json" >> "$O/orthrus.log" 2>&1 || stop "$k seeds"
    timed "$k.tracing" "$n runs, 6 workers" docker exec -u pids -w /home/artifacts -e PYTHONPATH=/home/artifacts/orthrus-src mtpids-app \
      /opt/conda/envs/pids/bin/python /home/artifacts/seeded_tracing.py --seeds "$AD/$k/seeds.json" --graphs "$AD/$NX" \
      --orthrus-src /home/artifacts/orthrus-src --workers 6 --out "$AD/$k/traced.json" >> "$O/orthrus.log" 2>&1 || stop "$k tracing"
    timed "$k.records" "$n runs" python -m mtcore.baselines.provenance.seeded records --conv "$V" --group held_out \
      --findings-from "$W/go" --k 10 --traced "$A/$k/traced.json" --out-dir "$O" >> "$O/orthrus.log" 2>&1 || stop "$k records"
    cp "$A/$k/seeds.json" "$A/$k/traced.json" "$O/"
    st "DONE $k: $(grep -c "^$k\." "$W/steps.tsv") steps, $(awk -F'\t' -v k="$k." 'index($1,k)==1 {s+=$4} END {print s}' "$W/steps.tsv") s"
    up
  done
done
st "ALL_DONE"
