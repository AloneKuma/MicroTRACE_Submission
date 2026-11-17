#!/usr/bin/env bash
# Exp. 3 seeded ORTHRUS row (user decision 2026-11-17, after the GO and SAGE rows were scored; a
# post-hoc row, disclosed as such). Unattended: started by mt-job.service on a SCORING machine
# (Terraform -var scoring=true -var autorun=true -var job_script=experiments/exp3/orthrus_job_aws.sh)
# as ubuntu, with BUCKET, COMMIT and SESSION set. The machine shuts down when this script exits.
#
# Same seeded ORTHRUS as Exp. 2 (run_seeded_orthrus.sh, frozen src/params/frozen/pidsmaker.v0.yaml:
# PIDSMaker 3.0.0 graphs, the authors' DEPIMPACT tracer, component + degree, no model, K = 10), on
# each scored Exp. 3 condition, seeded from that condition's GO Full findings, scored exactly as the
# condition's SAGE rows (score_pilot.py --correlator sage --sage-variant ag --stage score
# --fault-log-root): Core nofault, loss-transit-05, loss-transit-10 (session exp3-a) and Targeted
# nofault (exp3-b), on the runs of each condition's scored split.
#
# Input streams: the received dumps of these conditions were not kept, so each is rebuilt from the
# run's base stream minus the records the injector logged as dropped (mtcore.exp3.rebuild; every run
# must match the receiver's own event count, and exp3-a nofault is compared with its real dumps).
# Truth is fetched only after every condition's ORTHRUS records are written.
#
# A condition is split into parts (every n-th run of its split from the i-th), each converted into
# its own Postgres database, since convert.py is serial; the parts' records are merged into one
# folder per condition, which is scored once. Training group for convert.py: a few PILOT FIT runs
# (convert.py needs one; seeded tracing reads only each test run's own graph).
# Output: s3://$BUCKET/results/$SESSION/ and s3://$BUCKET/scored/2026-11-17-orthrus/exp3/<set>/.
set -uo pipefail
: "${BUCKET:?}" "${COMMIT:?}" "${SESSION:?}"
HELDOUT_BUCKET=${HELDOUT_BUCKET:-<SEALED_BUCKET>}
CODE=${CODE:-$HOME/code}; W=${W:-$HOME/e3o}; P=$HOME/pidsmaker; PM=$CODE/experiments/baselines/pidsmaker
A=$P/artifacts/e3o; AD=/home/artifacts/e3o; DATA=$HOME/data
SCORED=${SCORED:-scored/2026-11-17-orthrus/exp3}; SPLITS_FROM=${SPLITS_FROM:-scored/2026-11-17/exp3}    # the scored splits (failed transports removed)
TRAIN_N=${TRAIN_N:-12}; ORTHRUS_REF=e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543
CM=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml; CT=src/params/frozen/fit-ri-on.K10.yaml
# part key:session:condition:set:params:db:i/n   (db = convert.py --name, its own database)
CONDS=${CONDS:-"cnf1:exp3-a:nofault:held_out:$CM:E3A:1/2
cnf2:exp3-a:nofault:held_out:$CM:E3B:2/2
cl051:exp3-a:loss-transit-05:held_out:$CM:E3C:1/2
cl052:exp3-a:loss-transit-05:held_out:$CM:E3D:2/2
cl101:exp3-a:loss-transit-10:held_out:$CM:E3E:1/2
cl102:exp3-a:loss-transit-10:held_out:$CM:E3F:2/2
tnf1:exp3-b:nofault:held_out_cases:$CT:E3G:1/4
tnf2:exp3-b:nofault:held_out_cases:$CT:E3H:2/4
tnf3:exp3-b:nofault:held_out_cases:$CT:E3I:3/4
tnf4:exp3-b:nofault:held_out_cases:$CT:E3J:4/4"}
conds() { echo "$CONDS" | awk -F: -v f="$1" 'NF {n = split(f, x, ","); s = $x[1]; for (i = 2; i <= n; i++) s = s ":" $x[i]; print s}' | sort -u; }
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$W/logs" "$DATA"; S=$W/STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null; }
up() { aws s3 sync --only-show-errors "$W" "$R" --exclude 'rb/*' --exclude 'base/*' --exclude 'conv/*' \
         --exclude 'truth/*' --exclude 'cond/*' --exclude '*/received.jsonl' --exclude '*.jsonl.gz' < /dev/null; }
stop() { st "STOP $*"; up; exit 1; }
trap up EXIT
st "START exp3 seeded ORTHRUS, code ${COMMIT:0:7}"

BUCKET=$BUCKET COMMIT=$COMMIT MT_SKIP_SAGE=1 bash "$CODE/experiments/heldout/bootstrap.sh" > "$W/logs/bootstrap.log" 2>&1 \
  || stop "bootstrap (logs/bootstrap.log)"
. "$HOME/mt-env.sh"
. "$CODE/.venv/bin/activate"; export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
st "READY"

# --- PIDSMaker tree and containers (as run_baselines_aws.sh step 3), in the background.
containers() {
  mkdir -p "$P" && cd "$P" || return 1
  cp "$PM"/{compose.aws.yml,mt_construct.py,seeded_tracing.py} . && rm -rf patches && cp -r "$PM/patches" . || return 1
  git clone --quiet --branch 3.0.0 --depth 1 https://github.com/ubc-provenance/PIDSMaker.git < /dev/null || return 1
  for p in patches/*.patch; do sed -i 's/\r$//' "$p"; git -C PIDSMaker apply "$PWD/$p" || return 1; done
  [ "$(git -C PIDSMaker rev-parse HEAD)" = 438a05a7c55256f639e5b5945cf4828fe3ee078e ] || return 1
  mkdir -p artifacts/e3o data && chmod -R 777 artifacts
  git clone --quiet https://github.com/ubc-provenance/orthrus.git orthrus < /dev/null \
    && git -C orthrus checkout --quiet $ORTHRUS_REF || return 1
  mkdir -p artifacts/orthrus-src && cp orthrus/src/attack_reconstruction/tracing_methods/*.py orthrus/src/provnet_utils.py \
    orthrus/src/config.py artifacts/orthrus-src/ || return 1
  cp mt_construct.py seeded_tracing.py artifacts/
  export APP_MEM=$(( $(free -g | awk '/Mem:/ {print $2}') - 28 ))g
  docker compose -f compose.aws.yml build app > "$W/logs/build.log" 2>&1 \
    && docker compose -f compose.aws.yml up -d > "$W/logs/up.log" 2>&1 || return 1
  until docker exec mtpids-postgres pg_isready -U postgres > /dev/null 2>&1; do sleep 5; done
}
( containers > "$W/logs/containers.log" 2>&1 && touch "$W/.containers-ok" || touch "$W/.containers-failed" ) &
CPID=$!

# --- Training group for convert.py (a few PILOT FIT runs, at least one of them a validation run).
python3 - "$CODE/experiments/heldout/splits/pilot_fit.json" "$W/train.json" "$TRAIN_N" <<'PY' || stop "train subset"
import json, sys
from mtcore.baselines.provenance.convert import val_runs
fit = sorted(json.load(open(sys.argv[1]))["fit"]); n = int(sys.argv[3])
while not val_runs(fit[:n], 0.15) or len(val_runs(fit[:n], 0.15)) == n:
    n += 1
json.dump({"fit": fit[:n]}, open(sys.argv[2], "w"), indent=2)
print(n, "FIT runs,", len(val_runs(fit[:n], 0.15)), "validation")
PY
for r in $(python3 -c "import json;print(' '.join(json.load(open('$W/train.json'))['fit']))"); do
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$BUCKET/dev/pilot-fit/$r" "$DATA/pilot_fit/$r" < /dev/null \
    || stop "fetch FIT run $r"
  [ -f "$DATA/pilot_fit/$r/restricted/truth_actions.pb" ] || stop "FIT run $r has no restricted/truth_actions.pb"
done
st "TRAIN $(python3 -c "import json;print(len(json.load(open('$W/train.json'))['fit']))") FIT runs"

# --- Shared inputs: base streams per session; per condition the scored split, received metadata,
# fault logs, GO Full findings, and for exp3-a nofault the real dumps (compared with the rebuild).
for sess in $(conds 2); do
  aws s3 sync --only-show-errors "s3://$BUCKET/results/$sess/exp3/base" "$W/base/$sess" < /dev/null || stop "base $sess"
done
st "BASE $(du -sh "$W/base" | cut -f1)"
for sc in $(conds 2,3,4); do
  IFS=: read -r sess c set <<< "$sc"; SW=$W/sets/$set; CD=$W/cond/$sess/$c
  mkdir -p "$SW/splits" "$SW/received/$c" "$CD"
  aws s3 cp --only-show-errors "s3://$BUCKET/$SPLITS_FROM/$set/splits/$c.json" "$SW/splits/$c.json" < /dev/null \
    && aws s3 sync --only-show-errors "s3://$BUCKET/results/$sess/exp3/received/$c" "$SW/received/$c" --exclude '*.gz' < /dev/null \
    && aws s3 sync --only-show-errors "s3://$BUCKET/results/$sess-faultlogs/$c" "$CD/faultlogs" < /dev/null \
    && aws s3 sync --only-show-errors "s3://$BUCKET/results/$sess/exp3/detect/$c/full" "$CD/go" \
         --exclude '*' --include 'runs/*/output.jsonl.gz' < /dev/null || stop "fetch $sess $c"
  if [ "$sess:$c" = exp3-a:nofault ]; then
    aws s3 sync --only-show-errors "s3://$BUCKET/results/$sess/exp3/received/$c" "$CD/real" < /dev/null || stop "real dumps"
  fi
  st "FETCHED $sess $c: $(python3 -c "import json;print(len(json.load(open('$SW/splits/$c.json'))['runs']))") runs, $(find "$CD/go/runs" -name output.jsonl.gz | wc -l) GO outputs"
done

# --- Per part: rebuild, convert (all parts in parallel).
prepare() {  # key session cond set params db part
  local k=$1 sess=$2 c=$3 set=$4 db=$6 part=$7 SW=$W/sets/$4 CD=$W/cond/$2/$3 runs chk=()
  runs=$(python3 -c "import json;i,n=map(int,'$part'.split('/'));r=json.load(open('$SW/splits/$c.json'))['runs'];print(' '.join(r[i-1::n]))")
  python3 -c "import json,sys;json.dump({'runs':sys.argv[1:]},open('$W/part-$k.json','w'))" $runs
  for r in $runs; do
    [ -d "$W/base/$sess/$r/nodes" ] || { echo "no base stream for $r"; return 1; }
    [ -f "$CD/go/runs/$r/output.jsonl.gz" ] || { echo "no GO output for $r"; return 1; }
  done
  [ -d "$CD/real" ] && chk=(--check-against "$CD/real")
  python -m mtcore.exp3.rebuild --base "$W/base/$sess" --faultlogs "$CD/faultlogs" --received "$SW/received/$c" \
    --runs $runs --out "$W/rb/$k" --workers 3 "${chk[@]}" > "$W/logs/rebuild-$k.log" 2>&1 || return 1
  cp "$W/rb/$k/rebuild-check.json" "$W/logs/rebuild-check-$k.json"
  python -m mtcore.baselines.provenance.convert --out "$W/conv/$k" --name "$db" \
    --runs "train=$DATA/pilot_fit@$W/train.json:fit" --runs "$k=$W/rb/$k@$W/part-$k.json:runs" --sealed "$k" \
    > "$W/logs/convert-$k.log" 2>&1 || return 1
  rm -rf "$W/rb/$k"/*/shipper                               # converted; free the disk
}
pids=""
while IFS=: read -r k sess c set params db part; do
  [ -n "$k" ] || continue
  ( prepare "$k" "$sess" "$c" "$set" "$params" "$db" "$part" && st "PREPARED $k $(tail -1 "$W/logs/rebuild-$k.log")" \
      || { st "FAILED prepare $k (logs/rebuild-$k.log, convert-$k.log)"; exit 1; } ) &
  pids="$pids $!"
done <<< "$CONDS"
fail=0; for p in $pids; do wait "$p" || fail=1; done
[ "$fail" = 0 ] || stop "prepare"
rm -rf "$W/base"
wait "$CPID"; [ -f "$W/.containers-ok" ] || stop "containers (logs/containers.log, build.log)"
st "CONTAINERS up"

# --- Databases and registry (one Postgres, one database per part).
cd "$P" || stop "pidsmaker dir"
Q() { docker exec mtpids-postgres psql -U postgres -q "$@"; }
while IFS=: read -r k sess c set params db part; do
  [ -n "$k" ] || continue
  d=$(echo "$db" | tr A-Z a-z)
  Q -c "DROP DATABASE IF EXISTS $d;" -c "CREATE DATABASE $d;" || stop "create database $d"
  docker exec -i mtpids-postgres psql -U postgres -q -d "$d" -v ON_ERROR_STOP=1 < "$PM/mt-schema.sql" || stop "schema $d"
  mkdir -p "data/$d" && cp "$W/conv/$k"/*_table.csv "$W/conv/$k/load.sql" "data/$d/"
  docker exec -w "/data/$d" mtpids-postgres psql -U postgres -d "$d" -q -v ON_ERROR_STOP=1 -f load.sql < /dev/null \
    || stop "load $d"
  rm -f data/$d/*_table.csv
  python3 - "$W/conv/$k/config.json" PIDSMaker/pidsmaker/config/mt_datasets.json <<'PY' || stop "registry $k"
import json, os, sys
c = json.load(open(sys.argv[1])); reg = sys.argv[2]
r = json.load(open(reg)) if os.path.exists(reg) else {}
r.update(c); json.dump(r, open(reg, "w"), indent=2)
PY
  mkdir -p PIDSMaker/Ground_Truth/orthrus && cp -r "$W/conv/$k"/ground_truth/* PIDSMaker/Ground_Truth/orthrus/ \
    || stop "ground truth placeholders $k"
  st "DATABASE $d $(Q -d "$d" -tAc 'select count(*) from event_table') events"
done <<< "$CONDS"

# --- Graphs, seeds, tracing, records per part (parallel; no truth on the machine yet).
mkdir -p "$A/seeds" && chmod -R 777 "$A"
trace() {  # key session cond db
  local k=$1 sess=$2 c=$3 db=$4 ds nx t0 GO=$W/cond/$2/$3/go
  t0=$(date +%s); ds=$(echo "${db}_$k" | tr a-z A-Z)
  docker exec -u pids -w /home/pids -e PYTHONPATH=/home/pids mtpids-app /opt/conda/envs/pids/bin/python \
    /home/artifacts/mt_construct.py orthrus "$ds" --cpu --artifact_dir "$AD/" > "$W/logs/graphs-$k.log" 2>&1 || return 1
  nx=$(cd "$A" && ls -d construction/"$ds"/construction/*/nx)
  [ "$(echo "$nx" | wc -l)" = 1 ] || { echo "graph dirs: $nx"; return 1; }
  python -m mtcore.baselines.provenance.seeded seeds --conv "$W/conv/$k" --group "$k" --findings-from "$GO" \
    --out "$A/seeds/seeds-$k.json" > "$W/logs/seeded-$k.log" 2>&1 || return 1
  docker exec -u pids -w /home/artifacts -e PYTHONPATH=/home/artifacts/orthrus-src mtpids-app \
    /opt/conda/envs/pids/bin/python /home/artifacts/seeded_tracing.py --seeds "$AD/seeds/seeds-$k.json" \
    --graphs "$AD/$nx" --orthrus-src /home/artifacts/orthrus-src --workers 3 \
    --out "$AD/seeds/traced-$k.json" >> "$W/logs/seeded-$k.log" 2>&1 || return 1
  python -m mtcore.baselines.provenance.seeded records --conv "$W/conv/$k" --group "$k" --findings-from "$GO" \
    --k 10 --traced "$A/seeds/traced-$k.json" --out-dir "$W/parts/$k" >> "$W/logs/seeded-$k.log" 2>&1 || return 1
  cp "$A/seeds/seeds-$k.json" "$A/seeds/traced-$k.json" "$W/logs/"
  echo "$(( $(date +%s) - t0 )) s; $(python3 -c "
import json
s=json.load(open('$A/seeds/seeds-$k.json')); t=json.load(open('$A/seeds/traced-$k.json'))
print(len(s),'runs',sum(len(v['seeds']) for v in s.values()),'seed findings',sum(v['seed_nodes_absent'] for v in t.values()),'seed nodes absent')")"
}
pids=""
while IFS=: read -r k sess c set params db part; do
  [ -n "$k" ] || continue
  ( m=$(trace "$k" "$sess" "$c" "$db") && st "TRACED $k $m" \
      || { st "FAILED trace $k (logs/graphs-$k.log, seeded-$k.log)"; exit 1; } ) &
  pids="$pids $!"
done <<< "$CONDS"
fail=0; for p in $pids; do wait "$p" || fail=1; done
[ "$fail" = 0 ] || stop "tracing"
# Merge the parts' records (disjoint runs, one file per run) into one folder per condition.
for sc in $(conds 2,3,4); do
  IFS=: read -r sess c set <<< "$sc"; D=$W/sets/$set/detect/$c/orthrus_seeded; n=0
  mkdir -p "$D/sage/ag"
  for k in $(echo "$CONDS" | awk -F: -v s="$sess" -v c="$c" 'NF && $2 == s && $3 == c {print $1}'); do
    cp "$W/parts/$k/sage/ag/"*.jsonl "$D/sage/ag/" || stop "merge $k"
    n=$((n + $(ls "$W/parts/$k/sage/ag/" | wc -l)))
  done
  want=$(python3 -c "import json;print(len(json.load(open('$W/sets/$set/splits/$c.json'))['runs']))")
  [ "$n" = "$want" ] || stop "merge $sess $c: $n record files, expected $want"
  echo "{\"system\": \"orthrus-seeded\", \"k\": 10, \"runs\": $n}" > "$D/sage/run.json"
done
up
st "DETECTED all conditions (records written; truth not yet read)"

# --- Truth, scoring (as the condition's SAGE rows), summary.
for set in $(conds 4); do
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/truth/$set" "$W/truth/$set" < /dev/null \
    || stop "truth $set"
  bad=0
  for r in $(ls "$W/truth/$set" | grep -v '^_'); do
    (cd "$W/truth/$set/$r" && sha256sum -c --quiet SHA256SUMS < /dev/null) || bad=$((bad + 1))
  done
  [ "$bad" = 0 ] || stop "truth $set: $bad checksum failures"
done
st "TRUTH fetched and checked"
fail=0
for scp in $(conds 2,3,4,5); do
  IFS=: read -r sess c set params <<< "$scp"; SW=$W/sets/$set; CD=$W/cond/$sess/$c; k=$sess-$c
  if (cd "$CODE" && python src/scripts/pilot/score_pilot.py --correlator sage --sage-variant ag --pilot "$SW/received/$c" \
        --truth-root "$W/truth/$set" --split "$SW/splits/$c.json" --half runs --params "$CODE/$params" \
        --findings-from "$CD/go" --out-dir "$SW/detect/$c/orthrus_seeded" --stage score \
        --fault-log-root "$CD/faultlogs" --workers 8 < /dev/null) > "$W/logs/score-$k.log" 2>&1; then
    st "SCORED $k $(grep '^Links:' "$SW/detect/$c/orthrus_seeded/summary.md"); $(grep '^Paths:' "$SW/detect/$c/orthrus_seeded/summary.md")"
  else
    st "FAILED score $k (logs/score-$k.log)"; fail=$((fail + 1))
  fi
done
for set in $(conds 4); do
  python -m mtcore.exp3.summary --work "$W/sets/$set" > "$W/logs/summary-$set.log" 2>&1 || st "FAILED summary $set"
  aws s3 sync --only-show-errors "$W/sets/$set" "s3://$BUCKET/$SCORED/$set" --exclude 'received/*' \
    --exclude '*/sage/ag/*.jsonl' < /dev/null
done
up
[ "$fail" = 0 ] && st "ALL_DONE" || st "FINISHED with $fail failed score(s)"
