#!/usr/bin/env bash
# KAIROS and ORTHRUS on the held-out sets, on the AWS analysis host (docs/plans/heldout-aws-plan.md),
# with the frozen settings of src/params/frozen/pidsmaker.v0.yaml. Runs after run_analysis_aws.sh
# (seeded ORTHRUS needs the GO's held-out findings) and after bootstrap.sh. No held-out truth is
# on this machine (only the sealed readable parts, checked against their frozen manifests):
#   1. fetch the PILOT FIT runs (training data; their development truth is needed to strip
#      scenario events) and the held-out runs; check both
#   2. convert.py: train = PILOT FIT, test groups held_out and held_out_cases, both --sealed
#   3. database mt (schema from mt-schema.sql), tables, registry, placeholder ground truth
#   4. bundle (make_mt_bundle.sh) -> s3 results/$SESSION/bundle
#   5. run_mt_aws.sh: KAIROS run 1 and run 2 and ORTHRUS per held-out set, CPU, deterministic
#   6. run_seeded_orthrus.sh STAGE=detect on the GO's main-row findings of each set
#   7. score_mt_detected.sh STAGE=detect: the ORTHRUS context row's tracing and records
# SETS lists set:go_pass:params for each held-out set (default: the two real sets). The set name
# is its S3 folder, its split file experiments/heldout/splits/<set>.json (key <set>), its manifest
# manifests/<set>.tsv, its convert group and its PIDSMaker dataset MT_<SET>; go_pass is the
# analysis pass whose findings seed ORTHRUS for that set, params its frozen parameter file.
# The smoke test uses SETS="smoke:go_main:...". 
# STOP_AFTER=bundle ends after step 4 (Exp. 4 timing session). Scoring of all of it happens later in score_heldout.sh. The machine shuts down when the
# script exits (AUTO_SHUTDOWN=0 turns that off).
#
#   . ~/mt-env.sh; BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> SESSION=<name> \
#     ANALYSIS=<run_analysis_aws.sh session> nohup bash run_baselines_aws.sh > baselines.out 2>&1 &
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${SESSION:?}" "${ANALYSIS:?}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; W=${W:-$HOME/pidsmaker}; CONV=$W/conv
VENV=${VENV:-$CODE/.venv}; PM=$CODE/experiments/baselines/pidsmaker; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
SPLITS=$HERE/splits; FIT_SPLIT=${FIT_SPLIT:-$SPLITS/pilot_fit.json}
ORTHRUS_REF=e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543
SETS=${SETS:-"held_out:go_main:src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml held_out_cases:cases_full:src/params/frozen/fit-ri-on.K10.yaml"}
SET_NAMES=$(for x in $SETS; do echo -n "${x%%:*} "; done)
ds() { echo "MT_$(echo "$1" | tr a-z A-Z)"; }
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$W/logs" "$DATA"; S=$W/BASELINES_STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/BASELINES_STATUS" < /dev/null; }
stop() { st "STOP $*"; exit 1; }

# Prerequisites (no shutdown on these).
. "$VENV/bin/activate" || { echo "no venv $VENV"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
for f in "$PM/mt-schema.sql" "$FIT_SPLIT" $(for s in $SET_NAMES; do echo "$SPLITS/$s.json $HERE/manifests/$s.tsv"; done); do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
docker info > /dev/null 2>&1 || { echo "docker not usable"; exit 1; }
finish() {
  aws s3 sync --only-show-errors --no-follow-symlinks "$W/logs" "$R/logs" < /dev/null
  if [ "$AUTO_SHUTDOWN" = 1 ]; then st "SHUTDOWN"; sudo shutdown -h now; fi
}
trap finish EXIT
st "START code $(git -C "$CODE" rev-parse --short HEAD), record $(sha256sum "$CODE/src/params/frozen/pidsmaker.v0.yaml" | cut -c1-12)"

# 1. Data.
if [ ! -f "$DATA/.fetched-pilot_fit" ]; then
  aws s3 sync --only-show-errors --no-follow-symlinks "s3://$BUCKET/dev/pilot-fit" "$DATA/pilot_fit" < /dev/null \
    || stop "fetch pilot_fit"
  touch "$DATA/.fetched-pilot_fit"
fi
python3 - "$DATA/pilot_fit" "$FIT_SPLIT" < /dev/null <<'PY' || stop "pilot_fit runs incomplete"
import json, os, sys
d, split = sys.argv[1:]
want = json.load(open(split))["fit"]
miss = [r for r in want if not os.path.exists(os.path.join(d, r, "restricted", "truth_actions.pb"))]
if miss:
    sys.exit(f"{len(miss)} FIT runs lack restricted/truth_actions.pb, e.g. {miss[0]}")
PY
for s in $SET_NAMES; do
  if [ ! -f "$DATA/.fetched-$s" ]; then
    aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$s" "$DATA/$s" < /dev/null \
      || stop "fetch $s"
    bash "$HERE/check_fetch.sh" "$DATA/$s" "$HERE/manifests/$s.tsv" "$CODE" >> "$S" 2>&1 || stop "$s does not match its manifest"
    touch "$DATA/.fetched-$s"
  fi
done
st "DATA $(for s in pilot_fit $SET_NAMES; do echo -n "$s $(find "$DATA/$s" -mindepth 1 -maxdepth 1 -type d | wc -l) "; done)"

# 2. Conversion (one database: training days, then each test set's days).
if [ ! -f "$CONV/manifest.json" ]; then
  rm -rf "$CONV"
  cargs=(--runs "train=$DATA/pilot_fit@$FIT_SPLIT:fit")
  for s in $SET_NAMES; do cargs+=(--runs "$s=$DATA/$s@$SPLITS/$s.json:$s" --sealed "$s"); done
  python -m mtcore.baselines.provenance.convert --out "$CONV" --name MT "${cargs[@]}" < /dev/null \
    > "$W/logs/convert.log" 2>&1 || stop "convert (logs/convert.log)"
fi
st "CONVERTED $(python3 -c "import json;m=json.load(open('$CONV/manifest.json'));print(len(m['runs']),'runs, sealed',m['sealed'])")"

# 3. PIDSMaker tree, containers, database mt.
cd "$W" || stop "work dir"
cp "$PM"/{run_mt_aws.sh,compose.aws.yml,compose.gpu.yml,mt_detected.py,mt_construct.py,seeded_tracing.py,make_mt_bundle.sh} . \
  && rm -rf patches && cp -r "$PM/patches" . || stop "copy scripts"
[ -d PIDSMaker/.git ] || git clone --quiet --branch 3.0.0 --depth 1 https://github.com/ubc-provenance/PIDSMaker.git < /dev/null \
  || stop "clone PIDSMaker"
for p in patches/*.patch; do sed -i 's/\r$//' "$p"
  git -C PIDSMaker apply --reverse --check "$PWD/$p" 2>/dev/null || git -C PIDSMaker apply "$PWD/$p" || stop "patch $p"; done
[ "$(git -C PIDSMaker rev-parse HEAD)" = 438a05a7c55256f639e5b5945cf4828fe3ee078e ] || stop "PIDSMaker is not 3.0.0 (438a05a7)"
mkdir -p artifacts data/mt && chmod 777 artifacts
if [ ! -f artifacts/orthrus-src/provnet_utils.py ]; then
  [ -d orthrus/.git ] || git clone --quiet https://github.com/ubc-provenance/orthrus.git orthrus < /dev/null || stop "clone orthrus"
  git -C orthrus checkout --quiet $ORTHRUS_REF || stop "orthrus $ORTHRUS_REF"
  mkdir -p artifacts/orthrus-src \
    && cp orthrus/src/attack_reconstruction/tracing_methods/*.py orthrus/src/provnet_utils.py orthrus/src/config.py \
          artifacts/orthrus-src/ || stop "orthrus source"
fi
cp mt_construct.py seeded_tracing.py artifacts/
export APP_MEM=${APP_MEM:-$(( $(free -g | awk '/Mem:/ {print $2}') - 28 ))g}
docker compose -f compose.aws.yml build app > logs/build.log 2>&1 && docker compose -f compose.aws.yml up -d > logs/up.log 2>&1 \
  || stop "containers"
Q() { docker exec mtpids-postgres psql -U postgres -q "$@"; }
until docker exec mtpids-postgres pg_isready -U postgres > /dev/null 2>&1; do sleep 5; done
if [ "$(Q -d mt -tAc 'select count(*) from event_table' 2>/dev/null || echo 0)" = 0 ]; then
  Q -c "DROP DATABASE IF EXISTS mt;" -c "CREATE DATABASE mt;" || stop "create database"
  docker exec -i mtpids-postgres psql -U postgres -q -d mt -v ON_ERROR_STOP=1 < "$PM/mt-schema.sql" || stop "schema"
  cp "$CONV"/*_table.csv "$CONV/load.sql" data/mt/
  docker exec -w /data/mt mtpids-postgres psql -U postgres -d mt -q -v ON_ERROR_STOP=1 -f load.sql < /dev/null || stop "load"
  rm -f data/mt/*_table.csv                      # loaded; free the disk
fi
python3 - "$CONV/config.json" PIDSMaker/pidsmaker/config/mt_datasets.json < /dev/null <<'PY' || stop "registry"
import json, os, sys
cfg, reg = sys.argv[1:]
c = json.load(open(cfg))
r = json.load(open(reg)) if os.path.exists(reg) else {}
r.update(c)
json.dump(r, open(reg, "w"), indent=2)
print({k: (len(v["train_dates"]), len(v["val_dates"]), len(v["test_dates"])) for k, v in c.items()})
PY
mkdir -p PIDSMaker/Ground_Truth/orthrus && cp -r "$CONV"/ground_truth/* PIDSMaker/Ground_Truth/orthrus/ || stop "ground truth files"
st "DATABASE $(Q -d mt -tAc 'select count(*) from event_table') events"

# 4. Bundle (no held-out truth in it: make_mt_bundle.sh refuses unsealed sets).
if [ ! -f bundle/SHA256SUMS ]; then
  DSS=$(for s in $SET_NAMES; do echo -n "$(ds "$s") "; done)
  P=$W CONV=$CONV OUT=$W/bundle DATASETS="$DSS" SEALED="$DSS" \
    CHECK_STATUS=0 bash make_mt_bundle.sh < /dev/null > logs/bundle.log 2>&1 || stop "bundle"
fi
aws s3 sync --only-show-errors bundle "$R/bundle" < /dev/null || stop "bundle upload"
st "BUNDLE $(du -sh bundle | cut -f1)"
# Exp. 4 timing session (experiments/exp4/orthrus_step.sh prep): data, conversion, database, tree and
# containers only; training and detection are run and timed by the Exp. 4 runner.
if [ "${STOP_AFTER:-}" = bundle ]; then st "STOP_AFTER bundle"; exit 0; fi

# 5. Training and detection, one system at a time (run_mt_aws.sh logs time and memory per step
#    and exits non-zero if any step fails).
BUCKET=$BUCKET BUNDLE=results/$SESSION/bundle RESULTS=results/$SESSION/pidsmaker AUTO_SHUTDOWN=0 GPU=0 \
  STEPS="$(for s in $SET_NAMES; do d=$(ds "$s"); echo -n "kairos:$d kairos:$d:run2 orthrus:$d "; done)" \
  bash run_mt_aws.sh < /dev/null > logs/run_mt_aws.out 2>&1 || stop "run_mt_aws.sh exit $? (see STATUS)"
rm -rf data/mt-bundle                            # restored copy, no longer needed
st "TRAINED $(grep -c ' DONE .* exit 0 ' STATUS) steps with exit 0"

# 6. Seeded ORTHRUS on the GO's main-row findings (detect only).
SEED_GROUPS=""; CTX_GROUPS=""
# The analysis session may still be running (sessions A and B run side by side, 2026-11-15): a
# sync of an unfinished pass would copy part of its findings without any error. So wait until
# that session's timing.tsv shows the pass finished (exit 0) on every run of the set, up to
# WAIT_GO_HOURS, and check the copy holds one finished output per run.
WAIT_GO_HOURS=${WAIT_GO_HOURS:-12}
go_ready() {   # $1 pass, $2 expected runs
  aws s3 cp --only-show-errors "s3://$BUCKET/results/$ANALYSIS/timing.tsv" - 2>/dev/null < /dev/null \
    | awk -F'\t' -v p="$1" -v n="$2" '$1 == p && $2 == 0 && $4 == n { ok = 1 } END { exit !ok }'
}
for x in $SETS; do
  IFS=: read -r s gp pf <<< "$x"
  n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))[sys.argv[2]]))" "$SPLITS/$s.json" "$s")
  deadline=$(( $(date +%s) + WAIT_GO_HOURS * 3600 ))
  until go_ready "$gp" "$n"; do
    [ "$(date +%s)" -lt "$deadline" ] || stop "GO pass $gp of $ANALYSIS not finished on $n runs after $WAIT_GO_HOURS h"
    st "WAIT GO pass $gp of $ANALYSIS ($n runs)"; sleep 600
  done
  aws s3 sync --only-show-errors "s3://$BUCKET/results/$ANALYSIS/$gp" "$W/go/$gp" --exclude '*/offline.log' < /dev/null \
    || stop "fetch GO findings $gp"
  got=$(find "$W/go/$gp/runs" -mindepth 2 -maxdepth 2 -name output.jsonl.gz | wc -l)
  [ "$got" = "$n" ] || stop "GO findings $gp: $got outputs, expected $n"
  st "GO findings $gp: $n runs"
  SEED_GROUPS+="$s:$(ds "$s"):$DATA/$s:$W/go/$gp:$SPLITS/$s.json:$CODE/$pf:$s "
  CTX_GROUPS+="$s:$(ds "$s"):$DATA/$s:-:$W/go/$gp:$SPLITS/$s.json:$CODE/$pf:$s "
done
mkdir -p "$W/seeded" && ln -sfn "$CONV" "$W/seeded/out"
B=$W/seeded P=$W ASUB=seeded CODE=$CODE VENV=$VENV WAIT_CONV=0 LOAD=0 STAGE=detect WORKERS=8 \
  BGROUPS="$SEED_GROUPS" bash "$PM/run_seeded_orthrus.sh" < /dev/null || stop "seeded ORTHRUS"

# 7. ORTHRUS context row: tracing and records (no truth), on the same graphs.
mkdir -p "$W/res" && aws s3 sync --only-show-errors "s3://$BUCKET/results/$SESSION/pidsmaker/results" "$W/res" < /dev/null
RES=$W/res STAGE=detect A=$W/artifacts ASUB=seeded CONV=$CONV CODE=$CODE VENV=$VENV BGROUPS="$CTX_GROUPS" \
  bash "$PM/score_mt_detected.sh" < /dev/null || stop "context-row detect (see $W/res/SCORE_STATUS)"

aws s3 sync --only-show-errors --no-follow-symlinks "$W/seeded" "$R/seeded" --exclude 'out' --exclude 'out/*' < /dev/null \
  && aws s3 sync --only-show-errors "$W/res" "$R/pidsmaker/results" < /dev/null \
  && aws s3 sync --only-show-errors "$CONV" "$R/conv" --exclude '*_table.csv' < /dev/null || stop "upload"
st "ALL_DONE"
