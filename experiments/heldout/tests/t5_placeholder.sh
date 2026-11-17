#!/usr/bin/env bash
# Host test (docs/plans/heldout-aws-plan.md section 7, tests 3-4): PIDSMaker with the sealed
# placeholder ground truth, on CPU, plus KAIROS run 2. Small set from development runs:
# 7 PILOT FIT runs for training (1 becomes validation), 2 PILOT SCORE runs as the test group.
# Converted twice with the current code: plain (group t5real, real GT) and --sealed (group
# t5seal, placeholder GT); the tables must be identical, so one scratch database mtt5 serves
# both registry entries MTT5_T5REAL and MTT5_T5SEAL. Runs use exactly the frozen MT_ARGS
# (no --cpu: PIDSMaker falls back to CPU), default epochs, each in a fresh artifact folder.
# Everything it creates is removed at the end except the results in $T.
#
#   CODE=~/microtrace-dryrun/code nohup bash t5_placeholder.sh > t5.log 2>&1 &
set -uo pipefail
CODE=${CODE:?}; T=${T:-$HOME/microtrace-dryrun/t5}
P=$HOME/microtrace-baselines/pidsmaker; A=$P/artifacts/t5; AD=/home/artifacts/t5
D=$HOME/microtrace-pilot-multistep/pilot-multistep; SPLIT=$D/_gates/pilot-multistep-split.json
REG=$P/PIDSMaker/pidsmaker/config/mt_datasets.json; GT=$P/PIDSMaker/Ground_Truth/orthrus
PY=/opt/conda/envs/pids/bin/python; MT_ARGS="--training.deterministic=True"
st() { echo "$(date -u +%FT%TZ) $*"; }
pass() { st "PASS $*"; }
fail() { st "FAIL $*"; FAILS=$((FAILS + 1)); }
FAILS=0
Q() { docker exec mtpids-postgres psql -U postgres -q "$@"; }
cleanup() {
  [ -f "$T/mt_datasets.json.bak" ] && cp "$T/mt_datasets.json.bak" "$REG"
  rm -rf "$GT/t5real" "$GT/t5seal" "$P/data/mtt5"
  docker exec -u root mtpids-app rm -rf "$AD" 2>/dev/null
  Q -c "DROP DATABASE IF EXISTS mtt5;" 2>/dev/null
  st "CLEANUP done (registry restored, scratch GT/data/artifacts/database removed)"
}
trap cleanup EXIT
rm -rf "$T"; mkdir -p "$T"
. "$HOME/microtrace-pilot-multistep/code/.venv/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
st "START code $(git -C "$CODE" rev-parse --short HEAD)"
for n in t5real t5seal; do [ -e "$GT/$n" ] && { st "STOP $GT/$n exists"; exit 1; }; done
grep -q '"MTT5_' "$REG" && { st "STOP MTT5 entries already in the registry"; exit 1; }

# 1. Two conversions of the same runs.
python3 - "$SPLIT" "$T/split.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"fit": sorted(s["fit"])[:7], "score": sorted(s["score"])[:2]}, open(sys.argv[2], "w"))
PY
python -m mtcore.baselines.provenance.convert --out "$T/conv_real" --name MTT5 --val-fraction 0.15 \
  --runs "train=$D@$T/split.json:fit" --runs "t5real=$D@$T/split.json:score" > "$T/conv_real.log" 2>&1 \
  || { st "STOP convert real"; exit 1; }
python -m mtcore.baselines.provenance.convert --out "$T/conv_seal" --name MTT5 --val-fraction 0.15 \
  --runs "train=$D@$T/split.json:fit" --runs "t5seal=$D@$T/split.json:score" --sealed t5seal > "$T/conv_seal.log" 2>&1 \
  || { st "STOP convert sealed"; exit 1; }
same=1
for t in event_table file_node_table netflow_node_table subject_node_table; do
  cmp -s "$T/conv_real/$t.csv" "$T/conv_seal/$t.csv" || { same=0; fail "table $t differs between plain and sealed conversion"; }
done
[ $same = 1 ] && pass "tables identical between plain and sealed conversion"
python3 - "$T/conv_real" "$T/conv_seal" <<'PY' && pass "sealed GT: one placeholder row per test run; real GT present" || fail "GT files"
import csv, glob, os, sys
r, s = sys.argv[1:]
real = sorted(glob.glob(os.path.join(r, "ground_truth", "t5real", "*.csv")))
seal = sorted(glob.glob(os.path.join(s, "ground_truth", "t5seal", "*.csv")))
assert len(real) == len(seal) == 2, (real, seal)
assert all(len(list(csv.reader(open(f)))) == 1 for f in seal)
# a real GT file may be empty (a test run with no present host step); at least one is not
assert any(len(list(csv.reader(open(f)))) >= 1 for f in real)
for f in seal:
    print(os.path.basename(f), "placeholder", list(csv.reader(open(f)))[0][:2])
PY

# 2. Scratch database and twin registry entries.
cp "$REG" "$T/mt_datasets.json.bak"
mkdir -p "$P/data/mtt5" && cp "$T/conv_real"/*_table.csv "$T/conv_real/load.sql" "$P/data/mtt5/"
Q -c "DROP DATABASE IF EXISTS mtt5;" -c "CREATE DATABASE mtt5;" || { st "STOP create db"; exit 1; }
docker exec -i mtpids-postgres psql -U postgres -q -d mtt5 -v ON_ERROR_STOP=1 < "$CODE/experiments/baselines/pidsmaker/mt-schema.sql" \
  || { st "STOP schema"; exit 1; }
docker exec -w /data/mtt5 mtpids-postgres psql -U postgres -d mtt5 -q -v ON_ERROR_STOP=1 -f load.sql > /dev/null \
  || { st "STOP load"; exit 1; }
st "DB mtt5 $(Q -d mtt5 -tAc 'select count(*) from event_table') events"
python3 - "$REG" "$T/conv_real/config.json" "$T/conv_seal/config.json" <<'PY' || { st "STOP registry"; exit 1; }
import json, sys
reg, a, b = sys.argv[1:]
r = json.load(open(reg))
for f in (a, b):
    for k, v in json.load(open(f)).items():
        r[k] = v
        print(k, v["database"], len(v["train_dates"]), len(v["val_dates"]), len(v["test_dates"]))
json.dump(r, open(reg, "w"), indent=2)
PY
cp -r "$T/conv_real/ground_truth/t5real" "$T/conv_seal/ground_truth/t5seal" "$GT/"

# 3. Runs.
mkdir -p "$A" && chmod 777 "$A"
cp "$CODE/experiments/baselines/pidsmaker/mt_detected.py" "$HOME/microtrace-b3/peak.py" "$A/" && chmod a+r "$A"/*.py
run() {   # name model dataset [artifact subfolder]
  local name=$1 model=$2 ds=$3 art=$AD/${4:-$1}/ t0=$(date +%s)
  mkdir -p "$A/${4:-$1}" && chmod 777 "$A/${4:-$1}"
  docker exec -u pids -w /home/pids -e PYTHONPATH=/home/pids mtpids-app $PY $AD/peak.py \
    pidsmaker/main.py "$model" "$ds" $MT_ARGS --artifact_dir "$art" > "$T/$name.log" 2>&1
  local rc=$?
  st "RUN $name exit $rc in $(( $(date +%s) - t0 )) s; $(grep '^PEAK' "$T/$name.log")"
  [ $rc = 0 ] || { fail "$name exit $rc"; return 1; }
  docker exec -u pids -w /home/pids -e PYTHONPATH=/home/pids -e MT_OUT="${art}out" mtpids-app $PY \
    $AD/mt_detected.py "$model" "$ds" $MT_ARGS --artifact_dir "$art" >> "$T/$name.log" 2>&1 \
    || { fail "$name export"; return 1; }
  mkdir -p "$T/$name" && cp "$A/${4:-$1}/out"/* "$T/$name/"
  st "EXPORT $name $(grep '^EPOCH' "$T/$name.log" | tail -1); val-loss epochs logged: $(grep -c 'Validation finished' "$T/$name.log")"
}
run kairos_real kairos MTT5_T5REAL
run kairos_seal kairos MTT5_T5SEAL
run kairos_seal_run2 kairos MTT5_T5SEAL run2/kairos_seal
run orthrus_real orthrus MTT5_T5REAL
run orthrus_seal orthrus MTT5_T5SEAL

# 4. Checks.
cmpdir() {   # a b label
  local ok=1
  for f in flagged.csv val_loss.tsv; do
    if [ -f "$T/$1/$f" ] && [ -f "$T/$2/$f" ]; then
      cmp -s "$T/$1/$f" "$T/$2/$f" || { ok=0; fail "$3: $f differs"; }
    else ok=0; fail "$3: $f missing"; fi
  done
  # choice.json names its own artifact folder and dataset in two path fields; everything else must match
  python3 - "$T/$1/choice.json" "$T/$2/choice.json" <<'PY' || { ok=0; fail "$3: choice.json differs beyond its own paths"; }
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:])
for x in (a, b):
    for k in ("result_file", "edge_losses_dir"):
        x.pop(k, None)
assert a == b, (a, b)
PY
  [ $ok = 1 ] && pass "$3: flagged.csv, choice.json, val_loss.tsv identical ($(($(wc -l < "$T/$1/flagged.csv") - 1)) flagged nodes)"
}
cmpdir kairos_real kairos_seal "KAIROS real GT vs placeholder"
cmpdir orthrus_real orthrus_seal "ORTHRUS real GT vs placeholder"
cmpdir kairos_seal kairos_seal_run2 "KAIROS run 1 vs run 2"
if ls -d "$A/run2/kairos_seal/construction" > /dev/null 2>&1 && [ -n "$(find "$A/run2/kairos_seal" -name '*.pth' -print -quit)" ]; then
  pass "run 2 built its own construction and model files in its own folder"
else fail "run 2 has no construction/model files of its own"; fi
for k in kairos_real kairos_seal; do
  g=t5real; c=$T/conv_real; [ $k = kairos_seal ] && { g=t5seal; c=$T/conv_seal; }
  python -m mtcore.baselines.provenance.detected kairos --conv "$c" --group "$g" --data "$D" --flagged "$T/$k/flagged.csv" \
    --out "$T/$k/kairos.json" > /dev/null 2>&1 || fail "$k scoring"
  python -m mtcore.baselines.provenance.detected kairos-nodes --conv "$c" --group "$g" --data "$D" --flagged "$T/$k/flagged.csv" \
    --out "$T/$k/kairos-nodes.json" > /dev/null 2>&1 || fail "$k node report"
done
python3 - "$T" <<'PY' && pass "KAIROS step scoring identical for real and placeholder runs" || fail "KAIROS step scoring differs"
import json, sys
t = sys.argv[1]
a, b = (json.load(open(f"{t}/{k}/kairos.json")) for k in ("kairos_real", "kairos_seal"))
for x in (a, b):
    x.pop("group", None)
print("steps", a["steps"], "nodes", a["nodes"])
assert a == b
PY
st "SUMMARY $FAILS failures"
st "T5_DONE"
