#!/usr/bin/env bash
# Seeded ORTHRUS (Exp. 2 main row) on the full conversion, on the test host: no AWS,
# no training. Waits for ~/microtrace-convert to report DONE, then registers MT_PILOT
# and MT_CASES, loads database mt, builds graphs, traces and scores both groups.
# Stops at the first failed step and says why in $B/ORTHRUS_STATUS.
#
#   nohup bash run_seeded_orthrus.sh > ~/microtrace-convert/orthrus.out 2>&1 &
#
# Every path can be set from the environment; the defaults are the development run.
# Held-out (sealed truth), e.g. on the AWS analysis host:
#   B=<conversion work dir> WAIT_CONV=0 STAGE=detect \
#   BGROUPS="held_out:MT_HELD_OUT:<runs>:<GO detect out>:<split>:<frozen params>:held_out ..." \
#   bash run_seeded_orthrus.sh
# BGROUPS lists group:dataset:data:findings:split:params:half. STAGE=detect stops before
# scoring (no truth read; score later with score_pilot.py --stage score --truth-root).
# LOAD=0 skips registration and the database load (already done). ASUB puts the graphs
# in artifacts/$ASUB/ (on a machine that also trains KAIROS and ORTHRUS, whose own graph
# folders would otherwise sit next to them).
set -uo pipefail
B=${B:-$HOME/microtrace-convert}; P=${P:-$HOME/microtrace-baselines/pidsmaker}; ASUB=${ASUB:-}; A=$P/artifacts${ASUB:+/$ASUB}; AD=/home/artifacts${ASUB:+/$ASUB}; OUT=$A/mt-full
D=$HOME/microtrace-pilot-multistep/pilot-multistep; DC=$HOME/microtrace-pilot-cases/pilot-cases
BGROUPS=${BGROUPS:-"pilot:MT_PILOT:$D:$HOME/microtrace-pilot-multistep/d23/cache-t0:$D/_gates/pilot-multistep-split.json:$D/_gates/pilot-multistep-fit.yaml:score cases:MT_CASES:$DC:$DC/_gates/twin_safety:$DC/_gates/tactic/split60.json:$DC/_gates/fit-ri-on.yaml:score"}
CODE=${CODE:-$B/code}; VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}
STAGE=${STAGE:-all}; WAIT_CONV=${WAIT_CONV:-1}; LOAD=${LOAD:-1}
S=$B/ORTHRUS_STATUS
st() { echo "$(date -u +%FT%TZ) $*" >> "$S"; }
stop() { st "STOP $*"; exit 1; }
Q() { docker exec mtpids-postgres psql -U postgres -q "$@"; }

if [ "$WAIT_CONV" = 1 ]; then
  st "WAIT conversion"
  while :; do
    l=$(tail -1 "$B/STATUS")
    case "$l" in *" DONE "*) break;; *" STOP "*) stop "conversion: $l";; esac
    sleep 30
  done
  st "CONVERSION $l"
fi
if [ "$LOAD" = 1 ]; then

# Register: the conversion started before convert.py wrote attack_to_time_window.
python3 - "$B/out" "$P/PIDSMaker/pidsmaker/config/mt_datasets.json" <<'PY' || stop "registration"
import json, os, sys
out, reg = sys.argv[1:]
cfg = json.load(open(os.path.join(out, "config.json")))
runs = {r["run_id"]: r for r in json.load(open(os.path.join(out, "manifest.json")))["runs"]}
for name, c in cfg.items():
    if not c["val_dates"]:
        sys.exit(f"{name}: no validation dates")
    c.setdefault("attack_to_time_window", [])
    if not c["attack_to_time_window"]:
        for gt in c["ground_truth_relative_path"]:
            d = runs[os.path.splitext(os.path.basename(gt))[0]]["date"]
            c["attack_to_time_window"].append([gt, d + " 00:00:00", d + " 23:59:59"])
all_ = json.load(open(reg)) if os.path.exists(reg) else {}
all_.update(cfg)
json.dump(all_, open(reg, "w"), indent=2)
print({k: (len(v["train_dates"]), len(v["val_dates"]), len(v["test_dates"])) for k, v in cfg.items()})
PY

mkdir -p "$P/PIDSMaker/Ground_Truth/orthrus" && cp -r "$B"/out/ground_truth/* "$P/PIDSMaker/Ground_Truth/orthrus/" \
  || stop "copy ground truth"
mkdir -p "$P/data/mt" "$OUT" && chmod 777 "$OUT"
cp "$B"/out/*_table.csv "$B/out/load.sql" "$P/data/mt/" || stop "copy tables"
Q -c "CREATE DATABASE mt;" || stop "create database"
docker exec mtpids-postgres pg_dump -U postgres -s theia_e3 > /tmp/mt_schema.sql
docker exec -i mtpids-postgres psql -U postgres -q -d mt < /tmp/mt_schema.sql > /dev/null 2>&1
docker exec -w /data/mt mtpids-postgres psql -U postgres -d mt -q -v ON_ERROR_STOP=1 -f load.sql || stop "load"
rm -f /tmp/mt_schema.sql
for t in event_table file_node_table netflow_node_table subject_node_table; do
  st "COUNT $t $(Q -d mt -tAc "select count(*) from $t")"
done
fi

. "$VENV/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || stop "code"
st "START code $(git rev-parse --short HEAD 2>/dev/null || echo '?') stage $STAGE"
mkdir -p "$OUT" && chmod 777 "$A" "$OUT" || stop "artifact folders"

run_group() {  # group, dataset name, data, findings, split, params, half
  local g=$1 name=$2 data=$3 find=$4 split=$5 params=$6 half=${7:-score} t0=$(date +%s) nx
  docker exec -u pids -w /home/pids -e PYTHONPATH=/home/pids mtpids-app /opt/conda/envs/pids/bin/python \
      /home/artifacts/mt_construct.py orthrus "$name" --cpu --artifact_dir "$AD/" \
      > "$B/orthrus-graphs-$g.log" 2>&1 || stop "$g graphs (see orthrus-graphs-$g.log)"
  nx=$(cd "$A" && ls -d construction/"$name"/construction/*/nx)
  [ "$(echo "$nx" | wc -l)" = 1 ] || stop "$g: expected one graph directory, found: $nx"
  st "GRAPHS $g $(du -sh "$A/$nx" | cut -f1) in $(( $(date +%s) - t0 )) s"
  python -m mtcore.baselines.provenance.seeded seeds --conv "$B/out" --group "$g" --findings-from "$find" \
      --out "$OUT/seeds-$g.json" >> "$B/orthrus-$g.log" 2>&1 || stop "$g seeds (see orthrus-$g.log)"
  docker exec -u pids -w /home/artifacts -e PYTHONPATH=/home/artifacts/orthrus-src mtpids-app \
      /opt/conda/envs/pids/bin/python /home/artifacts/seeded_tracing.py --seeds "$AD/mt-full/seeds-$g.json" \
      --graphs "$AD/$nx" --orthrus-src /home/artifacts/orthrus-src --workers 6 \
      --out "$AD/mt-full/traced-$g.json" >> "$B/orthrus-$g.log" 2>&1 || stop "$g tracing (see orthrus-$g.log)"
  python -m mtcore.baselines.provenance.seeded records --conv "$B/out" --group "$g" --findings-from "$find" --k 10 \
      --traced "$OUT/traced-$g.json" --out-dir "$B/score-$g" >> "$B/orthrus-$g.log" 2>&1 || stop "$g records (see orthrus-$g.log)"
  python src/scripts/pilot/score_pilot.py --correlator sage --sage-variant ag --pilot "$data" --split "$split" \
      --half "$half" --stage "$STAGE" --params "$params" --findings-from "$find" --out-dir "$B/score-$g" \
      --workers "${WORKERS:-4}" >> "$B/orthrus-$g.log" 2>&1 || stop "$g score (see orthrus-$g.log)"
  if [ "$STAGE" = detect ]; then
    st "DETECTED_$g in $(( $(date +%s) - t0 )) s (not scored; truth not read)"
    return
  fi
  st "DONE_$g in $(( $(date +%s) - t0 )) s; $(python3 -c "
import json,sys
s=json.load(open('$OUT/seeds-$g.json')); t=json.load(open('$OUT/traced-$g.json'))
print(len(s),'runs',sum(len(v['seeds']) for v in s.values()),'seed findings',sum(v['seed_nodes_absent'] for v in t.values()),'seed nodes absent')"); $(grep "^Links:" "$B/score-$g/summary.md"); $(grep "^Paths:" "$B/score-$g/summary.md")"
}

for spec in $BGROUPS; do
  IFS=: read -r g name data find split params half <<< "$spec"
  run_group "$g" "$name" "$data" "$find" "$split" "$params" "$half"
done
st ALL_DONE
