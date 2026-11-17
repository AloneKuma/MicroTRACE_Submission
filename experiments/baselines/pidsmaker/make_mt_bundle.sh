#!/usr/bin/env bash
# The data run_mt_aws.sh needs, built where database mt is loaded (run_seeded_orthrus.sh
# loads it and registers the datasets). Writes $OUT (default ~/microtrace-b3/mt-bundle/):
#   mt.dump              pg_dump -Fc of database mt
#   mt_datasets.json     the $DATASETS entries of PIDSMaker's registry
#   ground_truth.tar.gz  $CONV/ground_truth (placeholder files for sealed sets: convert.py --sealed)
#   sealed.txt           the datasets in $SEALED (their truth is not in the bundle)
#   counts.tsv           row count of each table, checked after the restore on AWS
#   SHA256SUMS
# Nothing here reads truth beyond copying the files PIDSMaker's own reports use; for a
# sealed set those files are placeholders, so the bundle holds no held-out truth.
#
#   bash make_mt_bundle.sh                                     # development: MT_PILOT, MT_CASES
#   DATASETS="MT_HELD_OUT MT_HELD_OUT_CASES" SEALED="MT_HELD_OUT MT_HELD_OUT_CASES" \
#     CONV=<conversion out> OUT=<bundle dir> CHECK_STATUS=0 bash make_mt_bundle.sh
set -euo pipefail
P=${P:-$HOME/microtrace-baselines/pidsmaker}; CONV=${CONV:-$HOME/microtrace-convert/out}
OUT=${OUT:-$HOME/microtrace-b3/mt-bundle}
DATASETS=${DATASETS:-"MT_PILOT MT_CASES"}; SEALED=${SEALED:-}
if [ "${CHECK_STATUS:-1}" = 1 ]; then
  grep -q "COUNT subject_node_table" "$HOME/microtrace-convert/ORTHRUS_STATUS" \
    || { echo "database mt is not loaded yet (ORTHRUS_STATUS)"; exit 1; }
fi
for s in $SEALED; do
  case " $DATASETS " in *" $s "*) ;; *) echo "sealed $s is not in DATASETS"; exit 1;; esac
done
python3 - "$CONV/manifest.json" $SEALED <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
want = {s.split("_", 1)[1].lower() for s in sys.argv[2:]}      # MT_HELD_OUT -> held_out
missing = want - set(m.get("sealed", []))
if missing:
    sys.exit(f"conversion did not seal {sorted(missing)} (convert.py --sealed); refusing to bundle its truth")
PY
mkdir -p "$OUT"
docker exec mtpids-postgres pg_dump -U postgres -Fc -d mt -f /tmp/mt.dump
docker cp mtpids-postgres:/tmp/mt.dump "$OUT/mt.dump"
docker exec mtpids-postgres rm -f /tmp/mt.dump
: > "$OUT/counts.tsv"
for t in event_table file_node_table netflow_node_table subject_node_table; do
  echo -e "$t\t$(docker exec mtpids-postgres psql -U postgres -d mt -tAc "SELECT count(*) FROM $t")" >> "$OUT/counts.tsv"
done
python3 - "$P/PIDSMaker/pidsmaker/config/mt_datasets.json" "$OUT/mt_datasets.json" $DATASETS <<'PY'
import json, sys
reg = json.load(open(sys.argv[1]))
out = {k: reg[k] for k in sys.argv[3:]}
for k, v in out.items():
    assert v["database"] == "mt" and v["val_dates"] and len(v["attack_to_time_window"]) == len(v["test_dates"]), k
json.dump(out, open(sys.argv[2], "w"), indent=2)
print({k: (len(v["train_dates"]), len(v["val_dates"]), len(v["test_dates"])) for k, v in out.items()})
PY
echo "$SEALED" | xargs -n1 2>/dev/null > "$OUT/sealed.txt" || : > "$OUT/sealed.txt"
tar czf "$OUT/ground_truth.tar.gz" -C "$CONV/ground_truth" .
(cd "$OUT" && sha256sum mt.dump mt_datasets.json ground_truth.tar.gz sealed.txt counts.tsv > SHA256SUMS)
cat "$OUT/counts.tsv"; du -sh "$OUT"/*
