#!/usr/bin/env bash
# Build, verify, seal and upload the held-out sets on the test host, one batch at a time
# (docs/plans/heldout-aws-plan.md step 4; build plan phase 8). For each batch:
#   1. a batch matrix = the frozen matrix with a slice of its runs (same header, same seeds)
#   2. src/scripts/pilot/run_pilot.py builds and verifies the runs (generator verification,
#      phase 4). Its logs and reports are truth-derived: they go to the sealed side
#      (heldout/truth/<set>/_build/<batch>/); only counts and pass/fail are printed here.
#   3. experiments/heldout/upload_batch.sh splits, uploads and checks every run, then deletes it
# A failed verification stops the job (fixes only by a declared generator bug fix, applied to
# all splits). Resumable: finished batches are marked in $W/done/. The uploader credentials are
# re-read from ~/.mt-uploader.env before every batch (refresh it before it expires).
# HOLD_BATCHES="held_out-04 ..." skips those batches and leaves their folders untouched. A batch
# starts only with MIN_FREE_GB (default 50) free: a 70-run HELD_OUT batch is ~34 GB, a 30-run
# HELD_OUT-cases batch ~39 GB (2026-11-11: a batch filled the shared disk; guard added).
#
#   CODE=<repo checkout> BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> \
#     nohup bash build_heldout.sh > build.log 2>&1 &
set -uo pipefail
: "${CODE:?}" "${BUCKET:?}" "${HELDOUT_BUCKET:?}"
W=${W:-$HOME/microtrace-heldout-build}; VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}
WORKERS=${WORKERS:-3}; VWORKERS=${VWORKERS:-2}
# set:batch size:matrix[,matrix]   (held_out runs ~0.5 GB, held_out_cases ~1.3 GB)
SETS=${SETS:-"held_out:70:spec/generator/run-matrix.held_out.yaml held_out_cases:30:spec/generator/run-matrix.held_out-cases.yaml,spec/generator/run-matrix.held_out-cases-tactic.yaml"}
mkdir -p "$W/done" "$W/matrices" "$W/reports"
st() { echo "$(date -u +%FT%TZ) $*"; }
. "$VENV/bin/activate" || { st "STOP venv"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1
cd "$CODE" || exit 1
st "START code $(git rev-parse --short HEAD), $(df -h ~ | awk 'END {print $4}') free"

for spec in $SETS; do
  IFS=: read -r set size mats <<< "$spec"
  # Batch matrices (deterministic slices of the frozen matrices; each keeps its own header).
  python3 - "$W/matrices" "$set" "$size" ${mats//,/ } <<'PY' || { st "STOP batch matrices $set"; exit 1; }
import os, sys, yaml
out, sset, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
k = 0
for path in sys.argv[4:]:
    m = yaml.safe_load(open(path))
    runs = m["runs"]
    for i in range(0, len(runs), size):
        k += 1
        b = dict(m, runs=runs[i:i + size])
        b["description"] = f"{sset} batch {k}: runs {i + 1}-{i + len(b['runs'])} of {path} (slice of the frozen matrix)"
        with open(os.path.join(out, f"{sset}-{k:02d}.yaml"), "w") as fh:
            yaml.safe_dump(b, fh, sort_keys=False)
print(k)
PY
  for bm in "$W/matrices/$set"-*.yaml; do
    batch=$(basename "$bm" .yaml)
    [ -f "$W/done/$batch" ] && { st "SKIP $batch (done)"; continue; }
    case " ${HOLD_BATCHES:-} " in *" $batch "*) st "HOLD $batch (held back, left as is)"; continue;; esac
    . "$HOME/.mt-uploader.env"
    aws sts get-caller-identity > /dev/null 2>&1 || { st "STOP uploader credentials expired: refresh ~/.mt-uploader.env and rerun"; exit 1; }
    # A fresh reports folder per attempt (a rerun after a failed attempt otherwise cannot move
    # its new _logs over the old one, and the logs stay in the batch folder: 2026-11-12).
    B=$W/batch/$batch; R=$W/reports/$batch; rm -rf "$R"; mkdir -p "$B" "$R"
    want=$(python3 -c "import yaml,sys;print(len(yaml.safe_load(open(sys.argv[1]))['runs']))" "$bm")
    free=$(df -BG --output=avail ~ | tail -1 | tr -dc 0-9)
    if [ "$free" -lt "${MIN_FREE_GB:-50}" ]; then
      st "STOP $batch: only ${free} GB free (need ${MIN_FREE_GB:-50}; the host disk is shared)"; exit 1
    fi
    st "BUILD $batch: $want runs, $(df -h ~ | awk 'END {print $4}') free"
    t0=$(date +%s)
    python src/scripts/pilot/run_pilot.py --matrix "$bm" --out "$B" --workers "$WORKERS" --verify-workers "$VWORKERS" \
      < /dev/null > "$R/run_pilot.log" 2>&1
    rc=$?
    # Only counts and pass/fail leave the sealed reports.
    read -r built passed overall <<< "$(python3 - "$B" <<'PY'
import json, os, sys
b = sys.argv[1]
runs = [d for d in os.listdir(b) if os.path.exists(os.path.join(b, d, "manifest.json"))]
v = json.load(open(os.path.join(b, "verify_results.json"))) if os.path.exists(os.path.join(b, "verify_results.json")) else {}
ok = sum(1 for r in v.get("runs", {}).values() if r.get("passed"))
print(len(runs), ok, v.get("overall_pass"))
PY
)"
    st "BUILT $batch: exit $rc, $built of $want runs, verify passed $passed, overall $overall, $(( ($(date +%s) - t0) / 60 )) min"
    for f in "$B"/_logs "$B"/*.json; do [ -e "$f" ] && mv "$f" "$R/"; done
    if [ "$rc" != 0 ] || [ "$built" != "$want" ] || [ "$passed" != "$want" ] || [ "$overall" != True ]; then
      st "STOP $batch failed build or verification (details sealed in $R; nothing uploaded)"; exit 1
    fi
    aws s3 sync --only-show-errors --no-follow-symlinks "$R" "s3://$HELDOUT_BUCKET/heldout/truth/$set/_build/$batch/" < /dev/null \
      || { st "STOP $batch report upload"; exit 1; }
    HELDOUT_BUCKET=$HELDOUT_BUCKET SET=$set SRC=$B CODE=$CODE VENV=$VENV DELETE=1 \
      bash "$CODE/experiments/heldout/upload_batch.sh" < /dev/null > "$W/upload-$batch.log" 2>&1 \
      || { st "STOP $batch upload ($(tail -1 "$B/UPLOAD_STATUS"))"; exit 1; }
    left=$(find "$B" -mindepth 1 -maxdepth 1 -type d ! -name '.seal' | wc -l)
    [ "$left" = 0 ] || { st "STOP $batch: $left run folders left after upload"; exit 1; }
    st "UPLOADED $batch: $(tail -1 "$B/UPLOAD_STATUS" | cut -d' ' -f2-)"
    rm -rf "$B" "$R"; touch "$W/done/$batch"
  done
done
st "BUILD_DONE${HOLD_BATCHES:+ (held: $HOLD_BATCHES)} $(df -h ~ | awk 'END {print $4}') free"
