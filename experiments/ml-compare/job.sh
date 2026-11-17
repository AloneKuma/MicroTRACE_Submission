#!/usr/bin/env bash
# ML model comparison, unattended (docs/plans/ml-model-compare-plan.md; rule RULE-modelcompare.md).
# On AWS it is started by mt-job.service (Terraform -var autorun=true) as ubuntu, with BUCKET,
# COMMIT and SESSION set; it needs nobody logged in. On the test host (dry run):
#
#   SKIP_BOOTSTRAP=1 AUTO_SHUTDOWN=0 NO_S3=1 DATA=<pilot dir> ML=~/microtrace-ml OUT=<dir> \
#   CODE=<checkout> RUNS=<folds subset json> DEADLINE=$(( $(date +%s) + 3*3600 )) bash job.sh
#
# Hard deadline: the machine's cost cap (/etc/mt-deadline, Terraform max_hours) ends it in any
# case. Soft deadline: before each stage the time left must cover the stage's budget plus 30 min,
# else the stage and all after it are skipped (DEADLINE_SKIP) and the report says so.
# Resumable: results/<session>/ is pulled back first and finished stages (done/<stage>) skip.
# Output: s3://$BUCKET/results/$SESSION/ (STATUS, REPORT.md, compare/, step1.json, step2.json,
# table/, logs/). The machine shuts down when this script exits (AUTO_SHUTDOWN=0 turns it off).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data/pilot_fit}; ML=${ML:-$HOME/ml}; OUT=${OUT:-$HOME/results}
WORKERS=${WORKERS:-24}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}; NO_S3=${NO_S3:-0}; SKIP_BOOTSTRAP=${SKIP_BOOTSTRAP:-0}
SESSION=${SESSION:-mlcompare}; R="s3://${BUCKET:-none}/results/$SESSION"
mkdir -p "$OUT/logs" "$OUT/done"; S=$OUT/STATUS; SKIPPED=""
exec >> "$OUT/logs/job.out" 2>&1        # everything this job prints is synced with the results
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
s3() { [ "$NO_S3" = 1 ] || aws "$@" < /dev/null; }

sync_up() {
  s3 s3 cp --only-show-errors "$S" "$R/STATUS"
  s3 s3 sync --only-show-errors --no-follow-symlinks "$OUT" "$R" --exclude STATUS --exclude "*.tmp" \
    --exclude "cached/*" --exclude "step2/*/runs/*/output.jsonl.gz"
}
report() {
  [ -f "$OUT/done/report" ] && return
  (cd "$CODE" && python src/scripts/pilot/model_compare.py report --compare "$OUT/compare/compare.json" \
     --step1 "$OUT/step1.json" --step2 "$OUT/step2.json" --out "$OUT/REPORT.md" --skipped "$SKIPPED") \
     >> "$OUT/logs/report.log" 2>&1 && status "REPORT written"
}
SAMPLER=""
finish() {
  rc=$?
  [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null
  command -v python > /dev/null && report
  status "END exit $rc"
  sync_up
  if [ "$AUTO_SHUTDOWN" = 1 ]; then status "SHUTDOWN after final copy"; sync_up; sudo shutdown -h now; fi
}
trap finish EXIT                       # first: every exit below copies results and shuts down

# Soft deadline (seconds since epoch): DEADLINE, else the machine's cost-cap file.
DL=${DEADLINE:-$(cat /etc/mt-deadline 2>/dev/null)}
case "$DL" in ''|*[!0-9]*) status "STOP no deadline (DEADLINE or /etc/mt-deadline)"; exit 1 ;; esac
need() {   # need <stage> <budget minutes>: 0 if there is time, else mark skipped
  local left=$(( DL - $(date +%s) ))
  if [ -n "$SKIPPED" ] || [ "$left" -lt $(( ($2 + 30) * 60 )) ]; then
    SKIPPED="$SKIPPED $1"; status "DEADLINE_SKIP $1 (left $((left / 60)) min, needs $2 + 30)"; return 1
  fi
}
done_() { touch "$OUT/done/$1"; sync_up; }
is_done() { [ -f "$OUT/done/$1" ]; }

s3 s3 sync --only-show-errors "$R" "$OUT" || true          # resume
status "START $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB, session $SESSION, deadline $(date -u -d @"$DL" +%FT%TZ)"

if [ "$SKIP_BOOTSTRAP" != 1 ]; then
  (MT_SKIP_SAGE=1 BUCKET=$BUCKET COMMIT=$COMMIT bash "$CODE/experiments/heldout/bootstrap.sh") > "$OUT/logs/bootstrap.log" 2>&1 \
    || { status "STOP bootstrap failed (logs/bootstrap.log)"; exit 1; }
  . "$HOME/mt-env.sh"
  . "$VENV/bin/activate" || { status "STOP venv $VENV"; exit 1; }   # mt-env.sh sets paths only
else
  . "${VENV:-$CODE/.venv}/bin/activate" || { status "STOP venv"; exit 1; }
  export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
fi
export PYTHONHASHSEED=1
command -v python > /dev/null || { status "STOP no python on PATH"; exit 1; }
RULE=$CODE/experiments/ml-compare/RULE-modelcompare.md
RULE_SHA=$(sha256sum "$RULE" | cut -c1-12)
status "CODE $(git -C "$CODE" rev-parse --short HEAD) rule $RULE_SHA workers $WORKERS"
(
  n=0
  while true; do
    echo "$(date -u +%T) avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo) load=$(cut -d' ' -f1 /proc/loadavg)" \
      >> "$OUT/logs/memory.log"
    n=$((n + 1)); [ $((n % 60)) -eq 0 ] && sync_up
    sleep 15
  done
) &
SAMPLER=$!
MC() { (cd "$CODE" && python src/scripts/pilot/model_compare.py "$@"); }
logged() { local tag=$1 out rc; shift; out=$(MC "$@"); rc=$?; status "$tag $out"; return $rc; }   # keeps MC's exit code

# ---- data: PILOT FIT runs and the cross-fit files, checked against their sums ----------------
if [ ! -f "$DATA/.fetched" ]; then           # a machine-local marker: a new machine fetches again
  if [ "$NO_S3" != 1 ]; then
    mkdir -p "$DATA" "$ML"
    s3 s3 sync --only-show-errors --no-follow-symlinks "s3://$BUCKET/dev/pilot-fit" "$DATA" || { status "STOP fetch pilot-fit"; exit 1; }
    s3 s3 sync --only-show-errors --no-follow-symlinks "s3://$BUCKET/dev/ml-crossfit" "$ML" || { status "STOP fetch ml-crossfit"; exit 1; }
    (cd "$DATA" && sha256sum --quiet -c SHA256SUMS) > "$OUT/logs/sums.log" 2>&1 || { status "STOP pilot-fit sums"; exit 1; }
    (cd "$ML" && sha256sum --quiet -c SHA256SUMS) >> "$OUT/logs/sums.log" 2>&1 || { status "STOP ml-crossfit sums"; exit 1; }
  fi
  # host paths in the fold configs -> this machine
  for f in "$ML"/cfg/*.yaml; do sed -i "s#/home/siit/microtrace-ml#$ML#g" "$f"; done
  if grep -l "/home/siit" "$ML"/cfg/*.yaml > /dev/null 2>&1 && [ "$ML" != /home/siit/microtrace-ml ]; then
    status "STOP fold configs still name /home/siit paths: $(grep -l /home/siit "$ML"/cfg/*.yaml | head -2)"; exit 1
  fi
  status "DATA $(find "$DATA" -mindepth 1 -maxdepth 1 -type d | wc -l) runs, $(du -sh "$DATA" | cut -f1); ml $(du -sh "$ML" | cut -f1)"
  touch "$DATA/.fetched"
fi
RUNS=${RUNS:-$ML/folds.json}                     # folds file (A, B, all); a subset for dry runs
for F in A B; do python3 -c "import json;d=json.load(open('$RUNS'));json.dump({'fit':d['$F']},open('$OUT/test$F.json','w'))"; done

# ---- step 0: the table run (rules-only findings with Isolation Forest scores) ----------------
if ! is_done table && need table 90; then
  mkdir -p "$OUT/cfg"
  for F in A B; do
    MC cfg --src "$ML/cfg/fold$F-qmax_g0.001.yaml" --out "$OUT/cfg/fold$F-score.yaml" --version "PILOT-CV-fold$F-mcscore" \
      || { status "STOP cfg $F"; exit 1; }
    status "RUN table fold $F"
    (cd "$CODE" && python src/scripts/pilot/score_pilot.py --pilot "$DATA" --split "$OUT/test$F.json" --half fit \
       --params "$OUT/cfg/fold$F-score.yaml" --out-dir "$OUT/raw" --workers "$WORKERS") > "$OUT/logs/raw-$F.log" 2>&1 \
      || { status "STOP score_pilot fold $F (logs/raw-$F.log)"; exit 1; }
  done
  logged CHECK check1 --raw "$OUT/raw" --ref "$ML/cv/qmax_gnone" --runs "$RUNS:all" \
    || { status "STOP C1 failed"; exit 1; }
  MC table --pilot "$DATA" --raw "$OUT/raw" --folds "$RUNS" --out-dir "$OUT/table" --workers "$WORKERS" \
    2> "$OUT/logs/table.log" || { status "STOP table (logs/table.log)"; exit 1; }
  logged CHECK check2 --table "$OUT/table" --ref "$ML/cv-veto/qmax_confirmB3" --models "$ML/models" \
    --folds "$RUNS" --runs "$RUNS:all" || { status "STOP C2 failed"; exit 1; }
  MC frozen-drops --table "$OUT/table" --models "$ML/models" --folds "$RUNS" --out "$OUT/frozen_drops.json" \
    >> "$S" || { status "STOP frozen-drops"; exit 1; }
  done_ table
fi

# ---- step 1: compare and select ------------------------------------------------------------
if is_done table && ! is_done compare && need compare 20; then
  MC compare --pilot "$DATA" --table "$OUT/table" --rows "$ML/rows" --models "$ML/models" --folds "$RUNS" \
    --out-dir "$OUT/compare" --rule-sha "$RULE_SHA" --workers 10 > "$OUT/logs/compare.log" 2>&1 \
    || { status "STOP compare (logs/compare.log)"; exit 1; }
  logged SELECT1 select1 --compare "$OUT/compare/compare.json" --out "$OUT/step1.json" \
    --frozen-drops "$OUT/frozen_drops.json" || { status "STOP select1"; exit 1; }
  done_ compare
fi

# ---- step 2: filter, replay GO, score; check C3; select -------------------------------------
if is_done compare && ! is_done step2 && need step2 45; then
  mapfile -t CONFIGS < <(python3 -c "import json;print('\n'.join(json.load(open('$OUT/step1.json'))['configs']))")
  for C in "${CONFIGS[@]}"; do
    MC filter --raw "$OUT/raw" --dropsets "$OUT/dropsets.json" --config "$C" --runs "$RUNS:all" \
      --out-dir "$OUT/cached/$C" --workers 8 >> "$OUT/logs/filter.log" 2>&1 || { status "STOP filter $C"; exit 1; }
  done
  rm -rf "$OUT/shards"; mkdir -p "$OUT/shards"
  python3 - "$RUNS" "$OUT/shards" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for F in ("A", "B"):
    for i in range(0, len(d[F]), 4):
        json.dump({"score": d[F][i:i + 4]}, open(f"{sys.argv[2]}/{F}-{i // 4:03d}.json", "w"))
PY
  : > "$OUT/logs/replay.jobs"
  for C in "${CONFIGS[@]}"; do for sh in "$OUT"/shards/*.json; do
    F=$(basename "$sh" | cut -c1); echo "$C $F $sh" >> "$OUT/logs/replay.jobs"
  done; done
  status "RUN replay $(wc -l < "$OUT/logs/replay.jobs") shards for ${#CONFIGS[@]} configs"
  export CODE DATA OUT
  xargs -P "$WORKERS" -L 1 bash -c 'cd "$CODE" && python src/scripts/pilot/replay_scores.py "$DATA" "$OUT/cached/$0" \
      --params "$OUT/cfg/fold$1-score.yaml" --split "$2" --out-dir "$OUT/step2/$0" \
      > "$OUT/logs/replay-$0-$(basename "$2" .json).log" 2>&1' < "$OUT/logs/replay.jobs" \
    || { status "STOP replay (logs/replay-*.log)"; exit 1; }
  logged CHECK check3 --none "$OUT/step2/none" --frozen "$OUT/step2/frozen" --ref-none "$ML/cv/qmax_gnone" \
    --ref-frozen "$ML/cv-veto/qmax_confirmB3" --runs "$RUNS:all" || { status "STOP C3 failed"; exit 1; }
  logged SELECT2 select2 --step1 "$OUT/step1.json" --step2-dir "$OUT/step2" --runs "$RUNS:all" \
    --out "$OUT/step2.json" || { status "STOP select2"; exit 1; }
  rm -rf "$OUT/cached"
  done_ step2
fi

report && done_ report
if [ -n "$SKIPPED" ]; then status "PARTIAL skipped:$SKIPPED"; else status "ALL_DONE"; fi
