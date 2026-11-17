#!/usr/bin/env bash
# Exp. 4 runner: archived-finding replay of the GO configurations and the ORTHRUS timing steps, one
# timing session (docs/plans/heldout-aws-plan.md section 8, T1-T5; evaluation-plan.md section 4 row 4).
# Core logic: src/python/mtcore/harness/exp4.py. Settings: configs.tsv, workloads.tsv, caps.tsv,
# commands.tsv and the pass list (PASSES), all in this folder; PROPOSED values in
# docs/plans/exp4-runner-worklog.md section 4.
#
# AWS (timing session, on-demand m7i.8xlarge, after bootstrap.sh):
#   . ~/mt-env.sh; BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> SESSION=<name> ANALYSIS=heldout-a \
#     nohup bash experiments/exp4/run_exp4.sh > exp4.out 2>&1 &
# Local (development data only, no AWS, no S3, no shutdown):
#   MODE=local CODE=<repo> OUT=<dir> RUNS_DIR=<runs> FINDINGS_DIR=<archived outputs> \
#     RUN_LIST=<id,id,..> | SPLIT=<split.json> HALF=<key>  PASSES=experiments/exp4/passes.local.tsv \
#     bash experiments/exp4/run_exp4.sh
#
# Steps (exp4.py plan): "prep" (untimed setup of command units), "accuracy" (every unit once: the
# accuracy outputs and, for timed units, the one untimed warm-up; ORTHRUS training timed once there),
# then rep1..rep$REPEATS (timed units only, order rotated by one per repeat). Every GO step is one
# configuration on one workload, its units in WORKERS parallel processes, each under its time cap.
# Accuracy steps keep the GO output (for path recall and link-set checks); timed repeats keep stats
# and digests only. Then exp4.py score writes exp4_summary.{json,tsv} (no truth is read anywhere).
#
# Resumable: $OUT/timing.tsv lists finished steps (exit 0; a capped unit or command is a result, not
# a failure). On AWS the results folder is pulled back from S3 first. An unfinished timed step is
# rerun from scratch (its time must be one uninterrupted pass); an unfinished accuracy step keeps its
# finished units. Output (AWS: s3://$BUCKET/results/$SESSION/): STATUS, timing.tsv, plan.json,
# passes/<step>/, logs/, exp4_summary.{json,tsv}.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=${MODE:-aws}
CODE=${CODE:-$HOME/code}; OUT=${OUT:-$HOME/exp4}; VENV=${VENV:-$CODE/.venv}
X=${SETTINGS:-$CODE/experiments/exp4}                  # the committed settings of the code being run
PASSES=${PASSES:-$X/passes.aws.tsv}; CONFIGS=${CONFIGS:-$X/configs.tsv}
WORKLOADS=${WORKLOADS:-$X/workloads.tsv}; CAPS=${CAPS:-$X/caps.tsv}; COMMANDS=${COMMANDS:-$X/commands.tsv}
PARAMS=${PARAMS:-src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml}   # go_main's file (the archive's)
CACHE=${CACHE:-$OUT/cache}; CACHE_WORKERS=${CACHE_WORKERS:-8}
REPEATS=${REPEATS:-3}; CHECK_ARCHIVE=${CHECK_ARCHIVE:-1}; ARCHIVE_CONFIG=${ARCHIVE_CONFIG:-full}
PY=${PYTHON:-python3}
abspath() { (cd "$(dirname "$1")" && echo "$(pwd)/$(basename "$1")"); }
PASSES=$(abspath "$PASSES"); CONFIGS=$(abspath "$CONFIGS"); WORKLOADS=$(abspath "$WORKLOADS")
CAPS=$(abspath "$CAPS"); COMMANDS=$(abspath "$COMMANDS")
case "$PARAMS" in /*|[A-Za-z]:*) ;; *) PARAMS=$CODE/$PARAMS ;; esac

if [ "$MODE" = aws ]; then
  : "${BUCKET:?set BUCKET}" "${HELDOUT_BUCKET:?set HELDOUT_BUCKET}" "${SESSION:?set SESSION}" "${ANALYSIS:?set ANALYSIS}"
  SET=${SET:-held_out}; FINDINGS_PASS=${FINDINGS_PASS:-go_main}; DATA=${DATA:-$HOME/data}
  RUNS_DIR=$DATA/$SET; FINDINGS_DIR=$DATA/findings/$FINDINGS_PASS
  SPLIT=${SPLIT:-$CODE/experiments/heldout/splits/$SET.json}; HALF=${HALF:-$SET}; RUN_LIST=""
  AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}; R="s3://$BUCKET/results/$SESSION"
elif [ "$MODE" = local ]; then
  : "${RUNS_DIR:?set RUNS_DIR}" "${FINDINGS_DIR:?set FINDINGS_DIR}"
  RUN_LIST=${RUN_LIST:-}; SPLIT=${SPLIT:-}; HALF=${HALF:-}
  [ -n "$RUN_LIST" ] || { [ -n "$SPLIT" ] && [ -n "$HALF" ]; } || { echo "set RUN_LIST or SPLIT and HALF"; exit 1; }
  AUTO_SHUTDOWN=0
else
  echo "MODE must be aws or local"; exit 1
fi
mkdir -p "$OUT/logs" "$OUT/passes"; S=$OUT/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }

# Prerequisites (no shutdown on these: fix and rerun).
if [ -f "$VENV/bin/activate" ]; then . "$VENV/bin/activate"; elif [ "$MODE" = aws ]; then status "FAILED venv $VENV"; exit 1; fi
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
[ -d "$CODE/src/python/gen/microtrace/v0" ] || { status "FAILED no generated protobuf code (bootstrap.sh)"; exit 1; }
if [ "$MODE" = aws ]; then
  [ -x /usr/bin/time ] || { status "FAILED /usr/bin/time missing: CPU and memory would not be recorded"; exit 1; }
  [ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || { status "FAILED code tree has local changes"; exit 1; }
  aws s3 sync --only-show-errors "$R" "$OUT" < /dev/null || true          # resume after an interruption
fi
sync_up() {
  [ "$MODE" = aws ] || return 0
  aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null
  [ -f "$OUT/timing.tsv" ] && aws s3 cp --only-show-errors "$OUT/timing.tsv" "$R/timing.tsv" < /dev/null
  aws s3 sync --only-show-errors --no-follow-symlinks "$OUT" "$R" --exclude "STATUS" --exclude "timing.tsv" \
    --exclude "*.tmp" --exclude "cache/*" < /dev/null
}
SAMPLER=""
if [ -r /proc/meminfo ]; then
  (
    n=0
    while true; do
      echo "$(date -u +%T) avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)" \
           "load=$(cut -d' ' -f1 /proc/loadavg)" \
           "max_py_rss_mb=$(ps -C python,python3 -o rss= 2>/dev/null | sort -n | tail -1 | awk '{print int($1/1024)}')" \
           >> "$OUT/logs/memory.log"
      n=$((n + 1)); [ $((n % 60)) -eq 0 ] && sync_up
      sleep 15
    done
  ) &
  SAMPLER=$!
fi
finish() {
  [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null
  sync_up
  if [ "$AUTO_SHUTDOWN" = 1 ]; then status "SHUTDOWN after final copy"; sync_up; sudo shutdown -h now; fi
}
trap finish EXIT

status "START mode $MODE, $(nproc 2>/dev/null || echo ?) cpu, code $(git -C "$CODE" rev-parse --short HEAD 2>/dev/null)," \
       "passes $PASSES ($(sha256sum "$PASSES" | cut -c1-12)), configs $(sha256sum "$CONFIGS" | cut -c1-12)," \
       "workloads $(sha256sum "$WORKLOADS" | cut -c1-12), caps $(sha256sum "$CAPS" | cut -c1-12)," \
       "commands $(sha256sum "$COMMANDS" | cut -c1-12), params $(sha256sum "$PARAMS" | cut -c1-12), repeats $REPEATS," \
       "clock $(tail -1 /var/log/mt-clock.txt 2>/dev/null)"

if [ "$MODE" = aws ]; then
  # The seal: this role may list heldout/truth/ but must not read it (as run_analysis_aws.sh). Exp. 4
  # reads no truth at all; the check only proves this machine could not have.
  list=$(aws s3api list-objects-v2 --bucket "$HELDOUT_BUCKET" --prefix heldout/truth/ --max-keys 1 --no-paginate \
           --query 'Contents[0].Key' --output text < /dev/null 2>&1) || { status "FAILED seal check: cannot list ($list)"; exit 1; }
  if [ "$list" = None ] || [ -z "$list" ]; then status "FAILED seal check: no truth objects listed (wrong bucket?)"; exit 1; fi
  err=$(aws s3api get-object --bucket "$HELDOUT_BUCKET" --key "$list" /dev/null < /dev/null 2>&1 >/dev/null)
  case "$err" in
    *AccessDenied*) status "SEAL ok: truth not readable here (AccessDenied)" ;;
    "") status "FAILED seal: this machine can read $list"; exit 1 ;;
    *) status "FAILED seal check inconclusive: $err"; exit 1 ;;
  esac
  # The held-out runs (readable part), checked against the frozen manifest.
  if [ ! -f "$DATA/.fetched-$SET" ]; then
    aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$SET" "$RUNS_DIR" < /dev/null \
      || { status "FAILED fetch $SET"; exit 1; }
    bash "$CODE/experiments/heldout/check_fetch.sh" "$RUNS_DIR" "$CODE/experiments/heldout/manifests/$SET.tsv" "$CODE" >> "$S" 2>&1 \
      || { status "FAILED $SET does not match manifests/$SET.tsv"; exit 1; }
    touch "$DATA/.fetched-$SET"
  fi
  # The archive: the analysis session's finished findings pass (every run, exit 0 in its timing.tsv).
  n=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))[sys.argv[2]]))" "$SPLIT" "$HALF")
  aws s3 cp --only-show-errors "s3://$BUCKET/results/$ANALYSIS/timing.tsv" - < /dev/null 2>/dev/null \
    | awk -F'\t' -v p="$FINDINGS_PASS" -v n="$n" '$1 == p && $2 == 0 && $4 == n { ok = 1 } END { exit !ok }' \
    || { status "FAILED $ANALYSIS/$FINDINGS_PASS is not a finished pass over $n runs"; exit 1; }
  if [ ! -f "$DATA/.fetched-findings-$FINDINGS_PASS" ]; then
    aws s3 sync --only-show-errors "s3://$BUCKET/results/$ANALYSIS/$FINDINGS_PASS/runs" "$FINDINGS_DIR/runs" \
      --exclude '*' --include '*/output.jsonl.gz' --include '*/time.json' < /dev/null || { status "FAILED fetch findings"; exit 1; }
    got=$(find "$FINDINGS_DIR/runs" -mindepth 2 -maxdepth 2 -name output.jsonl.gz | wc -l)
    [ "$got" = "$n" ] || { status "FAILED findings $FINDINGS_PASS: $got outputs, expected $n"; exit 1; }
    touch "$DATA/.fetched-findings-$FINDINGS_PASS"
  fi
  status "DATA $SET $(find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l) runs, findings $FINDINGS_PASS $n runs"
  sync_up
fi

# The plan: every name and cap checked before any work starts.
(cd "$CODE/src/python" && $PY -m mtcore.harness.exp4 plan --passes "$PASSES" --repeats "$REPEATS" --configs "$CONFIGS" \
   --workloads "$WORKLOADS" --caps "$CAPS" --commands "$COMMANDS" --out "$OUT/plan.json" > "$OUT/logs/plan.log" 2>&1) \
  || { status "FAILED plan ($(tail -1 "$OUT/logs/plan.log"))"; exit 1; }
mapfile -t STEPS < <($PY - "$OUT/plan.json" <<'PY'
import json, sys
for s in json.load(open(sys.argv[1])):
    print("\t".join(str(s.get(k, "")) for k in ("step", "phase", "rep", "unit", "system", "config", "workload",
                                                 "workers", "action", "timed", "cap_s", "cmd")))
PY
)
status "PLAN ${#STEPS[@]} steps; rotation $($PY -c "
import json, sys; sys.path.insert(0, sys.argv[2])
from mtcore.harness.exp4 import rotation
print(json.dumps(rotation(json.load(open(sys.argv[1])))))" "$OUT/plan.json" "$CODE/src/python")"

run_args=()
if [ -n "$RUN_LIST" ]; then run_args=(--run-list "$RUN_LIST"); else run_args=(--split "$SPLIT" --half "$HALF"); fi
# Untimed prep: every run's GO inputs and archived findings decoded once into a binary cache (the JSON
# parse is ~30x the GO's own time and the same for every configuration; same envelopes, same order).
status "CACHE start ($CACHE_WORKERS workers)"
(cd "$CODE/src/python" && $PY -m mtcore.harness.exp4 cache --runs-dir "$RUNS_DIR" --findings-dir "$FINDINGS_DIR" \
   "${run_args[@]}" --cache "$CACHE" --workers "$CACHE_WORKERS" < /dev/null) > "$OUT/logs/cache.log" 2>&1 \
  || { status "FAILED cache (logs/cache.log: $(grep -c FAILED "$OUT/logs/cache.log") runs)"; exit 1; }
status "CACHE done $(du -sh "$CACHE" 2>/dev/null | cut -f1)"

T=$OUT/timing.tsv
[ -f "$T" ] || printf 'step\tphase\trep\tunit\tsystem\tconfig\tworkload\tworkers\ttimed\texit\twall_s\tunits\tfinished\tcapped\tsum_unit_wall_s\tsum_unit_cpu_s\tmax_unit_rss_mb\tgo_seconds\tfindings\tpairs_tested\tnote\n' > "$T"
failed=0
for line in "${STEPS[@]}"; do
  IFS=$'\t' read -r step phase rep unit system config workload workers action timed cap cmd <<< "$line"
  if awk -F'\t' -v s="$step" '$1 == s && $10 == 0' "$T" | grep -q .; then status "SKIP $step (done)"; continue; fi
  d=$OUT/passes/$step
  [ "$timed" = True ] && rm -rf "$d"                # a timed step is one uninterrupted pass
  status "RUN $step: $system $config ${workload:+on $workload} ($action, timed $timed, cap ${cap}s)"
  t0=$(date +%s.%N)
  if [ "$system" = go ]; then
    a=(pass --runs-dir "$RUNS_DIR" --findings-dir "$FINDINGS_DIR" "${run_args[@]}" --params "$PARAMS"
       --configs "$CONFIGS" --config "$config" --workloads "$WORKLOADS" --workload "$workload" --caps "$CAPS"
       --workers "${workers:-8}" --cache "$CACHE" --out "$d")
    [ "$phase" = accuracy ] && a+=(--keep-output)
    [ "$phase" = accuracy ] && [ "$CHECK_ARCHIVE" = 1 ] && [ "$config" = "$ARCHIVE_CONFIG" ] && a+=(--check-archive)
    (cd "$CODE/src/python" && $PY -m mtcore.harness.exp4 "${a[@]}" < /dev/null) > "$OUT/logs/$step.log" 2>&1
    rc=$?
  else
    (cd "$CODE/src/python" && CODE=$CODE OUT=$OUT STEP=$step REP=$rep $PY -m mtcore.harness.exp4 cmdstep \
       --cmd "$cmd" --cap "$cap" --cwd "$CODE" --name "$config" --out "$d" < /dev/null) > "$OUT/logs/$step.log" 2>&1
    rc=$?; [ "$rc" = 5 ] && rc=0                      # capped: a result (recorded in time.json), not a failure
  fi
  wall=$($PY -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 1))" "$t0" "$(date +%s.%N)")
  $PY - "$d" "$line" "$rc" "$wall" >> "$T" < /dev/null <<'PY'
import json, os, sys
d, line, rc, wall = sys.argv[1:]
step, phase, rep, unit, system, config, workload, workers, action, timed, cap = line.split("\t")[:11]
row = [step, phase, rep, unit, system, config, workload or "-", workers or "-", timed, rc, wall]
p, t = os.path.join(d, "pass.json"), os.path.join(d, "time.json")
if system == "go" and os.path.exists(p):
    s = json.load(open(p))
    row += [s["units"], s["finished"], len(s["capped"]), s["sum_unit_wall_s"], s["sum_unit_cpu_s"], s["max_unit_rss_mb"],
            s["go_seconds"], s["findings"], s["pairs_tested"], f"failed {len(s['failed'])}" if s["failed"] else ""]
elif os.path.exists(t):
    s = json.load(open(t))
    cpu = s["cpu_user_s"] + s["cpu_sys_s"] if s.get("cpu_user_s") is not None and s.get("cpu_sys_s") is not None else None
    row += [1, int(s["exit"] == 0 and not s["capped"]), int(bool(s["capped"])), s["wall_s"], cpu, s.get("peak_rss_mb"),
            "-", "-", "-", action]
else:
    row += ["-"] * 9 + ["no result"]
print("\t".join("-" if x is None else str(x) for x in row))
PY
  [ "$rc" = 0 ] || failed=$((failed + 1))
  status "DONE $step exit $rc in ${wall}s"
  sync_up
done

(cd "$CODE/src/python" && $PY -m mtcore.harness.exp4 score --session "$OUT" --plan-json "$OUT/plan.json" --params "$PARAMS" \
   > "$OUT/logs/score.log" 2>&1) && status "SCORED exp4_summary.tsv" || { status "FAILED score (logs/score.log)"; failed=$((failed + 1)); }
if [ "$failed" -gt 0 ]; then status "FAILED_STEPS $failed"; exit 1; fi
status "ALL_DONE"
