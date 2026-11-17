#!/usr/bin/env bash
# ORTHRUS steps of the Exp. 4 timing session (T1, T4), called by run_exp4.sh through commands.tsv:
#
#   orthrus_step.sh prep     untimed: run_baselines_aws.sh steps 1-4 for the one set (FIT and held-out
#                            data, conversion --sealed, database mt, PIDSMaker tree, containers, bundle),
#                            STOP_AFTER=bundle, so no KAIROS and no training happen there
#   orthrus_step.sh train    timed once (T4): PIDSMaker orthrus on MT_<SET> with the frozen MT_ARGS in a
#                            fresh artifact folder (artifacts/exp4), then mt_detected.py (flagged nodes)
#   orthrus_step.sh detect   timed, warm-up + repeats: ORTHRUS_DETECT_CMD (see the worklog, open
#                            question on what "detection only" means inside PIDSMaker); refuses to run
#                            while it is unset, so no step is timed under a guessed definition
#
# The work runs inside the mtpids-app container, where /usr/bin/time around `docker exec` would see
# only the client, so this script measures the step itself and writes wall seconds, CPU user and system
# seconds (the container cgroup's cpu.stat before and after) and peak memory (largest cgroup
# memory.current, sampled every 5 s) to $EXP4_STEP_JSON, which exp4.py cmdstep takes over.
set -uo pipefail
action=${1:?prep, train or detect}
CODE=${CODE:-$HOME/code}; W=${W:-$HOME/pidsmaker}; SET=${SET:-held_out}
PARAMS=${PARAMS:-src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml}
DS="MT_$(echo "$SET" | tr a-z A-Z)"
PY=/opt/conda/envs/pids/bin/python
MT_ARGS="--training.deterministic=True"           # as run_mt_aws.sh (decided 2026-11-01)
ADIR=/home/artifacts/exp4/

cg() { docker exec mtpids-app cat "/sys/fs/cgroup/$1" 2>/dev/null; }
usec() { cg cpu.stat | awk -v k="$1" '$1 == k {print $2}'; }
measured() {   # run "$@" in the container's work; write $EXP4_STEP_JSON
  local u0 s0 t0 rc peakf=$(mktemp)
  u0=$(usec user_usec); s0=$(usec system_usec); t0=$(date +%s.%N)
  ( m=0; while :; do c=$(cg memory.current); [ -n "$c" ] && [ "$c" -gt "$m" ] && m=$c && echo "$m" > "$peakf"; sleep 5; done ) &
  local sampler=$!
  "$@"; rc=$?
  kill $sampler 2>/dev/null
  local u1 s1 t1; u1=$(usec user_usec); s1=$(usec system_usec); t1=$(date +%s.%N)
  python3 - "$t0" "$t1" "${u0:-}" "${u1:-}" "${s0:-}" "${s1:-}" "$(cat "$peakf" 2>/dev/null)" > "${EXP4_STEP_JSON:-/dev/stdout}" <<'PY'
import json, sys
t0, t1, u0, u1, s0, s1, peak = sys.argv[1:]
num = lambda a, b: round((int(b) - int(a)) / 1e6, 3) if a and b else None  # noqa: E731
print(json.dumps({"wall_s": round(float(t1) - float(t0), 3), "cpu_user_s": num(u0, u1), "cpu_sys_s": num(s0, s1),
                  "peak_rss_mb": round(int(peak) / 1048576, 1) if peak else None,
                  "measured_by": "container cgroup (cpu.stat, memory.current)"}))
PY
  rm -f "$peakf"
  return $rc
}

case "$action" in
  prep)
    : "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${SESSION:?}" "${ANALYSIS:?}"
    SETS="$SET:${FINDINGS_PASS:-go_main}:$PARAMS" STOP_AFTER=bundle AUTO_SHUTDOWN=0 W=$W \
      bash "$CODE/experiments/heldout/run_baselines_aws.sh"
    ;;
  train)
    docker exec mtpids-app true || { echo "container mtpids-app not running (prep first)"; exit 1; }
    mkdir -p "$W/artifacts/exp4" && chmod 777 "$W/artifacts/exp4"
    cp "$W/mt_detected.py" "$W/PIDSMaker/" || exit 1                 # as run_mt_aws.sh
    measured docker exec -u pids -w /home/pids mtpids-app $PY pidsmaker/main.py orthrus "$DS" $MT_ARGS --artifact_dir "$ADIR" \
      || exit $?
    # The epoch choice and flagged nodes (validation loss only; no test metric is read), untimed.
    docker exec -u pids -w /home/pids -e MT_OUT="/home/artifacts/mt-results/exp4_orthrus" mtpids-app \
      $PY mt_detected.py orthrus "$DS" $MT_ARGS --artifact_dir "$ADIR"
    ;;
  detect)
    # Q2 option (c), user 2026-11-16: ORTHRUS training (which includes PIDSMaker's test inference)
    # is timed once; detection is not timed separately. ORTHRUS_DETECT_CMD=none makes this a no-op.
    if [ "${ORTHRUS_DETECT_CMD:-}" = none ]; then echo "detection not timed separately (Q2 option c)"; exit 0; fi
    [ -n "${ORTHRUS_DETECT_CMD:-}" ] || { echo "ORTHRUS_DETECT_CMD is not set: the detection-only step is an open question (docs/plans/exp4-runner-worklog.md)"; exit 2; }
    measured bash -c "$ORTHRUS_DETECT_CMD"
    ;;
  *) echo "unknown action $action"; exit 2 ;;
esac
