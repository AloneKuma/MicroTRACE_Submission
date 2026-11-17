#!/usr/bin/env bash
# Exp. 5 part A (crash recovery) on the AWS analysis host. Settings: experiments/exp5/SETTINGS.md
# (user 2026-11-16, fixed before any Exp. 5 run). Run after bootstrap.sh, as ubuntu:
#
#   . ~/mt-env.sh; BUCKET=<work> HELDOUT_BUCKET=<sealed> SESSION=exp5 \
#     nohup bash code/experiments/exp5/run_exp5_aws.sh > exp5.out 2>&1 &
#
# No truth is read: every crash run is compared with the uncrashed run A on the same input.
# Stages (each skipped when its DONE marker exists, so the script resumes):
#   1 toolchain   setup-dev-host.sh (Go, JDK, Kafka, Postgres) + Go binaries into $MT_DEV/bin
#   2 shakedown   one PILOT FIT run: MT_CRASHRUN tests, a short at-once matrix, a pace-1 cell;
#                 every group must have no errors and run C must equal A, else stop (no held-out cell)
#   3 select      fetch the 32 clean Reference HELD_OUT runs (readable side), check their
#                 SHA256SUMS, select_inputs.py: 3 median-volume inputs, sweep input, history
#   4 main        per input: crashrun, every point (22 cells x 5 reps + A, A'), input at once
#   5 sweeps      sweep input: one factor at a time around pace 1 / outage 3 s / history 600 s,
#                 GO points, mode C, 3 reps; then the corner pace 4 / outage 600 s / history 4 h
# Output: s3://$BUCKET/results/$SESSION/ (STATUS, stage folders). The machine shuts down at the end.
set -uo pipefail
: "${BUCKET:?}" "${HELDOUT_BUCKET:?}" "${SESSION:?}"
CODE=${CODE:-$HOME/code}; OUT=${OUT:-$HOME/exp5}; DATA=${DATA:-$HOME/exp5-data}
export MT_DEV=${MT_DEV:-$HOME/microtrace-dev}
PARAMS=$CODE/src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml
MAIN_PARALLEL=${MAIN_PARALLEL:-8}; SWEEP_PARALLEL=${SWEEP_PARALLEL:-6}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$OUT" "$DATA"; S=$OUT/STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null; }
up() { aws s3 sync --only-show-errors --no-follow-symlinks "$OUT" "$R" --exclude STATUS --exclude '*/stacks/*' --exclude .done-toolchain < /dev/null; }
# The machine shuts itself down only once setup (toolchain, protobuf, Go build) has passed;
# a setup failure leaves it running with its logs uploaded (fix and rerun; the cost cap still holds).
ARMED=0
finish() { up; if [ "$AUTO_SHUTDOWN" = 1 ] && [ "$ARMED" = 1 ]; then st "SHUTDOWN"; sudo shutdown -h now; else st "STOPPED (machine left running)"; fi; }
stop() { st "FAILED $*"; exit 1; }
# Resume: STATUS, stage markers and finished stages. The toolchain lives on this machine, so its
# marker is never restored from S3 (a new machine restored it on 2026-11-16 and skipped the install).
aws s3 sync --only-show-errors "$R" "$OUT" --exclude .done-toolchain < /dev/null || true
rm -f "$OUT/.done-toolchain"
trap finish EXIT
[ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || stop "code tree has local changes"
st "START code $(git -C "$CODE" rev-parse --short HEAD), params $(sha256sum "$PARAMS" | cut -c1-12), $(nproc) cpu"

# 1. Toolchain. The code venv (Python 3.13, the frozen models' version) runs every Python process.
if [ ! -f "$OUT/.done-toolchain" ]; then
  # Postgres 17 configure needs bison and flex even from a release tarball (found 2026-11-16).
  sudo apt-get install -y -q bison flex > "$OUT/apt.log" 2>&1 || stop "apt-get bison flex"
  bash "$CODE/src/scripts/setup-dev-host.sh" > "$OUT/toolchain.log" 2>&1     || { cp -r "$MT_DEV/logs" "$OUT/toolchain-logs" 2>/dev/null; stop "setup-dev-host.sh (toolchain.log, toolchain-logs/; machine left running)"; }
  . "$MT_DEV/env.sh"
  # Generated protobuf code is gitignored; gen-proto.sh writes the Go and the Python half.
  (export PATH="$CODE/.venv/bin:$PATH"; bash "$CODE/src/scripts/gen-proto.sh") >> "$OUT/toolchain.log" 2>&1     || { cp -r "$MT_DEV/logs" "$OUT/toolchain-logs" 2>/dev/null; stop "gen-proto.sh (toolchain.log)"; }
  mkdir -p "$MT_DEV/bin"
  (cd "$CODE/src/go" && for c in receiver shipper devcerts trace-check faultinject; do
     go build -o "$MT_DEV/bin/$c" "./cmd/$c" || exit 1; done) >> "$OUT/toolchain.log" 2>&1 || stop "go build"
  touch "$OUT/.done-toolchain"; st "TOOLCHAIN ready"
fi
ARMED=1
. "$MT_DEV/env.sh"
export PATH="$CODE/.venv/bin:$PATH" VIRTUAL_ENV="$CODE/.venv" PYTHONPATH=$CODE/src/python PYTHONHASHSEED=1
PY=$CODE/.venv/bin/python
crash() { (cd "$CODE/src/python" && "$PY" -m mtcore.harness.crashrun --params "$PARAMS" "$@" < /dev/null); }
sweep() { (cd "$CODE/src/python" && "$PY" -m mtcore.harness.sweep --params "$PARAMS" "$@" < /dev/null); }
# Shipper node IDs = each stream's eBPF node_id (node_args.py; the file names cut the UID short).
inputs_of() { "$PY" "$CODE/experiments/exp5/node_args.py" --flag input "$1" || stop "node IDs of $1"; }
# gate (shakedown only): no group with errors; with STRICT=1 also every C and X cell identical to A
# and fired (D, the negative control, may differ). A and A' ok is enforced by run_matrix.
gate() { STRICT=${STRICT:-0} "$PY" - "$1" <<'PY'
import json, os, sys
s = json.load(open(sys.argv[1]))
bad = {k: v["errors"] for k, v in s.items() if v.get("errors")}
if os.environ["STRICT"] == "1":
    for k, v in s.items():
        run = k.split("|")[0]
        t = v.get("tally") or {}
        if run in ("C", "X") and (v.get("not_fired") or t.get("failures", 1) != 0):
            bad[k] = {"tally": t, "not_fired": v.get("not_fired")}
print(json.dumps({k: (v.get("tally") or {}).get("identical") for k, v in s.items()}))
sys.exit(f"gate: {json.dumps(bad)[:600]}" if bad else 0)
PY
}

# 2. Shakedown on development data (one PILOT FIT run; no held-out data yet).
if [ ! -f "$OUT/.done-shakedown" ]; then
  D=$OUT/shakedown; mkdir -p "$D"
  run=$("$PY" -c "import json;print(sorted(json.load(open('$CODE/experiments/heldout/splits/pilot_fit.json'))['fit'])[0])")
  aws s3 sync --only-show-errors "s3://$BUCKET/dev/pilot-fit/$run/shipper" "$DATA/dev-raw/$run/shipper" < /dev/null || stop "fetch dev run"
  # Development streams still carry ground.truth.v0 lines (held-out ones are sealed): strip them, so
  # the shakedown input has the held-out layout (strip_truth.py; the receiver rejects that topic).
  (cd "$CODE/src/python" && "$PY" "$CODE/experiments/exp5/strip_truth.py" "$DATA/dev-raw/$run" "$DATA/dev/$run") \
    > "$D/strip.log" 2>&1 || stop "strip truth from the dev run (shakedown/strip.log)"
  command -v kafka-storage.sh > /dev/null && [ -x "$MT_DEV/bin/faultinject" ] || stop "toolchain missing before the shakedown"
  (cd "$CODE/src/python" && MT_CRASHRUN=1 "$PY" -m pytest -q -rs tests/test_crashrun.py tests/test_crash_points.py) \
    > "$D/pytest.log" 2>&1 || stop "MT_CRASHRUN tests (shakedown/pytest.log)"
  # The crash-runner tests must have run, not skipped (they skip without the toolchain).
  ! grep -q "SKIPPED.*test_crashrun" "$D/pytest.log" || stop "MT_CRASHRUN tests skipped (shakedown/pytest.log)"
  t0=$(date +%s)
  crash $(inputs_of "$DATA/dev/$run") --out "$D/at-once" --parallel "$MAIN_PARALLEL" --reps 1 \
    --points go.after_flush_before_commit,agent.window_open,tgs.mid_transaction > "$D/at-once.log" 2>&1 \
    || stop "shakedown at-once matrix (shakedown/at-once.log)"
  STRICT=1 gate "$D/at-once/summary.json" > "$D/gate.txt" 2>&1 || stop "shakedown at-once: $(cat "$D/gate.txt")"
  t1=$(date +%s)
  crash $(inputs_of "$DATA/dev/$run") --out "$D/pace1" --parallel 3 --reps 1 --pace 1 --modes C \
    --points go.after_flush_before_commit > "$D/pace1.log" 2>&1 || stop "shakedown pace-1 cell (shakedown/pace1.log)"
  STRICT=1 gate "$D/pace1/summary.json" > "$D/gate.txt" 2>&1 || stop "shakedown pace 1: $(cat "$D/gate.txt")"
  t2=$(date +%s)
  echo -e "stage\twall_s\nat_once_6_runs\t$((t1 - t0))\npace1_3_runs\t$((t2 - t1))" > "$D/timing.tsv"
  touch "$OUT/.done-shakedown"; up; st "SHAKEDOWN ok (dev run $run; at-once $((t1 - t0)) s, pace-1 $((t2 - t1)) s)"
fi

# 3. Select the inputs (readable side of the held-out runs only).
if [ ! -f "$OUT/.done-select" ]; then
  mapfile -t cand < <("$PY" -c "
import yaml
m = yaml.safe_load(open('$CODE/spec/generator/run-matrix.held_out.yaml'))
print('\n'.join(sorted(r['run_id'] for r in m['runs'] if r['world_name'] == 'Reference' and r['observability_profile'] == 'clean')))")
  [ "${#cand[@]}" = 32 ] || stop "expected 32 candidates, got ${#cand[@]}"
  bad=0
  for r in "${cand[@]}"; do
    if [ ! -f "$DATA/held_out/$r/.ok" ]; then
      aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/held_out/$r" "$DATA/held_out/$r" < /dev/null \
        || { bad=$((bad + 1)); continue; }
      want=$(awk -F'\t' -v r="$r" '$1 == r {print $2}' "$CODE/experiments/heldout/manifests/held_out.tsv")
      [ "$(sha256sum "$DATA/held_out/$r/SHA256SUMS" | cut -d' ' -f1)" = "$want" ] \
        && (cd "$DATA/held_out/$r" && sha256sum -c --quiet SHA256SUMS < /dev/null) && touch "$DATA/held_out/$r/.ok" || bad=$((bad + 1))
    fi
  done
  [ "$bad" = 0 ] || stop "$bad candidate runs failed fetch or checksum"
  (cd "$CODE/src/python" && "$PY" "$CODE/experiments/exp5/select_inputs.py" --matrix "$CODE/spec/generator/run-matrix.held_out.yaml" \
     --runs "$DATA/held_out" --out "$OUT/select") > "$OUT/select.log" 2>&1 || stop "select_inputs.py (select.log)"
  touch "$OUT/.done-select"; up; st "SELECTED $(tail -3 "$OUT/select.log" | cut -d' ' -f1-2 | xargs)"
fi
mapfile -t INPUTS < <("$PY" -c "import json;[print(x['run_id']) for x in json.load(open('$OUT/select/selection.json'))['inputs']]")
SWEEP_IN=$("$PY" -c "import json;print(json.load(open('$OUT/select/selection.json'))['sweep_input'])")

# 4. Main matrix: correctness, input at once (user 2026-11-16), every point, 5 reps.
for r in "${INPUTS[@]}"; do
  [ -f "$OUT/.done-main-$r" ] && continue
  t0=$(date +%s)
  crash $(inputs_of "$DATA/held_out/$r") --out "$OUT/main/$r" --parallel "$MAIN_PARALLEL" --reps 5 --seed 1 \
    > "$OUT/main-$r.log" 2>&1 || stop "main matrix $r (main-$r.log)"
  touch "$OUT/.done-main-$r"; up; st "MAIN $r done in $(( $(date +%s) - t0 )) s"
done

# 5. Sweeps on the sweep input: GO points, mode C, 3 reps; history from select/history.
GOPTS=$("$PY" -c "from mtcore.failpoint import POINTS;print(','.join(p for p in POINTS if p.startswith('go.')))")
PRE=($("$PY" "$CODE/experiments/exp5/node_args.py" --flag prefill "$DATA/held_out/$SWEEP_IN" "$OUT/select/history"))   || stop "prefill node IDs"
if [ ! -f "$OUT/.done-sweep" ]; then
  t0=$(date +%s)
  sweep $(inputs_of "$DATA/held_out/$SWEEP_IN") "${PRE[@]}" --out "$OUT/sweep" --points "$GOPTS" --modes C --reps 3 \
    --paces 1,2,4 --outages 3,60,600 --histories 600,3600,14400 --base-pace 1 --base-outage 3 --base-history 600 \
    --parallel "$SWEEP_PARALLEL" --seed 1 > "$OUT/sweep.log" 2>&1 || stop "sweep (sweep.log)"
  touch "$OUT/.done-sweep"; up; st "SWEEP done in $(( $(date +%s) - t0 )) s"
fi
if [ ! -f "$OUT/.done-corner" ]; then
  t0=$(date +%s)
  sweep $(inputs_of "$DATA/held_out/$SWEEP_IN") "${PRE[@]}" --out "$OUT/corner" --points "$GOPTS" --modes C --reps 3 \
    --paces 4 --outages 600 --histories 14400 --base-pace 4 --base-outage 600 --base-history 14400 \
    --parallel "$SWEEP_PARALLEL" --seed 1 > "$OUT/corner.log" 2>&1 || stop "corner (corner.log)"
  touch "$OUT/.done-corner"; up; st "CORNER done in $(( $(date +%s) - t0 )) s"
fi
st "ALL_DONE"
