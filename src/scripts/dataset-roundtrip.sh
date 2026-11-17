#!/usr/bin/env bash
# dataset-roundtrip.sh — Transport round-trip kit for the MicroTRACE test host.
#
# Usage:
#   bash src/scripts/dataset-roundtrip.sh [--skip-clean] [--pace N]
#
#   --skip-clean   Skip the initial clean run (useful when resuming after a
#                  failed faulted-run pass).
#   --pace N       Override the -pace argument passed to faultinject/shipper
#                  during faulted runs (default: 0 = as fast as possible).
#                  Pass --pace 1 for real-time pacing.
#   --plans=A,B    Run only these fault plans (names without .yaml).
#   --skip-paced   Skip the real-time (-pace 1) replay at the end.
#
# Prerequisites:
#   1. Run src/scripts/setup-dev-host.sh on this Linux host first.
#   2. Source ~/microtrace-dev/env.sh so that $MT_DEV, PATH, etc. are set.
#   3. Build the Go binaries with:
#        (cd src/go && for c in receiver shipper devcerts faultinject; do
#           go build -o "$MT_DEV/bin/$c" ./cmd/$c; done)
#   4. Generate TLS certs with:
#        devcerts -out "$MT_DEV/certs" -nodes node-1
#   5. Generate proto stubs with:
#        bash src/scripts/gen-proto.sh
#
# What this script does:
#   1. Sources env.sh and builds missing binaries.
#   2. Starts Kafka (if not already running), waits for broker readiness.
#   3. Starts the ingest receiver.
#   4. Builds the Small dev run with `python -m mtgen build`, then writes
#      $MT_DEV/roundtrip/suppress.yaml with real logical_ids in place of the
#      placeholders in spec/faults/roundtrip/suppress.yaml.
#   5. Performs one clean replay (no faults) and reconciles.
#   6. For each fault plan under spec/faults/roundtrip/:
#      a. Runs faultinject on the base stream (source-stage faults).
#      b. Replays through the shipper with -faults (transit-stage faults).
#      c. Archives the received Kafka messages with the Python archiver.
#      d. Runs `python -m mtgen reconcile` and records PASS/FAIL.
#   7. Runs one clean replay at -pace 1 (real-time pacing).
#   8. Stops the receiver, and Kafka only if this script started it, on any exit.
#   9. Prints a final PASS/FAIL summary per plan.
#
# Exit code: 0 if every plan (clean + faulted + paced) reconciles OK, 1 otherwise.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SKIP_CLEAN=0
SKIP_PACED=0
ONLY_PLANS=""
PACE=0

for arg in "$@"; do
  case "$arg" in
    --skip-clean) SKIP_CLEAN=1 ;;
    --skip-paced) SKIP_PACED=1 ;;
    --plans=*)    ONLY_PLANS=",${arg#--plans=}," ;;
    --pace)       shift; PACE="$1" ;;
    --pace=*)     PACE="${arg#--pace=}" ;;
  esac
done

# ---------------------------------------------------------------------------
# Env and paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_SH="${MT_DEV:-$HOME/microtrace-dev}/env.sh"

if [[ -f "$ENV_SH" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_SH"
fi

MT_DEV="${MT_DEV:-$HOME/microtrace-dev}"
BINS="$MT_DEV/bin"
CERTS="$MT_DEV/certs"
ROUNDTRIP_DIR="$MT_DEV/roundtrip"
RUN_DIR="$ROUNDTRIP_DIR/run"
ARCHIVE_DIR="$ROUNDTRIP_DIR/archive"
SPOOL_DIR="$ROUNDTRIP_DIR/spool"
RX_STATE="$ROUNDTRIP_DIR/rx-state"
FAULT_PLANS_DIR="$REPO_ROOT/spec/faults/roundtrip"
PY_SRC="$REPO_ROOT/src/python"

mkdir -p "$RUN_DIR" "$ARCHIVE_DIR" "$SPOOL_DIR" "$RX_STATE"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${YELLOW}[roundtrip]${NC} $*"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ---------------------------------------------------------------------------
# 1. Build missing binaries
# ---------------------------------------------------------------------------
info "Checking binaries …"
for cmd in receiver shipper faultinject devcerts; do
  if [[ ! -x "$BINS/$cmd" ]]; then
    info "Building $cmd …"
    (cd "$REPO_ROOT/src/go" && go build -o "$BINS/$cmd" "./cmd/$cmd")
  fi
done

# ---------------------------------------------------------------------------
# 2. Start Kafka (only if not running)
# ---------------------------------------------------------------------------
# kafka-up.sh and kafka-down.sh keep the pid at $MT_DEV/kafka.pid. A stale file
# (process gone) counts as not running.
KAFKA_PID_FILE="$MT_DEV/kafka.pid"
KAFKA_WE_STARTED=0
if ! { [[ -f "$KAFKA_PID_FILE" ]] && kill -0 "$(cat "$KAFKA_PID_FILE")" 2>/dev/null; }; then
  info "Starting Kafka …"
  bash "$REPO_ROOT/src/scripts/kafka-up.sh"
  KAFKA_WE_STARTED=1
fi

# Wait for the broker to become ready (up to 30 s)
info "Waiting for Kafka broker …"
for i in $(seq 1 30); do
  if "$BINS/receiver" -check-kafka 2>/dev/null; then
    break
  fi
  sleep 1
done

# Create topics if needed
(cd "$PY_SRC" && python -m mtcore.kafka_topics) || true

# ---------------------------------------------------------------------------
# 3. Receiver: one per replay (started in replay_run)
# ---------------------------------------------------------------------------
# Every replay sends the same node and boot from sequence 0, so each gets a
# fresh receiver with its own state folder; a shared one would reject the
# second replay as a lost spool.
RX_PID=""
ARCHIVE_TOPICS="norm.events.v0,source.completeness.v0,context.cluster.v0,ground.truth.v0"
# The receiver's default allowlist plus source.completeness.v0: generated
# shipper files carry each source's own completeness reports, and topics.yaml
# lets any producer write that topic.
RX_ALLOW="raw.ebpf.v0,raw.audit.v0,raw.gateway.v0,raw.kyverno.v0,raw.dbaudit.v0,raw.pathflow.v0,context.cluster.v0,norm.events.v0,source.completeness.v0"
start_receiver() {
  local state="$1"
  rm -rf "$state"; mkdir -p "$state"
  "$BINS/receiver" \
    -cert "$CERTS/receiver.crt" \
    -key  "$CERTS/receiver.key" \
    -ca   "$CERTS/ca.crt" \
    -topics "$REPO_ROOT/spec/kafka/topics.yaml" \
    -allow "$RX_ALLOW" \
    -state "$state" \
    &
  RX_PID=$!
  sleep 2  # let receiver connect to Kafka
}
stop_receiver() {
  [[ -n "$RX_PID" ]] || return 0
  kill "$RX_PID" 2>/dev/null || true
  wait "$RX_PID" 2>/dev/null || true
  RX_PID=""
}

# Stop the receiver, and Kafka if this script started it, however the script
# exits (set -e included).
cleanup() {
  stop_receiver
  if [[ "$KAFKA_WE_STARTED" -eq 1 ]]; then
    info "Stopping Kafka …"
    bash "$REPO_ROOT/src/scripts/kafka-down.sh" || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 4. Build Small dev run
# ---------------------------------------------------------------------------
info "Building Small dev run …"
(cd "$PY_SRC" && python -m mtgen build \
  --world Small \
  --shape clean \
  --scenarios all \
  --split PILOT \
  --seed 20261011 \
  --duration-s 3600 \
  --out "$RUN_DIR")

BASE_STREAM="$RUN_DIR/base.pb"
NODE1_INPUT="$RUN_DIR/shipper/node-$(ls "$RUN_DIR/shipper/" | head -1 | sed 's/node-//' | sed 's/\.jsonl//')"
# Fallback: use the first shipper file found
FIRST_SHIPPER="$(ls "$RUN_DIR/shipper/"*.jsonl 2>/dev/null | head -1)"

# suppress.yaml names placeholder logical_ids; real ones exist only now. Write a
# filled copy that drops two evidence events of a PRESENT finding opportunity,
# taken from the replayed shipper file so the drop actually happens.
SUPPRESS_PLAN="$ROUNDTRIP_DIR/suppress.yaml"
info "Filling suppress plan with real logical_ids …"
(cd "$PY_SRC" && python - <<EOF
import json
from pathlib import Path
from mtgen.verify import _load_truth_files, dataset_pb2  # mtgen puts gen/ on sys.path

shipped = set()
with open("$FIRST_SHIPPER", encoding="utf-8") as fh:
    for line in fh:
        lid = json.loads(line).get("envelope", {}).get("logical_id")
        if lid:
            shipped.add(lid)
_, findings, _ = _load_truth_files(Path("$RUN_DIR"))
ids = sorted({e for f in findings
              if f.expected_state == dataset_pb2.PRESENT
              for e in f.evidence_event_ids if e in shipped})
if len(ids) < 2:
    raise SystemExit(f"suppress: only {len(ids)} PRESENT evidence ids in $FIRST_SHIPPER")
text = Path("$FAULT_PLANS_DIR/suppress.yaml").read_text(encoding="utf-8")
text = text.replace("__PLACEHOLDER_SUPPRESS_ID_1__", ids[0])
text = text.replace("__PLACEHOLDER_SUPPRESS_ID_2__", ids[1])
Path("$SUPPRESS_PLAN").write_text(text, encoding="utf-8")
print(f"[suppress] {ids[0]} {ids[1]}")
EOF
)

# ---------------------------------------------------------------------------
# Helper: replay one shipper file (optionally with fault plan)
# ---------------------------------------------------------------------------
replay_run() {
  local label="$1"
  local input_file="$2"
  local fault_plan="${3:-}"
  local archive_sub="$ARCHIVE_DIR/$label"
  local rx_archive="$archive_sub/kafka"
  local reconcile_report="$archive_sub/reconcile.json"
  local src_log="$archive_sub/src-faults.jsonl"
  local transit_log="$archive_sub/transit-faults.jsonl"

  # Start from nothing left by an earlier attempt (the source fault log in
  # $archive_sub was just written by faultinject and stays).
  rm -rf "$SPOOL_DIR/$label" "$rx_archive" "$transit_log" "$reconcile_report"
  mkdir -p "$rx_archive"
  # Note where each archived topic ends now; the archiver reads from there,
  # so this replay's archive holds none of the earlier replays' records.
  local start_offsets="$archive_sub/start-offsets.json"
  (cd "$PY_SRC" && python - <<EOF
import json
from mtgen.archiver import end_offsets
offs = end_offsets("127.0.0.1:9092", "$ARCHIVE_TOPICS".split(","))
json.dump([[t, p, o] for (t, p), o in offs.items()], open("$start_offsets", "w"))
EOF
)
  info "[$label] starting receiver …"
  start_receiver "$RX_STATE/$label"

  # (a) Shipper flags
  local shipper_args=(
    -node-id node-1
    -cert "$CERTS/node-cert-node-1.crt"
    -key  "$CERTS/node-cert-node-1.key"
    -ca   "$CERTS/ca.crt"
    -spool "$SPOOL_DIR/$label"
    -input "$input_file"
    -drain
  )
  if [[ -n "$fault_plan" ]]; then
    shipper_args+=(-faults "$fault_plan" -fault-log "$transit_log")
  fi

  # (b) Replay
  info "[$label] replaying …"
  mkdir -p "$SPOOL_DIR/$label"
  # A failed plan is recorded and the next one runs.
  if ! "$BINS/shipper" "${shipper_args[@]}"; then
    stop_receiver
    RESULTS+=("FAIL  $label (shipper)")
    fail "$label (shipper)"
    OVERALL_OK=1
    return 0
  fi

  # The shipper drained with every batch acknowledged, so all records are in
  # Kafka. Stop the receiver first: its heartbeats every second would keep the
  # archiver's idle-stop from ever firing.
  stop_receiver

  # (c) Archive via Python archiver (reads Kafka, writes topic=/partition= files)
  info "[$label] archiving …"
  (cd "$PY_SRC" && python - <<EOF
import sys; sys.path.insert(0, ".")
import json
from pathlib import Path
from mtgen.archiver import KafkaArchiver

ka = KafkaArchiver(
  bootstrap_servers="127.0.0.1:9092",
  topics="$ARCHIVE_TOPICS".split(","),
  archive_root=Path("$rx_archive"),
  idle_stop_after_s=15,
  start_offsets={(t, p): o for t, p, o in json.load(open("$start_offsets"))},
)
a = ka.run()
files = a.flush()
print(f"[archiver] {a.record_count()} records, {len(files)} partition files")
EOF
)

  # (d) Reconcile
  info "[$label] reconciling …"
  local reconcile_args=(
    --base "$BASE_STREAM"
    --shipper-input "$FIRST_SHIPPER"
    --archive "$rx_archive"
    --out "$reconcile_report"
  )
  if [[ -f "$src_log" ]]; then
    reconcile_args+=(--src-log "$src_log")
  fi
  if [[ -f "$transit_log" ]]; then
    reconcile_args+=(--transit-log "$transit_log")
  fi
  if [[ -d "$RUN_DIR/restricted" ]]; then
    reconcile_args+=(--truth "$RUN_DIR/restricted")
  fi

  # A fault plan that logged nothing never acted (e.g. a trigger time outside
  # the run), so reconcile would pass on an unfaulted replay.
  local fault_entries=0
  if [[ -n "$fault_plan" ]]; then
    fault_entries=$(cat "$src_log" "$transit_log" 2>/dev/null | grep -vc '"header"' || true)
  fi
  if [[ -n "$fault_plan" && "$fault_entries" -eq 0 ]]; then
    RESULTS+=("FAIL  $label (fault had no effect)")
    fail "$label (fault had no effect)"
    OVERALL_OK=1
  elif (cd "$PY_SRC" && python -m mtgen reconcile "${reconcile_args[@]}"); then
    RESULTS+=("PASS  $label")
    pass "$label"
  else
    RESULTS+=("FAIL  $label")
    fail "$label"
    OVERALL_OK=1
  fi
}

# ---------------------------------------------------------------------------
# 5. Clean run
# ---------------------------------------------------------------------------
RESULTS=()
OVERALL_OK=0

if [[ "$SKIP_CLEAN" -eq 0 ]]; then
  replay_run "clean" "$FIRST_SHIPPER"
fi

# ---------------------------------------------------------------------------
# 6. Faulted runs (one per plan)
# ---------------------------------------------------------------------------
for plan_file in "$FAULT_PLANS_DIR"/*.yaml; do
  plan_name="$(basename "$plan_file" .yaml)"
  [[ -z "$ONLY_PLANS" || "$ONLY_PLANS" == *",$plan_name,"* ]] || continue
  [[ "$plan_name" == suppress ]] && plan_file="$SUPPRESS_PLAN"
  faulted_input="$ROUNDTRIP_DIR/faulted-${plan_name}.jsonl"
  src_log_path="$ARCHIVE_DIR/${plan_name}/src-faults.jsonl"
  mkdir -p "$ARCHIVE_DIR/$plan_name"

  # Source-stage injection (produces faulted stream + src log)
  info "[$plan_name] running faultinject (source stage) …"
  if ! "$BINS/faultinject" \
    -plan "$plan_file" \
    -node node-1 \
    -log  "$src_log_path" \
    -input "$FIRST_SHIPPER" \
    -output "$faulted_input" \
    ${PACE:+-pace $PACE}; then
    RESULTS+=("FAIL  $plan_name (faultinject)")
    fail "$plan_name (faultinject)"
    OVERALL_OK=1
    continue
  fi

  replay_run "$plan_name" "$faulted_input" "$plan_file"
done

# ---------------------------------------------------------------------------
# 7. Paced run at -pace 1
# ---------------------------------------------------------------------------
if [[ "$SKIP_PACED" -eq 0 ]]; then
  info "Building paced faulted input at -pace 1 …"
  PACED_INPUT="$ROUNDTRIP_DIR/paced.jsonl"
  PACED_SRC_LOG="$ARCHIVE_DIR/paced/src-faults.jsonl"
  mkdir -p "$ARCHIVE_DIR/paced"
  "$BINS/faultinject" \
    -plan "$FAULT_PLANS_DIR/source-loss.yaml" \
    -node node-1 \
    -log  "$PACED_SRC_LOG" \
    -input "$FIRST_SHIPPER" \
    -output "$PACED_INPUT" \
    -pace 1

  replay_run "paced" "$PACED_INPUT" "$FAULT_PLANS_DIR/source-loss.yaml"
fi

# 8. The EXIT trap (cleanup) stops the receiver and, if this script started
#    it, Kafka.

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------
echo ""
echo "===== Round-trip summary ====="
for line in "${RESULTS[@]}"; do
  echo "  $line"
done
echo "=============================="

if [[ "$OVERALL_OK" -eq 0 ]]; then
  pass "All plans reconcile OK."
else
  fail "One or more plans FAILED."
fi

exit "$OVERALL_OK"
