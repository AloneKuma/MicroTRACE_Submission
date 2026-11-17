#!/usr/bin/env bash
# Full check of src/ on the dev host: spec checks (when paper/ is present),
# code generation, Go vet and race tests, Python tests against the dev Kafka
# (agents, restreamer and end-to-end included), topic configuration, and a
# clean-up check. Needs: source $MT_DEV/env.sh, Kafka started by kafka-up.sh,
# and the TGS Postgres started by pg-up.sh (its credentials are read from
# $MT_DEV/pg.env; without it the Postgres store tests skip).
set -uo pipefail

: "${MT_DEV:?source env.sh first}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0
step() { echo; echo "== $*"; }
result() { if [ "$1" -eq 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; fail=1; fi; }

step "generate code from spec/proto"
bash "$REPO/src/scripts/gen-proto.sh" >/dev/null
result $? "gen-proto"

step "spec checks"
if [ -f "$REPO/paper/D3_v4.tex" ]; then
  out="$(cd "$REPO" && python spec/tools/check_gap1.py 2>&1)"
  rc=$?
  echo "$out" | grep -E '^\[FAIL\]|passed,'
  result "$rc" "check_gap1"
else
  echo "SKIP: check_gap1 needs paper/ (full checkout)"
fi

step "go vet"
(cd "$REPO/src/go" && go vet ./...)
result $? "go vet"

step "go test -race"
(cd "$REPO/src/go" && go test -race -count=1 ./...)
result $? "go test -race"

step "build binaries"
(cd "$REPO/src/go" && mkdir -p "$MT_DEV/bin" &&
  for c in receiver shipper devcerts trace-check faultinject; do go build -o "$MT_DEV/bin/$c" "./cmd/$c" || exit 1; done)
result $? "go build"

step "topics"
(cd "$REPO/src/python" && python -m mtcore.kafka_topics)
result $? "kafka topics"

step "postgres"
# shellcheck disable=SC1091
[ -f "$MT_DEV/pg.env" ] && . "$MT_DEV/pg.env"
pg_ctl -D "$MT_DEV/pg-data" status > /dev/null 2>&1
result $? "TGS postgres running (pg-up.sh)"

step "python tests"
rm -rf "$MT_DEV/pytest-tmp"
(cd "$REPO/src/python" && python -m pytest -q -p no:cacheprovider --basetemp="$MT_DEV/pytest-tmp" tests 2>&1 |
  grep -v '^%[0-9]|')
result "${PIPESTATUS[0]}" "pytest"

step "topic configuration"
(cd "$REPO/src/python" && python -c '
from mtcore.kafka_topics import check_configs
bad = check_configs("127.0.0.1:9092")
print("\n".join(bad) or "all managed topic configs match src/kafka/dev-topics.yaml")
raise SystemExit(1 if bad else 0)')
result $? "topic configuration"

step "clean-up"
stray="$(pgrep -af "$MT_DEV/bin/(receiver|shipper|trace-check)|mtcore\.(restream|agents\.run|orchestrator|tgs\.run)" || true)"
[ -z "$stray" ] || echo "$stray"
kpid="$(cat "$MT_DEV/kafka.pid" 2>/dev/null || true)"
echo "our Kafka pid: ${kpid:-none}"
[ -z "$stray" ] && [ -n "$kpid" ] && kill -0 "$kpid" 2>/dev/null
result $? "no stray receiver/shipper/restreamer/agent/orchestrator processes; our Kafka still running"

echo
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
