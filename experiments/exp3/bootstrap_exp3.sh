#!/usr/bin/env bash
# Exp. 3 setup on a session machine (analysis host and every sender node), after
# experiments/heldout/bootstrap.sh (senders: MT_SKIP_SAGE=1). bootstrap.sh builds Python only;
# Exp. 3 also needs the Go transport (faultinject, shipper, receiver, devcerts) and, on the
# analysis host, Kafka with a JDK. Versions as src/scripts/setup-dev-host.sh (Go 1.27.1,
# Temurin JDK 21.0.12.1+1, Kafka 4.3.1), every download checked against its published hash.
#
#   . ~/mt-env.sh; ROLE=analysis|sender bash experiments/exp3/bootstrap_exp3.sh
#
# Appends MT_BIN, KAFKA_HOME, JAVA and the Go path to ~/mt-env.sh and checks: Go unit tests of the
# fault injector, shipper, spool and receiver; test_exp3.py; (analysis) a slot's Kafka starts and
# its topics are made.
set -euo pipefail
: "${ROLE:?ROLE=analysis or sender}" "${CODE:?. ~/mt-env.sh first}"
T=$HOME/mt-tools; BIN=$HOME/mt-bin; LOG=$HOME/bootstrap-exp3.log
GO_VERSION=go1.27.1; JDK_RELEASE="jdk-21.0.12.1+1"; KAFKA_VERSION=4.3.1; SCALA_VERSION=2.13
say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }
fetch() { curl -fsSL --retry 3 --max-time 600 -o "$2" "$1"; }
check_sha() { echo "$3  $2" | "${1}sum" -c --quiet - || { say "STOP $2: $1 mismatch"; exit 1; }; }
mkdir -p "$T/dl" "$BIN"
cd "$T"
. "$VENV/bin/activate"

if [ ! -x "$T/go/bin/go" ]; then
  f="$GO_VERSION.linux-amd64.tar.gz"
  fetch "https://go.dev/dl/$f" "dl/$f"
  sha=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | python -c '
import json, sys
for rel in json.load(sys.stdin):
    for fl in rel["files"]:
        if fl["filename"] == sys.argv[1]:
            print(fl["sha256"]); sys.exit()
sys.exit("not listed: " + sys.argv[1])' "$f")
  check_sha sha256 "dl/$f" "$sha"
  tar -xzf "dl/$f"
fi
export PATH=$T/go/bin:$HOME/go/bin:$PATH GOTOOLCHAIN=local

if [ "$ROLE" = analysis ] && [ ! -x "$T/jdk/bin/java" ]; then
  rel=$(python -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$JDK_RELEASE")
  meta=$(curl -fsSL "https://api.adoptium.net/v3/assets/release_name/eclipse/$rel?architecture=x64&image_type=jdk&os=linux")
  link=$(printf '%s' "$meta" | python -c 'import json,sys; print(json.load(sys.stdin)["binaries"][0]["package"]["link"])')
  sha=$(printf '%s' "$meta" | python -c 'import json,sys; print(json.load(sys.stdin)["binaries"][0]["package"]["checksum"])')
  fetch "$link" dl/jdk.tar.gz
  check_sha sha256 dl/jdk.tar.gz "$sha"
  mkdir -p jdk && tar -xzf dl/jdk.tar.gz -C jdk --strip-components=1
fi
if [ "$ROLE" = analysis ] && [ ! -d "$T/kafka/libs" ]; then
  f="kafka_$SCALA_VERSION-$KAFKA_VERSION.tgz"
  base="https://downloads.apache.org/kafka/$KAFKA_VERSION"
  fetch "$base/$f" "dl/$f" || fetch "https://archive.apache.org/dist/kafka/$KAFKA_VERSION/$f" "dl/$f"
  fetch "$base/$f.sha512" "dl/$f.sha512" || fetch "https://archive.apache.org/dist/kafka/$KAFKA_VERSION/$f.sha512" "dl/$f.sha512"
  want=$(cut -d: -f2- "dl/$f.sha512" | tr -d ' \n\r' | tr 'A-F' 'a-f')
  check_sha sha512 "dl/$f" "$want"
  mkdir -p kafka && tar -xzf "dl/$f" -C kafka --strip-components=1
fi

# Go protobuf code (gitignored), as src/scripts/gen-proto.sh does it, then the four binaries.
if [ ! -d "$CODE/src/go/gen/microtracev0" ]; then
  (cd "$CODE/src/go" && go install google.golang.org/protobuf/cmd/protoc-gen-go)
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
  WKT=$(python -c 'import grpc_tools, os; print(os.path.join(os.path.dirname(grpc_tools.__file__), "_proto"))')
  M=github.com/AloneKuma/MicroTRACE/src/go; PKG=$M/gen/microtracev0
  files=(); opts=("--go_opt=module=$M")
  for f in "$CODE"/spec/proto/microtrace/v0/*.proto; do files+=("microtrace/v0/$(basename "$f")"); done
  for f in "${files[@]}"; do opts+=("--go_opt=M$f=$PKG"); done
  mkdir -p "$CODE/src/go/gen"
  (cd "$CODE/spec/proto" && python -m grpc_tools.protoc -I . -I "$WKT" \
     --plugin=protoc-gen-go="$HOME/go/bin/protoc-gen-go" --plugin=protoc-gen-go-grpc="$HOME/go/bin/protoc-gen-go-grpc" \
     --go_out="$CODE/src/go" "${opts[@]}" --go-grpc_out="$CODE/src/go" "${opts[@]/--go_opt/--go-grpc_opt}" "${files[@]}")
fi
for c in faultinject shipper receiver devcerts; do
  (cd "$CODE/src/go" && go build -o "$BIN/$c" "./cmd/$c")
done
(cd "$CODE/src/go" && go test ./internal/faults/ ./internal/shipper/ ./internal/spool/ ./internal/receiver/ ./cmd/faultinject/) \
  >> "$LOG" 2>&1 || { say "STOP Go tests failed (see $LOG)"; exit 1; }

grep -q MT_BIN "$HOME/mt-env.sh" || cat >> "$HOME/mt-env.sh" <<EOF
export MT_BIN=$BIN PATH=$T/go/bin:\$PATH
EOF
if [ "$ROLE" = analysis ]; then
  grep -q KAFKA_HOME "$HOME/mt-env.sh" || echo "export KAFKA_HOME=$T/kafka JAVA=$T/jdk/bin/java" >> "$HOME/mt-env.sh"
  . "$HOME/mt-env.sh"
  python - <<'PY'
import os, tempfile
from mtcore.exp3.slot import Slot
with tempfile.TemporaryDirectory() as d:
    s = Slot(os.path.join(d, "s"), index=9)
    try:
        s.up()
        print("kafka ok")
    finally:
        s.down()
PY
fi
python -m pytest -q "$CODE/src/python/tests/test_exp3.py" >> "$LOG" 2>&1 || { say "STOP test_exp3 failed (see $LOG)"; exit 1; }
say "EXP3 READY role $ROLE, go $(go version | cut -d' ' -f3), bin $BIN$( [ "$ROLE" = analysis ] && echo ", kafka $KAFKA_VERSION")"
