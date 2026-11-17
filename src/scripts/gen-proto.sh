#!/usr/bin/env bash
# Generate Python and Go code from spec/proto. Output is not committed;
# re-run after any .proto change. Needs: source $MT_DEV/env.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PROTO="$REPO/spec/proto"
PY_OUT="$REPO/src/python/gen"
GO_MODULE="github.com/AloneKuma/MicroTRACE/src/go"
GO_PKG="$GO_MODULE/gen/microtracev0"

files=()
for f in "$PROTO"/microtrace/v0/*.proto; do
  files+=("microtrace/v0/$(basename "$f")")
done

# Go import path for each file; the spec .proto files carry no go_package.
go_opts=("--go_opt=module=$GO_MODULE")
for f in "${files[@]}"; do
  go_opts+=("--go_opt=M$f=$GO_PKG")
done

# protoc-gen-go at the version pinned in src/go/go.mod; the gRPC plugin is a
# separate module, pinned here.
GRPC_GEN_VERSION="v1.6.2"
(cd "$REPO/src/go" && go install google.golang.org/protobuf/cmd/protoc-gen-go)
go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@$GRPC_GEN_VERSION"

WKT="$(python -c 'import grpc_tools, os; print(os.path.join(os.path.dirname(grpc_tools.__file__), "_proto"))')"

rm -rf "$PY_OUT" "$REPO/src/go/gen"
mkdir -p "$PY_OUT" "$REPO/src/go/gen"

cd "$PROTO"
python -m grpc_tools.protoc -I "$PROTO" -I "$WKT" \
  --python_out="$PY_OUT" --pyi_out="$PY_OUT" "${files[@]}"
python -m grpc_tools.protoc -I "$PROTO" -I "$WKT" \
  --plugin=protoc-gen-go="$(go env GOPATH)/bin/protoc-gen-go" \
  --plugin=protoc-gen-go-grpc="$(go env GOPATH)/bin/protoc-gen-go-grpc" \
  --go_out="$REPO/src/go" "${go_opts[@]}" \
  --go-grpc_out="$REPO/src/go" "${go_opts[@]/--go_opt/--go-grpc_opt}" "${files[@]}"

echo "generated: $PY_OUT and $REPO/src/go/gen"
