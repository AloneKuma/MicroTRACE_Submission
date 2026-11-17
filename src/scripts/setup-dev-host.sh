#!/usr/bin/env bash
# Install the MicroTRACE development toolchain into one folder, with no
# system-wide changes: Python (via uv) + venv, Go, a JDK, Kafka, and Postgres
# (built from source; needs gcc and make).
#
#   MT_DEV=~/microtrace-dev bash src/scripts/setup-dev-host.sh
#   source ~/microtrace-dev/env.sh
#
# Every download is checked against its published checksum. Re-running is
# safe: finished components are skipped.
set -euo pipefail

MT_DEV="${MT_DEV:-$HOME/microtrace-dev}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

# Pinned versions (2026-10-08). Change here only, then re-run.
UV_VERSION="0.12.23"
PYTHON_VERSION="3.12"
GO_VERSION="go1.27.1"
JDK_RELEASE="jdk-21.0.12.1+1"
KAFKA_VERSION="4.3.1"
SCALA_VERSION="2.13"
PG_VERSION="17.6"

mkdir -p "$MT_DEV"/{dl,logs}
cd "$MT_DEV"

fetch() { curl -fsSL --retry 3 --max-time 600 -o "$2" "$1"; }

check_sha() {  # algo file expected-hex
  local got
  got="$("${1}sum" "$2" | awk '{print $1}')"
  if [ "$got" != "$3" ]; then
    echo "checksum mismatch for $2" >&2
    exit 1
  fi
}

# uv (standalone binary) -> Python
if [ ! -x "$MT_DEV/uv/uv" ]; then
  f="uv-x86_64-unknown-linux-gnu.tar.gz"
  base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
  fetch "$base/$f" "dl/$f"
  fetch "$base/$f.sha256" "dl/$f.sha256"
  check_sha sha256 "dl/$f" "$(awk '{print $1}' "dl/$f.sha256")"
  mkdir -p uv && tar -xzf "dl/$f" -C uv --strip-components=1
fi
export UV_PYTHON_INSTALL_DIR="$MT_DEV/python" UV_CACHE_DIR="$MT_DEV/uv-cache"
if [ ! -x "$MT_DEV/venv/bin/python" ]; then
  "$MT_DEV/uv/uv" python install "$PYTHON_VERSION"
  "$MT_DEV/uv/uv" venv --python "$PYTHON_VERSION" "$MT_DEV/venv"
fi
# Exact versions from requirements.lock when present, else the loose list.
req="$REPO/src/python/requirements.lock"
[ -f "$req" ] || req="$REPO/src/python/requirements.txt"
VIRTUAL_ENV="$MT_DEV/venv" "$MT_DEV/uv/uv" pip install -r "$req"

# Go
if [ ! -x "$MT_DEV/go/bin/go" ]; then
  f="$GO_VERSION.linux-amd64.tar.gz"
  fetch "https://go.dev/dl/$f" "dl/$f"
  sha="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | "$MT_DEV/venv/bin/python" -c '
import json, sys
name = sys.argv[1]
for rel in json.load(sys.stdin):
    for fl in rel["files"]:
        if fl["filename"] == name:
            print(fl["sha256"]); sys.exit()
sys.exit("not listed: " + name)' "$f")"
  check_sha sha256 "dl/$f" "$sha"
  tar -xzf "dl/$f"
fi

# JDK (Eclipse Temurin)
if [ ! -x "$MT_DEV/jdk/bin/java" ]; then
  rel="$("$MT_DEV/venv/bin/python" -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$JDK_RELEASE")"
  meta="$(curl -fsSL "https://api.adoptium.net/v3/assets/release_name/eclipse/$rel?architecture=x64&image_type=jdk&os=linux")"
  link="$(printf '%s' "$meta" | "$MT_DEV/venv/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["binaries"][0]["package"]["link"])')"
  sha="$(printf '%s' "$meta" | "$MT_DEV/venv/bin/python" -c 'import json,sys; print(json.load(sys.stdin)["binaries"][0]["package"]["checksum"])')"
  fetch "$link" dl/jdk.tar.gz
  check_sha sha256 dl/jdk.tar.gz "$sha"
  mkdir -p jdk && tar -xzf dl/jdk.tar.gz -C jdk --strip-components=1
fi

# Kafka (KRaft mode, no ZooKeeper)
if [ ! -x "$MT_DEV/kafka/bin/kafka-server-start.sh" ]; then
  f="kafka_$SCALA_VERSION-$KAFKA_VERSION.tgz"
  base="https://downloads.apache.org/kafka/$KAFKA_VERSION"
  fetch "$base/$f" "dl/$f" || fetch "https://archive.apache.org/dist/kafka/$KAFKA_VERSION/$f" "dl/$f"
  fetch "$base/$f.sha512" "dl/$f.sha512" || fetch "https://archive.apache.org/dist/kafka/$KAFKA_VERSION/$f.sha512" "dl/$f.sha512"
  # The .sha512 file is "name: HEX HEX ..." split over lines.
  want="$(cut -d: -f2- "dl/$f.sha512" | tr -d ' \n\r' | tr 'A-F' 'a-f')"
  check_sha sha512 "dl/$f" "$want"
  mkdir -p kafka && tar -xzf "dl/$f" -C kafka --strip-components=1
fi

# Postgres (TGS graph store), built from the official source release. No ICU,
# readline or zlib: none is needed by a local, single-user evaluation store.
if [ ! -x "$MT_DEV/pgsql/bin/pg_ctl" ]; then
  f="postgresql-$PG_VERSION.tar.bz2"
  base="https://ftp.postgresql.org/pub/source/v$PG_VERSION"
  fetch "$base/$f" "dl/$f"
  fetch "$base/$f.sha256" "dl/$f.sha256"
  check_sha sha256 "dl/$f" "$(awk '{print $1}' "dl/$f.sha256")"
  rm -rf pg-src && mkdir -p pg-src && tar -xjf "dl/$f" -C pg-src --strip-components=1
  (cd pg-src && ./configure --prefix="$MT_DEV/pgsql" --without-icu --without-readline --without-zlib \
      > "$MT_DEV/logs/pg-configure.log" 2>&1 &&
    make -j"$(nproc)" > "$MT_DEV/logs/pg-build.log" 2>&1 && make install >> "$MT_DEV/logs/pg-build.log" 2>&1) ||
    { echo "postgres build failed; see $MT_DEV/logs/pg-configure.log and pg-build.log" >&2; exit 1; }
  rm -rf pg-src
fi

cat > "$MT_DEV/env.sh" <<EOF
# Source this to use the MicroTRACE toolchain.
export MT_DEV="$MT_DEV"
export JAVA_HOME="$MT_DEV/jdk"
export GOROOT="$MT_DEV/go"
export GOPATH="$MT_DEV/gopath"
export GOMODCACHE="$MT_DEV/gopath/pkg/mod"
export GOCACHE="$MT_DEV/go-cache"
export GOTOOLCHAIN=local
export UV_PYTHON_INSTALL_DIR="$MT_DEV/python"
export UV_CACHE_DIR="$MT_DEV/uv-cache"
export PATH="$MT_DEV/venv/bin:$MT_DEV/go/bin:$MT_DEV/gopath/bin:$MT_DEV/jdk/bin:$MT_DEV/kafka/bin:$MT_DEV/pgsql/bin:$MT_DEV/uv:\$PATH"
export VIRTUAL_ENV="$MT_DEV/venv"
EOF

echo "Toolchain ready in $MT_DEV. Run: source $MT_DEV/env.sh"
