#!/usr/bin/env bash
# Fetch, patch and build SAGE and FlexFringe for the SAGE baseline (test host).
#
#   source ~/microtrace-dev/env.sh
#   bash src/scripts/baselines/fetch-sage.sh        # -> $MT_DEV/baselines/sage
#   export MT_SAGE_HOME=$MT_DEV/baselines/sage
#
# Layout of $MT_SAGE_HOME: SAGE/ (pinned commit + our patch), FlexFringe/
# (pinned commit, built, with SAGE's spdfa-config.ini), venv/ (SAGE's own
# Python with src/baselines/sage/requirements.txt), and the pinned IANA port
# table. Re-running resets both checkouts to their pins and re-applies the
# patch. Needs git, make, a C++ compiler and uv (from setup-dev-host.sh).
set -euo pipefail

: "${MT_DEV:?source ~/microtrace-dev/env.sh first}"
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
DEST=${MT_SAGE_HOME:-$MT_DEV/baselines/sage}
SAGE_COMMIT=707a190e7ace8ebbe0800c68f3bd934e58006b50
FF_COMMIT=1a87e3b
PY_VERSION=3.12
HERE=$REPO/src/baselines/sage

mkdir -p "$DEST"
cd "$DEST"

if [ ! -d SAGE/.git ]; then
  git -c core.autocrlf=false clone -q https://github.com/tudelft-cda-lab/SAGE.git SAGE
fi
git -C SAGE fetch -q origin
git -C SAGE checkout -q -f "$SAGE_COMMIT"
git -C SAGE reset -q --hard "$SAGE_COMMIT"
git -C SAGE apply "$HERE/patches/0001-microtrace-export.patch"

if [ ! -d FlexFringe/.git ]; then
  git -c core.autocrlf=false clone -q https://github.com/tudelft-cda-lab/FlexFringe.git FlexFringe
fi
git -C FlexFringe fetch -q origin
git -C FlexFringe checkout -q -f "$FF_COMMIT"
git -C FlexFringe reset -q --hard "$FF_COMMIT"
make -C FlexFringe clean all > flexfringe-build.log 2>&1 || { tail -40 flexfringe-build.log; exit 1; }
cp SAGE/spdfa-config.ini FlexFringe/ini/

gunzip -c "$HERE/iana-service-names-port-numbers.csv.gz" > iana-service-names-port-numbers.csv

if [ ! -x venv/bin/python ]; then
  uv venv -q --python "$PY_VERSION" venv
fi
uv pip install -q --python venv/bin/python -r "$HERE/requirements.txt"

echo "SAGE $(git -C SAGE rev-parse --short HEAD) + patch, FlexFringe $(git -C FlexFringe rev-parse --short HEAD)"
echo "export MT_SAGE_HOME=$DEST"
