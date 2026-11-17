#!/usr/bin/env bash
# Session machine setup, part 2 (part 1, system packages and the ENA PTP driver, is the
# session stack's user data). Run once as ubuntu over EC2 Instance Connect after the first
# reboot, before any runner:
#
#   BUCKET=<work bucket> COMMIT=<full sha> bash bootstrap.sh
#
# Gets the code from s3://$BUCKET/code/<COMMIT>.bundle (git bundle, made on the laptop with
# `git bundle create <sha>.bundle <sha>` and copied up by the Terraform role), builds the
# Python environment from src/python/requirements.lock with Python 3.13 (the version the
# frozen models were scored with), generates src/python/gen without Go, installs SAGE and
# FlexFringe at their pins, and checks every runner prerequisite. Writes ~/mt-env.sh.
set -euo pipefail
: "${BUCKET:?}" "${COMMIT:?}"
CODE=$HOME/code; SAGE=$HOME/sage; LOG=$HOME/bootstrap.log
say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }

[ -f /var/lib/mt-system-ready ] || { say "STOP system setup (user data) not finished"; exit 1; }
for c in docker aws git make g++ chronyc /usr/bin/time; do
  command -v "$c" > /dev/null || { say "STOP missing $c"; exit 1; }
done
docker info > /dev/null 2>&1 || { say "STOP docker not usable by $(whoami) (log out and in after usermod?)"; exit 1; }

if [ ! -d "$CODE/.git" ]; then
  aws s3 cp --only-show-errors "s3://$BUCKET/code/$COMMIT.bundle" /tmp/code.bundle
  git clone -q /tmp/code.bundle "$CODE"
fi
git -C "$CODE" checkout -q "$COMMIT"
[ "$(git -C "$CODE" rev-parse HEAD)" = "$COMMIT" ] || { say "STOP code is not $COMMIT"; exit 1; }
[ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || { say "STOP code tree dirty"; exit 1; }

command -v uv > /dev/null || { curl -LsSf https://astral.sh/uv/install.sh | sh; }
export PATH=$HOME/.local/bin:$PATH
if [ ! -x "$CODE/.venv/bin/python" ]; then
  uv venv -q --python 3.13 "$CODE/.venv"
  uv pip install -q --python "$CODE/.venv/bin/python" -r "$CODE/src/python/requirements.lock"
fi
. "$CODE/.venv/bin/activate"

# Protobuf code (gitignored): the Python half of src/scripts/gen-proto.sh, no Go needed.
if [ ! -d "$CODE/src/python/gen/microtrace/v0" ]; then
  WKT=$(python -c 'import grpc_tools, os; print(os.path.join(os.path.dirname(grpc_tools.__file__), "_proto"))')
  mkdir -p "$CODE/src/python/gen"
  (cd "$CODE/spec/proto" && python -m grpc_tools.protoc -I . -I "$WKT" --python_out="$CODE/src/python/gen" \
     --pyi_out="$CODE/src/python/gen" microtrace/v0/*.proto)
fi

if [ "${MT_SKIP_SAGE:-0}" != 1 ] && [ ! -x "$SAGE/FlexFringe/flexfringe" ]; then   # MT_SKIP_SAGE=1: jobs without SAGE
  MT_DEV=$HOME MT_SAGE_HOME=$SAGE bash "$CODE/src/scripts/baselines/fetch-sage.sh" >> "$LOG" 2>&1
fi

cat > "$HOME/mt-env.sh" <<EOF
export PATH=$HOME/.local/bin:\$PATH
export CODE=$CODE VENV=$CODE/.venv MT_SAGE_HOME=$SAGE
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
EOF
. "$HOME/mt-env.sh"

# Prerequisite checks the runners rely on.
python - <<'PY'
import numpy, sklearn
import mtcore  # noqa: F401  (puts src/python/gen on the path)
from microtrace.v0 import envelope_pb2, dataset_pb2  # noqa: F401
from mtcore.agents.params import Params
from mtcore.agents.ml.scorer import Scorer
import os
p = Params.load(os.path.join(os.environ["CODE"], "src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml"))
Scorer.load(p)                       # model files exist and pass their content hash
print("python ok", numpy.__version__, sklearn.__version__)
PY
python -m pytest -q "$CODE/src/python/tests/test_seal.py" "$CODE/src/python/tests/test_score_pilot_stages.py" \
  "$CODE/src/python/tests/test_params_models.py" >> "$LOG" 2>&1 || { say "STOP tests failed (see $LOG)"; exit 1; }
say "clock: $(chronyc -n tracking | grep -E 'Reference ID|System time' | xargs)"
say "clock source file: $(tail -1 /var/log/mt-clock.txt 2>/dev/null)"
say "READY code $COMMIT, python $(python -V), sage $(git -C "$SAGE/SAGE" rev-parse --short HEAD 2>/dev/null || echo skipped)"
