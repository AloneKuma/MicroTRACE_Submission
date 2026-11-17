#!/usr/bin/env bash
# Freeze of the chosen ML setting (qmax_confirmB3, user choice 2026-11-10): Isolation Forests for B, G, H
# trained on the whole PILOT FIT half (proper / calibration halves as for the Q thresholds) with the frozen
# K10 parameter set, gamma at alpha 0.001. Code ~/microtrace-ml/code3 (CODE3_COMMIT). Writes
# ~/microtrace-ml/freeze/{rows,models}; STATUS lines prefixed FREEZE; ends FREEZE_DONE.
# Needs ~/microtrace-ml/freeze/pilot-multistep-fit.K10.yaml (copied from src/params/frozen/).
set -uo pipefail
W=$HOME/microtrace-ml; S=$W/STATUS; CODE=$W/code3; Z=$W/freeze
D=$HOME/microtrace-pilot-multistep/pilot-multistep
NW=${NW:-5}
st() { echo "$(date -u +%FT%TZ) FREEZE $*" | tee -a "$S"; }
. "$HOME/microtrace-pilot-multistep/code/.venv/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || exit 1
X() { python src/scripts/pilot/crossfit_ml.py "$@"; }
P=$Z/pilot-multistep-fit.K10.yaml
[ -f $P ] || { st "STOP no $P"; exit 1; }
st "START code $(cat $W/CODE3_COMMIT) params $(sha256sum $P | cut -c1-12) runs $(python -c "import json;print(len(json.load(open('$W/folds.json'))['all']))")"
X extract --pilot $D --params $P --runs $W/folds.json:all --out-dir $Z/rows --workers $NW 2> $Z/rows.log \
  || { st "STOP extract"; exit 1; }
X train --pilot $D --params $P --rows-dir $Z/rows --runs $W/folds.json:all --out-dir $Z/models --alphas 0.001 \
  > $Z/models.log 2>&1 || { st "STOP train"; exit 1; }
st "models $(cat $Z/models.log)"
st "gamma $(python -c "import json;print(json.dumps(json.load(open('$Z/models/train.json'))['gamma']))")"
st "FREEZE_DONE disk $(df -h ~ | awk 'END{print $4}') free"
