#!/usr/bin/env bash
# Reference arms (rule addendum 2026-11-09, user option B): cross-fitted max thresholds,
# rules-only (qmax_gnone) and with ML at alpha_g 0.001 (qmax_g0.001). Starts after CV_DONE.
# Code in ~/microtrace-ml/code2 (CODE2_COMMIT). STATUS ends ARMS_DONE.
set -uo pipefail
W=$HOME/microtrace-ml; S=$W/STATUS; CODE=$W/code2
D=$HOME/microtrace-pilot-multistep/pilot-multistep; G=$D/_gates
BASE=$G/pilot-multistep-fit.yaml
NW=${NW:-6}; SW=${SW:-5}
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
# Anchored on the timestamp "Z " so free text in STATUS notes cannot trigger the start.
until grep -qE "Z (CV_DONE disk|STOP)" $S; do sleep 120; done
grep -qE "Z STOP" $S && { st "ARMS not started (CV stopped)"; exit 1; }
. "$HOME/microtrace-pilot-multistep/code/.venv/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || exit 1
X() { python src/scripts/pilot/crossfit_ml.py "$@"; }
other() { [ "$1" = A ] && echo B || echo A; }
st "ARMS_START code $(cat $W/CODE2_COMMIT) rule $(sha256sum $W/RULE.md | cut -c1-12)"
for F in A B; do
  T=$(other $F); P=$W/params/fold$F-qmax.yaml
  [ -f $P ] || X params --threshold max --pilot $D --cache $W/fitcache.pkl --base $BASE --runs $W/folds.json:$T \
      --version PILOT-CV-fold$F-qmax --out $P > $W/params/fold$F-qmax.log 2>&1 || { st "STOP params max $F"; exit 1; }
  X extract --pilot $D --params $P --runs $W/folds.json:$T --out-dir $W/rows/fold$F-max --workers $NW \
      2> $W/rows/fold$F-max.log || { st "STOP extract max $F"; exit 1; }
  [ -f $W/models/fold$F-max/train.json ] || X train --pilot $D --params $P --rows-dir $W/rows/fold$F-max \
      --runs $W/folds.json:$T --out-dir $W/models/fold$F-max --alphas 0.001 > $W/models/fold$F-max.log 2>&1 \
      || { st "STOP train max $F"; exit 1; }
  st "fold$F max models: $(cat $W/models/fold$F-max.log)"
  cp $P $W/cfg/fold$F-qmax_gnone.yaml
  X config --params $P --models $W/models/fold$F-max --alpha-g 0.001 --version PILOT-CV-fold$F-qmax_g0.001 \
      --out $W/cfg/fold$F-qmax_g0.001.yaml || { st "STOP config max $F"; exit 1; }
done
for C in qmax_gnone qmax_g0.001; do
  [ -f $W/cv/$C/DONE ] && continue
  for F in A B; do
    python src/scripts/pilot/score_pilot.py --pilot $D --split $W/test$F.json --half fit --params $W/cfg/fold$F-$C.yaml \
        --out-dir $W/cv/$C --workers $SW > $W/cv/$C.fold$F.log 2>&1 || st "$C fold$F score exit $?"
  done
  st "$C $(X summarize --pilot $D --out-dir $W/cv/$C --runs $W/folds.json:all)"
  rm -f $W/cv/$C/runs/*/output.jsonl.gz; touch $W/cv/$C/DONE
done
st "select (with arms) $(X select --cv-dir $W/cv --out $W/selection.json)"
st "ARMS_DONE disk $(df -h ~ | awk 'END{print $4}') free"
