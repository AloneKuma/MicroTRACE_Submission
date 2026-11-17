#!/usr/bin/env bash
# Cross-fitted choice of alpha_q / alpha_g on the PILOT FIT half
# (docs/plans/ml-threshold-crossfit-plan.md; rule in ~/microtrace-ml/RULE.md).
# Resumable: each stage skips work already done. STATUS ends CV_DONE.
set -uo pipefail
W=$HOME/microtrace-ml; S=$W/STATUS; CODE=$W/code
D=$HOME/microtrace-pilot-multistep/pilot-multistep; G=$D/_gates
BASE=$G/pilot-multistep-fit.yaml; SPLIT=$G/pilot-multistep-split.json
NW=${NW:-6}; SW=${SW:-5}
ALPHAS="0.01 0.001 0.0001"
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
. "$HOME/microtrace-pilot-multistep/code/.venv/bin/activate"
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
cd "$CODE" || exit 1
X() { python src/scripts/pilot/crossfit_ml.py "$@"; }
other() { [ "$1" = A ] && echo B || echo A; }

st "CV_START code $(cat $W/CODE_COMMIT) rule $(sha256sum $W/RULE.md | cut -c1-12)"
[ -f $W/fitcache.pkl ] || { X fitcache --pilot $D --runs $SPLIT:fit --base $BASE --out $W/fitcache.pkl \
    --workers $NW 2> $W/fitcache.log || { st "STOP fitcache"; exit 1; }; }
st "checkmax $(X checkmax --pilot $D --cache $W/fitcache.pkl --base $BASE)" || true
X checkmax --pilot $D --cache $W/fitcache.pkl --base $BASE > /dev/null || { st "STOP checkmax differs"; exit 1; }
[ -f $W/folds.json ] || X folds --pilot $D --runs $SPLIT:fit --out $W/folds.json
for F in A B; do python -c "import json;d=json.load(open('$W/folds.json'));json.dump({'fit':d['$F']},open('$W/test$F.json','w'))"; done

# models for testing fold F are fitted on the other fold
mkdir -p $W/params $W/rows $W/models $W/cfg $W/cv
for F in A B; do
  T=$(other $F)
  for Q in $ALPHAS; do
    P=$W/params/fold$F-q$Q.yaml
    [ -f $P ] || X params --pilot $D --cache $W/fitcache.pkl --base $BASE --runs $W/folds.json:$T --alpha $Q \
        --version PILOT-CV-fold$F-q$Q --out $P > $W/params/fold$F-q$Q.log 2>&1 \
        || { st "fold$F q$Q infeasible ($(tail -1 $W/params/fold$F-q$Q.log))"; rm -f $P; }
  done
  P=$(ls $W/params/fold$F-q*.yaml | head -1)
  X extract --pilot $D --params $P --runs $W/folds.json:$T --out-dir $W/rows/fold$F --workers $NW \
      2> $W/rows/fold$F.log || { st "STOP extract fold$F"; exit 1; }
  [ -f $W/models/fold$F/train.json ] || X train --pilot $D --params $P --rows-dir $W/rows/fold$F \
      --runs $W/folds.json:$T --out-dir $W/models/fold$F > $W/models/fold$F.log 2>&1 \
      || { st "STOP train fold$F"; exit 1; }
  st "fold$F models: $(cat $W/models/fold$F.log)"
done

ok() { python -c "import json,sys;print(json.load(open('$W/models/fold$1/train.json'))['feasible']['$2'])"; }
for Q in $ALPHAS; do
  for A in $ALPHAS; do
    C=q${Q}_g${A}
    if [ ! -f $W/params/foldA-q$Q.yaml ] || [ ! -f $W/params/foldB-q$Q.yaml ] \
       || [ "$(ok A $A)" != True ] || [ "$(ok B $A)" != True ]; then st "$C dropped (not feasible)"; continue; fi
    [ -f $W/cv/$C/summary.json ] && [ -f $W/cv/$C/DONE ] && continue
    for F in A B; do
      CF=$W/cfg/fold$F-$C.yaml
      X config --params $W/params/fold$F-q$Q.yaml --models $W/models/fold$F --alpha-g $A \
          --version PILOT-CV-fold$F-$C --out $CF || { st "STOP config $C $F"; exit 1; }
      python src/scripts/pilot/score_pilot.py --pilot $D --split $W/test$F.json --half fit --params $CF \
          --out-dir $W/cv/$C --workers $SW > $W/cv/$C.fold$F.log 2>&1 || st "$C fold$F score exit $?"
    done
    st "$C $(X summarize --pilot $D --out-dir $W/cv/$C --runs $W/folds.json:all)"
    rm -f $W/cv/$C/runs/*/output.jsonl.gz; touch $W/cv/$C/DONE
  done
done
st "select $(X select --cv-dir $W/cv --out $W/selection.json)"
st "CV_DONE disk $(df -h ~ | awk 'END{print $4}') free"
