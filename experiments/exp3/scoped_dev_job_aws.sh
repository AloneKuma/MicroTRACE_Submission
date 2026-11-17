#!/usr/bin/env bash
# Scoped loss, development check (2026-11-17, post-hoc fix after the held-out Exp. 3 loss rows).
# Unattended: mt-job.service on an ANALYSIS machine (Terraform -var autorun=true
# -var job_script=experiments/exp3/scoped_dev_job_aws.sh), as ubuntu, with BUCKET, COMMIT, SESSION.
# Development data only (PILOT FIT runs); no held-out data is read.
#
# 1. Bootstrap (Python + Go; the Go protobuf code is generated from this commit's ship.proto),
#    then the Go unit tests of the injector and receiver (scope of a gap notice, merge of scopes).
# 2. The first N PILOT FIT runs by run ID (input-only choice) through the real transport
#    (mtcore.exp3.run --role local: injector, shipper, receiver, Kafka) under nofault-fast
#    (no fault, at once), loss-transit-05 and loss-transit-10, with three GO passes on each
#    received stream: full (frozen, node-wide loss), full_scoped (same + scoped_loss) and
#    no_coverage (loss ignored), then scored against development truth.
# Expected if the fix works: full_scoped equals full without faults, and under loss keeps most of
# no_coverage's path recall with a false-chain rate near full's no-fault one.
# Output: s3://$BUCKET/results/$SESSION/ (STATUS, exp3-summary.*, go-test.log, logs).
set -uo pipefail
: "${BUCKET:?}" "${COMMIT:?}" "${SESSION:?}"
N=${N:-24}; SLOTS=${SLOTS:-8}; WORKERS=${WORKERS:-8}
R=s3://$BUCKET/results/$SESSION; S=$HOME/JOB_STATUS; W=$HOME/sdev
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS"; }
up() { aws s3 sync --only-show-errors "$W" "$R/work" --exclude '*/received/*' --exclude '*/slots/*' \
         --exclude '*/base/*' --exclude '*.jsonl' --exclude '*/output.jsonl.gz' ; }
st "START scoped-loss dev check, code $COMMIT"
(cd ~/code/experiments/heldout && BUCKET=$BUCKET COMMIT=$COMMIT bash bootstrap.sh > ~/bootstrap.log 2>&1) \
  || { st "FAILED bootstrap $(tail -2 ~/bootstrap.log)"; exit 1; }
. ~/mt-env.sh
ROLE=analysis bash ~/code/experiments/exp3/bootstrap_exp3.sh > ~/bootstrap_exp3.log 2>&1 \
  || { st "FAILED bootstrap_exp3 $(tail -3 ~/bootstrap_exp3.log | tr '\n' ' ')"; aws s3 cp --only-show-errors ~/bootstrap_exp3.log "$R/"; exit 1; }
. ~/mt-env.sh; . "$VENV/bin/activate"; export PYTHONPATH=$HOME/code/src/python PYTHONHASHSEED=1
st "READY $(tail -1 ~/bootstrap_exp3.log)"

(cd ~/code/src/go && go test ./internal/faults/ ./internal/receiver/ > ~/go-test.log 2>&1); rc=$?
aws s3 cp --only-show-errors ~/go-test.log "$R/go-test.log"
[ $rc -eq 0 ] || { st "FAILED go test (go-test.log)"; exit 1; }
st "GO_TEST ok"
(cd ~/code/src/python && python -m pytest -q tests/test_scoped_loss.py tests/test_orch_admission.py \
   tests/test_agent_gaps.py tests/test_gapindex_equivalence.py > ~/py-test.log 2>&1); rc=$?
aws s3 cp --only-show-errors ~/py-test.log "$R/py-test.log"
[ $rc -eq 0 ] || { st "FAILED python tests (py-test.log)"; exit 1; }
st "PY_TEST $(tail -1 ~/py-test.log)"

mkdir -p ~/dev ~/devman "$W/cfg"
aws s3 sync --only-show-errors s3://$BUCKET/dev/pilot-fit/ ~/devman/ --exclude '*' --include '*/manifest.json'
python - "$N" > "$W/runs.json" <<'PY'
import glob, json, os, sys
runs = sorted(os.path.basename(os.path.dirname(m)) for m in glob.glob(os.path.expanduser("~/devman/*/manifest.json")))
print(json.dumps({"runs": runs[:int(sys.argv[1])]}))
PY
for r in $(python -c "import json; print(' '.join(json.load(open('$W/runs.json'))['runs']))"); do
  aws s3 sync --only-show-errors "s3://$BUCKET/dev/pilot-fit/$r" ~/dev/$r
done
st "DEV $(ls ~/dev | wc -l) runs"

cd ~/code
mkdir -p "$W/plans"; cp experiments/exp3/plans/*.yaml "$W/plans/"     # templates resolve next to cfg/
cp experiments/exp3/configs/conditions.tsv "$W/cfg/conditions.tsv"
printf 'nofault-fast\tnofault.yaml\toffline\t0\t1\t-\tno fault, at once\n' >> "$W/cfg/conditions.tsv"
MAIN=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml
printf '%s\n' "full	go	@main	-	-	-	*" \
  "full_scoped	go	src/params/frozen/pilot-multistep-fit.K10.mlv2.scoped-loss.yaml	-	-	-	*" \
  "no_coverage	go	@main	no_coverage	-	-	*" > "$W/cfg/passes.tsv"
ONLY=nofault-fast,loss-transit-05,loss-transit-10
common=(--data "$HOME/dev" --runs "$W/runs.json:runs" --conditions "$W/cfg/conditions.tsv" --passes "$W/cfg/passes.tsv"
        --main-params "$MAIN" --workers "$WORKERS")
t0=$(date +%s)
python -m mtcore.exp3.run --role local "${common[@]}" --slots "$SLOTS" --work "$W" --only "$ONLY" > ~/run.log 2>&1
rc=$?; aws s3 cp --only-show-errors ~/run.log "$R/run.log"
st "DETECT exit $rc after $(( ($(date +%s) - t0) / 60 )) min"
python -m mtcore.exp3.run --role score "${common[@]}" --work "$W" --truth-root "$HOME/dev" --only "$ONLY" > ~/score.log 2>&1
rc2=$?; aws s3 cp --only-show-errors ~/score.log "$R/score.log"
python -m mtcore.exp3.summary --work "$W" > ~/summary.log 2>&1
aws s3 cp --only-show-errors "$W/exp3-summary.md" "$R/exp3-summary.md"
aws s3 cp --only-show-errors "$W/exp3-summary.json" "$R/exp3-summary.json"
up
st "SCORE exit $rc2; summary $(test -f "$W/exp3-summary.md" && echo ok || echo missing)"
st "ALL_DONE"
