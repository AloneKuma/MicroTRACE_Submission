#!/usr/bin/env bash
# Scalability supplement (user decision 2026-11-17, post-freeze, disclosed as such): SAGE on nested
# Core subsets of 41, 82, 164 and 328 held-out runs (held_out_s<N>.json: the first N runs ordered by
# sha256(run id)), three repeats each, seeded from the scored heldout-a/go_main findings. The GO side
# needs no run (summed from the Exp. 4 timing session's per-run times); seeded ORTHRUS is a separate job.
#
# Unattended: started by mt-job.service on an ANALYSIS machine (Terraform -var autorun=true
# -var job_script=experiments/exp4/scaling/sage_job.sh) as ubuntu, with BUCKET, COMMIT and SESSION set.
# No truth is read. Each pass gets its own copy of the subset's GO findings, so run_analysis_aws.sh
# computes SAGE afresh for every pass (it reuses a computation only between passes with the same
# findings folder). Output: s3://$BUCKET/results/$SESSION/ (STATUS, timing.tsv, sage_*/sage/run.json).
set -uo pipefail
: "${BUCKET:?}" "${COMMIT:?}" "${SESSION:?}"
export HELDOUT_BUCKET=${HELDOUT_BUCKET:-<SEALED_BUCKET>}
CODE=${CODE:-$HOME/code}; OUT=${OUT:-$HOME/results}; SRC=${SRC:-heldout-a/go_main}
PARAMS=src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml
mkdir -p "$OUT/logs"
echo "$(date -u +%FT%TZ) START sage scaling job, code ${COMMIT:0:7}" | tee -a "$OUT/STATUS"
aws s3 cp --only-show-errors "$OUT/STATUS" "s3://$BUCKET/results/$SESSION/STATUS" < /dev/null

stop() { echo "$(date -u +%FT%TZ) STOP $*" >> "$OUT/STATUS"
         aws s3 sync --only-show-errors "$OUT" "s3://$BUCKET/results/$SESSION" < /dev/null; exit 1; }
BUCKET=$BUCKET COMMIT=$COMMIT bash "$CODE/experiments/heldout/bootstrap.sh" > "$OUT/logs/bootstrap.log" 2>&1 \
  || stop "bootstrap (logs/bootstrap.log)"
. "$HOME/mt-env.sh"

# The scored GO findings once, then per pass a folder with only the subset's runs.
G=$HOME/go_main
aws s3 sync --only-show-errors "s3://$BUCKET/results/$SRC/runs" "$G/runs" --exclude '*' --include '*/output.jsonl.gz' < /dev/null \
  || stop "fetch $SRC"
[ "$(find "$G/runs" -name output.jsonl.gz | wc -l)" = 328 ] || stop "$SRC: expected 328 outputs"
CFG=$HOME/sage-scaling.tsv; : > "$CFG"
for n in 41 82 164 328; do
  if [ "$n" = 328 ]; then split=experiments/heldout/splits/held_out.json; else split=experiments/exp4/scaling/held_out_s$n.json; fi
  runs=$(python3 -c "import json,sys;print(' '.join(json.load(open(sys.argv[1]))['held_out']))" "$CODE/$split")
  for rep in 1 2 3; do
    f=go_s${n}_r$rep
    # Hard links outside $OUT, linked in by a symlink: the runner's uploads skip symlinks, so the
    # findings (about 28 MB per run) are not copied back to S3.
    for r in $runs; do mkdir -p "$HOME/gof/$f/runs/$r" && ln -f "$G/runs/$r/output.jsonl.gz" "$HOME/gof/$f/runs/$r/" || stop "link $r"; done
    ln -sfn "$HOME/gof/$f" "$OUT/$f"
    printf 'sage_s%s_r%s\tsage\t%s\theld_out\t%s\theld_out\t%s\tag\n' "$n" "$rep" "$PARAMS" "$split" "$f" >> "$CFG"
  done
  echo "$(date -u +%FT%TZ) FINDINGS s$n: $(echo $runs | wc -w) runs x 3" >> "$OUT/STATUS"
done

# Memory (user request 2026-11-17): every second, the machine's used memory (MemTotal - MemAvailable)
# and the largest RSS of any python or flexfringe process; each pass's peak is read against the pass
# start and end times in STATUS. SAGE passes take seconds, so a 1 s sample is the resolution.
(
  echo -e "utc\tused_mb\tmax_proc_rss_mb\tproc" > "$OUT/memsample.tsv"
  while true; do
    used=$(awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print int((t-a)/1024)}' /proc/meminfo)
    top=$(ps -C python,python3,flexfringe -o rss=,comm= 2>/dev/null | sort -n | tail -1 | awk '{print int($1/1024) "\t" $2}')
    echo -e "$(date -u +%FT%T.%3NZ)\t$used\t${top:-0	-}" >> "$OUT/memsample.tsv"
    sleep 1
  done
) &
cd "$CODE" && BUCKET=$BUCKET SESSION=$SESSION CONFIGS=$CFG OUT=$OUT bash experiments/heldout/run_analysis_aws.sh
