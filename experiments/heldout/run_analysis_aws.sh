#!/usr/bin/env bash
# MicroTRACE and SAGE detection passes on the AWS analysis host (docs/plans/heldout-aws-plan.md).
# One configuration at a time, WORKERS parallel worker processes each (8, decision 2026-11-11),
# --stage detect only: no truth is on this machine and none is read. Scoring happens later,
# once, in the scoring session (score_heldout.sh). Run after bootstrap.sh (it writes ~/mt-env.sh).
#
#   . ~/mt-env.sh; BUCKET=<work bucket> HELDOUT_BUCKET=<sealed bucket> SESSION=<name> \
#     CONFIGS=configs/<file>.tsv nohup bash run_analysis_aws.sh > run.out 2>&1 &
#
# CONFIGS: one line per pass, tab-separated, '#' comments:
#   name  correlator  params(repo-relative)  set  split(repo-relative)  half  [findings_from  [sage_variant]]
# correlator is go or sage; for sage, findings_from names an earlier go pass of this file; for go,
# that column may be drop:EBPF|GATEWAY|KYVERNO|AUDIT (Exp. 1 telemetry ablation). Two
# sage passes on the same findings share one SAGE computation (the second copies its sage/).
# set is the held-out set folder under s3://$HELDOUT_BUCKET/heldout/runs/ (held_out, held_out_cases),
# checked against experiments/heldout/manifests/<set>.tsv after download.
#
# Resumable: on start it pulls s3://$BUCKET/results/$SESSION/ back, so finished passes and runs
# (time.json with the same params and code) are skipped after a Spot interruption or cost cap.
# Output: s3://$BUCKET/results/$SESSION/: STATUS, timing.tsv, logs/, <pass>/runs/<run>/
# (output.jsonl.gz, time.json, offline.log). The machine shuts down when the script exits
# (AUTO_SHUTDOWN=0 turns that off); prerequisite failures exit before the trap is set.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BUCKET:?set BUCKET}" "${HELDOUT_BUCKET:?set HELDOUT_BUCKET}" "${SESSION:?set SESSION}" "${CONFIGS:?set CONFIGS}"
CODE=${CODE:-$HOME/code}; DATA=${DATA:-$HOME/data}; OUT=${OUT:-$HOME/results}
WORKERS=${WORKERS:-8}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}; VENV=${VENV:-$CODE/.venv}
CONFIGS=$(cd "$(dirname "$CONFIGS")" && pwd)/$(basename "$CONFIGS")
R="s3://$BUCKET/results/$SESSION"
mkdir -p "$OUT/logs"; S=$OUT/STATUS
status() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }

# Prerequisites (no shutdown on these: fix and rerun).
. "$VENV/bin/activate" || { status "FAILED venv $VENV"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=1
[ -d "$CODE/src/python/gen/microtrace/v0" ] || { status "FAILED no generated protobuf code (bootstrap.sh)"; exit 1; }
[ -x /usr/bin/time ] || { status "FAILED /usr/bin/time missing: peak memory would not be recorded"; exit 1; }
if grep -v '^#' "$CONFIGS" | awk -F'\t' '$2 == "sage"' | grep -q .; then
  [ -n "${MT_SAGE_HOME:-}" ] && [ -d "$MT_SAGE_HOME/SAGE" ] || { status "FAILED MT_SAGE_HOME not set (bootstrap.sh)"; exit 1; }
fi
[ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || { status "FAILED code tree has local changes"; exit 1; }

aws s3 sync --only-show-errors "$R" "$OUT" < /dev/null || true          # resume after an interruption
sync_up() {
  aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null
  [ -f "$OUT/timing.tsv" ] && aws s3 cp --only-show-errors "$OUT/timing.tsv" "$R/timing.tsv" < /dev/null
  aws s3 sync --only-show-errors --no-follow-symlinks "$OUT" "$R" --exclude "STATUS" --exclude "timing.tsv" \
    --exclude "*.tmp" --exclude "*/output.jsonl" < /dev/null
}
(
  n=0
  while true; do
    echo "$(date -u +%T) avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)" \
         "load=$(cut -d' ' -f1 /proc/loadavg)" \
         "max_py_rss_mb=$(ps -C python,python3 -o rss= 2>/dev/null | sort -n | tail -1 | awk '{print int($1/1024)}')" \
         >> "$OUT/logs/memory.log"
    n=$((n + 1)); [ $((n % 60)) -eq 0 ] && sync_up
    sleep 15
  done
) &
SAMPLER=$!
finish() {
  kill $SAMPLER 2>/dev/null
  sync_up
  if [ "$AUTO_SHUTDOWN" = 1 ]; then status "SHUTDOWN after final copy"; sync_up; sudo shutdown -h now; fi
}
trap finish EXIT

status "START $(nproc) cpu, $(free -g | awk '/Mem:/ {print $2}') GB, $(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null)," \
       "code $(git -C "$CODE" rev-parse --short HEAD), workers $WORKERS, configs $CONFIGS ($(sha256sum "$CONFIGS" | cut -c1-12))," \
       "clock $(tail -1 /var/log/mt-clock.txt 2>/dev/null)"

# The seal: this role may list heldout/truth/ but must not read it. Only AccessDenied counts.
list=$(aws s3api list-objects-v2 --bucket "$HELDOUT_BUCKET" --prefix heldout/truth/ --max-keys 1 --no-paginate \
         --query 'Contents[0].Key' --output text < /dev/null 2>&1) || { status "FAILED seal check: cannot list ($list)"; exit 1; }
if [ "$list" = None ] || [ -z "$list" ]; then status "FAILED seal check: no truth objects listed (wrong bucket?)"; exit 1; fi
err=$(aws s3api get-object --bucket "$HELDOUT_BUCKET" --key "$list" /dev/null < /dev/null 2>&1 >/dev/null)
case "$err" in
  *AccessDenied*) status "SEAL ok: truth not readable here (AccessDenied)" ;;
  "") status "FAILED seal: this machine can read $list"; exit 1 ;;
  *) status "FAILED seal check inconclusive: $err"; exit 1 ;;
esac

# Fetch each held-out set once and check it against its frozen manifest.
for set in $(grep -v '^#' "$CONFIGS" | awk -F'\t' 'NF {print $4}' | sort -u); do
  if [ ! -f "$DATA/.fetched-$set" ]; then
    aws s3 sync --only-show-errors --no-follow-symlinks "s3://$HELDOUT_BUCKET/heldout/runs/$set" "$DATA/$set" < /dev/null \
      || { status "FAILED fetch $set"; exit 1; }
    bash "$HERE/check_fetch.sh" "$DATA/$set" "$HERE/manifests/$set.tsv" "$CODE" >> "$S" 2>&1 \
      || { status "FAILED $set does not match manifests/$set.tsv"; exit 1; }
    touch "$DATA/.fetched-$set"
  fi
  status "DATA $set $(find "$DATA/$set" -mindepth 1 -maxdepth 1 -type d | wc -l) runs, $(du -sh "$DATA/$set" | cut -f1)"
done
sync_up

[ -f "$OUT/timing.tsv" ] || printf 'pass\texit\twall_s\truns\tsum_run_wall_s\tmax_run_rss_mb\tsum_run_cpu_s\tnote\n' > "$OUT/timing.tsv"
mapfile -t PASSES < <(grep -v '^#' "$CONFIGS" | grep .)
failed=0
for line in "${PASSES[@]}"; do
  IFS=$'\t' read -r name corr params set split half from variant <<< "$line"
  if awk -F'\t' -v n="$name" '$1 == n && $2 == 0' "$OUT/timing.tsv" | grep -q .; then status "SKIP $name (done)"; continue; fi
  args=(--pilot "$DATA/$set" --split "$CODE/$split" --half "$half" --params "$CODE/$params"
        --out-dir "$OUT/$name" --workers "$WORKERS" --stage detect)
  # A go pass may carry drop:<SOURCE> in the findings_from column: the Exp. 1 telemetry ablation
  # (score_pilot.py --drop-source; decided 2026-11-15).
  case "$from" in drop:*) [ "$corr" = go ] && args+=(--drop-source "${from#drop:}") ;; esac
  note=""
  if [ "$corr" = sage ]; then
    args+=(--correlator sage --findings-from "$OUT/$from" --sage-variant "${variant:-ag}")
    # One SAGE computation per findings source: reuse a finished one of an earlier sage pass.
    for prev in "${PASSES[@]}"; do
      IFS=$'	' read -r pn pc _ _ _ _ pf _ <<< "$prev"
      [ "$pn" = "$name" ] && break
      [ "$pc" = sage ] && [ "$pf" = "$from" ] && [ -f "$OUT/$pn/sage/run.json" ] || continue
      python3 -c "import json,sys;sys.exit(json.load(open('$OUT/$pn/sage/run.json')).get('sage_status')=='failed')" || continue
      mkdir -p "$OUT/$name" && rm -rf "$OUT/$name/sage" && cp -r "$OUT/$pn/sage" "$OUT/$name/sage"
      note="sage copied from $pn"; break
    done
  fi
  status "RUN $name: $corr $params on $set ($half) $note"
  t0=$(date +%s.%N)
  (cd "$CODE" && python src/scripts/pilot/score_pilot.py "${args[@]}" < /dev/null) > "$OUT/logs/$name.log" 2>&1
  rc=$?; wall=$(python3 -c "print(round($(date +%s.%N) - $t0, 1))")
  python3 - "$OUT/$name" "$name" "$rc" "$wall" "$note" >> "$OUT/timing.tsv" < /dev/null <<'PY'
import glob, json, os, sys
d, name, rc, wall, note = sys.argv[1:]
t = [json.load(open(f)) for f in glob.glob(os.path.join(d, "runs", "*", "time.json"))]
rss = [x["peak_rss_mb"] for x in t if x.get("peak_rss_mb") is not None]
sage = os.path.join(d, "sage", "run.json")
if os.path.exists(sage) and not t:
    note = (note + "; " if note else "") + f"sage_seconds {json.load(open(sage)).get('sage_seconds')}"
cpu = [x["cpu_user_s"] + x["cpu_sys_s"] for x in t if x.get("cpu_user_s") is not None and x.get("cpu_sys_s") is not None]
print("\t".join(map(str, (name, rc, wall, len(t), round(sum(x["wall_s"] for x in t), 1), max(rss) if rss else "-",
                          round(sum(cpu), 1) if cpu else "-", note))))
PY
  [ "$rc" = 0 ] || failed=$((failed + 1))
  status "DONE $name exit $rc in ${wall}s"
  sync_up
done
if [ "$failed" -gt 0 ]; then status "FAILED_PASSES $failed"; exit 1; fi
status "ALL_DONE"
