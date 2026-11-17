#!/usr/bin/env bash
# Test host -> S3, one build batch of held-out runs (docs/plans/heldout-aws-plan.md).
# Each run folder is split by mtcore.harness.seal (refuses symlinks and unknown entries):
#   readable part -> s3://$HELDOUT_BUCKET/heldout/runs/<set>/<run>/   shipper files without the
#                    ground.truth.v0 lines, evidence/, context_history.jsonl, redacted manifest
#   truth part    -> s3://$HELDOUT_BUCKET/heldout/truth/<set>/<run>/  restricted/, base.pb, full
#                    manifest, the removed shipper lines (sealed by the bucket policy)
# Each part gets a SHA256SUMS. The uploader role can put but not read, so the upload is checked
# by listing (every local file present with the same size). Only then, and only with DELETE=1,
# is the local run folder removed. A run already in S3 is never uploaded again (no silent
# replacement; a changed run must get a new run ID).
#
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \   (uploader role, 12 h)
#   HELDOUT_BUCKET=<sealed bucket> SET=held_out SRC=<batch dir> CODE=<repo checkout> [DELETE=1] \
#     bash upload_batch.sh
# The sealed bucket has Object Lock, so every put needs a checksum: AWS CLI v2.23+ (checked).
set -uo pipefail
: "${HELDOUT_BUCKET:?}" "${SET:?}" "${SRC:?}" "${CODE:?}"
DELETE=${DELETE:-0}; VENV=${VENV:-$HOME/microtrace-pilot-multistep/code/.venv}
WORK=${WORK:-$SRC/.seal}
S=$SRC/UPLOAD_STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
aws sts get-caller-identity --query Arn --output text | grep -q "MicroTRACE-heldout-uploader" \
  || { st "STOP not running as the uploader role"; exit 1; }
v=$(aws --version 2>&1 | sed -n 's#^aws-cli/\([0-9]*\)\.\([0-9]*\).*#\1 \2#p')
read -r vmaj vmin <<< "${v:-0 0}"
{ [ "$vmaj" -gt 2 ] || { [ "$vmaj" = 2 ] && [ "$vmin" -ge 23 ]; }; } \
  || { st "STOP AWS CLI $(aws --version 2>&1 | cut -d' ' -f1) too old for Object Lock puts (need v2.23+)"; exit 1; }
. "$VENV/bin/activate" || { st "STOP venv $VENV"; exit 1; }
export PYTHONPATH=$CODE/src/python PYTHONDONTWRITEBYTECODE=1
B=s3://$HELDOUT_BUCKET/heldout
st "START batch $SRC set $SET delete $DELETE code $(git -C "$CODE" rev-parse --short HEAD)"
n=0; bad=0
for d in "$SRC"/*/; do
  d=${d%/}; run=$(basename "$d"); [ -f "$d/manifest.json" ] || continue
  if [ -n "$(aws s3api list-objects-v2 --bucket "$HELDOUT_BUCKET" --prefix "heldout/runs/$SET/$run/" --max-keys 1 --no-paginate \
              --query 'Contents[0].Key' --output text < /dev/null 2>/dev/null | grep -v '^None$')" ]; then
    st "SKIP $run already in S3 (never replaced)"; continue
  fi
  r=$WORK/$run/readable; t=$WORK/$run/truth
  rm -rf "$WORK/$run"; mkdir -p "$WORK/$run"
  python -m mtcore.harness.seal "$d" --readable "$r" --truth "$t" < /dev/null >> "$S" 2>&1 \
    || { st "FAILED seal $run"; bad=$((bad + 1)); continue; }
  for part in "$r" "$t"; do
    (cd "$part" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  done
  aws s3 sync --only-show-errors --no-progress --no-follow-symlinks "$r" "$B/runs/$SET/$run/" < /dev/null \
    || { st "FAILED upload runs $run"; bad=$((bad + 1)); continue; }
  aws s3 sync --only-show-errors --no-progress --no-follow-symlinks "$t" "$B/truth/$SET/$run/" < /dev/null \
    || { st "FAILED upload truth $run"; bad=$((bad + 1)); continue; }
  ok=$(python3 - "$r" "$t" "$HELDOUT_BUCKET" "$SET" "$run" < /dev/null <<'PY'
import json, os, subprocess, sys
r, t, bucket, sset, run = sys.argv[1:]
def listing(prefix):
    out = subprocess.run(["aws", "s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix,
                          "--query", "Contents[].[Key,Size]", "--output", "json"], capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"list failed: {out.stderr.strip()}")
    return {k[len(prefix):]: s for k, s in (json.loads(out.stdout or "null") or [])}
miss = 0
for part, prefix in ((r, f"heldout/runs/{sset}/{run}/"), (t, f"heldout/truth/{sset}/{run}/")):
    got = listing(prefix)
    for root, _, files in os.walk(part):
        for f in files:
            p = os.path.join(root, f)
            miss += got.get(os.path.relpath(p, part).replace(os.sep, "/")) != os.path.getsize(p)
print("ok" if miss == 0 else f"{miss} files missing or different")
PY
)
  if [ "$ok" != ok ]; then st "FAILED check $run: $ok"; bad=$((bad + 1)); continue; fi
  n=$((n + 1))
  st "OK $run readable $(du -sh "$r" | cut -f1) truth $(du -sh "$t" | cut -f1) sums $(sha256sum "$r/SHA256SUMS" | cut -c1-16)"
  rm -rf "$WORK/$run"
  [ "$DELETE" = 1 ] && rm -rf "$d"
done
st "DONE $n runs uploaded, $bad failed"
[ $bad = 0 ]
