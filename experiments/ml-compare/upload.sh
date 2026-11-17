#!/usr/bin/env bash
# Test host -> S3 for the ML model comparison (docs/plans/ml-model-compare-plan.md, step C.4).
#   s3://$BUCKET/dev/pilot-fit/<run>/   the 170 PILOT FIT runs (development data, truth allowed;
#                                       also the KAIROS/ORTHRUS training data of the held-out plan),
#                                       without base.pb (23.6 GB; read only by the generator and the
#                                       re-truth tools, never by the agents, GO, scoring or converter)
#   s3://$BUCKET/dev/ml-crossfit/       folds.json, rows/fold*-max, models/fold*-max, the fold
#                                       configs, and the qmax_gnone / qmax_confirmB3 scores
# Each prefix gets a SHA256SUMS that job.sh checks after download. The uploader role can put but
# not read, so the upload is checked by listing (every file present with the same size).
# Resumable (aws s3 sync). Run with nohup from a short ssh command:
#
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... BUCKET=<work bucket> \
#     nohup bash upload.sh > ~/microtrace-mlcompare/upload.out 2>&1 &
set -uo pipefail
: "${BUCKET:?}"
D=${D:-$HOME/microtrace-pilot-multistep/pilot-multistep}; W=${W:-$HOME/microtrace-ml}
STAGE=${STAGE:-$HOME/microtrace-mlcompare/stage}; S=$HOME/microtrace-mlcompare/UPLOAD_STATUS
mkdir -p "$(dirname "$S")"
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; }
aws sts get-caller-identity --query Arn --output text < /dev/null | grep -q "MicroTRACE-heldout-uploader" \
  || { st "STOP not running as the uploader role"; exit 1; }

mapfile -t RUNS < <(python3 -c "import json;print('\n'.join(json.load(open('$W/folds.json'))['all']))")
[ "${#RUNS[@]}" = 170 ] || { st "STOP folds.json lists ${#RUNS[@]} runs, not 170"; exit 1; }
need=( "$W/folds.json" "$W/rows/foldA-max" "$W/rows/foldB-max" "$W/models/foldA-max/train.json"
       "$W/models/foldB-max/train.json" "$W/cfg/foldA-qmax_g0.001.yaml" "$W/cfg/foldB-qmax_g0.001.yaml" )
for p in "${need[@]}"; do [ -e "$p" ] || { st "STOP missing $p"; exit 1; }; done
for r in "${RUNS[@]}"; do
  [ -f "$D/$r/manifest.json" ] || { st "STOP run $r not in $D"; exit 1; }
  [ -f "$W/cv/qmax_gnone/runs/$r/score.json" ] || { st "STOP no qmax_gnone score for $r"; exit 1; }
  for f in score.json findings.json; do
    [ -f "$W/cv-veto/qmax_confirmB3/runs/$r/$f" ] || { st "STOP no qmax_confirmB3 $f for $r"; exit 1; }
  done
done
st "START ${#RUNS[@]} runs from $D, cross-fit files from $W"

# ml-crossfit: staged copy (only the files the job reads)
M=$STAGE/ml-crossfit; rm -rf "$M"; mkdir -p "$M/cfg" "$M/rows" "$M/models" "$M/cv/qmax_gnone/runs" "$M/cv-veto/qmax_confirmB3/runs"
cp "$W/folds.json" "$M/"
cp "$W"/cfg/fold{A,B}-qmax_g0.001.yaml "$W"/cfg/fold{A,B}-qmax_confirmB3.yaml "$M/cfg/" 2>/dev/null \
  || cp "$W"/cfg/fold{A,B}-qmax_g0.001.yaml "$M/cfg/"
cp -r "$W/rows/foldA-max" "$W/rows/foldB-max" "$M/rows/"
cp -r "$W/models/foldA-max" "$W/models/foldB-max" "$M/models/"
for r in "${RUNS[@]}"; do
  mkdir -p "$M/cv/qmax_gnone/runs/$r" "$M/cv-veto/qmax_confirmB3/runs/$r"
  cp "$W/cv/qmax_gnone/runs/$r/score.json" "$M/cv/qmax_gnone/runs/$r/"
  cp "$W/cv-veto/qmax_confirmB3/runs/$r/"{score,findings}.json "$M/cv-veto/qmax_confirmB3/runs/$r/"
done
(cd "$M" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
st "STAGED ml-crossfit $(du -sh "$M" | cut -f1), sums $(sha256sum "$M/SHA256SUMS" | cut -c1-16)"

# pilot-fit: sums over the run folders as they are (no copy)
P=$STAGE/pilot-fit.SHA256SUMS
if [ ! -s "$P" ]; then
  (cd "$D" && find "${RUNS[@]}" -type f ! -path "*/base.pb" -print0 | sort -z | xargs -0 sha256sum) > "$P.tmp" && mv "$P.tmp" "$P" \
    || { st "STOP sums pilot-fit"; exit 1; }
fi
st "SUMS pilot-fit $(wc -l < "$P") files, $(sha256sum "$P" | cut -c1-16)"

bad=0
for r in "${RUNS[@]}"; do
  aws s3 sync --only-show-errors --no-progress --no-follow-symlinks --exclude base.pb "$D/$r" "s3://$BUCKET/dev/pilot-fit/$r/" < /dev/null \
    || { st "FAILED upload $r"; bad=$((bad + 1)); }
done
aws s3 cp --only-show-errors "$P" "s3://$BUCKET/dev/pilot-fit/SHA256SUMS" < /dev/null || bad=$((bad + 1))
aws s3 sync --only-show-errors --no-progress --no-follow-symlinks "$M" "s3://$BUCKET/dev/ml-crossfit/" < /dev/null \
  || { st "FAILED upload ml-crossfit"; bad=$((bad + 1)); }
[ $bad = 0 ] || { st "STOP $bad uploads failed (rerun to resume)"; exit 1; }

# check by listing: every local file present with the same size
ok=$(python3 - "$BUCKET" "$D" "$M" "${RUNS[@]}" < /dev/null <<'PY'
import json, os, subprocess, sys
bucket, d, m, runs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
def listing(prefix):
    out = subprocess.run(["aws", "s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix,
                          "--query", "Contents[].[Key,Size]", "--output", "json"], capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"list failed: {out.stderr.strip()}")
    return {k[len(prefix):]: s for k, s in (json.loads(out.stdout or "null") or [])}
miss = 0
got = listing("dev/pilot-fit/")
for r in runs:
    for root, _, files in os.walk(os.path.join(d, r)):
        for f in files:
            p = os.path.join(root, f)
            if f == "base.pb" and root == os.path.join(d, r):
                continue
            miss += got.get(os.path.relpath(p, d).replace(os.sep, "/")) != os.path.getsize(p)
got = listing("dev/ml-crossfit/")
for root, _, files in os.walk(m):
    for f in files:
        p = os.path.join(root, f)
        miss += got.get(os.path.relpath(p, m).replace(os.sep, "/")) != os.path.getsize(p)
print("ok" if miss == 0 else f"{miss} files missing or different")
PY
)
[ "$ok" = ok ] || { st "STOP check: $ok"; exit 1; }
st "UPLOAD_DONE pilot-fit and ml-crossfit checked by listing"
