#!/usr/bin/env bash
# After the last batch of a set is uploaded: record what the held-out set IS, so no later
# session can use a replaced or partial copy. Writes experiments/heldout/manifests/<set>.tsv
# (run ID, sha256 of the readable part's SHA256SUMS, S3 version ID of that file), to be
# committed. Every session checks its download against it (check_fetch.sh). Run from the
# laptop with a profile that can list and read heldout/runs/ (analysis role or the
# Terraform role; never truth). On Windows Git Bash run with MSYS_NO_PATHCONV=1 (CRs that
# aws.exe prints are stripped here).
#
# Two bulk calls, not two per run (the per-run version broke on a flaky link, 2026-11-13):
# one version listing of the SHA256SUMS keys, and one `aws s3 sync` that fetches only those
# files (resumable). A run whose SHA256SUMS has versions with different content is refused
# (a replaced run); identical versions (a CLI retry of a PUT that had succeeded, seen once on
# 2026-11-11) are allowed and the latest is used.
#
#   HELDOUT_BUCKET=<sealed bucket> SET=held_out bash freeze_manifest.sh
set -euo pipefail
: "${HELDOUT_BUCKET:?}" "${SET:?}"
cd "$(dirname "$0")"; mkdir -p manifests
out=manifests/$SET.tsv; tmp=.freeze-tmp/$SET; mkdir -p "$tmp"
prefix=heldout/runs/$SET/
aws s3api list-object-versions --bucket "$HELDOUT_BUCKET" --prefix "$prefix" \
  --query "Versions[?ends_with(Key, '/SHA256SUMS')].[Key,VersionId,IsLatest,ETag]" --output text \
  | tr -d '\r' > "$tmp/versions.tsv"
[ -s "$tmp/versions.tsv" ] || { echo "no runs under $prefix"; exit 1; }
aws s3 sync --only-show-errors "s3://$HELDOUT_BUCKET/$prefix" "$tmp/sums" --exclude '*' --include '*/SHA256SUMS'
python3 - "$tmp" "$prefix" "$out" <<'PY'
import collections, hashlib, os, sys
tmp, prefix, out = sys.argv[1:]
rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(tmp, "versions.tsv")) if l.strip()]
etags = collections.defaultdict(set)
count = collections.Counter()
for key, _vid, _latest, etag in rows:
    etags[key].add(etag)
    count[key] += 1
replaced = sorted(k for k, e in etags.items() if len(e) > 1)
if replaced:
    sys.exit(f"refused: {len(replaced)} runs have SHA256SUMS versions with different content, e.g. {replaced[0]}")
dups = sorted(k for k, n in count.items() if n > 1)
if dups:
    print(f"note: {len(dups)} runs have identical repeated SHA256SUMS versions (PUT retry), latest used: "
          + ", ".join(k[len(prefix):].split("/")[0] for k in dups))
lines = ["run_id\tsums_sha256\tsums_version_id"]
for key, vid, latest, _etag in sorted(rows):
    if latest.strip() != "True":
        continue
    run = key[len(prefix):].split("/")[0]
    with open(os.path.join(tmp, "sums", run, "SHA256SUMS"), "rb") as fh:
        lines.append(f"{run}\t{hashlib.sha256(fh.read()).hexdigest()}\t{vid}")
open(out, "w", newline="\n").write("\n".join(lines) + "\n")
print(f"{out}: {len(lines) - 1} runs")
PY
rm -rf "$tmp"
