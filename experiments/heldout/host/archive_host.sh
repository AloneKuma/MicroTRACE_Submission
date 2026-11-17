#!/usr/bin/env bash
# Free disk on the test host before the held-out build (user decision 2026-11-11): stream each
# folder as one tar into s3://$BUCKET/archive/ (Glacier Deep Archive, no local copy), with a
# file list and the stream's sha256 next to it; delete the local folder only after the S3 object
# size equals the streamed byte count. Then clear the Docker build cache. Resumable (a finished
# item leaves archive/<name>.done in S3 and is skipped).
#
#   . ~/.mt-uploader.env; BUCKET=<work bucket> nohup bash archive_host.sh > archive.log 2>&1 &
set -uo pipefail
: "${BUCKET:?}"
W=${W:-$HOME/microtrace-archive}; mkdir -p "$W"
ITEMS=${ITEMS:-"pre-retruth-gt:$HOME/microtrace-pilot-multistep/pilot-multistep/_gates/pre-retruth-gt
pidsmaker-feat_inference:$HOME/microtrace-baselines/pidsmaker/artifacts/feat_inference"}
st() { echo "$(date -u +%FT%TZ) $*"; }
st "START $(df -h ~ | awk 'END {print $4}') free"
while IFS=: read -r name dir; do
  [ -n "$name" ] || continue
  . "$HOME/.mt-uploader.env"
  if [ "$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "archive/$name.done" --max-keys 1 --no-paginate \
          --query 'Contents[0].Key' --output text 2>/dev/null)" = "archive/$name.done" ]; then
    st "SKIP $name (archived)"; [ -d "$dir" ] && st "NOTE $dir still present"; continue
  fi
  [ -d "$dir" ] || { st "MISSING $dir"; continue; }
  size=$(du -sb "$dir" | cut -f1)
  (cd "$dir" && find . -type f -printf '%P\t%s\n' | sort) > "$W/$name.files.tsv"
  st "TAR $name $(du -sh "$dir" | cut -f1), $(wc -l < "$W/$name.files.tsv") files"
  t0=$(date +%s)
  tar -C "$(dirname "$dir")" -cf - "$(basename "$dir")" \
    | tee >(sha256sum | cut -d' ' -f1 > "$W/$name.sha256") >(wc -c > "$W/$name.bytes") \
    | aws s3 cp - "s3://$BUCKET/archive/$name.tar" --storage-class DEEP_ARCHIVE --expected-size $((size + size / 20)) \
        --only-show-errors
  rc=$?; sleep 2
  # The uploader may list but not read (no head-object): the size comes from a listing. du -sb
  # also counts directory entries, so it is no lower bound for the tar; tar's own exit status
  # (pipefail, in rc) says the archive is complete. (Fixed after 2026-11-11.)
  bytes=$(cat "$W/$name.bytes"); got=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "archive/$name.tar" \
            --max-keys 1 --no-paginate --query 'Contents[0].Size' --output text 2>/dev/null)
  if [ $rc != 0 ] || [ "$bytes" != "$got" ]; then
    st "FAILED $name: rc $rc, streamed $bytes, in S3 ${got:-none}, folder $size; local copy kept"; continue
  fi
  aws s3 cp --only-show-errors "$W/$name.files.tsv" "s3://$BUCKET/archive/$name.files.tsv" --storage-class STANDARD \
    && aws s3 cp --only-show-errors "$W/$name.sha256" "s3://$BUCKET/archive/$name.tar.sha256" --storage-class STANDARD \
    || { st "FAILED $name: side files; local copy kept"; continue; }
  rm -rf "$dir" 2>/dev/null || docker exec -u root mtpids-app rm -rf "/home/artifacts/$(basename "$dir")"
  [ -d "$dir" ] && { st "FAILED $name: could not delete $dir"; continue; }
  echo "$(date -u +%FT%TZ) $bytes $(cat "$W/$name.sha256")" | aws s3 cp - "s3://$BUCKET/archive/$name.done" --only-show-errors
  st "OK $name $bytes bytes in $(( $(date +%s) - t0 )) s, sha256 $(cut -c1-16 "$W/$name.sha256"), local deleted"
done <<< "$ITEMS"
docker builder prune -f > "$W/prune.log" 2>&1 && st "PRUNED docker build cache: $(tail -1 "$W/prune.log")"
st "ARCHIVE_DONE $(df -h ~ | awk 'END {print $4}') free"
