#!/usr/bin/env bash
# Check a downloaded held-out set against the frozen manifest (freeze_manifest.sh):
# exactly the frozen runs, each part's SHA256SUMS equal to the frozen one, every file
# matching its checksum, and no truth on this side (mtcore.harness.seal verify).
#
#   bash check_fetch.sh <set dir> <manifest tsv> <code dir>
set -uo pipefail
dir=$1; man=$2; code=$3
[ -f "$man" ] || { echo "no frozen manifest $man"; exit 1; }
want=$(tail -n +2 "$man" | cut -f1 | sort)
have=$(cd "$dir" && find . -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' | sort)
[ "$want" = "$have" ] || { echo "run list differs from $man: $(comm -3 <(echo "$want") <(echo "$have") | head -3 | xargs)"; exit 1; }
bad=0
while IFS=$'\t' read -r run sums _; do
  [ "$run" = run_id ] && continue
  [ "$(sha256sum "$dir/$run/SHA256SUMS" | cut -d' ' -f1)" = "$sums" ] || { echo "SHA256SUMS changed: $run"; bad=$((bad + 1)); continue; }
  (cd "$dir/$run" && sha256sum -c --quiet SHA256SUMS < /dev/null) || { echo "checksum failure: $run"; bad=$((bad + 1)); }
done < "$man"
[ -z "$(find "$dir" -type l -print -quit)" ] || { echo "symlink in $dir"; exit 1; }
PYTHONPATH=$code/src/python python3 - "$dir" < /dev/null <<'PY' || exit 1
import os, sys
from mtcore.harness import seal
d = sys.argv[1]
bad = [(r, x) for r in sorted(os.listdir(d)) if not r.startswith(".") for x in seal.verify(os.path.join(d, r))]
if bad:
    sys.exit(f"truth on the readable side: {bad[:3]}")
PY
[ $bad = 0 ] && echo "OK $(echo "$want" | wc -l) runs match $man"
