"""Copy a DEVELOPMENT run's node streams without ground truth, for the Exp. 5 shakedown.

Development runs (dev/pilot-fit) still carry ground.truth.v0 lines in their shipper streams; the
held-out runs have them sealed away (check_fetch.sh, seal.verify), and the receiver rightly rejects
the topic (found 2026-11-16: the shakedown's first real dev run). This writes <dst>/shipper/*.jsonl
with every truth line removed by the same rule as the Exp. 3 base export (mtcore.exp3.base.is_truth),
so the shakedown input has the held-out layout. No other line changes.

    python strip_truth.py <dev run dir> <dst run dir>
"""
import glob
import json
import os
import sys

from mtcore.exp3.base import is_truth


def main(src_run, dst_run):
    files = sorted(glob.glob(os.path.join(src_run, "shipper", "*.jsonl")))
    if not files:
        sys.exit(f"no shipper files in {src_run}")
    os.makedirs(os.path.join(dst_run, "shipper"), exist_ok=True)
    kept = dropped = 0
    for f in files:
        with open(f, encoding="utf-8") as fin, \
                open(os.path.join(dst_run, "shipper", os.path.basename(f)), "w", encoding="utf-8") as fout:
            for line in fin:
                if line.strip() and is_truth(json.loads(line)):
                    dropped += 1
                    continue
                fout.write(line)
                kept += 1
    print(f"kept {kept} lines, dropped {dropped} truth lines from {len(files)} streams")


if __name__ == "__main__":
    main(*sys.argv[1:3])
