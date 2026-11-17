"""Test helper: run `python -m mtgen build` with the generator's identity resolver switched to the
latest-mapping model (option G of the Exp. 3 No-History ablation, simulated without changing mtgen).

    python tests/exp3_nohistory_gsim.py build --world Small --duration-s 300 --seed 7 --out DIR

WorldHistory.at answers "PodIP" and "Pod:name" lookups made by the normalizer's resolution sites
(render/ebpf.py _wrap, render/audit.py _derive_audit, render/offnode.py _make_offnode_derived and
_classify_remote) with the key's latest mapping for the whole run: the state with the latest
validity start among every state the key ever had (ties: larger UID). Every other lookup (the
world's own behaviour, e.g. which Pod a connect physically reached) keeps the time-indexed answer.
tests/test_exp3_nohistory.py compares this build with mtcore.exp3.nohistory applied to a normal one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mtcore  # noqa: E402,F401  (generated protobuf path)
from mtgen import history as H  # noqa: E402

RESOLVERS = {"_wrap", "_derive_audit", "_make_offnode_derived", "_classify_remote"}
KINDS = {"PodIP", "Pod:name"}
_orig_at = H.WorldHistory.at


def _latest_at(self, kind, key, t):
    if kind in KINDS and sys._getframe(1).f_code.co_name in RESOLVERS:
        entries = self._entries.get((kind, key), [])
        if not entries:
            return None
        return max(entries, key=lambda e: (e[0], getattr(e[2], "uid", "")))[2]
    return _orig_at(self, kind, key, t)


H.WorldHistory.at = _latest_at

if __name__ == "__main__":
    from mtgen.__main__ import main
    main()
