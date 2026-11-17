"""Witness index: postings per witness type and key (paper Lemma 1).

A posting (order time, finding ID) is never truncated. It is dropped only
once the processing frontier has passed t + H_w, where H_w = W_w + eps_bar +
2A: no later finding can then form a time-valid witness of type w with it.
The frontier is the event time of the finding being processed, not the raw
watermark (proofs/README.md: evicting by watermark loses links).
"""


class WitnessIndex:
    def __init__(self, horizon_ns):
        """horizon_ns: witness type -> H_w."""
        self.horizon_ns = horizon_ns
        self.postings = {}           # (witness type, key) -> [(t, finding ID)]

    def lookup_and_add(self, wtype, key, t, fid, frontier):
        """Finding IDs posted earlier under (wtype, key) that are still within
        the horizon at frontier; then post (t, fid)."""
        lst = self.postings.setdefault((wtype, key), [])
        h = self.horizon_ns(wtype)
        lst[:] = [(tg, g) for tg, g in lst if tg + h >= frontier]
        found = [g for _tg, g in lst if g != fid]
        lst.append((t, fid))
        return found

    def sweep(self, frontier):
        """Drop expired postings under every key (keys that never recur would
        otherwise keep theirs)."""
        for k in list(self.postings):
            h = self.horizon_ns(k[0])
            lst = [(tg, g) for tg, g in self.postings[k] if tg + h >= frontier]
            if lst:
                self.postings[k] = lst
            else:
                del self.postings[k]

    def size(self):
        return sum(len(v) for v in self.postings.values())
