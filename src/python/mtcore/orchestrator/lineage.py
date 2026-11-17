"""Process ancestry on the parent chain (exp2-gaps-plan A1; D3_v5.tex
tab:witnesses "verified process ancestry").

A shared lineage_id says two processes run in one container lineage, not
that one descends from the other: siblings share it too (G-0). The
orchestrator therefore keeps, per node and boot, each process's parent as
the sensor reported it when the process was born (proc.fork and proc.exec
records name the child as process and the forking process as parent), and
walks the target's parent chain:

- the source's process is met (the target's own process included): the
  source is an ancestor, ANCESTOR (or SAME);
- the lineage root, a process already walked, or a known ancestor of the
  source (a sibling's parent) is reached without meeting it: NOT an
  ancestor, since a process cannot descend from its own descendant;
- a process on the way has no recorded birth (its fork and exec were lost):
  UNKNOWN. Unknown loss is not a refutation.

An input event's own (process, parent) pair is the sensor's statement of the
same birth link, so the decision also uses those of the two findings' events.
The map is checkpointed: the records it came from may be evicted.
"""
SAME, ANCESTOR, NOT, UNKNOWN = "same", "ancestor", "not", "unknown"
BIRTH_FAMILIES = ("proc.fork", "proc.exec")


def pkey(k):
    """A ProcessKey as a hashable tuple, or None when unset."""
    if k is None or not k.node_id or not k.tgid:
        return None
    return (k.node_id, k.boot_id, k.tgid, k.start_time_ns)


class ProcessTree:
    def __init__(self):
        self.parent = {}          # process key -> parent key, from births

    def observe(self, ev):
        """Record the birth link of a proc.fork or proc.exec event (Ev)."""
        e = ev.ebpf
        if e is None or e.event_family not in BIRTH_FAMILIES:
            return
        child, parent = pkey(e.process), pkey(e.parent)
        if child is not None and parent is not None and child != parent:
            self.parent.setdefault(child, parent)

    def relation(self, src_ev, tgt_ev, extra=()):
        """SAME, ANCESTOR, NOT or UNKNOWN for the source event's process and
        the target event's process. extra: events whose own (process, parent)
        pairs count as birth links too."""
        src, tgt = pkey(src_ev.ebpf.process), pkey(tgt_ev.ebpf.process)
        root = pkey(tgt_ev.ebpf.lineage_root)
        if src is None or tgt is None:
            return UNKNOWN
        if src == tgt:
            return SAME
        local = {}
        for ev in extra:
            c, p = pkey(ev.ebpf.process), pkey(ev.ebpf.parent)
            if c is not None and p is not None and c != p:
                local.setdefault(c, p)
        up, k = set(), src                       # the source's known ancestors
        while True:
            k = self.parent.get(k) or local.get(k)
            if k is None or k in up:
                break
            up.add(k)
        cur, seen = tgt, {tgt}
        while True:
            if cur == root or cur in up:
                return NOT
            nxt = self.parent.get(cur) or local.get(cur)
            if nxt is None:
                return UNKNOWN
            if nxt == src:
                return ANCESTOR
            if nxt in seen:
                return NOT
            seen.add(nxt)
            cur = nxt
