#!/usr/bin/env python3
"""Deterministic, hand-built cases for the suppression proof (Prop. 2).

epoch_onset_case: deleting an unrelated agent record on node n2 opens a
suspected epoch whose onset falls after the contradiction interval's event-time
end but before the contradicting record's receipt. The contradiction becomes
degraded (nondecisive). If Covered checks epochs only up to the interval end in
event time, the deletion creates a link; checking up to end + beta prevents it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correlator_ref as R  # noqa: E402


def epoch_onset_case():
    f = {0: dict(t=100.0, node="n1", inst="i1", tactic=None, keys={"request": "k"}, wkeys={}),
         1: dict(t=110.0, node="n2", inst="i2", tactic=None, keys={"request": "k"}, wkeys={}),
         2: dict(t=126.0, node="n2", inst="i3", tactic=None, keys={"process": "p2"}, wkeys={}),
         3: dict(t=128.0, node="n2", inst="i3", tactic=None, keys={"process": "p3"}, wkeys={})}
    ev = [dict(id=1, fid=0, w="request", t=101.0, src="agent@n1", dirrank=101.0, recv=103.0),
          dict(id=2, fid=1, w="request", t=112.0, src="agent@n2", dirrank=112.0, recv=115.0),
          dict(id=3, fid=2, w="process", t=126.0, src="agent@n2", dirrank=126.0, recv=127.0),
          dict(id=4, fid=3, w="process", t=128.0, src="agent@n2", dirrank=128.0, recv=130.0)]
    act = [dict(id=10 + k, fid=k, kind="aid", val=f"a{k}", t=f[k]["t"], src="audit", recv=f[k]["t"]) for k in f]
    clk = [dict(id=20 + n, src=s, t=90.0, eps=0.5, recv=90.0)
           for n, s in enumerate(("agent@n1", "agent@n2", "audit", "ctx"))]
    # Decisive sensor contradiction for the request witness, event time inside the interval
    # [85, 125], received after the interval end.
    ctr = [dict(id=30, a=0, b=1, w="request", origin="sensor", src="agent@n2", t=124.0, recv=131.0, producer="i2")]
    E = R.Evidence(f, ev, act, ctr, clk, [], [], set())
    # Suppress event 4 (an unrelated record on agent@n2): the last record before the gap is event 3.
    loss = dict(id=40, src="agent@n2", lo=min(128.0, 127.0), hi=130.0, tau=127.0, t=130.0, recv=130.0)
    E2 = E.copy(events=[e for e in ev if e["id"] != 4], losses=[loss])
    out = {}
    for name, V in (("paper", R.Variant()), ("covered_epoch_event_time", R.Variant(covered_epoch_event_time=True))):
        P = R.Params()
        out[name] = {"before": R.link(R.Ctx(E, P, V), 0, 1), "after_suppression": R.link(R.Ctx(E2, P, V), 0, 1)}
    return out



def self_trigger_case():
    """A process link into the finding whose own trigger (a C1b-like host
    transition) opens node n1's epoch at the target's event time. The interval
    always reaches that onset; the target's own trigger must not block the link
    (D3_v5 text did), but a contradiction the epoch degrades must, and
    suppressing that contradiction must not create the link."""
    f = {0: dict(t=100.0, node="n1", inst="i1", tactic=None, keys={"process": "p"}, wkeys={}),
         1: dict(t=120.0, node="n1", inst="i1", tactic=None, keys={"process": "p"}, wkeys={})}
    ev = [dict(id=1, fid=0, w="process", t=100.0, src="agent@n1", dirrank=100.0, recv=101.0),
          dict(id=2, fid=1, w="process", t=120.0, src="agent@n1", dirrank=120.0, recv=122.0)]
    act = [dict(id=10 + k, fid=k, kind="aid", val=f"a{k}", t=f[k]["t"], src="audit", recv=f[k]["t"]) for k in f]
    clk = [dict(id=20 + n, src=s, t=90.0, eps=0.5, recv=90.0) for n, s in enumerate(("agent@n1", "audit", "ctx"))]
    trig = [dict(id=30, node="n1", t=120.0, eps=1.0, recv=122.0, src="agent@n1", fid=1)]   # onset 119
    E = R.Evidence(f, ev, act, [], clk, [], trig, set())
    # A sensor contradiction for the pair, event time 115, received 125: after the onset, so degraded.
    ctr = dict(id=40, a=0, b=1, w="process", origin="sensor", src="agent@n1", t=115.0, recv=125.0, producer="i1")
    Ec = E.copy(contras=[ctr])
    loss = dict(id=41, src="agent@n1", lo=115.0, hi=125.0, tau=122.0, t=125.0, recv=125.0)    # its suppression
    Es = E.copy(losses=[loss])
    out = {}
    for name, V in (("paper", R.Variant()), ("no_trigger_exemption", R.Variant(no_trigger_exemption=True))):
        P = R.Params()
        out[name] = {k: R.link(R.Ctx(x, P, V), 0, 1)
                     for k, x in (("clean", E), ("degraded_contradiction", Ec), ("after_suppression", Es))}
    return out


def clock_tie_case():
    """Two clock records of one source at the same time, with different
    uncertainty. The small one admits an artifact link (total eps 4.7 <= eps_bar
    5); the large one does not (11.7). The decision must not depend on the order
    of the clock records (arrival order in a stream), and the tie must resolve
    conservatively to the larger uncertainty."""
    f = {0: dict(t=100.0, node="n1", inst="i1", tactic=None, keys={"artifact": "img"}, wkeys={}),
         1: dict(t=150.0, node="n1", inst="i2", tactic=None, keys={"artifact": "img"}, wkeys={})}
    ev = [dict(id=1, fid=0, w="artifact", t=100.0, src="admission", dirrank=100.0, recv=101.0),
          dict(id=2, fid=1, w="artifact", t=150.0, src="admission", dirrank=150.0, recv=151.0)]
    act = [dict(id=10 + k, fid=k, kind="aid", val=f"a{k}", t=f[k]["t"], src="audit", recv=f[k]["t"]) for k in f]
    small = dict(id=20, src="admission", t=90.0, eps=0.5, recv=90.0)
    large = dict(id=21, src="admission", t=90.0, eps=4.0, recv=90.0)
    other = [dict(id=22 + n, src=s, t=90.0, eps=0.5, recv=90.0) for n, s in enumerate(("audit", "ctx"))]
    P = R.Params()
    out = {}
    for name, clk in (("small_first", [small, large]), ("large_first", [large, small])):
        E = R.Evidence(f, ev, act, [], clk + other, [], [], set())
        out[name] = R.link(R.Ctx(E, P, R.Variant()), 0, 1)
    E1 = R.Evidence(f, ev, act, [], [small] + other, [], [], set())
    out["small_only"] = R.link(R.Ctx(E1, P, R.Variant()), 0, 1)
    return out


if __name__ == "__main__":
    print(epoch_onset_case())
    print(self_trigger_case())
    print(clock_tie_case())
