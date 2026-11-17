"""GapIndex lookup index (2026-11-17): query() gives exactly the answers of the version before it.

The reference is the class as it was at e6e99b0 (tests/reference/completeness_e6e99b0.py, a verbatim
copy). Both indexes get the same random stream of gap records (bounded, open, closed later, node,
family and source scoped, very long, idle), events, prunes and queries (short and long windows,
uncertainty, node sets, families); every answer must be equal.
"""
import random

import agent_fixtures as F
import pytest
from microtrace.v0 import common_pb2

from mtcore.agents import completeness as NEW
from tests.reference import completeness_e6e99b0 as OLD

SRC = ["EBPF", "AUDIT", "GATEWAY", "KYVERNO", "SOURCE_UNSPECIFIED"]
REASONS = ["DROPPED_BEFORE", "SOURCE_IDLE", "TRUNCATED", "POLICY_EXCLUDED", "LATE_ARRIVAL", "JOIN_UNCERTAIN"]
NODES = ["n1", "n2", "n3"]
FAMS = ["net.connect", "proc.exec", "proc.fork", "file.open"]
SV = {n: common_pb2.Source.Value(n) for n in SRC}


def _reason_ok(name):
    return name in common_pb2.GapReason.keys()


def _gap(rng, t_max):
    lo = rng.uniform(0, t_max)
    kind = rng.random()
    if kind < 0.90:
        start, end = lo, lo + rng.choice([0.001, 0.5, 5, 90, 400])         # bounded, short to minutes
    elif kind < 0.92:
        start, end = lo, lo + rng.uniform(70000, 90000)                   # very long (> MAX_GAP_BUCKETS)
    elif kind < 0.98:
        start, end = lo, None                                             # open end
    else:
        start, end = None, lo / 20                                        # open start, early end
    reason = rng.choice([r for r in REASONS if _reason_ok(r)])
    rec = F.loss(start, end, source=rng.choice(SRC), node=rng.choice(NODES), reason=reason)
    if rng.random() < 0.2:
        rec[1].source_completeness.gaps[0].scope = "family=" + ",".join(rng.sample(FAMS, rng.randint(1, 2)))
    return rec, (start, end)


@pytest.mark.parametrize("bucket_ns", [60 * 10**9, 10**9, 10**6])    # small buckets: edges everywhere
@pytest.mark.parametrize("seed", range(12))
def test_query_answers_equal_the_reference(seed, bucket_ns, monkeypatch):
    monkeypatch.setattr(NEW, "BUCKET_NS", bucket_ns)
    check_equal(seed)


def check_equal(seed):
    rng = random.Random(seed)
    shipped = None if seed % 2 else {"default": {SV["EBPF"], SV["AUDIT"]}, "n2": {SV["EBPF"]}}
    old, new = OLD.GapIndex(shipped), NEW.GapIndex(shipped)
    t_max, opened, asked = 30000.0, [], 0
    for step in range(1500):
        r = rng.random()
        if r < 0.20:
            rec, (s, e) = _gap(rng, t_max)
            sc = rec[1].source_completeness
            assert old.add_source_completeness(sc, rec[1].logical_id) == \
                new.add_source_completeness(sc, rec[1].logical_id)
            if e is None and s is not None:
                opened.append(rec)
        elif r < 0.30 and opened:                         # a closing record for an open gap
            rec = opened.pop(rng.randrange(len(opened)))
            sc = type(rec[1].source_completeness)()
            sc.CopyFrom(rec[1].source_completeness)
            end = F.ts(rng.uniform(0, t_max) + 3000)
            sc.interval_end.CopyFrom(end)
            sc.gaps[0].to.CopyFrom(end)
            old.add_source_completeness(sc, f"close-{step}")
            new.add_source_completeness(sc, f"close-{step}")
        elif r < 0.60:                                    # an event closes open gaps of its node/source
            src = rng.choice(SRC[:4])
            node = rng.choice(NODES) if src == "EBPF" else None
            t = F.ns(rng.uniform(0, t_max))
            old.observe(SV[src], node, t)
            new.observe(SV[src], node, t)
        elif r < 0.63:
            b = F.ns(rng.uniform(0, t_max / 2))
            old.prune(b)
            new.prune(b)
            assert len(old.gaps) == len(new.gaps)
        else:                                             # a query
            t = rng.uniform(-50, t_max + 50)
            w = rng.choice([0, 0.5, 30, 600, 10000, 400000])
            lo, hi = F.ns(t), F.ns(t + w)
            unc = rng.choice([0, 1000, 2 * 10**9, 75 * 10**9])
            sources = set(rng.sample([SV[s] for s in SRC[:4]], rng.randint(1, 3)))
            nodes = rng.choice([None, {rng.choice(NODES)}, set(NODES[:2])])
            fams = rng.choice([None, frozenset(rng.sample(FAMS, 2))])
            assert old.query(sources, nodes, lo, hi, unc, fams) == new.query(sources, nodes, lo, hi, unc, fams), \
                (seed, step)
            asked += 1
    assert asked > 500


def test_many_short_gaps_query_in_time_independent_of_their_number():
    """10,000 short transit-loss gaps across 3 h; a short window touches only a few buckets."""
    import time
    gi = NEW.GapIndex()
    for i in range(10000):
        gi.add_source_completeness(F.loss(i, i + 0.2, node=f"n{i % 4}")[1].source_completeness)
    t0 = time.perf_counter()
    for i in range(20000):
        gi.query({SV["EBPF"]}, {"n1"}, F.ns(i % 10000), F.ns(i % 10000 + 1), 1000)
    assert time.perf_counter() - t0 < 5
