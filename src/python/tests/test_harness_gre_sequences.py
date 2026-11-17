"""Build step 8e: randomised GRE sequences. With every guard on, no
sequence violates a property, and the sequences reach every interruption
point, every rejection the guards give, refused and accepted writes, and
passing and failing probes. With one guard off, its property is violated
in some sequence and no other property is: the sequences tell the guards
apart. Seeds are fixed, so a failure names a reproducible sequence."""
import pytest

from mtcore.harness import gre_sequences as G

SEEDS, STEPS = range(60), 40


def runs(ablate=()):
    return [G.run(s, STEPS, ablate) for s in SEEDS]


@pytest.fixture(scope="module")
def guarded():
    return runs()


def test_with_every_guard_no_sequence_violates_a_property(guarded):
    bad = [(r.seed, p, v[0]) for r in guarded for p, v in r.violations.items() if v]
    assert bad == [], bad[:3]


def test_the_sequences_are_not_vacuous(guarded):
    total = {}
    for r in guarded:
        for k, n in r.coverage.items():
            total[k] = total.get(k, 0) + n
    for point in G.POINTS:
        assert total.get("killed:" + point, 0) > 0, point
    for reason in ("nonce already used", "graph check failed", "approval signature does not match the request",
                   "target UID differs from the approved one (object recreated)",
                   "fields the action depends on changed since review"):
        assert total.get("Rejected:" + reason, 0) > 0, reason
    for k in ("accepted_writes", "refused_writes", "passing_probes", "failing_probes", "Verified", "Failed"):
        assert total.get(k, 0) > 0, k


@pytest.mark.parametrize("guard, prop", [("nonce", "one_execution"), ("snapshot", "fresh_approval"),
                                         ("revalidation", "fresh_approval"), ("postcondition", "verified_probe")])
def test_without_a_guard_its_property_and_only_it_is_violated(guard, prop):
    reports = runs((guard,))
    hit = {p for r in reports for p, v in r.violations.items() if v}
    assert hit == {prop}


def test_the_snapshot_and_revalidation_violations_differ():
    def found(guard):
        return [v for r in runs((guard,)) for v in r.violations["fresh_approval"]]
    assert all("approval bound to incident version" in v for v in found("snapshot"))
    assert all("target changed since review" in v or "wrote another object" in v for v in found("revalidation"))


def test_permissions_are_graded_on_kind_not_here():
    assert all(r.ok for r in runs(("permissions",)))


def test_a_seed_replays_the_same_sequence():
    a, b = G.run(7, STEPS), G.run(7, STEPS)
    strip = [ln for ln in a.log if "rq-" not in ln]                 # request IDs carry random nonces
    assert len(a.log) == len(b.log) and strip == [ln for ln in b.log if "rq-" not in ln]
    assert a.coverage == b.coverage
