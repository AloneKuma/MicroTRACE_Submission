"""GRE build step 7.5, without a cluster: guard ablation (evaluation-plan.md
section 4, Exp. 5 part B: "no nonce store, no snapshot check, no target
revalidation, no postcondition check, broad permissions; each must fail a
named row").

Each case is run with every guard on and with each single guard off. A
case must be breached exactly when its own guard is off: that shows which
Table V row each guard prevents, and that no other guard covers for it.
The same pairs run against kind in test_gre_kube_ablation.py. Every test
runs on the memory stores and on Postgres."""
import copy
import dataclasses

import pytest

import test_gre_execute as X
import test_gre_reconcile as RC
import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.gre import verify as V
from mtcore.gre.execute import ISOLATION_LABEL, SERVICE_ACCOUNTS
from mtcore.gre.validate import GUARDS, GreConfig
from mtcore.tgs import apply as A

INEFFECTIVE = V.Result("Failed", "the Pod is still reachable at 10.0.0.7:80 (REFUSED)", "pod microtrace-probe/p")


class Probe:
    """The real verifier's answer for an isolation that does not take effect."""

    def verify(self, req, pc):
        return INEFFECTIVE


@pytest.fixture
def rig(store, monkeypatch):
    r = RC.make_rig(store, monkeypatch)
    r["tgs"] = store
    return r


def configure(rig, ablate):
    gre = rig["ex"].gre
    gre.config = dataclasses.replace(gre.config, ablate=frozenset(ablate))
    rig["ex"].verifier = V.AcceptanceVerifier() if "postcondition" in ablate else Probe()


def writes(rig):
    """Writes the API server accepted (its audit log, not the GRE's report)."""
    return [e for e in rig["api"].audit if e["verb"] != "get" and e["responseStatus"]["code"] == 200]


# --- the cases: each returns True when the row's expected outcome is breached ---------------
def undo(rig):
    """An operator lifts the isolation: the label goes, nothing else changes."""
    pod = copy.deepcopy(rig["api"].objects[X.POD])
    pod["metadata"]["labels"].pop(ISOLATION_LABEL, None)
    rig["api"].put(X.POD, pod)


def replayed_nonce(rig):
    """Repeated nonce: at most one execution. A replay right after the write
    is also stopped by revalidation (the write changed the labels), so the
    replay comes after the effect was undone, while the approval is valid."""
    req = rig["req"]()
    rig["ex"].execute(req)
    undo(rig)
    rig["ex"].execute(copy.deepcopy(req))
    return len(writes(rig)) > 1


def stale_snapshot(rig):
    """Stale graph snapshot: reject the approval."""
    req = rig["req"]()
    A.apply_batch(rig["tgs"], T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",), version=2),
                                      topic=T.INC, start=1))
    rig["ex"].execute(req)
    return len(writes(rig)) > 0


def recreated_target(rig):
    """Target UID/version conflict: reject or revalidate."""
    req = rig["req"]()
    pod = copy.deepcopy(rig["api"].objects[X.POD])
    pod["metadata"]["uid"] = "pod-uid-2"                           # deleted and recreated under the same name
    rig["api"].put(X.POD, pod)
    rig["ex"].execute(req)
    return len(writes(rig)) > 0


def ineffective_action(rig):
    """Accepted but ineffective action: not verified."""
    out = rig["ex"].execute(rig["req"]())
    assert writes(rig)                                             # the API accepted it in every configuration
    return out.status == "Verified"


def broad_identity(rig):
    """Compromised executor: bounded by RBAC and admission. Without a
    cluster, the bound is the identity the write is made with; the
    compromised-token cases are in test_gre_kube_ablation.py."""
    rig["ex"].execute(rig["req"]())
    return any(sa not in SERVICE_ACCOUNTS.values() for sa in rig["api"].minted)


CASES = {"nonce": replayed_nonce, "snapshot": stale_snapshot, "revalidation": recreated_target,
         "postcondition": ineffective_action, "permissions": broad_identity}


@pytest.mark.parametrize("case", GUARDS)
@pytest.mark.parametrize("off", (None,) + GUARDS)
def test_each_case_is_breached_exactly_when_its_guard_is_off(rig, case, off):
    configure(rig, [off] if off else [])
    assert CASES[case](rig) is (off == case)


def test_ablation_names_known_guards_only():
    with pytest.raises(ValueError, match="unknown guards"):
        GreConfig("c", frozenset(), {}, ablate=frozenset({"nonce", "audit"}))


# --- what each ablation does, in detail ---------------------------------------------------
def test_without_revalidation_a_change_between_check_and_write_lands(rig, monkeypatch):
    configure(rig, ["revalidation"])

    def meddle(req, live):
        pod = copy.deepcopy(rig["api"].objects[X.POD])
        pod["metadata"]["labels"] = {"app": "other"}
        rig["api"].put(X.POD, pod)

    monkeypatch.setattr(rig["ex"], "_before_write", meddle)
    out = rig["ex"].execute(rig["req"]())
    assert out.timings_ms["rounds"] == 1                           # no precondition, so no conflict
    assert rig["api"].objects[X.POD]["metadata"]["labels"] == {"app": "other", ISOLATION_LABEL: "true"}
    patch = [c for c in rig["api"].calls if c[1] == "PATCH"]
    assert len(patch) == 1


def test_without_the_nonce_store_nothing_is_consumed(rig):
    configure(rig, ["nonce"])
    req = rig["req"]()
    statuses = []
    for _ in range(3):
        statuses.append(rig["ex"].execute(req).status)
        undo(rig)
    assert statuses == ["Failed"] * 3                              # Probe: ineffective; never Rejected
    assert len(writes(rig)) == 3
    assert rig["store"].unclosed_nonces(10**30) == []


def test_without_the_postcondition_check_acceptance_is_reported_as_verified(rig):
    configure(rig, ["postcondition"])
    req = rig["req"]()
    out = rig["ex"].execute(req)
    assert (out.status, out.attempt["ref_verify"]) == ("Verified", "ablated: no check")
    assert out.reason == "postcondition check ablated: API acceptance taken as containment"


def test_broad_permissions_use_one_identity_for_every_action(rig):
    configure(rig, ["permissions"])
    rig["ex"].execute(rig["req"]())
    assert rig["api"].minted == ["gre-broad"]
    assert {c[0] for c in rig["api"].calls if c[1] != "GET"} == {"gre-broad"}
