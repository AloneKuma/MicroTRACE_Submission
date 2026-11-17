"""Agent F (F1, F2) and the RBAC effective-rights evaluator."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, gates_on, of, outcomes, reasons, run

POD = "pod-checkout-1"
CTX = [F.pod(-50, uid=POD, owner="checkout")]


def creds(t, before=(1000, 0), after=(0, 0), via="/bin/su", has_before=True, op="COMMIT_CREDS"):
    ne = F.ebpf(t, "priv.creds")
    p = ne.ebpf.privilege
    p.op = {"COMMIT_CREDS": 1, "SETUID_FAMILY": 2, "CAPSET": 3}[op]
    if has_before:
        p.before.euid, p.before.cap_effective = before
    p.after.euid, p.after.cap_effective = after
    if via:
        p.via_executable.resolved_path = via
    return F.done(ne)


@covers("F1", "positive")
def test_f1_fires_on_euid_to_root_and_new_capability():
    findings, _, _ = run(F.stream(*CTX, creds(1), creds(2, before=(0, 0x1), after=(0, 0x201), via="")), ["F1"])
    assert len(of(findings, "F1")) == 2 and of(findings, "F1")[0].primary_tactic == 4


@covers("F1", "neg:0")
def test_f1_declared_helper_does_not_fire():
    findings, evals, _ = run(F.stream(*CTX, creds(1, via="/usr/bin/sudo")), ["F1"])
    assert not findings and outcomes(evals, "F1") == [NOT_FIRED]


@covers("F1", "neg:1")
def test_f1_capability_drop_does_not_fire():
    findings, _, _ = run(F.stream(*CTX, creds(1, before=(0, 0x3), after=(0, 0x1))), ["F1"])
    assert not findings


@covers("F1", "abstain:0")
def test_f1_unknown_before_state_abstains():
    _, evals, _ = run(F.stream(*CTX, creds(1, has_before=False)), ["F1"])
    assert outcomes(evals, "F1") == [ABSTAINED]


# --- F2 -----------------------------------------------------------------------
R = "rbac.authorization.k8s.io"
SA = ("ServiceAccount", "checkout", "shop")
BASE = [
    F.rbac_obj(-60, "Role", "reader", "role-reader", namespace="shop", rules=[([""], ["pods"], ["get", "list"])]),
    F.rbac_obj(-60, "ClusterRole", "secret-admin", "cr-secret", rules=[([""], ["secrets"], ["get", "list"])]),
    F.rbac_obj(-50, "RoleBinding", "rb-reader", "rb-1", namespace="shop", subjects=[SA], role_ref=("Role", "reader")),
]


def mutation(t, verb, resource, name, uid, rv, namespace="shop", code=201):
    return F.audit(t, verb=verb, resource=resource, group=R, namespace=namespace, name=name, uid=uid,
                   resource_version=rv, code=code, principal="system:serviceaccount:shop:deployer")


def grant(t=1, obs_t=2, rv="5", subjects=(SA,), ref=("ClusterRole", "secret-admin"), uid="rb-2", name="rb-new"):
    return [mutation(t, "create", "rolebindings", name, uid, rv),
            F.rbac_obj(obs_t, "RoleBinding", name, uid, namespace="shop", subjects=list(subjects), role_ref=ref, rv=rv)]


@covers("F2", "positive")
def test_f2_fires_on_new_effective_right():
    findings, _, _ = run(F.stream(*BASE, *grant()), ["F2"], p=gates_on())
    [f] = of(findings, "F2")
    assert f.attributes["subject"] == "ServiceAccount:shop/checkout"
    assert "shop:get:/secrets" in f.attributes["added_rights"] and f.attributes["binding_uid"] == "rb-2"


def test_f2_gated_off_by_default():
    _, evals, _ = run(F.stream(*BASE, *grant()), ["F2"])
    assert reasons(evals, "F2") == ["CONDITIONAL_JOIN_UNVALIDATED"]


@covers("F2", "neg:0")
def test_f2_redundant_binding_adds_nothing():
    findings, evals, _ = run(F.stream(*BASE, *grant(ref=("Role", "reader"))), ["F2"], p=gates_on())
    assert not findings and outcomes(evals, "F2") == [NOT_FIRED]


@covers("F2", "neg:1")
def test_f2_aggregation_reconciliation_adds_nothing():
    agg = [F.rbac_obj(-60, "ClusterRole", "viewer", "cr-view", rules=[([""], ["configmaps"], ["get"])],
                      labels={"rbac.example/aggregate": "true"}),
           F.rbac_obj(-60, "ClusterRole", "agg", "cr-agg", selectors=["rbac.example/aggregate=true"], rv="1"),
           F.rbac_obj(-50, "ClusterRoleBinding", "crb-agg", "crb-1", subjects=[SA], role_ref=("ClusterRole", "agg"))]
    # The controller writes the union into agg's rules: no subject gains a right.
    recon = [mutation(1, "update", "clusterroles", "agg", "cr-agg", "2", namespace=""),
             F.rbac_obj(2, "ClusterRole", "agg", "cr-agg", rules=[([""], ["configmaps"], ["get"])],
                        selectors=["rbac.example/aggregate=true"], rv="2", change="MODIFIED")]
    findings, _, _ = run(F.stream(*BASE, *agg, *recon), ["F2"], p=gates_on())
    assert not findings


@covers("F2", "neg:2")
def test_f2_binding_to_system_masters_member_adds_nothing():
    findings, _, _ = run(F.stream(*BASE, *grant(subjects=[("User", "cluster-admin", "")])), ["F2"], p=gates_on())
    assert not findings


@covers("F2", "neg:3")
def test_f2_delete_does_not_fire_and_recreate_is_attributed_to_the_new_uid():
    # Strict reading of the rule: the delete removes a right (no finding); the
    # recreate adds back a right absent immediately before it and is reported
    # against the new object UID, never matched to the deleted one.
    delete = [mutation(1, "delete", "rolebindings", "rb-reader", "rb-1", "9", code=200),
              F.rbac_obj(2, "RoleBinding", "rb-reader", "rb-1", namespace="shop", subjects=[SA],
                         role_ref=("Role", "reader"), rv="9", change="DELETED")]
    findings, evals, _ = run(F.stream(*BASE, *delete), ["F2"], p=gates_on())
    assert not findings and outcomes(evals, "F2") == [NOT_FIRED]
    recreate = grant(t=5, obs_t=6, rv="11", ref=("Role", "reader"), uid="rb-1b", name="rb-reader")
    findings, _, _ = run(F.stream(*BASE, *delete, *recreate), ["F2"], p=gates_on())
    [f] = of(findings, "F2")
    assert f.attributes["binding_uid"] == "rb-1b"


@covers("F2", "abstain:0")
def test_f2_watch_gap_abstains():
    _, evals, _ = run(F.stream(*BASE, *grant(), F.watch_gap(-10, 1.5)), ["F2"], p=gates_on())
    assert reasons(evals, "F2") == ["WATCH_RELIST_GAP"]


@covers("F2", "abstain:1")
def test_f2_unattributable_transition_abstains():
    _, evals, _ = run(F.stream(*BASE, grant()[0]), ["F2"], p=gates_on())   # no observation with that version
    assert reasons(evals, "F2") == ["JOIN_UNCERTAIN"]


@covers("F2", "abstain:2")
def test_f2_external_group_without_history_abstains():
    p = gates_on().with_overrides(artifacts={"external_groups": ["corp:devs"]})
    _, evals, _ = run(F.stream(*BASE, *grant(subjects=[("Group", "corp:devs", "")])), ["F2"], p=p)
    assert outcomes(evals, "F2") == [ABSTAINED]


@covers("F2", "abstain:3")
def test_f2_unknown_authorizer_chain_abstains():
    p = gates_on().with_overrides(artifacts={"authorizer_chain_known": False})
    _, evals, _ = run(F.stream(*BASE, *grant()), ["F2"], p=p)
    assert outcomes(evals, "F2") == [ABSTAINED]


def test_rbac_wildcards_and_resource_names():
    from microtrace.v0 import context_pb2
    from mtcore.agents import rbac
    rule = context_pb2.RbacRule(api_groups=["*"], resources=["*"], verbs=["get"])
    named = context_pb2.RbacRule(api_groups=[""], resources=["secrets"], verbs=["get"], resource_names=["a"])
    assert rbac.rule_allows(rule, ("res", "apps", "deployments", "get", "x"))
    assert not rbac.rule_allows(rule, ("res", "apps", "deployments", "list", "x"))
    assert rbac.rule_allows(named, ("res", "", "secrets", "get", "a"))
    assert not rbac.rule_allows(named, ("res", "", "secrets", "get", "b"))
    # A named-only rule does not cover "get any secret".
    assert not rbac._covered(("res", "", "secrets", "get", "*"), [named])
    sub = context_pb2.RbacRule(api_groups=[""], resources=["*/exec"], verbs=["create"])
    assert rbac.rule_allows(sub, ("res", "", "pods/exec", "create", ""))
