"""Agent D (D1, D2) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, gates_on, of, outcomes, reasons, run

OWNER = "pod-checkout-1"


def token_read(t, process="/bin/cat", reader="READER_POD_PROCESS", resolved=True, result="SUCCESS",
               nbytes=900, family="file.read", pod=OWNER, host_process=None, gaps=(), dev=64, ino=1001):
    tok = F.token_version(owner=OWNER) if resolved else None
    ne = F.ebpf(t, family, pod=pod, process=process if not host_process else None, host_process=host_process,
                reader=reader, result=result, token=tok, gaps=gaps)
    fa = ne.ebpf.file_access
    fa.op = 2 if family == "file.read" else 1
    fa.bytes = nbytes
    fa.file.dev, fa.file.ino = dev, ino
    fa.file.projected.CopyFrom(F.token_version(owner=OWNER))
    return F.done(ne)


CTX = [F.pod(-50, uid=OWNER, owner="checkout")]


@covers("D1", "positive")
def test_d1_fires_on_unexpected_reader_and_host_reader_kept_separate():
    findings, _, _ = run(F.stream(*CTX, token_read(1), token_read(2, reader="READER_HOST_PROCESS",
                                                                  host_process="/usr/bin/kubelet-helper", pod=None,
                                                                  ino=1002)), ["D1"])
    fs = sorted(of(findings, "D1"), key=lambda f: f.attributes["reader_class"])
    assert [f.attributes["reader_class"] for f in fs] == ["READER_HOST_PROCESS", "READER_POD_PROCESS"]
    assert fs[0].attributes["reader_pod_uid"] == "" and fs[1].attributes["reader_pod_uid"] == OWNER
    assert fs[0].attributes["token_owner_pod_uid"] == OWNER and fs[0].primary_tactic == 5


@covers("D1", "neg:0")
def test_d1_expected_reader_does_not_fire():
    findings, evals, _ = run(F.stream(*CTX, token_read(1, process="/app/checkout")), ["D1"])
    assert not findings and outcomes(evals, "D1") == [NOT_FIRED]


@covers("D1", "neg:1", "abstain:1")
def test_d1_open_without_read_is_not_evaluated():
    findings, evals, _ = run(F.stream(*CTX, token_read(1, family="file.open")), ["D1"])
    assert not findings and not outcomes(evals, "D1")


@covers("D1", "neg:2", "abstain:0")
def test_d1_unresolved_token_identity_abstains():
    findings, evals, _ = run(F.stream(*CTX, token_read(1, resolved=False)), ["D1"])
    assert not findings and outcomes(evals, "D1") == [ABSTAINED]


@covers("D1", "neg:3")
def test_d1_kubelet_rotation_write_is_not_a_read():
    ne = F.ebpf(1, "file.mutation", pod=None, process="/usr/bin/kubelet", token=F.token_version())
    findings, evals, _ = run(F.stream(*CTX, F.done(ne)), ["D1"])
    assert not findings and not outcomes(evals, "D1")


@covers("D1", "abstain:2")
def test_d1_failed_or_empty_read_does_not_fire():
    findings, evals, _ = run(F.stream(*CTX, token_read(1, result="FAILURE"), token_read(2, nbytes=0, ino=7)), ["D1"])
    assert not findings and set(outcomes(evals, "D1")) == {NOT_FIRED}


@covers("D1", "abstain:3")
def test_d1_unresolved_reader_abstains():
    _, evals, _ = run(F.stream(*CTX, token_read(1, reader="READER_UNATTRIBUTED")), ["D1"])
    assert reasons(evals, "D1") == ["JOIN_UNCERTAIN"]


@covers("D1", "abstain:4")
def test_d1_owner_workload_not_declared_abstains():
    ctx = [F.pod(-50, uid=OWNER, owner="unknown-workload")]
    _, evals, _ = run(F.stream(*ctx, token_read(1)), ["D1"])
    assert outcomes(evals, "D1") == [ABSTAINED]


def use(t, bound="pod-x", routes=("pod-z", "pod-z"), jti="jti-1"):
    return F.audit(t, verb="get", resource="secrets", used_jti=jti, bound_pod=bound, caller_routes=routes)


@covers("D2", "positive", "neg:4")
def test_d2_fires_when_both_routes_agree_on_another_pod():
    findings, _, _ = run(F.stream(use(1)), ["D2"], p=gates_on())
    [f] = of(findings, "D2")
    assert f.attributes["caller_pod_uid"] == "pod-z" and f.action_id == f.attributes["audit_id"]


def test_d2_gated_off_by_default():
    _, evals, _ = run(F.stream(use(1)), ["D2"])
    assert reasons(evals, "D2") == ["CONDITIONAL_JOIN_UNVALIDATED"]


@covers("D2", "neg:0")
def test_d2_stay_in_x_does_not_fire():
    findings, evals, _ = run(F.stream(use(1, routes=("pod-x", "pod-x"))), ["D2"], p=gates_on())
    assert not findings and outcomes(evals, "D2") == [NOT_FIRED]


@covers("D2", "neg:1", "neg:2", "neg:3", "abstain:0", "abstain:2", "abstain:3")
def test_d2_missing_caller_route_abstains():
    # Node-name claim only, forged XFF (not the last source IP), host-network
    # peer, or no covering connection: the normalizer leaves a route absent.
    for routes in [(None, None), ("pod-z", None), (None, "pod-z")]:
        _, evals, _ = run(F.stream(use(1, routes=routes)), ["D2"], p=gates_on())
        assert outcomes(evals, "D2") == [ABSTAINED]


@covers("D2", "abstain:1")
def test_d2_disagreeing_routes_abstain():
    _, evals, _ = run(F.stream(use(1, routes=("pod-z", "pod-w"))), ["D2"], p=gates_on())
    assert reasons(evals, "D2") == ["JOIN_UNCERTAIN"]


@covers("D2", "abstain:4")
def test_d2_unbound_token_abstains():
    _, evals, _ = run(F.stream(use(1, bound=None)), ["D2"], p=gates_on())
    assert outcomes(evals, "D2") == [ABSTAINED]
