"""Agent G (G1a, G1c, G1b, G2) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, gates_on, of, outcomes, reasons, run
from mtcore.agents import routing
from mtcore.agents.rules.common import argv_hash

SRC = "pod-checkout-1"
CTX = [F.pod(-50, uid=SRC, owner="checkout"), F.pod(-50, uid="pod-payments-1", owner="payments"),
       F.pod(-50, uid="pod-db-1", owner="orders-db"), F.pod(-50, uid="pod-payments-2", owner="payments")]


def connect(t, remote_pod, port, result="SUCCESS", gaps=(), remote_class="cluster_pod", lineage="ln-1"):
    ne = F.ebpf(t, "net.connect", remote_class=remote_class, remote_pod=remote_pod, result=result, gaps=gaps,
                lineage=lineage)
    s = ne.ebpf.socket
    s.op, s.remote.ip, s.remote.port = 1, "10.2.0.9", port
    s.flow.node_id, s.flow.boot_id, s.flow.socket_cookie = F.NODE, F.BOOT, int(t * 1000)
    return F.done(ne)


@covers("G1a", "positive")
def test_g1a_fires_on_unbaselined_edge_only():
    findings, _, _ = run(F.stream(*CTX, connect(1, "pod-payments-1", 8080), connect(2, "pod-db-1", 5432)), ["G1a"])
    [f] = of(findings, "G1a")
    assert (f.attributes["destination_workload"], f.attributes["port"]) == ("orders-db", "5432")
    assert f.detection_path == 1


@covers("G1a", "neg:0")
def test_g1a_baselined_edge_after_ip_reuse_resolves_to_the_new_holder():
    # The normalizer resolves the reused IP to its holder at event time.
    findings, evals, _ = run(F.stream(*CTX, connect(1, "pod-payments-2", 8080)), ["G1a"])
    assert not findings and outcomes(evals, "G1a") == [NOT_FIRED]


@covers("G1a", "abstain:0")
def test_g1a_ambiguous_remote_abstains():
    _, evals, _ = run(F.stream(*CTX, connect(1, None, 8080, gaps=["JOIN_UNCERTAIN"])), ["G1a"])
    assert reasons(evals, "G1a") == ["JOIN_UNCERTAIN"]


def accept(t, pod, remote_pod, port, result="SUCCESS", gaps=(), remote_class="cluster_pod"):
    """An accepted inbound connection in pod from remote_pod, on local port."""
    ne = F.ebpf(t, "net.accept", pod=pod, remote_class=remote_class, remote_pod=remote_pod, result=result,
                gaps=gaps, lineage=f"ln-{pod}")
    s = ne.ebpf.socket
    s.op, s.remote.ip, s.remote.port, s.local.ip, s.local.port = 2, "10.2.0.9", 40000, "10.2.0.7", port
    s.flow.node_id, s.flow.boot_id, s.flow.socket_cookie = F.NODE, F.BOOT, int(t * 1000)
    return F.done(ne)


@covers("G1c", "positive")
def test_g1c_fires_on_an_unbaselined_inbound_edge_only():
    # checkout -> payments:8080 is baselined; orders-db -> payments:8080 is not.
    findings, _, _ = run(F.stream(*CTX, accept(1, "pod-payments-1", SRC, 8080),
                                  accept(2, "pod-payments-1", "pod-db-1", 8080)), ["G1c"])
    [f] = of(findings, "G1c")
    assert (f.attributes["source_workload"], f.attributes["destination_workload"], f.attributes["port"]) ==         ("orders-db", "payments", "8080")
    assert f.detection_path == 1


@covers("G1c", "neg:0")
def test_g1c_baselined_edge_after_ip_reuse_resolves_to_the_new_holder():
    # The normalizer resolves the peer's reused IP to its holder at event time.
    findings, evals, _ = run(F.stream(*CTX, accept(1, "pod-db-1", "pod-payments-2", 5432)), ["G1c"])
    assert not findings and outcomes(evals, "G1c") == [NOT_FIRED]


@covers("G1c", "abstain:0")
def test_g1c_ambiguous_peer_abstains():
    _, evals, _ = run(F.stream(*CTX, accept(1, "pod-payments-1", None, 8080, gaps=["JOIN_UNCERTAIN"])), ["G1c"])
    assert reasons(evals, "G1c") == ["JOIN_UNCERTAIN"]


def test_g1c_reads_accepts_and_g1a_connects():
    # Each rule sees only its own side of a connection.
    findings, _, _ = run(F.stream(*CTX, accept(1, "pod-payments-1", "pod-db-1", 8080),
                                  connect(2, "pod-db-1", 9999)), ["G1a", "G1c"])
    assert sorted(f.finding_type for f in findings) == ["G1a", "G1c"]


JTI = "jti-7"


def cred(env, jti=JTI):
    return ("credential.instance.v0", env, routing.encode("credential.instance.v0", [("JTI", jti)]))


def read(t):
    ne = F.ebpf(t, "file.read", token=F.token_version(), process="/bin/cat")
    ne.ebpf.file_access.bytes = 900
    return F.done(ne)


def pivot(target_ns="payments-ns", subresource="", jti=JTI, code=200):
    return [*CTX, cred(read(1)),
            cred(F.audit(5, verb="get", resource="secrets" if not subresource else "pods", namespace=target_ns,
                         subresource=subresource, used_jti=jti, code=code), jti=JTI)]


@covers("G1b", "positive")
def test_g1b_fires_on_read_then_use_across_declared_boundary():
    findings, _, _ = run(pivot(), ["G1b"], p=gates_on())
    [f] = of(findings, "G1b")
    assert f.primary_tactic == 7 and f.attributes["boundary"] == "shop->payments-ns" and f.attributes["jti"] == JTI


@covers("G1b", "abstain:0")
def test_g1b_gated_off_by_default():
    _, evals, _ = run(pivot(), ["G1b"])
    assert reasons(evals, "G1b") == ["CONDITIONAL_JOIN_UNVALIDATED"]


@covers("G1b", "neg:0")
def test_g1b_other_token_of_same_account_does_not_join():
    findings, _, _ = run(pivot(jti="jti-other"), ["G1b"], p=gates_on())
    assert not findings


@covers("G1b", "neg:1")
def test_g1b_stay_in_x_crosses_no_boundary():
    findings, _, _ = run(pivot(target_ns="shop"), ["G1b"], p=gates_on())
    assert not findings


@covers("G1b", "abstain:1")
def test_g1b_exec_effect_is_left_to_g2():
    findings, _, _ = run(pivot(subresource="exec"), ["G1b"], p=gates_on())
    assert not findings


ARGV = ["sh", "-c", "id"]
URI = "/api/v1/namespaces/shop/pods/checkout-x/exec?container=checkout&command=sh&command=-c&command=id&stdout=true"


def exec_request(t, code=101, target=SRC):
    return F.audit(t, verb="create", resource="pods", subresource="exec", stage="ResponseStarted", code=code,
                   request_uri=URI, target_pod=target, audit_id="aud-exec-1")


def target_exec(t, argv=ARGV, container="checkout", new=True):
    ne = F.ebpf(t, "proc.exec", container=container, lineage="ln-exec")
    ne.ebpf.exec.argv_sha256, ne.ebpf.exec.starts_new_lineage = argv_hash(argv), new
    return F.done(ne)


@covers("G2", "positive")
def test_g2_joins_accepted_exec_to_target_process():
    findings, _, _ = run(F.stream(*CTX, exec_request(1), target_exec(1.2)), ["G2"])
    [f] = of(findings, "G2")
    assert f.action_id == "aud-exec-1" and f.primary_tactic == 2 and len(f.input_event_ids) == 2


def _unc(env, ms):
    env.normalized_event.time.clock_uncertainty_ns = ms * 1_000_000
    return env


def test_g2_exec_timed_just_before_the_request_within_clock_uncertainty_joins():
    # The node clock runs behind the API server: the exec appears 2 ms early.
    req = _unc(exec_request(1), 5)
    findings, _, _ = run(F.stream(*CTX, req, _unc(target_exec(0.998), 5)), ["G2"])
    assert len(of(findings, "G2")) == 1
    # 100 ms early is beyond both uncertainties (10 ms): no join.
    _, evals, _ = run(F.stream(*CTX, _unc(exec_request(1), 5), _unc(target_exec(0.9), 5)), ["G2"])
    assert outcomes(evals, "G2") == [ABSTAINED]


@covers("G2", "neg:0")
def test_g2_denied_exec_does_not_fire():
    findings, evals, _ = run(F.stream(*CTX, exec_request(1, code=403), target_exec(1.2)), ["G2"])
    assert not findings and outcomes(evals, "G2") == [NOT_FIRED]


@covers("G2", "neg:1")
def test_g2_probe_exec_without_audit_request_is_not_evaluated():
    findings, evals, _ = run(F.stream(*CTX, target_exec(1)), ["G2"])
    assert not findings and not outcomes(evals, "G2")


@covers("G2", "abstain:0")
def test_g2_unresolved_target_pod_is_not_routed():
    findings, evals, stats = run(F.stream(*CTX, exec_request(1, target=None), target_exec(1.2)), ["G2"])
    assert not findings and not outcomes(evals, "G2")


@covers("G2", "abstain:1")
def test_g2_no_matching_exec_in_window_abstains():
    _, evals, _ = run(F.stream(*CTX, exec_request(1), target_exec(1.2, argv=["sh"]), target_exec(30)), ["G2"])
    assert outcomes(evals, "G2") == [ABSTAINED]
