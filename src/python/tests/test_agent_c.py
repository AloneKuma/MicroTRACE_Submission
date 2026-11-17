"""Agent C (C1a, C1b, C2) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, of, outcomes, reasons, run
from microtrace.v0 import ebpf_pb2

HOST = dict(mnt=4026531840, pid=4026531836)
CONT = dict(mnt=4026532900, pid=4026532901)


def ns_change(t, op="SETNS", before=CONT, after=HOST, family="ns.change", **kw):
    ne = F.ebpf(t, family, **kw)
    d = ne.ebpf.namespace_change
    d.op = ebpf_pb2.NamespaceOp.Value(op)
    if before is not None:
        d.before.mnt, d.before.pid = before["mnt"], before["pid"]
    d.after.mnt, d.after.pid = after["mnt"], after["pid"]
    d.host_reference.mnt, d.host_reference.pid = HOST["mnt"], HOST["pid"]
    return F.done(ne)


def bpf(t, sensor, **kw):
    ne = F.ebpf(t, "bpf.call", **kw)
    ne.ebpf.bpf.cmd, ne.ebpf.bpf.caller_is_sensor = 5, sensor
    return F.done(ne)


@covers("C1a", "positive")
def test_c1a_fires_on_pod_setns_and_runtime_socket_and_bpf():
    sock = F.ebpf(3, "ipc.runtime_socket", lineage="ln-2")
    sock.ebpf.socket.remote.unix_path = "/run/containerd/containerd.sock"
    findings, _, _ = run(F.stream(ns_change(1, after=CONT), F.done(sock), bpf(5, False, lineage="ln-3")), ["C1a"])
    kinds = sorted(f.attributes["indicator_kind"] for f in of(findings, "C1a"))
    assert kinds == ["bpf", "runtime_socket", "setns"]


@covers("C1a", "neg:0")
def test_c1a_sensor_bpf_and_runtime_setns_do_not_fire():
    findings, evals, _ = run(F.stream(bpf(1, True), ns_change(2, pod=None, lineage="ln-rt")), ["C1a"])
    assert not findings and set(outcomes(evals, "C1a")) == {NOT_FIRED}


@covers("C1a", "abstain:0")
def test_c1a_uncertain_pod_attribution_abstains():
    _, evals, _ = run(F.stream(ns_change(1, after=CONT, gaps=["JOIN_UNCERTAIN"])), ["C1a"])
    assert outcomes(evals, "C1a") == [ABSTAINED] and reasons(evals, "C1a") == ["JOIN_UNCERTAIN"]


@covers("C1b", "positive")
def test_c1b_fires_once_on_transition_into_host_namespaces():
    findings, _, _ = run(F.stream(ns_change(1, op="NS_SAMPLE", family="ns.sample", before=None, after=CONT),
                                  ns_change(2), ns_change(3, op="NS_SAMPLE", family="ns.sample", before=None)),
                         ["C1b", "C1a"])
    [f] = of(findings, "C1b")
    assert f.primary_tactic == 4 and f.attributes["via_operation"] == "setns"
    assert len(of(findings, "C1a")) == 1      # the attempt is also reported (weaker type)


@covers("C1b", "neg:0")
def test_c1b_daemonset_in_host_namespaces_from_start_does_not_fire():
    findings, evals, _ = run(F.stream(ns_change(1, op="NS_SAMPLE", family="ns.sample", before=HOST),
                                      F.done(F.ebpf(2, "proc.exec", host_ns_after=True))), ["C1b"])
    assert not findings and set(outcomes(evals, "C1b")) == {NOT_FIRED}


@covers("C1b", "abstain:0")
def test_c1b_lineage_gap_abstains():
    rec = F.stream(ns_change(10, op="NS_SAMPLE", family="ns.sample", before=None, after=CONT), ns_change(20),
                   F.loss(15, 25, source="EBPF"))
    findings, evals, _ = run(rec, ["C1b"])
    assert not findings and "DROPPED_BEFORE" in reasons(evals, "C1b")


def test_loss_on_another_node_does_not_apply_to_ebpf_rules():
    rec = F.stream(ns_change(1, after=CONT), F.loss(0, 5, source="EBPF", node="node-9"))
    findings, _, _ = run(rec, ["C1a"])
    assert len(findings) == 1


def ptrace(t, request, **kw):
    ne = F.ebpf(t, "proc.ptrace", **kw)
    ne.ebpf.ptrace.request = request
    ne.ebpf.ptrace.target.tgid = 42
    return F.done(ne)


@covers("C2", "positive")
def test_c2_fires_on_attach_and_seize():
    findings, _, _ = run(F.stream(ptrace(1, 16), ptrace(2, 0x4206, lineage="ln-9")), ["C2"])
    assert len(of(findings, "C2")) == 2


@covers("C2", "neg:0")
def test_c2_proc_status_read_is_not_ptrace():
    # Reading /proc/<pid>/status produces no ptrace record; a PEEKDATA request is not attach/seize.
    findings, evals, _ = run(F.stream(F.done(F.ebpf(1, "file.read")), ptrace(2, 2)), ["C2"])
    assert not findings and outcomes(evals, "C2") == [NOT_FIRED]
