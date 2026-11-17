"""Agent E (E1, E2, E3) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import ABSTAINED, NOT_FIRED, covers, gates_on, of, outcomes, reasons, run

POD = "pod-checkout-1"
CTX = [F.pod(-50, uid=POD, owner="checkout", containers=(("checkout", 0, "containerd://c1", -40),))]


@covers("E1", "positive")
def test_e1_fires_on_audit_mode_failure_for_created_pod():
    findings, _, _ = run(F.stream(*CTX, F.kyverno(1)), ["E1"])
    [f] = of(findings, "E1")
    assert f.attributes["pod_uid_join_status"] == "observed" and f.attributes["policy"] == "verify-images"


@covers("E1", "neg:0", "abstain:0")
def test_e1_dry_run_abstains():
    findings, evals, _ = run(F.stream(*CTX, F.kyverno(1, dry_run=True)), ["E1"])
    assert not findings and outcomes(evals, "E1") == [ABSTAINED]


@covers("E1", "neg:1", "neg:2")
def test_e1_pass_and_enforce_do_not_fire():
    findings, evals, _ = run(F.stream(*CTX, F.kyverno(1, verdict="PASS"), F.kyverno(2, audit_mode=False)), ["E1"])
    assert not findings and set(outcomes(evals, "E1")) == {NOT_FIRED}


@covers("E1", "abstain:1")
def test_e1_pod_never_observed_abstains():
    _, evals, _ = run(F.stream(F.kyverno(1, resource_uid="pod-ghost", pod="pod-ghost")), ["E1"])
    assert reasons(evals, "E1") == ["JOIN_UNCERTAIN"]


def write(t, path="/app/bin/tool", executable=True, op="WRITE", process="/bin/sh", ino=500, mnt=30, **kw):
    ne = F.ebpf(t, "file.mutation", process=process, **kw)
    m = ne.ebpf.file_mutation
    m.op = {"WRITE": 1, "CREATE": 2, "CHMOD": 3, "RENAME": 4, "UNLINK": 5, "MMAP_SHARED_WRITE": 6}[op]
    m.file.resolved_path, m.file.dev, m.file.ino, m.file.mnt_id = path, 64, ino, mnt
    m.executable_after = executable
    return F.done(ne)


@covers("E2", "positive")
def test_e2_fires_on_executable_write_after_start():
    findings, _, _ = run(F.stream(*CTX, write(1), write(2, path="/usr/local/bin/x", executable=False, ino=9)), ["E2"])
    assert len(of(findings, "E2")) == 2


@covers("E2", "neg:0")
def test_e2_data_file_write_does_not_fire():
    findings, evals, _ = run(F.stream(*CTX, write(1, path="/app/data/x.json", executable=False)), ["E2"])
    assert not findings and outcomes(evals, "E2") == [NOT_FIRED]


@covers("E2", "neg:1")
def test_e2_declared_setup_write_does_not_fire():
    findings, _, _ = run(F.stream(*CTX, write(1, path="/app/cache/gen.so", process="/app/entrypoint.sh")), ["E2"])
    assert not findings


@covers("E2", "abstain:0")
def test_e2_shared_mmap_write_abstains():
    _, evals, _ = run(F.stream(*CTX, write(1, op="MMAP_SHARED_WRITE")), ["E2"])
    assert reasons(evals, "E2") == ["JOIN_UNCERTAIN"]


def test_e2_write_before_container_start_does_not_fire():
    ctx = [F.pod(-50, uid=POD, owner="checkout", containers=(("checkout", 0, "containerd://c1", 10),))]
    findings, _, _ = run(F.stream(*ctx, write(1)), ["E2"])
    assert not findings


def exec_(t, ino=500, mnt=30, container_id="containerd://c2", **kw):
    ne = F.ebpf(t, "proc.exec", container_id=container_id, **kw)
    x = ne.ebpf.exec
    x.executable.dev, x.executable.ino, x.executable.mnt_id = 64, ino, mnt
    return F.done(ne)


def implant(restart=True, reexec=True, gap=False, unlink=False):
    items = [*CTX, write(1, seq=10)]
    if unlink:
        items.append(write(2, op="UNLINK", seq=11))
    if restart:
        items.append(exec_(30, ino=777, seq=12))          # new container instance starts
    if reexec:
        items.append(exec_(40, seq=13))
    if gap:
        items.append(F.loss(20, 25, source="EBPF"))
    return F.stream(*items)


@covers("E3", "positive")
def test_e3_write_restart_reexec_fires_and_e2_remains():
    findings, _, _ = run(implant(), ["E3", "E2"], p=gates_on())
    [f] = of(findings, "E3")
    assert f.primary_tactic == 3 and f.attributes["artifact_identity"] == "mount-dev-ino:30:64:500"
    assert len(of(findings, "E2")) == 1


@covers("E3", "abstain:0", "abstain:1")
def test_e3_gated_until_artifact_identity_is_accepted():
    _, evals, _ = run(implant(), ["E3"])
    assert set(reasons(evals, "E3")) == {"CONDITIONAL_JOIN_UNVALIDATED"}


@covers("E3", "neg:0")
def test_e3_restart_without_write_does_not_fire():
    findings, _, _ = run(F.stream(*CTX, exec_(30, ino=777), exec_(40)), ["E3"], p=gates_on())
    assert not findings


@covers("E3", "neg:1")
def test_e3_other_replica_is_another_key():
    other = [F.pod(-50, uid="pod-checkout-2", owner="checkout")]
    findings, _, _ = run(F.stream(*CTX, *other, write(1, seq=10), exec_(30, ino=777, seq=12, pod="pod-checkout-2"),
                                  exec_(40, seq=13, pod="pod-checkout-2")), ["E3"], p=gates_on())
    assert not findings


@covers("E3", "neg:2")
def test_e3_written_file_never_executed_after_restart():
    findings, evals, _ = run(implant(reexec=False), ["E3"], p=gates_on())
    assert not findings and NOT_FIRED in outcomes(evals, "E3")


@covers("E3", "abstain:2")
def test_e3_dropped_interval_abstains():
    _, evals, _ = run(implant(gap=True), ["E3"], p=gates_on())
    assert "DROPPED_BEFORE" in reasons(evals, "E3")


def test_e3_unlink_breaks_file_continuity():
    findings, _, _ = run(implant(unlink=True), ["E3"], p=gates_on())
    assert not findings
