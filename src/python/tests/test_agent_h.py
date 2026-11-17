"""Agent H (H1-H5) against rulebook.v0."""
import agent_fixtures as F
from agent_testlib import NOT_FIRED, covers, of, outcomes, reasons, run

POD = "pod-checkout-1"
CTX = [F.pod(-50, uid=POD, owner="checkout")]


def flow_bytes(t, nbytes, dst="198.51.100.9", cookie=1, lineage="ln-1", seq=None):
    ne = F.ebpf(t, "net.flow_bytes", remote_class="external", lineage=lineage, seq=seq)
    fc = ne.ebpf.flow_counter
    fc.bytes_out, fc.remote.ip, fc.remote.port = nbytes, dst, 443
    fc.flow.node_id, fc.flow.boot_id, fc.flow.socket_cookie = F.NODE, F.BOOT, cookie
    return F.done(ne)


def ext_connect(t, dst="198.51.100.9", port=443, cookie=1, lineage="ln-1", seq=None):
    ne = F.ebpf(t, "net.connect", remote_class="external", lineage=lineage, seq=seq)
    s = ne.ebpf.socket
    s.op, s.remote.ip, s.remote.port = 1, dst, port
    s.flow.node_id, s.flow.boot_id, s.flow.socket_cookie = F.NODE, F.BOOT, cookie
    return F.done(ne)


@covers("H1", "positive")
def test_h1_fires_above_workload_baseline():
    findings, _, _ = run(F.stream(*CTX, flow_bytes(1, 700_000), flow_bytes(2, 600_000, cookie=2)), ["H1"])
    [f] = of(findings, "H1")
    assert f.attributes["bytes_out"] == "1300000"


@covers("H1", "neg:0")
def test_h1_backup_within_baseline():
    findings, evals, _ = run(F.stream(*CTX, flow_bytes(1, 900_000)), ["H1"])
    assert not findings and outcomes(evals, "H1") == [NOT_FIRED]


@covers("H1", "abstain:0")
def test_h1_counter_overlapping_sensor_loss_abstains():
    _, evals, _ = run(F.stream(*CTX, flow_bytes(1, 2_000_000), F.loss(100, 110, source="EBPF")), ["H1"])
    assert reasons(evals, "H1") == ["DROPPED_BEFORE"]   # the loss is inside the 300 s window


@covers("H2", "positive")
def test_h2_fires_on_undeclared_destination():
    findings, _, _ = run(F.stream(*CTX, ext_connect(1, dst="203.0.113.10"), ext_connect(2, dst="198.51.100.1")), ["H2"])
    [f] = of(findings, "H2")
    assert f.attributes["destination"] == "198.51.100.1"


@covers("H2", "neg:0")
def test_h2_exact_destination_set_has_no_ranges():
    # The dev set declares no ranges, so a new IP next to a declared one is new.
    findings, _, _ = run(F.stream(*CTX, ext_connect(1, dst="203.0.113.11")), ["H2"])
    assert len(findings) == 1


def secret(t, verb="get", name="s", ns="shop"):
    return F.audit(t, verb=verb, resource="secrets", name=name if verb == "get" else "", namespace=ns)


@covers("H3", "positive")
def test_h3_fires_on_bulk_secret_reads():
    findings, _, _ = run(F.stream(*[secret(i, name=f"s{i}") for i in range(18)],
                                  *[secret(30 + i, verb="list", ns=f"n{i}") for i in range(5)]), ["H3"])
    [f] = of(findings, "H3")
    assert f.attributes["distinct_secret_gets"] == "18" and f.attributes["list_requests"] == "5"


@covers("H3", "neg:0")
def test_h3_periodic_controller_list_below_threshold():
    findings, evals, _ = run(F.stream(*[secret(i * 10, verb="list") for i in range(5)]), ["H3"])
    assert not findings and outcomes(evals, "H3") == [NOT_FIRED]


@covers("H3", "abstain:0")
def test_h3_no_read_events_no_evaluation():
    findings, evals, _ = run(F.stream(F.audit(1, verb="get", resource="pods")), ["H3"])
    assert not findings and not outcomes(evals, "H3")


def data_read(t, lineage="ln-1", seq=None, klass="customer-pii"):
    ne = F.ebpf(t, "file.read", data_class=klass, lineage=lineage, seq=seq)
    ne.ebpf.file_access.bytes = 4096
    return F.done(ne)


@covers("H4", "positive")
def test_h4_read_then_external_transfer_in_one_lineage():
    findings, _, _ = run(F.stream(data_read(1, seq=100), ext_connect(2, seq=101), flow_bytes(3, 5000, seq=102)), ["H4"])
    [f] = of(findings, "H4")
    assert f.primary_tactic == 8 and len(f.input_event_ids) == 3


@covers("H4", "neg:0", "abstain:1", "abstain:2")
def test_h4_different_lineages_never_join():
    findings, _, _ = run(F.stream(data_read(1, seq=100), ext_connect(2, lineage="ln-2", seq=101),
                                  flow_bytes(3, 5000, lineage="ln-2", seq=102)), ["H4"])
    assert not findings


@covers("H4", "neg:1")
def test_h4_transfer_without_sensitive_read():
    findings, evals, _ = run(F.stream(data_read(1, seq=100, klass="logs"), ext_connect(2, seq=101),
                                      flow_bytes(3, 5000, seq=102)), ["H4"])
    assert not findings and not outcomes(evals, "H4")


@covers("H4", "abstain:0")
def test_h4_sequence_gap_abstains():
    _, evals, _ = run(F.stream(data_read(1, seq=100), ext_connect(20, seq=150), flow_bytes(21, 5000, seq=151),
                               F.loss(5, 10, source="EBPF")), ["H4"])
    assert reasons(evals, "H4") == ["DROPPED_BEFORE"]


@covers("H5", "positive")
def test_h5_read_then_offnode_egress():
    findings, _, _ = run(F.stream(F.db_read(1), F.path_flow(2, 30, octets=900)), ["H5"])
    [f] = of(findings, "H5")
    assert f.attributes["octets_out"] == "900" and f.attributes["source_address_class"] == "POD_ADDRESS"


@covers("H5", "neg:0")
def test_h5_below_rho_or_outside_window():
    findings, _, _ = run(F.stream(F.db_read(1), F.path_flow(2, 30, octets=100)), ["H5"])
    assert not findings
    findings, _, _ = run(F.stream(F.db_read(1), F.path_flow(200, 230, octets=900)), ["H5"])
    assert not findings


@covers("H5", "neg:1", "neg:2", "abstain:3")
def test_h5_host_component_flows_are_excluded():
    findings, evals, _ = run(F.stream(F.db_read(1), F.path_flow(2, 30, octets=5000, host_match="kubelet-image-pull")),
                             ["H5"])
    assert not findings and reasons(evals, "H5") == ["POLICY_EXCLUDED"]


@covers("H5", "abstain:0")
def test_h5_ambiguous_source_abstains():
    _, evals, _ = run(F.stream(F.db_read(1, klass="AMBIGUOUS"), F.path_flow(2, 30)), ["H5"])
    assert reasons(evals, "H5") == ["JOIN_UNCERTAIN"]


@covers("H5", "abstain:1")
def test_h5_bytes_not_logged_abstains():
    _, evals, _ = run(F.stream(F.db_read(1, bytes_returned=None), F.path_flow(2, 30)), ["H5"])
    assert reasons(evals, "H5") == ["FIELD_ABSENT"]


@covers("H5", "abstain:2")
def test_h5_sampled_flows_abstain():
    _, evals, _ = run(F.stream(F.db_read(1), F.path_flow(2, 30, sampled=True)), ["H5"])
    assert reasons(evals, "H5") == ["POLICY_EXCLUDED"]


@covers("H5", "abstain:4")
def test_h5_export_gap_abstains():
    _, evals, _ = run(F.stream(F.db_read(1), F.path_flow(2, 30), F.loss(10, 20, source="PATH_FLOW", node="observer")),
                      ["H5"])
    assert reasons(evals, "H5") == ["DROPPED_BEFORE"]


def test_h5_flow_must_end_after_read_plus_uncertainties():
    findings, _, _ = run(F.stream(F.db_read(10), F.path_flow(5, 10, octets=900)), ["H5"])
    assert not findings


def test_h5_flow_opened_before_the_read_and_ending_after_it_counts():
    # A long-lived connection: its flow record starts before the read.
    for order in ((F.path_flow(5, 40, octets=900), F.db_read(10)), (F.db_read(10), F.path_flow(5, 40, octets=900))):
        findings, _, _ = run(F.stream(*order), ["H5"])
        [f] = of(findings, "H5")
        assert f.attributes["octets_out"] == "900"
    # ... but not one that started more than W_H5 (120 s) before the read
    findings, _, _ = run(F.stream(F.path_flow(1, 300, octets=900), F.db_read(200)), ["H5"])
    assert not findings
