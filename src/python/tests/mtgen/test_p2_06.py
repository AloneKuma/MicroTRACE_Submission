"""Tests for Phase 2.4b: eBPF renderer.

Required tests (task spec):
  C1a: namespace escape / capset / runtime socket connect
  C1b: host-namespace-after set; lineage continuity across parent/child
  C2:  ptrace attach records correct target process key
  D1:  token read by unexpected reader – token_file.owner_pod_uid != pod_uid
  E2:  post-start executable write (make_executable -> executable_after=True)
  F1:  euid-to-root privilege change (euid 1000 -> 0)
  G1a/H2: net.connect external -> remote_class="external";
           internal -> "cluster_pod" with remote_pod_uid
  H1:  byte totals in net.flow_bytes FlowCounter
  H4:  sensitive read data_class="sensitive"; same lineage_id as subsequent connect
  Ambiguous cgroup: pod_uid absent + JOIN_UNCERTAIN gap
  Determinism: two fresh renderers produce identical serialised output
"""
import types

import pytest

import mtgen  # registers gen/ and spec/tools/ on sys.path
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.history import WorldHistory, FOREVER
from mtgen.render.ebpf import EbpfRenderer
from mtgen.world import NodeState, ContainerState, ProcessState
from microtrace.v0 import common_pb2, ebpf_pb2, normalized_pb2


# ---------------------------------------------------------------------------
# Shared world constants
# ---------------------------------------------------------------------------

NODE_UID = "node-uid-0001"
NODE_BOOT_ID = "boot-id-00000001"
NODE_INIT_MNT_NS = 4026531840
NODE_INIT_PID_NS = 4026531836

POD_UID = "pod-uid-0001"
CTR_UID = "ctr-uid-0001"
CTR_NAME = "app"
CGROUP = f"/kubepods/pod{POD_UID}/{CTR_UID}"

# Second pod: used in G1a/H2 internal connect tests
POD2_UID = "pod-uid-0002"
POD2_IP = "10.0.2.200"

RUN_START_NS = 1_704_067_200_000_000_000
T0 = RUN_START_NS + 10_000_000_000  # 10 s into the run

# C_H4 sensitive path
H4_SENSITIVE_PATH = "/run/secrets/env.conf"


# ---------------------------------------------------------------------------
# Process key helper (mirrors mtgen.world._process_key)
# ---------------------------------------------------------------------------

def _pkey(node_uid: str, boot_id: str, tgid: int, start_ns: int) -> str:
    return f"{node_uid[:8]}:{boot_id[:8]}:{tgid}:{start_ns:x}"


_INIT_TGID = 1
_INIT_START_NS = 100_000_000       # 0.1 s
_APP_TGID = 1234
_APP_START_NS = 200_000_000        # 0.2 s

INIT_PROC_KEY = _pkey(NODE_UID, NODE_BOOT_ID, _INIT_TGID, _INIT_START_NS)
APP_PROC_KEY = _pkey(NODE_UID, NODE_BOOT_ID, _APP_TGID, _APP_START_NS)


# ---------------------------------------------------------------------------
# Minimal world factory
# ---------------------------------------------------------------------------

def _make_world(extra_history=None):
    """Return a minimal fake World suitable for EbpfRenderer tests.

    Contains one node, one container (CGROUP), and two processes:
      init_proc (parent_key="") — lineage root
      app_proc  (parent_key=INIT_PROC_KEY) — typical workload process

    POD2_IP is registered in PodIP history for internal-connect tests.
    """
    history = WorldHistory()

    node = NodeState(
        uid=NODE_UID, name="node-01", boot_id=NODE_BOOT_ID,
        init_mnt_ns=NODE_INIT_MNT_NS, init_pid_ns=NODE_INIT_PID_NS,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    ctr = ContainerState(
        uid=CTR_UID, name=CTR_NAME, pod_uid=POD_UID,
        image_digest="sha256:" + "a" * 64, image_signed=True,
        is_sidecar=False, cgroup=CGROUP,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    init_proc = ProcessState(
        process_key=INIT_PROC_KEY, container_uid=CTR_UID, pod_uid=POD_UID,
        node_uid=NODE_UID, boot_id=NODE_BOOT_ID,
        tgid=_INIT_TGID, start_time_ns=_INIT_START_NS,
        executable="/pause",
        parent_process_key="",          # lineage root
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    app_proc = ProcessState(
        process_key=APP_PROC_KEY, container_uid=CTR_UID, pod_uid=POD_UID,
        node_uid=NODE_UID, boot_id=NODE_BOOT_ID,
        tgid=_APP_TGID, start_time_ns=_APP_START_NS,
        executable="/app/server",
        parent_process_key=INIT_PROC_KEY,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )

    history.add("Node", NODE_UID, RUN_START_NS, FOREVER, node)
    history.add("Cgroup", CGROUP, RUN_START_NS, FOREVER, ctr)
    history.add("PodIP", POD2_IP, RUN_START_NS, FOREVER,
                types.SimpleNamespace(uid=POD2_UID))
    history.add("Process", INIT_PROC_KEY, RUN_START_NS, FOREVER, init_proc)
    history.add("Process", APP_PROC_KEY, RUN_START_NS, FOREVER, app_proc)

    if extra_history:
        for (kind, key, vfrom, vto, state) in extra_history:
            history.add(kind, key, vfrom, vto, state)

    return types.SimpleNamespace(
        history=history,
        processes=[init_proc, app_proc],
        nodes=[node],
        run_start_ns=RUN_START_NS,
    )


def _make_renderer(world=None, c_h4=None):
    if world is None:
        world = _make_world()
    return EbpfRenderer(world, EvidenceArchive("test-ebpf"), c_h4=c_h4)


def _activity(kind: str, time_ns: int = T0, **params) -> Activity:
    return Activity(
        time_ns=time_ns,
        kind=kind,
        actor_uid=APP_PROC_KEY,
        actor_type="Process",
        target_uid="",
        target_type="",
        parameters=params,
    )


# ---------------------------------------------------------------------------
# Basic derivation sanity: pod_uid, container_name, node_seq, time
# ---------------------------------------------------------------------------

def test_pod_uid_and_container_name_from_cgroup():
    """EbpfDerived.pod_uid and container_name come from unambiguous cgroup lookup."""
    rend = _make_renderer()
    [ne] = rend.render(_activity("proc_exit", process_key=APP_PROC_KEY))
    assert ne.ebpf_derived.HasField("pod_uid")
    assert ne.ebpf_derived.pod_uid == POD_UID
    assert ne.ebpf_derived.container_name == CTR_NAME


def test_node_seq_strictly_increasing():
    """node_seq increases strictly for successive events on the same (node, boot)."""
    rend = _make_renderer()
    events = []
    for _ in range(3):
        events.extend(rend.render(_activity("proc_exit", process_key=APP_PROC_KEY)))
    seqs = [ne.ebpf.node_seq for ne in events]
    for i in range(1, len(seqs)):
        assert seqs[i] > seqs[i - 1]


def test_monotonic_ns_offset():
    """monotonic_ns equals time_ns minus run_start_ns."""
    rend = _make_renderer()
    [ne] = rend.render(_activity("proc_exit", process_key=APP_PROC_KEY, time_ns=T0))
    assert ne.ebpf.monotonic_ns == T0 - RUN_START_NS


def test_time_basis_ebpf_monotonic_corrected():
    """Event time basis is EBPF_MONOTONIC_CORRECTED."""
    rend = _make_renderer()
    [ne] = rend.render(_activity("proc_exit", process_key=APP_PROC_KEY))
    assert ne.time.event_time_basis == common_pb2.EBPF_MONOTONIC_CORRECTED


def test_source_native_id_format():
    """source_native_id is node_id/boot_id/node_seq; first event has seq=0."""
    rend = _make_renderer()
    [ne] = rend.render(_activity("proc_exit", process_key=APP_PROC_KEY))
    parts = ne.source_native_id.split("/")
    assert len(parts) == 3
    assert parts[0] == NODE_UID
    assert parts[1] == NODE_BOOT_ID
    assert parts[2] == "0"


# ---------------------------------------------------------------------------
# C1a: namespace escape / capset / runtime socket
# ---------------------------------------------------------------------------

def test_c1a_namespace_escape_host_after_true():
    """ns.change with after==node init ns sets host_namespace_after=True."""
    rend = _make_renderer()
    ne_list = rend.render(_activity(
        "namespace_escape",
        process_key=APP_PROC_KEY,
        mnt_after=NODE_INIT_MNT_NS,
        pid_after=NODE_INIT_PID_NS,
    ))
    assert len(ne_list) == 1
    ne = ne_list[0]
    assert ne.ebpf.event_family == "ns.change"
    assert ne.ebpf_derived.host_namespace_after


def test_c1a_namespace_escape_host_after_false():
    """ns.change with after != node init ns leaves host_namespace_after=False."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "namespace_escape",
        process_key=APP_PROC_KEY,
        mnt_after=4026532999,
        pid_after=4026532998,
    ))
    assert not ne.ebpf_derived.host_namespace_after


def test_c1a_capset():
    """capability_gain with op=CAPSET produces priv.creds with CAPSET op."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "capability_gain",
        process_key=APP_PROC_KEY,
        op="CAPSET",
        cap_effective_after=0x3FFFFF,
    ))
    assert ne.ebpf.event_family == "priv.creds"
    assert ne.ebpf.privilege.op == ebpf_pb2.CAPSET


def test_c1a_runtime_socket():
    """runtime_socket_connect produces ipc.runtime_socket with correct unix_path."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "runtime_socket_connect",
        process_key=APP_PROC_KEY,
        unix_path="/var/run/containerd/containerd.sock",
    ))
    assert ne.ebpf.event_family == "ipc.runtime_socket"
    assert ne.ebpf.socket.remote.unix_path == "/var/run/containerd/containerd.sock"


# ---------------------------------------------------------------------------
# C1b: host-namespace-after with lineage continuity
# ---------------------------------------------------------------------------

def test_c1b_lineage_continuity_parent_child_ns_escape():
    """Init, app, and app ns.change all share the same lineage_id (root = init)."""
    rend = _make_renderer()

    # Init process exec
    init_events = rend.render(_activity(
        "process_exec", process_key=INIT_PROC_KEY,
    ))
    init_lineage = init_events[0].ebpf_derived.lineage_id

    # App process exec (child of init)
    app_events = rend.render(_activity(
        "process_exec", process_key=APP_PROC_KEY,
    ))
    app_lineage = app_events[0].ebpf_derived.lineage_id

    # Namespace escape by app process
    [ns_ne] = rend.render(_activity(
        "namespace_escape",
        process_key=APP_PROC_KEY,
        mnt_after=NODE_INIT_MNT_NS,
        pid_after=NODE_INIT_PID_NS,
    ))
    ns_lineage = ns_ne.ebpf_derived.lineage_id

    # All three events share the lineage root (init_proc with parent_key="")
    assert init_lineage == app_lineage == ns_lineage
    # The namespace escape event also has host_namespace_after set
    assert ns_ne.ebpf_derived.host_namespace_after


# ---------------------------------------------------------------------------
# C2: ptrace
# ---------------------------------------------------------------------------

def test_c2_ptrace_correct_target_process_key():
    """proc.ptrace records correct attacher and target ProcessKey fields."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "ptrace_attach",
        attacher_process_key=APP_PROC_KEY,
        target_process_key=INIT_PROC_KEY,
    ))
    assert ne.ebpf.event_family == "proc.ptrace"
    # Attacher = app process
    assert ne.ebpf.process.tgid == _APP_TGID
    # Target = init process
    assert ne.ebpf.ptrace.request == 16  # PTRACE_ATTACH
    assert ne.ebpf.ptrace.target.node_id == NODE_UID
    assert ne.ebpf.ptrace.target.tgid == _INIT_TGID
    assert ne.ebpf.ptrace.target.start_time_ns == _INIT_START_NS


# ---------------------------------------------------------------------------
# D1: token read by unexpected reader (owner_pod_uid != reader pod_uid)
# ---------------------------------------------------------------------------

def test_d1_token_read_unexpected_reader():
    """Token file read: token_file.owner_pod_uid differs from reader's pod_uid."""
    rend = _make_renderer()
    foreign_pod = "pod-uid-foreign-0001"

    events = rend.render(_activity(
        "read_token_file",
        reader_process_key=APP_PROC_KEY,
        owner_pod_uid=foreign_pod,
        volume_name="kube-api-access-x",
    ))
    assert len(events) == 3
    families = [ne.ebpf.event_family for ne in events]
    assert families == ["token.file_index", "file.open", "file.read"]

    read_ne = events[2]
    assert read_ne.ebpf_derived.HasField("token_file")
    assert read_ne.ebpf_derived.token_file.owner_pod_uid == foreign_pod
    assert read_ne.ebpf_derived.token_file.volume_name == "kube-api-access-x"
    # Reader is in POD_UID (from cgroup)
    assert read_ne.ebpf_derived.HasField("pod_uid")
    assert read_ne.ebpf_derived.pod_uid == POD_UID
    # Cross-pod token read: owner differs from reader
    assert read_ne.ebpf_derived.token_file.owner_pod_uid != read_ne.ebpf_derived.pod_uid


def test_d1_token_file_index_has_no_token_file_in_derived():
    """token.file_index event itself does not have token_file in EbpfDerived."""
    rend = _make_renderer()
    events = rend.render(_activity(
        "read_token_file",
        reader_process_key=APP_PROC_KEY,
    ))
    idx_ne = events[0]
    assert idx_ne.ebpf.event_family == "token.file_index"
    assert not idx_ne.ebpf_derived.HasField("token_file")


# ---------------------------------------------------------------------------
# E2: post-start executable write
# ---------------------------------------------------------------------------

def test_e2_make_executable_sets_flag():
    """make_executable activity produces file.mutation with executable_after=True."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "make_executable",
        writer_process_key=APP_PROC_KEY,
        file_path="/tmp/injected.sh",
    ))
    assert ne.ebpf.event_family == "file.mutation"
    assert ne.ebpf.file_mutation.op == ebpf_pb2.CHMOD
    assert ne.ebpf.file_mutation.executable_after


def test_e2_file_write_no_exec_flag():
    """file_write does not set executable_after."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "file_write",
        writer_process_key=APP_PROC_KEY,
        file_path="/tmp/data.bin",
        bytes=2048,
    ))
    assert ne.ebpf.event_family == "file.mutation"
    assert not ne.ebpf.file_mutation.executable_after


# ---------------------------------------------------------------------------
# F1: euid to root
# ---------------------------------------------------------------------------

def test_f1_euid_to_root():
    """euid_to_root priv.creds has euid 1000 before and euid 0 after."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "euid_to_root",
        process_key=APP_PROC_KEY,
        euid_before=1000,
        uid_before=1000,
    ))
    assert ne.ebpf.event_family == "priv.creds"
    assert ne.ebpf.privilege.before.euid == 1000
    assert ne.ebpf.privilege.after.euid == 0


# ---------------------------------------------------------------------------
# G1a: external connect / H2: internal connect
# ---------------------------------------------------------------------------

def test_g1a_connect_external_remote_class():
    """connect_external to an IP not in PodIP history gives remote_class='external'."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "connect_external",
        source_process=APP_PROC_KEY,
        remote_ip="8.8.8.8",
        remote_port=443,
    ))
    assert ne.ebpf.event_family == "net.connect"
    assert ne.ebpf_derived.remote_class == "external"
    assert not ne.ebpf_derived.HasField("remote_pod_uid")


def test_h2_connect_internal_cluster_pod():
    """connect_internal to a cluster pod IP gives remote_class='cluster_pod' + pod uid."""
    rend = _make_renderer()
    [ne] = rend.render(_activity(
        "connect_internal",
        source_process=APP_PROC_KEY,
        remote_ip=POD2_IP,
        remote_port=8080,
    ))
    assert ne.ebpf.event_family == "net.connect"
    assert ne.ebpf_derived.remote_class == "cluster_pod"
    assert ne.ebpf_derived.HasField("remote_pod_uid")
    assert ne.ebpf_derived.remote_pod_uid == POD2_UID


# ---------------------------------------------------------------------------
# H1: byte totals in net.flow_bytes
# ---------------------------------------------------------------------------

def test_h1_flow_bytes_totals_and_monotonic():
    """net.flow_bytes FlowCounter records byte totals and correct monotonic offsets."""
    rend = _make_renderer()
    t_start = T0 + 1_000_000_000
    t_end = T0 + 2_000_000_000

    [ne] = rend.render(_activity(
        "egress_transfer",
        process_key=APP_PROC_KEY,
        remote_ip="8.8.8.8",
        remote_port=443,
        bytes_out=5000,
        bytes_in=200,
        socket_cookie=42,
        interval_start_ns=t_start,
        interval_end_ns=t_end,
    ))
    assert ne.ebpf.event_family == "net.flow_bytes"
    fc = ne.ebpf.flow_counter
    assert fc.bytes_out == 5000
    assert fc.bytes_in == 200
    assert fc.interval_start_mono_ns == t_start - RUN_START_NS
    assert fc.interval_end_mono_ns == t_end - RUN_START_NS


# ---------------------------------------------------------------------------
# H4: sensitive read data class + same lineage as subsequent connect
# ---------------------------------------------------------------------------

def test_h4_sensitive_read_data_class():
    """read_sensitive_file on a C_H4 path sets data_class='sensitive'."""
    rend = _make_renderer(c_h4=[H4_SENSITIVE_PATH])
    [open_ne, read_ne] = rend.render(_activity(
        "read_sensitive_file",
        reader_process_key=APP_PROC_KEY,
        file_path=H4_SENSITIVE_PATH,
    ))
    assert open_ne.ebpf.event_family == "file.open"
    assert open_ne.ebpf_derived.data_class == "sensitive"
    assert read_ne.ebpf.event_family == "file.read"
    assert read_ne.ebpf_derived.data_class == "sensitive"


def test_h4_path_list_gives_each_path_its_class():
    """A C_H4 mapping gives each path its own class; an explicit override wins."""
    rend = _make_renderer(c_h4={"/etc/passwd": "system", "/app/config/application.yaml": "application"})

    def cls(**p):
        return rend.render(_activity("read_sensitive_file", reader_process_key=APP_PROC_KEY,
                                     **p))[1].ebpf_derived.data_class
    assert cls(file_path="/etc/passwd") == "system"
    assert cls(file_path="/app/config/application.yaml") == "application"
    assert cls(file_path="/etc/hostname") == ""
    assert cls(file_path="/etc/passwd", data_class="credential") == "credential"


def test_the_spec_path_list_reaches_the_renderer():
    """generator-spec declares the C_H4 path list the build passes on (OQ-8)."""
    from mtgen import specs
    paths = specs.load_generator_spec()["declared_artifacts"]["sensitive_data_class_h4"]["paths"]
    assert paths["/etc/passwd"] == "system" and paths["/etc/shadow"] == "system"
    assert "/var/run/secrets/kubernetes.io/serviceaccount/token" not in paths


def test_h4_non_sensitive_path_no_data_class():
    """read_sensitive_file on a path not in C_H4 leaves data_class empty."""
    rend = _make_renderer(c_h4=[H4_SENSITIVE_PATH])
    [open_ne, _read_ne] = rend.render(_activity(
        "read_sensitive_file",
        reader_process_key=APP_PROC_KEY,
        file_path="/etc/hostname",
    ))
    assert open_ne.ebpf_derived.data_class == ""


def test_h4_sensitive_read_and_egress_share_lineage():
    """Sensitive read and subsequent connect in same lineage share lineage_id."""
    rend = _make_renderer(c_h4=[H4_SENSITIVE_PATH])

    [_open_ne, read_ne] = rend.render(_activity(
        "read_sensitive_file",
        reader_process_key=APP_PROC_KEY,
        file_path=H4_SENSITIVE_PATH,
    ))
    [conn_ne] = rend.render(_activity(
        "connect_external",
        source_process=APP_PROC_KEY,
        remote_ip="1.2.3.4",
    ))

    assert read_ne.ebpf_derived.data_class == "sensitive"
    assert read_ne.ebpf_derived.lineage_id == conn_ne.ebpf_derived.lineage_id


# ---------------------------------------------------------------------------
# Ambiguous cgroup: pod_uid absent + JOIN_UNCERTAIN gap
# ---------------------------------------------------------------------------

def test_ambiguous_cgroup_pod_uid_absent_with_gap():
    """Pod UID stays unset and a JOIN_UNCERTAIN gap is emitted for an ambiguous cgroup."""
    # Register two overlapping ContainerState entries for the same cgroup path
    ctr_old = ContainerState(
        uid="ctr-old", name="old-app", pod_uid="pod-old",
        image_digest="sha256:" + "b" * 64, image_signed=False,
        is_sidecar=False, cgroup=CGROUP,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    ctr_new = ContainerState(
        uid="ctr-new", name="new-app", pod_uid="pod-new",
        image_digest="sha256:" + "c" * 64, image_signed=True,
        is_sidecar=False, cgroup=CGROUP,
        valid_from=T0 - 1_000_000, valid_to=FOREVER,   # starts 1 ms before T0
    )
    # Build world with ambiguous cgroup (two entries overlap at T0)
    history = WorldHistory()
    node = NodeState(
        uid=NODE_UID, name="node-01", boot_id=NODE_BOOT_ID,
        init_mnt_ns=NODE_INIT_MNT_NS, init_pid_ns=NODE_INIT_PID_NS,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    history.add("Node", NODE_UID, RUN_START_NS, FOREVER, node)
    history.add("Cgroup", CGROUP, RUN_START_NS, FOREVER, ctr_old)
    history.add("Cgroup", CGROUP, T0 - 1_000_000, FOREVER, ctr_new)

    init_proc = ProcessState(
        process_key=INIT_PROC_KEY, container_uid=CTR_UID, pod_uid=POD_UID,
        node_uid=NODE_UID, boot_id=NODE_BOOT_ID,
        tgid=_INIT_TGID, start_time_ns=_INIT_START_NS,
        executable="/pause", parent_process_key="",
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    app_proc = ProcessState(
        process_key=APP_PROC_KEY, container_uid=CTR_UID, pod_uid=POD_UID,
        node_uid=NODE_UID, boot_id=NODE_BOOT_ID,
        tgid=_APP_TGID, start_time_ns=_APP_START_NS,
        executable="/app/server", parent_process_key=INIT_PROC_KEY,
        valid_from=RUN_START_NS, valid_to=FOREVER,
    )
    history.add("Process", INIT_PROC_KEY, RUN_START_NS, FOREVER, init_proc)
    history.add("Process", APP_PROC_KEY, RUN_START_NS, FOREVER, app_proc)

    world = types.SimpleNamespace(
        history=history,
        processes=[init_proc, app_proc],
        nodes=[node],
        run_start_ns=RUN_START_NS,
    )
    rend = EbpfRenderer(world, EvidenceArchive("test-ambiguous-cgroup"))

    [ne] = rend.render(_activity("proc_exit", process_key=APP_PROC_KEY, time_ns=T0))

    # pod_uid absent
    assert not ne.ebpf_derived.HasField("pod_uid"), (
        f"Expected pod_uid unset, got {ne.ebpf_derived.pod_uid!r}"
    )
    # JOIN_UNCERTAIN gap present
    gap_reasons = [g.reason for g in ne.completeness.gaps]
    assert common_pb2.JOIN_UNCERTAIN in gap_reasons, (
        f"Expected JOIN_UNCERTAIN gap, got reasons={gap_reasons}"
    )


# ---------------------------------------------------------------------------
# Determinism: two fresh renderers produce identical serialised output
# ---------------------------------------------------------------------------

def test_determinism_same_activity_same_bytes():
    """Two fresh EbpfRenderer instances produce byte-identical NormalizedEvents."""
    world = _make_world()
    act = _activity(
        "egress_transfer",
        process_key=APP_PROC_KEY,
        remote_ip="1.2.3.4",
        remote_port=443,
        bytes_out=1000,
        bytes_in=50,
        socket_cookie=7,
        interval_start_ns=T0,
        interval_end_ns=T0 + 1_000_000_000,
    )

    r1 = EbpfRenderer(world, EvidenceArchive("det-a"), c_h4=[H4_SENSITIVE_PATH])
    r2 = EbpfRenderer(world, EvidenceArchive("det-b"), c_h4=[H4_SENSITIVE_PATH])

    events1 = r1.render(act)
    events2 = r2.render(act)

    assert len(events1) == len(events2)
    for ne1, ne2 in zip(events1, events2):
        assert ne1.SerializeToString() == ne2.SerializeToString(), (
            f"Serialized output differs:\n  r1: {ne1!r}\n  r2: {ne2!r}"
        )
