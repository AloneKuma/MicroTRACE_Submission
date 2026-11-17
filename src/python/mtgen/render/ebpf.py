"""eBPF renderer: Activity -> List[NormalizedEvent] wrapping RawEbpfRecord + EbpfDerived.

Handles all event families needed by the 17 included findings:
  proc.exec / proc.fork / proc.exit
  file.open / file.read / file.mutation
  priv.creds
  ns.change
  ipc.runtime_socket
  proc.ptrace
  bpf.call
  net.connect / net.flow_bytes
  token.file_index

Derives EbpfDerived:
  pod_uid         — cgroup -> ContainerState -> pod_uid at event time;
                    absent (with JOIN_UNCERTAIN gap) when cgroup is ambiguous
  container_name  — from ContainerState at event time
  lineage_id      — logical_id("lineage", lineage-root ProcessKey fields)
  host_namespace_after — True when NamespaceDetail.after.mnt and .pid equal
                         the node's init-namespace inodes
  token_file      — ProjectedVersion from the token index, populated by
                    token.file_index events rendered earlier for the same node
  remote_class    — "cluster_pod" from PodIP history, "cluster_service" for an
                    infrastructure address, else "external"
  remote_pod_uid  — pod UID from PodIP history
  data_class      — the class the declared C_H4 path list gives the file
                    (generator-spec declared_artifacts.sensitive_data_class_h4)

Clock model: basis EBPF_MONOTONIC_CORRECTED.  monotonic_ns is the wall-clock
offset from run_start_ns (simulated).  clock_uncertainty_ns is a constructor
parameter (default 1 ms).

Per-(node_id, boot_id) node_seq is a strictly-increasing counter.  Rendering
the same sequence of activities on a fresh renderer always produces the same
node_seq values, giving deterministic output.
"""
import hashlib
import types
from typing import List, Optional

import mtcodec
from microtrace.v0 import common_pb2, ebpf_pb2, normalized_pb2
from .common import (
    CAPTURE_MANIFEST_VERSION, CONTEXT_VERSION, NORMALIZER_VERSION,
    completeness_gap, empty_completeness, event_id, make_time_info,
)
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive
from mtgen.history import Ambiguous, WorldHistory
from mtgen.ids import child_process_key, pod_init_processes

# ptrace request constants (PTRACE_ATTACH=16, PTRACE_SEIZE=16902)
PTRACE_ATTACH: int = 16
PTRACE_SEIZE: int = 16902

# IP protocol numbers
IPPROTO_TCP: int = 6
IPPROTO_UDP: int = 17

_EBPF_SOURCE_STAGE: str = "node"

_OP_NAME_MAP: dict = {
    "WRITE": ebpf_pb2.WRITE,
    "CREATE": ebpf_pb2.CREATE,
    "CHMOD": ebpf_pb2.CHMOD,
    "RENAME": ebpf_pb2.RENAME,
    "UNLINK": ebpf_pb2.UNLINK,
    "MMAP_SHARED_WRITE": ebpf_pb2.MMAP_SHARED_WRITE,
}

_PRIV_OP_MAP: dict = {
    "COMMIT_CREDS": ebpf_pb2.COMMIT_CREDS,
    "SETUID_FAMILY": ebpf_pb2.SETUID_FAMILY,
    "CAPSET": ebpf_pb2.CAPSET,
}

# Linux capability numbers (include/uapi/linux/capability.h)
_CAP_BITS: dict = {
    "CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
    "CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5, "CAP_SETGID": 6,
    "CAP_SETUID": 7, "CAP_SETPCAP": 8, "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13, "CAP_SYS_MODULE": 16,
    "CAP_SYS_RAWIO": 17, "CAP_SYS_CHROOT": 18, "CAP_SYS_PTRACE": 19,
    "CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22, "CAP_MKNOD": 27,
    "CAP_AUDIT_WRITE": 29, "CAP_SETFCAP": 31, "CAP_MAC_ADMIN": 33,
    "CAP_SYSLOG": 34, "CAP_PERFMON": 38, "CAP_BPF": 39,
}


def _cap_mask(names) -> int:
    """Bit mask of capability names; an unknown name is an error."""
    mask = 0
    for n in names:
        mask |= 1 << _CAP_BITS[str(n).upper()]
    return mask


_NS_OP_MAP: dict = {
    "setns": ebpf_pb2.SETNS,
    "unshare": ebpf_pb2.UNSHARE,
    "mount": ebpf_pb2.MOUNT,
}


class EbpfRenderer:
    """Renders eBPF-sourced Activities into lists of NormalizedEvent.

    Args:
        world:               World-like object with .history, .processes,
                             .nodes, and .run_start_ns attributes.
        archive:             EvidenceArchive for this run.
        clock_uncertainty_ns: Per-event clock uncertainty bound (1 ms default).
        c_h4:                C_H4 path list (H4 evidence): a mapping of file
                             path -> data class, or an iterable of paths, each
                             of class "sensitive".
        run_start_ns:        Run-start wall-clock time (ns since epoch).
                             Defaults to world.run_start_ns when omitted.
    """

    def __init__(
        self,
        world,
        archive: EvidenceArchive,
        clock_uncertainty_ns: int = 1_000_000,
        c_h4=None,
        run_start_ns: Optional[int] = None,
    ):
        self._history: WorldHistory = world.history
        self._archive = archive
        self._uncertainty_ns = clock_uncertainty_ns
        self._c_h4_paths: dict = (dict(c_h4) if isinstance(c_h4, dict)
                                  else {p: "sensitive" for p in (c_h4 or [])})
        self._run_start_ns: int = (
            run_start_ns if run_start_ns is not None else world.run_start_ns
        )

        # Process map: compact key string -> ProcessState (or dict)
        self._proc_map: dict = {p.process_key: p for p in world.processes}
        # Pod UID -> process_key for each pod's container-init process.
        # Needed when workload activities pass pod_uid as actor_uid (e.g. connect_internal).
        self._pod_init_proc: dict = pod_init_processes(world.processes)
        # Processes forked during the run (process_exec / shell_exec): compact
        # key -> _proc_info-style dict. A later activity may act as one of
        # them (a scenario step naming the process an exec step started).
        self._dyn_procs: dict = {}
        # process_key -> executable of its latest proc.exec; the image a
        # process runs after exec, as the normalizer's process table holds it.
        self._exec_of: dict = {}
        # Node map: uid -> NodeState, boot_id -> NodeState
        self._node_map: dict = {n.uid: n for n in world.nodes}

        # Per-(node_id, boot_id) monotonic sequence counter
        self._node_seq: dict = {}

        # Token index: (dev, ino) -> ProjectedVersion proto; populated by
        # token.file_index events rendered on this renderer instance.
        self._token_index: dict = {}

        # connect_internal targets: a Pod UID, a Service name (its Pods),
        # or an infrastructure element, which gets a fixed ClusterIP-range
        # address (classified cluster_service; it has no Pod IP).
        self._pod_by_uid: dict = {}
        self._pods_by_service: dict = {}
        for _pod in getattr(world, "pods", []):
            self._pod_by_uid[_pod.uid] = _pod
            self._pods_by_service.setdefault(_pod.service_name, []).append(_pod)
        self._infra_ip: dict = {}
        _infra = getattr(world, "infra", {}) or {}
        for _i, _kind in enumerate(sorted(_infra)):
            _ip = f"10.96.0.{10 + _i}"
            self._infra_ip[_kind] = _ip
            self._infra_ip[_infra[_kind].uid] = _ip
        self._service_ips: frozenset = frozenset(self._infra_ip.values())
        # (actor, remote_ip) -> (socket_cookie, remote_port) of the latest
        # connect, so a later egress_transfer counts bytes on that flow.
        self._flows: dict = {}
        # The same for scenario connects only: a scenario's transfer counts
        # bytes on its own scenario's connect, even when background traffic
        # of the same Pod connects to the same remote in between.
        self._scenario_flows: dict = {}
        # Connection a later accept_internal names (accept_of): a connect's
        # connection_id, and a scenario connect's action_seq. Client and
        # server endpoints, and the server Pod (None off a Pod).
        self._connections: dict = {}

    def render(self, activity: Activity) -> List["normalized_pb2.NormalizedEvent"]:
        """Render one Activity into zero or more NormalizedEvent records.

        Returns a list because some activities (process_exec / shell_exec)
        produce two records (proc.fork + proc.exec).  Most activities produce
        one record; read_token_file produces three (token.file_index + file.open
        + file.read).

        Activity.parameters expected by each kind are documented on the
        corresponding _render_* method.
        """
        kind = activity.kind
        if kind in ("process_exec", "shell_exec"):
            return self._render_exec(activity)
        if kind == "proc_exit":
            return self._render_proc_exit(activity)
        if kind == "read_token_file":
            return self._render_token_read(activity)
        if kind == "read_sensitive_file":
            return self._render_sensitive_read(activity)
        if kind == "file_write":
            return self._render_file_mutation(activity, ebpf_pb2.WRITE)
        if kind == "make_executable":
            return self._render_file_mutation(
                activity, ebpf_pb2.CHMOD, default_executable_after=True
            )
        if kind == "chmod":
            return self._render_file_mutation(activity, ebpf_pb2.CHMOD)
        if kind in ("privilege_change", "euid_to_root", "capability_gain"):
            return self._render_priv_creds(activity)
        if kind == "namespace_escape":
            return self._render_ns_change(activity)
        if kind == "ptrace_attach":
            return self._render_ptrace(activity)
        if kind in ("connect_external", "connect_internal"):
            return self._render_net_connect(activity)
        if kind == "accept_internal":
            return self._render_net_accept(activity)
        if kind == "egress_transfer":
            return self._render_flow_counter(activity)
        if kind == "bpf_call":
            return self._render_bpf_call(activity)
        if kind == "runtime_socket_connect":
            return self._render_runtime_socket(activity)
        return []

    # ------------------------------------------------------------------
    # Per-family renderers
    # ------------------------------------------------------------------

    def _render_exec(self, activity: Activity) -> list:
        """proc.fork + proc.exec.

        The actor (a process key, or a Pod acting through its init process)
        forks a child, which then execs the new image: both records name the
        child as process and the actor as parent. The child's key comes from
        ids.child_process_key, so the scenario engine can name it in later
        steps. A container's startup exec (source "startup") is the process
        itself starting: it renders in place, without a parent.

        Parameters:
          parent_process_key  str   forking process (default: the actor)
          process_key         str   the child's key; must equal the derived one
          executable          str   binary path (default "/bin/sh", or
                                    shell_binary for shell_exec)
          argv_sha256         str   SHA-256 of NUL-joined argv (default: hash of executable)
          argv0               str   argv[0] (default: basename of executable)
          starts_new_lineage  bool  True when this exec opens a new container lineage
        """
        p = activity.parameters
        executable = p.get("executable") or p.get("shell_binary") or "/bin/sh"
        if p.get("source") == "startup" or (
                p.get("process_key") and not p.get("parent_process_key")):
            # The named process itself execs (no fork).
            proc_key = p.get("process_key", activity.actor_uid)
            parent_key = ""
        else:
            parent_key = self._real_key(p.get("parent_process_key") or activity.actor_uid)
            proc_key = self._fork_child(parent_key, activity.time_ns)
            given = p.get("process_key")
            if given and given != proc_key:
                raise ValueError(
                    f"{activity.kind} at {activity.time_ns}: process_key {given!r} "
                    f"is not the child {proc_key!r} of {parent_key!r}")
        argv_sha256 = p.get("argv_sha256", "") or _sha256_str(executable)
        argv0 = p.get("argv0", executable.rsplit("/", 1)[-1])
        starts_new_lineage = bool(p.get("starts_new_lineage", False))

        proc_state = self._proc_info(proc_key, activity.time_ns)
        parent_state = self._proc_info(parent_key, activity.time_ns) if parent_key else None
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        exec_file = ebpf_pb2.FileIdentity(
            resolved_path=executable, path_as_opened=executable,
        )
        exec_detail = ebpf_pb2.ExecDetail(
            filename=executable,
            executable=exec_file,
            argv_sha256=argv_sha256,
            argv0=argv0,
            starts_new_lineage=starts_new_lineage,
        )

        # proc.fork (the new task group)
        fork_rec = self._make_record(
            node_id, boot_id, activity.time_ns, "proc.fork",
            proc_state, parent_state, cgroup, ebpf_pb2.SUCCESS,
        )
        fork_ne = self._wrap(fork_rec, activity.time_ns, cgroup, proc_state)
        self._exec_of[proc_state["process_key"]] = executable

        # proc.exec (image replacement in the forked task)
        exec_rec = self._make_record(
            node_id, boot_id, activity.time_ns, "proc.exec",
            proc_state, parent_state, cgroup, ebpf_pb2.SUCCESS,
        )
        exec_rec.exec.CopyFrom(exec_detail)
        exec_ne = self._wrap(exec_rec, activity.time_ns, cgroup, proc_state)

        return [fork_ne, exec_ne]

    def _render_proc_exit(self, activity: Activity) -> list:
        """proc.exit.

        Parameters:
          process_key  str  compact key of the exiting process (default actor_uid)
        """
        p = activity.parameters
        proc_key = p.get("process_key", activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "proc.exit",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        return [self._wrap(rec, activity.time_ns, cgroup, proc_state)]

    def _render_token_read(self, activity: Activity) -> list:
        """token.file_index + file.open + file.read.

        Populates the renderer's token index so subsequent reads of the same
        (dev, ino) resolve to the correct ProjectedVersion.

        Parameters:
          reader_process_key  str  compact key (falls back to process_key / actor_uid)
          reader_executable   str  executable the reader runs (default: the process's own)
          token_file_path     str  absolute path (default /var/run/secrets/.../token)
          bytes_to_read       int  bytes read (default 500)
          dev                 int  simulated device number (default: path-derived)
          ino                 int  simulated inode number (default: path-derived)
          mnt_ns_inum         int  mount namespace inode (default 4026531840)
          owner_pod_uid       str  token owner Pod UID (default: from proc cgroup)
          volume_name         str  projected volume name (default "kube-api-access")
          version_dir         str  kubelet version directory (default fixed timestamp)
          file_name           str  token file name (default "token")
        """
        p = activity.parameters
        proc_key = p.get(
            "reader_process_key", p.get("process_key", activity.actor_uid)
        )
        proc_state = self._proc_info(proc_key, activity.time_ns)
        if p.get("reader_executable"):
            proc_state = dict(proc_state, executable=p["reader_executable"])
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        path = p.get(
            "token_file_path",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        )
        dev = int(p.get("dev", _path_hash(path) % (2 ** 32)))
        ino = int(p.get("ino", _path_hash(path + ":ino") % (2 ** 32)))
        mnt_ns_inum = int(p.get("mnt_ns_inum", 4026531840))
        bytes_read = int(p.get("bytes_to_read", 500))

        owner_pod_uid = p.get("owner_pod_uid", proc_state.get("pod_uid", ""))
        projected = ebpf_pb2.ProjectedVersion(
            owner_pod_uid=owner_pod_uid,
            volume_name=p.get("volume_name", "kube-api-access"),
            version_dir=p.get("version_dir", "..2026_01_01_00_00_00.0000000"),
            file_name=p.get("file_name", "token"),
        )

        # Populate token index for later resolution
        self._token_index[(dev, ino)] = projected

        # 1) token.file_index
        idx_entry = ebpf_pb2.ProjectedIndexEntry(
            version=projected, dev=dev, ino=ino, current=True,
        )
        idx_rec = self._make_record(
            node_id, boot_id, activity.time_ns, "token.file_index",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        idx_rec.projected_index.CopyFrom(idx_entry)
        idx_ne = self._wrap(idx_rec, activity.time_ns, cgroup, proc_state)

        # 2) file.open
        fid = ebpf_pb2.FileIdentity(
            dev=dev, ino=ino, mnt_ns_inum=mnt_ns_inum,
            resolved_path=path, path_as_opened=path,
            projected=projected,
        )
        open_detail = ebpf_pb2.FileAccessDetail(
            op=ebpf_pb2.FILE_OPEN, file=fid, open_flags=0, fd=3, bytes=0,
        )
        open_rec = self._make_record(
            node_id, boot_id, activity.time_ns, "file.open",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        open_rec.file_access.CopyFrom(open_detail)
        open_ne = self._wrap(
            open_rec, activity.time_ns, cgroup, proc_state,
            file_identity=(dev, ino, path),
        )

        # 3) file.read
        read_detail = ebpf_pb2.FileAccessDetail(
            op=ebpf_pb2.FILE_READ, file=fid, fd=3, bytes=bytes_read,
        )
        read_rec = self._make_record(
            node_id, boot_id, activity.time_ns + 1, "file.read",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        read_rec.file_access.CopyFrom(read_detail)
        read_ne = self._wrap(
            read_rec, activity.time_ns + 1, cgroup, proc_state,
            file_identity=(dev, ino, path),
        )

        return [idx_ne, open_ne, read_ne]

    def _render_sensitive_read(self, activity: Activity) -> list:
        """file.open + file.read for a sensitive (C_H4) file.

        Parameters:
          reader_process_key  str  compact key (falls back to process_key / actor_uid)
          file_path           str  absolute file path (default "/etc/passwd")
          bytes_to_read       int  bytes read (default 100)
          dev                 int  simulated device number
          ino                 int  simulated inode number
          mnt_ns_inum         int  mount namespace inode (default 4026531840)
          data_class          str  explicit data_class override (default: infer from C_H4)
        """
        p = activity.parameters
        proc_key = p.get(
            "reader_process_key", p.get("process_key", activity.actor_uid)
        )
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        path = p.get("file_path", "/etc/passwd")
        dev = int(p.get("dev", _path_hash(path) % (2 ** 32)))
        ino = int(p.get("ino", _path_hash(path + ":ino") % (2 ** 32)))
        mnt_ns_inum = int(p.get("mnt_ns_inum", 4026531840))
        bytes_read = int(p.get("bytes_to_read", 100))
        data_class_override = p.get("data_class", "")

        fid = ebpf_pb2.FileIdentity(
            dev=dev, ino=ino, mnt_ns_inum=mnt_ns_inum,
            resolved_path=path, path_as_opened=path,
        )

        open_detail = ebpf_pb2.FileAccessDetail(
            op=ebpf_pb2.FILE_OPEN, file=fid, open_flags=0, fd=4, bytes=0,
        )
        open_rec = self._make_record(
            node_id, boot_id, activity.time_ns, "file.open",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        open_rec.file_access.CopyFrom(open_detail)
        open_ne = self._wrap(
            open_rec, activity.time_ns, cgroup, proc_state,
            file_identity=(dev, ino, path),
            data_class_override=data_class_override,
        )

        read_detail = ebpf_pb2.FileAccessDetail(
            op=ebpf_pb2.FILE_READ, file=fid, fd=4, bytes=bytes_read,
        )
        read_rec = self._make_record(
            node_id, boot_id, activity.time_ns + 1, "file.read",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        read_rec.file_access.CopyFrom(read_detail)
        read_ne = self._wrap(
            read_rec, activity.time_ns + 1, cgroup, proc_state,
            file_identity=(dev, ino, path),
            data_class_override=data_class_override,
        )

        return [open_ne, read_ne]

    def _render_file_mutation(
        self,
        activity: Activity,
        default_op: int,
        default_executable_after: bool = False,
    ) -> list:
        """file.mutation for file_write / make_executable / chmod.

        Parameters:
          writer_process_key  str  compact key (falls back to process_key / actor_uid)
          file_path           str  absolute path (default "/tmp/file")
          dev                 int  simulated device number
          ino                 int  simulated inode number
          op                  str  "WRITE"/"CREATE"/"CHMOD"/"RENAME"/"UNLINK" (string
                                   name); overrides the default_op when present
          executable_after    bool True when the file ends up with execute permission
          new_mode            int  new file mode bits (optional)
          bytes               int  bytes written (0 for chmod)
        """
        p = activity.parameters
        proc_key = p.get(
            "writer_process_key", p.get("process_key", activity.actor_uid)
        )
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        path = p.get("file_path", "/tmp/file")
        dev = int(p.get("dev", _path_hash(path) % (2 ** 32)))
        ino = int(p.get("ino", _path_hash(path + ":ino") % (2 ** 32)))
        exec_after = bool(p.get("executable_after", default_executable_after))
        bytes_written = int(p.get("bytes", 0))

        op_str = p.get("op", None)
        op_val = _OP_NAME_MAP.get(op_str, default_op) if op_str else default_op

        fid = ebpf_pb2.FileIdentity(
            dev=dev, ino=ino, resolved_path=path, path_as_opened=path,
        )
        mut = ebpf_pb2.FileMutationDetail(
            op=op_val, file=fid, executable_after=exec_after, bytes=bytes_written,
        )
        new_mode = p.get("new_mode", None)
        if new_mode is not None:
            mut.new_mode = int(new_mode)

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "file.mutation",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.file_mutation.CopyFrom(mut)
        return [self._wrap(rec, activity.time_ns, cgroup, proc_state)]

    def _render_priv_creds(self, activity: Activity) -> list:
        """priv.creds for privilege_change / euid_to_root / capability_gain.

        Defaults by kind (any explicit parameter below overrides them):
          euid_to_root      SETUID_FAMILY, uid/euid/gid/egid 1000 -> 0
          privilege_change  SETUID_FAMILY to target_euid / target_egid; without
                            a target, a privilege drop 0 -> 1000 (a service
                            shedding root); caps_to_gain are added
          capability_gain   CAPSET adding caps (default [CAP_SYS_ADMIN]); ids
                            unchanged

        Parameters:
          process_key         str  compact key (default actor_uid)
          op                  str  "SETUID_FAMILY"/"CAPSET"/"COMMIT_CREDS"
          caps / caps_to_gain list capability names added to the effective
                                   and permitted sets
          uid_before ... egid_after, cap_effective_before/after,
          cap_permitted_before/after   int  explicit credential values
        """
        p = activity.parameters
        proc_key = p.get("process_key", activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        kind = activity.kind
        if kind == "euid_to_root":
            ids_before, ids_after, gained = 1000, 0, []
        elif kind == "capability_gain":
            ids_before = ids_after = 1000
            gained = list(p.get("caps") or ["CAP_SYS_ADMIN"])
        else:   # privilege_change
            if "target_euid" in p:
                ids_before, ids_after = 1000, int(p["target_euid"])
            else:
                ids_before, ids_after = 0, 1000
            gained = list(p.get("caps_to_gain") or [])
        op_name = p.get("op", "CAPSET" if kind == "capability_gain" else "SETUID_FAMILY")
        op_val = _PRIV_OP_MAP.get(op_name, ebpf_pb2.SETUID_FAMILY)
        egid_target = int(p.get("target_egid", ids_after))

        cap_eff_before = int(p.get("cap_effective_before", 0))
        cap_perm_before = int(p.get("cap_permitted_before", 0))
        gain_mask = _cap_mask(gained)
        before = ebpf_pb2.Creds(
            uid=int(p.get("uid_before", ids_before)),
            euid=int(p.get("euid_before", ids_before)),
            gid=int(p.get("gid_before", ids_before)),
            egid=int(p.get("egid_before", ids_before)),
            cap_effective=cap_eff_before,
            cap_permitted=cap_perm_before,
        )
        after = ebpf_pb2.Creds(
            uid=int(p.get("uid_after", ids_after)),
            euid=int(p.get("euid_after", ids_after)),
            gid=int(p.get("gid_after", egid_target)),
            egid=int(p.get("egid_after", egid_target)),
            cap_effective=int(p.get("cap_effective_after", cap_eff_before | gain_mask)),
            cap_permitted=int(p.get("cap_permitted_after", cap_perm_before | gain_mask)),
        )
        priv = ebpf_pb2.PrivilegeDetail(op=op_val, before=before, after=after)

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "priv.creds",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.privilege.CopyFrom(priv)
        return [self._wrap(rec, activity.time_ns, cgroup, proc_state)]

    def _render_ns_change(self, activity: Activity) -> list:
        """ns.change for namespace_escape.

        Parameters:
          process_key   str  compact key (default actor_uid)
          method        str  "setns"/"unshare"/"mount" (default "setns")
          clone_flags   int  (default 0)
          mnt_before    int  mnt namespace inode before (default 4026532000)
          pid_before    int  pid namespace inode before (default 4026531836)
          net_before    int  (default 0 = leave unset)
          mnt_after     int  mnt inode after (default node.init_mnt_ns)
          pid_after     int  pid inode after (default node.init_pid_ns)
          net_after     int  (default 0 = leave unset)
          mount_source  str  mount source path for mount ops (default "")
          mount_target  str  mount target path for mount ops (default "")
        """
        p = activity.parameters
        proc_key = p.get("process_key", activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        method_str = p.get("method", "setns").lower()
        op_val = _NS_OP_MAP.get(method_str, ebpf_pb2.SETNS)

        # Node init namespace inodes (host reference)
        node = self._node_map.get(proc_state["node_id"])
        init_mnt = node.init_mnt_ns if node else 4026531840
        init_pid = node.init_pid_ns if node else 4026531836

        mnt_before = int(p.get("mnt_before", 4026532000))
        pid_before = int(p.get("pid_before", 4026531836))
        mnt_after = int(p.get("mnt_after", init_mnt))
        pid_after = int(p.get("pid_after", init_pid))

        before_kw: dict = {"mnt": mnt_before, "pid": pid_before}
        after_kw: dict = {"mnt": mnt_after, "pid": pid_after}
        if p.get("net_before", 0):
            before_kw["net"] = int(p["net_before"])
        if p.get("net_after", 0):
            after_kw["net"] = int(p["net_after"])

        ns_before = ebpf_pb2.NamespaceSet(**before_kw)
        ns_after_proto = ebpf_pb2.NamespaceSet(**after_kw)
        ns_host_ref = ebpf_pb2.NamespaceSet(mnt=init_mnt, pid=init_pid)

        ns_detail = ebpf_pb2.NamespaceDetail(
            op=op_val,
            clone_flags=int(p.get("clone_flags", 0)),
            before=ns_before,
            after=ns_after_proto,
            host_reference=ns_host_ref,
            mount_source=p.get("mount_source", ""),
            mount_target=p.get("mount_target", ""),
        )

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "ns.change",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.namespace_change.CopyFrom(ns_detail)
        return [self._wrap(
            rec, activity.time_ns, cgroup, proc_state,
            ns_after_mnt_pid=(mnt_after, pid_after),
            host_ns_mnt_pid=(init_mnt, init_pid),
        )]

    def _render_ptrace(self, activity: Activity) -> list:
        """proc.ptrace for ptrace_attach.

        Parameters:
          attacher_process_key  str  compact key (falls back to process_key / actor_uid)
          target_process_key    str  target's compact key (default "")
          ptrace_request        int  ptrace request constant (default PTRACE_ATTACH=16)
        """
        p = activity.parameters
        attacher_key = p.get(
            "attacher_process_key", p.get("process_key", activity.actor_uid)
        )
        target_key = p.get("target_process_key", "")
        request_val = int(p.get("ptrace_request", PTRACE_ATTACH))

        attacher_state = self._proc_info(attacher_key, activity.time_ns)
        cgroup = attacher_state["cgroup"]
        node_id, boot_id = attacher_state["node_id"], attacher_state["boot_id"]

        if target_key:
            ts = self._proc_info(target_key, activity.time_ns)
            target_pk = ebpf_pb2.ProcessKey(
                node_id=ts["node_id"], boot_id=ts["boot_id"],
                tgid=ts["tgid"], start_time_ns=ts["start_time_ns"],
            )
        else:
            target_pk = ebpf_pb2.ProcessKey()

        ptrace_detail = ebpf_pb2.PtraceDetail(request=request_val, target=target_pk)

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "proc.ptrace",
            attacher_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.ptrace.CopyFrom(ptrace_detail)
        return [self._wrap(rec, activity.time_ns, cgroup, attacher_state)]

    def _render_net_connect(self, activity: Activity) -> list:
        """net.connect for connect_external / connect_internal.

        Parameters:
          source_process  str  process compact key (falls back to process_key / actor_uid)
          local_ip        str  (default "10.0.0.1")
          local_port      int  (default: an ephemeral port of this connect)
          source_port     int  a source port the socket binds (catalogue; G2)
          remote_ip       str  (default: for connect_internal the resolved target, else "1.2.3.4")
          remote_port     int  (default target_port, then 443)
          protocol        int  IPPROTO_* (default IPPROTO_TCP=6)
          socket_cookie   int  FlowId socket cookie (default: derived from endpoints)
          connection_id   str  names the connection for a later accept_internal

        A bound source_port may be reused by a new socket once the previous
        one closed (SO_REUSEADDR, no TIME_WAIT block; G2): its default cookie
        also hashes the connect time, so each socket on the tuple has its own.
        """
        p = activity.parameters
        # source_process may be a descriptive name ("reverse_shell") rather
        # than a process key; fall back to the source Pod's process then.
        proc_key = self._first_known_process(
            p.get("source_process"), p.get("process_key"),
            p.get("source_pod"), activity.actor_uid,
        )
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        remote_ip = p.get("remote_ip") or (
            self._internal_target_ip(activity) if activity.kind == "connect_internal" else None
        ) or "1.2.3.4"
        remote_port = int(p.get("remote_port", p.get("target_port", 443)))
        # Local endpoint: the process's Pod IP and an ephemeral port of this
        # connect, so every connect has its own 4-tuple and socket cookie
        # (one fixed default made thousands of connects share one FlowId).
        local_ip = p.get("local_ip") or self._pod_ip(proc_state.get("pod_uid", "")) or "10.0.0.1"
        local_port = int(p.get("source_port") or p.get("local_port") or _ephemeral_port(
            proc_state["process_key"], activity.time_ns, remote_ip, remote_port))
        _proto_val = p.get("protocol", IPPROTO_TCP)
        _PROTO_NAMES = {"tcp": 6, "udp": 17, "icmp": 1}
        if isinstance(_proto_val, str):
            protocol = _PROTO_NAMES.get(_proto_val.lower(), IPPROTO_TCP)
        else:
            protocol = int(_proto_val)
        tuple_s = f"{local_ip}:{local_port}:{remote_ip}:{remote_port}"
        if p.get("source_port"):
            tuple_s += f":{activity.time_ns}"
        cookie = int(p.get("socket_cookie", _path_hash(tuple_s) % (2 ** 32)))

        flow = dict(cookie=cookie, remote_port=remote_port, process_key=proc_key,
                    local_ip=local_ip, local_port=local_port)
        maps = (self._flows, self._scenario_flows) if activity.action_seq is not None else (self._flows,)
        for flows in maps:
            flows[(activity.actor_uid, remote_ip)] = flow
            flows[("process", self._real_key(proc_key), remote_ip)] = flow
        if activity.kind == "connect_internal":
            server = self._history.at("PodIP", remote_ip, activity.time_ns)
            conn = dict(client_ip=local_ip, client_port=local_port, server_ip=remote_ip,
                        server_port=remote_port, protocol=protocol,
                        server_pod=server.uid if server is not None and server is not Ambiguous else None)
            for key in (p.get("connection_id"), activity.action_seq):
                if key is not None:
                    self._connections[str(key)] = conn

        flow_id = ebpf_pb2.FlowId(node_id=node_id, boot_id=boot_id, socket_cookie=cookie)
        local_ep = ebpf_pb2.Endpoint(ip=local_ip, port=local_port, protocol=protocol)
        remote_ep = ebpf_pb2.Endpoint(ip=remote_ip, port=remote_port, protocol=protocol)
        sock_detail = ebpf_pb2.SocketDetail(
            op=ebpf_pb2.CONNECT, local=local_ep, remote=remote_ep, flow=flow_id,
        )

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "net.connect",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.socket.CopyFrom(sock_detail)
        return [self._wrap(
            rec, activity.time_ns, cgroup, proc_state, remote_ip=remote_ip,
        )]

    def _render_net_accept(self, activity: Activity) -> list:
        """proc.fork + net.accept for accept_internal (G1).

        The server Pod's main process forks a handler for the connection,
        which accepts it: SocketDetail op ACCEPT with the server side of the
        connect's 4-tuple (local: the Pod IP and port the client connected
        to; remote: the client), and a new socket cookie on the server node.
        Nothing renders when the connection reached no Pod (an
        infrastructure address) or the Pod is gone by the accept.

        Parameters:
          accept_of           str  the connect's connection_id or action_seq
          server_pod          str  Pod UID; must be the Pod the connect reached
          parent_process_key  str  forking process (default: the Pod's main process)
          process_key         str  the handler's key; must equal the derived one
        """
        p = activity.parameters
        t = activity.time_ns
        key = str(p.get("accept_of", ""))
        # An automatic connection ID (workload.accepts) names one accept, so
        # it is dropped once used: under ebpf_accept the registry would
        # otherwise hold every background connect for the whole build.
        conn = self._connections.pop(key, None) if key.startswith("auto") else self._connections.get(key)
        if conn is None or not conn["server_pod"]:
            return []
        pod_uid = conn["server_pod"]
        if p.get("server_pod") and p["server_pod"] != pod_uid:
            raise ValueError(f"accept_internal at {t}: server_pod {p['server_pod']!r} "
                             f"is not the Pod {pod_uid!r} the connect reached")
        pod = self._pod_by_uid.get(pod_uid)
        main = self._real_key(p.get("parent_process_key") or pod_uid)
        if pod is None or not (pod.valid_from <= t < pod.valid_to) or main == pod_uid:
            return []
        handler = self._fork_child(main, t)
        if p.get("process_key") and p["process_key"] != handler:
            raise ValueError(f"accept_internal at {t}: process_key {p['process_key']!r} "
                             f"is not the handler {handler!r} of {main!r}")
        proc_state = self._proc_info(handler, t)
        parent_state = self._proc_info(main, t)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        fork_rec = self._make_record(
            node_id, boot_id, t, "proc.fork",
            proc_state, parent_state, cgroup, ebpf_pb2.SUCCESS,
        )
        fork_ne = self._wrap(fork_rec, t, cgroup, proc_state)

        cookie = _path_hash(
            f"accept:{conn['server_ip']}:{conn['server_port']}:"
            f"{conn['client_ip']}:{conn['client_port']}:{t}") % (2 ** 32)
        sock_detail = ebpf_pb2.SocketDetail(
            op=ebpf_pb2.ACCEPT,
            local=ebpf_pb2.Endpoint(ip=conn["server_ip"], port=conn["server_port"],
                                    protocol=conn["protocol"]),
            remote=ebpf_pb2.Endpoint(ip=conn["client_ip"], port=conn["client_port"],
                                     protocol=conn["protocol"]),
            flow=ebpf_pb2.FlowId(node_id=node_id, boot_id=boot_id, socket_cookie=cookie),
        )
        rec = self._make_record(
            node_id, boot_id, t, "net.accept",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.socket.CopyFrom(sock_detail)
        return [fork_ne, self._wrap(rec, t, cgroup, proc_state, remote_ip=conn["client_ip"])]

    def _render_flow_counter(self, activity: Activity) -> list:
        """net.flow_bytes for egress_transfer.

        Parameters:
          process_key          str  compact key (default actor_uid)
          socket_cookie        int  FlowId socket cookie (default: the actor's latest connect to remote_ip, else 0)
          remote_ip            str  (default: destination, then the target_pod's IP, else "1.2.3.4")
          remote_port          int  (default: that connect's port, else 443)
          bytes_out            int  (default 0)
          bytes_in             int  (default 0)
          interval_start_ns    int  wall-clock interval start (default time_ns)
          interval_end_ns      int  wall-clock interval end (default time_ns + 1 s)
        """
        p = activity.parameters
        target = p.get("target_pod") or p.get("target_service_or_pod")
        remote_ip = (p.get("remote_ip") or p.get("destination")
                     or (self._internal_target_ip(activity, target) if target else None)
                     or "1.2.3.4")
        # Bytes flow on the actor's latest connect to the same remote: its
        # cookie, port and process. A transfer naming its source_process
        # uses that process's latest connect instead, so another process's
        # later connect to the same remote (a decoy) does not take the flow.
        # The connect's local endpoint is written back as src_ip/src_port
        # (when absent) so the off-node path record of this transfer,
        # rendered next, names the same 4-tuple.
        flow = None
        maps = (self._scenario_flows, self._flows) if activity.action_seq is not None else (self._flows,)
        for flows in maps:
            if p.get("source_process"):
                src = self._first_known_process(p.get("source_process"), p.get("source_pod"))
                flow = flows.get(("process", self._real_key(src), remote_ip))
            flow = flow or flows.get((activity.actor_uid, remote_ip))
            if flow:
                break
        proc_key = p.get("process_key") or (flow["process_key"] if flow else activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]
        remote_port = int(p.get("remote_port", flow["remote_port"] if flow else 443))
        cookie = int(p.get("socket_cookie", flow["cookie"] if flow else 0))
        if flow:
            p.setdefault("src_ip", flow["local_ip"])
            p.setdefault("src_port", flow["local_port"])
        bytes_out = int(p.get("bytes_out", 0))
        bytes_in = int(p.get("bytes_in", 0))
        t_start = int(p.get("interval_start_ns", activity.time_ns))
        t_end = int(p.get("interval_end_ns", activity.time_ns + 1_000_000_000))

        flow_id = ebpf_pb2.FlowId(node_id=node_id, boot_id=boot_id, socket_cookie=cookie)
        remote_ep = ebpf_pb2.Endpoint(ip=remote_ip, port=remote_port, protocol=IPPROTO_TCP)
        fc = ebpf_pb2.FlowCounter(
            flow=flow_id, remote=remote_ep,
            bytes_out=bytes_out, bytes_in=bytes_in,
            interval_start_mono_ns=max(0, t_start - self._run_start_ns),
            interval_end_mono_ns=max(0, t_end - self._run_start_ns),
        )

        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "net.flow_bytes",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.flow_counter.CopyFrom(fc)
        return [self._wrap(
            rec, activity.time_ns, cgroup, proc_state, remote_ip=remote_ip,
        )]

    def _render_bpf_call(self, activity: Activity) -> list:
        """bpf.call.

        Parameters:
          process_key      str  compact key (default actor_uid)
          cmd              int  bpf command number (default 0)
          caller_is_sensor bool True when the caller is the MicroTRACE sensor
        """
        p = activity.parameters
        proc_key = p.get("process_key", activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        bpf_detail = ebpf_pb2.BpfDetail(
            cmd=int(p.get("cmd", 0)),
            caller_is_sensor=bool(p.get("caller_is_sensor", False)),
        )
        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "bpf.call",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.bpf.CopyFrom(bpf_detail)
        return [self._wrap(rec, activity.time_ns, cgroup, proc_state)]

    def _render_runtime_socket(self, activity: Activity) -> list:
        """ipc.runtime_socket.

        Parameters:
          process_key  str  compact key (default actor_uid)
          unix_path    str  container-runtime socket path (default /var/run/docker.sock)
        """
        p = activity.parameters
        proc_key = p.get("process_key", activity.actor_uid)
        proc_state = self._proc_info(proc_key, activity.time_ns)
        cgroup = proc_state["cgroup"]
        node_id, boot_id = proc_state["node_id"], proc_state["boot_id"]

        unix_path = p.get("unix_path", "/var/run/docker.sock")
        remote_ep = ebpf_pb2.Endpoint(unix_path=unix_path)
        sock_detail = ebpf_pb2.SocketDetail(
            op=ebpf_pb2.CONNECT, remote=remote_ep,
        )
        rec = self._make_record(
            node_id, boot_id, activity.time_ns, "ipc.runtime_socket",
            proc_state, None, cgroup, ebpf_pb2.SUCCESS,
        )
        rec.socket.CopyFrom(sock_detail)
        return [self._wrap(rec, activity.time_ns, cgroup, proc_state)]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_seq(self, node_id: str, boot_id: str) -> int:
        """Increment and return per-node sequence counter (0-based)."""
        key = (node_id, boot_id)
        seq = self._node_seq.get(key, 0)
        self._node_seq[key] = seq + 1
        return seq

    def _internal_target_ip(self, activity: Activity, target: Optional[str] = None) -> Optional[str]:
        """Remote IP of an in-cluster target (default: the step's
        target_service_or_pod, else its target_uid): a Pod's IP, a Service's
        backing Pod alive at the time (as seen after kube-proxy), or an
        infrastructure element's address. None when unresolved."""
        target = target or activity.parameters.get("target_service_or_pod") or activity.target_uid
        pod = self._pod_by_uid.get(target)
        if pod is not None:
            return pod.pod_ips[0] if pod.pod_ips else None
        if target in self._infra_ip:
            return self._infra_ip[target]
        t = activity.time_ns
        alive = sorted((q for q in self._pods_by_service.get(target, [])
                        if q.valid_from <= t < q.valid_to and q.pod_ips),
                       key=lambda q: q.uid)
        if not alive:
            return None
        return alive[t % len(alive)].pod_ips[0]

    def _first_known_process(self, *candidates) -> str:
        """Return the first candidate naming a known process or Pod.

        Falls back to the last non-empty candidate when none is known.
        """
        given = [c for c in candidates if c]
        for c in given:
            if c in self._proc_map or c in self._dyn_procs or c in self._pod_init_proc:
                return c
        return given[-1] if given else ""

    def _pod_ip(self, pod_uid: str) -> str:
        pod = self._pod_by_uid.get(pod_uid)
        return pod.pod_ips[0] if pod is not None and pod.pod_ips else ""

    def _real_key(self, key: str) -> str:
        """A Pod UID names the Pod's init process; any other key is itself."""
        return self._pod_init_proc.get(key, key)

    def _fork_child(self, parent_key: str, t: int) -> str:
        """Register the child ``parent_key`` forks at ``t``; return its key."""
        parent = self._proc_info(parent_key, t)
        key, tgid = child_process_key(
            parent["process_key"], parent["node_id"], parent["boot_id"], t)
        self._dyn_procs[key] = dict(
            parent, tgid=tgid, start_time_ns=t,
            parent_key=parent["process_key"], process_key=key,
        )
        return key

    def _proc_info(self, process_key: str, t: int = 0) -> dict:
        """Return a flat dict with node_id, boot_id, tgid, start_time_ns,
        cgroup, pod_uid, container_uid, parent_key for a process.

        First tries the world process map (world.processes), then processes
        forked during the run.  Falls back to parsing the compact key string
        for its prefix components, which gives only the 8-char node_uid
        prefix and boot_id prefix.
        """
        if process_key in self._dyn_procs:
            return dict(self._dyn_procs[process_key])
        proc = self._proc_map.get(process_key)
        if proc is not None:
            cgroup = (
                f"/kubepods/pod{proc.pod_uid}/{proc.container_uid}"
                if proc.container_uid else ""
            )
            return {
                "node_id": proc.node_uid,
                "boot_id": proc.boot_id,
                "tgid": proc.tgid,
                "start_time_ns": proc.start_time_ns,
                "cgroup": cgroup,
                "pod_uid": proc.pod_uid,
                "container_uid": getattr(proc, "container_uid", ""),
                "parent_key": proc.parent_process_key,
                "process_key": process_key,
            }
        # Parse compact key: "<node_prefix8>:<boot_prefix8>:<tgid>:<start_hex>"
        parts = process_key.split(":")
        if len(parts) == 4:
            tgid = int(parts[2]) if parts[2].isdigit() else 0
            try:
                start_ns = int(parts[3], 16)
            except ValueError:
                start_ns = 0
            return {
                "node_id": parts[0],
                "boot_id": parts[1],
                "tgid": tgid,
                "start_time_ns": start_ns,
                "cgroup": "",
                "pod_uid": "",
                "container_uid": "",
                "parent_key": "",
                "process_key": process_key,
            }
        # process_key may be a pod UID (e.g. from connect_internal actor_uid).
        real_key = self._pod_init_proc.get(process_key)
        if real_key:
            return self._proc_info(real_key, t)
        return {
            "node_id": process_key,
            "boot_id": "",
            "tgid": 0,
            "start_time_ns": 0,
            "cgroup": "",
            "pod_uid": "",
            "container_uid": "",
            "parent_key": "",
            "process_key": process_key,
        }

    def _lineage_root_info(self, proc_state: dict) -> dict:
        """Walk the parent chain to find the lineage-root process.

        The lineage root is the ancestor (inclusive) with parent_key == "".
        Uses the process itself as fallback if an ancestor is unknown.
        """
        state = proc_state
        for _ in range(64):
            parent_key = state.get("parent_key", "")
            if not parent_key:
                return state
            if parent_key not in self._dyn_procs and parent_key not in self._proc_map:
                return proc_state
            state = self._proc_info(parent_key)
        return proc_state

    def _compute_lineage_id(self, proc_state: dict) -> str:
        """Return the lineage logical ID for proc_state's lineage root."""
        root = self._lineage_root_info(proc_state)
        return mtcodec.logical_id("lineage", {
            "node_id": root["node_id"],
            "boot_id": root["boot_id"],
            "tgid": str(root["tgid"]),
            "start_time_ns": str(root["start_time_ns"]),
        })

    def _make_record(
        self,
        node_id: str,
        boot_id: str,
        time_ns: int,
        family: str,
        proc_state: dict,
        parent_state: Optional[dict],
        cgroup: str,
        result: int,
    ) -> "ebpf_pb2.RawEbpfRecord":
        """Build a RawEbpfRecord with all common fields set; detail is absent."""
        node_seq = self._next_seq(node_id, boot_id)
        mono_ns = max(0, time_ns - self._run_start_ns)

        process_pk = ebpf_pb2.ProcessKey(
            node_id=proc_state["node_id"],
            boot_id=proc_state["boot_id"],
            tgid=proc_state["tgid"],
            start_time_ns=proc_state["start_time_ns"],
        )
        if parent_state:
            parent_pk = ebpf_pb2.ProcessKey(
                node_id=parent_state["node_id"],
                boot_id=parent_state["boot_id"],
                tgid=parent_state["tgid"],
                start_time_ns=parent_state["start_time_ns"],
            )
        else:
            parent_pk = ebpf_pb2.ProcessKey()

        root_info = self._lineage_root_info(proc_state)
        lineage_root_pk = ebpf_pb2.ProcessKey(
            node_id=root_info["node_id"],
            boot_id=root_info["boot_id"],
            tgid=root_info["tgid"],
            start_time_ns=root_info["start_time_ns"],
        )

        # ContainerRef — looks up cgroup in history to determine pod_uid
        ctr_ref = self._make_container_ref(cgroup, time_ns)
        reader_class = (
            ebpf_pb2.READER_POD_PROCESS
            if ctr_ref.HasField("pod_uid") else ebpf_pb2.READER_HOST_PROCESS
        )

        return ebpf_pb2.RawEbpfRecord(
            node_id=node_id,
            boot_id=boot_id,
            node_seq=node_seq,
            monotonic_ns=mono_ns,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
            event_family=family,
            process=process_pk,
            parent=parent_pk,
            lineage_root=lineage_root_pk,
            container=ctr_ref,
            reader_class=reader_class,
            result=result,
            return_value=0,
        )

    def _make_container_ref(
        self, cgroup: str, t: int
    ) -> "ebpf_pb2.ContainerRef":
        """Look up the container state from cgroup history and build ContainerRef."""
        if not cgroup:
            return ebpf_pb2.ContainerRef()
        ctr_state = self._history.at("Cgroup", cgroup, t)
        if ctr_state is None or ctr_state is Ambiguous:
            return ebpf_pb2.ContainerRef(container_id="", cgroup_id=0)
        kw: dict = {
            "container_id": ctr_state.uid,
            "cgroup_id": _cgroup_hash(cgroup),
            "container_name": ctr_state.name,
        }
        if ctr_state.pod_uid:
            kw["pod_uid"] = ctr_state.pod_uid
        return ebpf_pb2.ContainerRef(**kw)

    def _wrap(
        self,
        rec: "ebpf_pb2.RawEbpfRecord",
        time_ns: int,
        cgroup: str,
        proc_state: dict,
        file_identity: Optional[tuple] = None,
        data_class_override: str = "",
        ns_after_mnt_pid: Optional[tuple] = None,
        host_ns_mnt_pid: Optional[tuple] = None,
        remote_ip: Optional[str] = None,
    ) -> "normalized_pb2.NormalizedEvent":
        """Wrap a RawEbpfRecord in a NormalizedEvent with EbpfDerived."""
        gaps: list = []

        # pod_uid / container_name from cgroup lookup
        pod_uid: Optional[str] = None
        container_name: str = ""
        if cgroup:
            ctr_state = self._history.at("Cgroup", cgroup, time_ns)
            if ctr_state is Ambiguous:
                gaps.append(completeness_gap(
                    reason=common_pb2.JOIN_UNCERTAIN,
                    scope="field=pod_uid",
                    detail=f"cgroup {cgroup!r} ambiguous at event time",
                ))
            elif ctr_state is not None:
                pod_uid = ctr_state.pod_uid or None
                container_name = ctr_state.name

        lineage_id = self._compute_lineage_id(proc_state)

        # host_namespace_after: True when ns.change record's after-namespaces
        # match the node's init namespaces on both mnt and pid dimensions.
        host_ns_after = False
        if ns_after_mnt_pid is not None and host_ns_mnt_pid is not None:
            host_ns_after = (
                ns_after_mnt_pid[0] == host_ns_mnt_pid[0]
                and ns_after_mnt_pid[1] == host_ns_mnt_pid[1]
            )

        # token_file from projected field in file_access detail
        token_file = None
        if rec.HasField("file_access"):
            fid = rec.file_access.file
            if fid.HasField("projected"):
                token_file = fid.projected
        if token_file is None and file_identity is not None:
            dev, ino, _path = file_identity
            token_file = self._token_index.get((dev, ino))

        # data_class from the C_H4 path list or explicit override
        data_class: str = data_class_override
        if not data_class and file_identity is not None:
            _dev, _ino, path = file_identity
            data_class = self._c_h4_paths.get(path, "")

        # remote_class and remote_pod_uid from PodIP history
        remote_class: str = ""
        remote_pod_uid: Optional[str] = None
        if remote_ip:
            ip_state = self._history.at("PodIP", remote_ip, time_ns)
            if ip_state is Ambiguous:
                gaps.append(completeness_gap(
                    reason=common_pb2.JOIN_UNCERTAIN,
                    scope="field=remote_pod_uid",
                    detail=f"Pod IP {remote_ip!r} ambiguous at event time",
                ))
                remote_class = "cluster_pod"
            elif ip_state is not None:
                remote_class = "cluster_pod"
                remote_pod_uid = ip_state.uid
            elif remote_ip in self._service_ips:
                remote_class = "cluster_service"
            else:
                remote_class = "external"

        # Assemble EbpfDerived
        derived_kw: dict = {
            "container_name": container_name,
            "lineage_id": lineage_id,
            "host_namespace_after": host_ns_after,
            "data_class": data_class,
            "remote_class": remote_class,
        }
        if pod_uid:
            derived_kw["pod_uid"] = pod_uid
        if token_file is not None:
            derived_kw["token_file"] = token_file
        if remote_pod_uid:
            derived_kw["remote_pod_uid"] = remote_pod_uid
        derived = normalized_pb2.EbpfDerived(**derived_kw)

        completeness = (
            common_pb2.Completeness(gaps=gaps) if gaps else empty_completeness()
        )

        # source_native_id for eBPF: node_id/boot_id/node_seq
        native_id = f"{rec.node_id}/{rec.boot_id}/{rec.node_seq}"
        ev_id = event_id("ebpf", native_id, _EBPF_SOURCE_STAGE)

        ne = normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.EBPF,
            source_native_id=native_id,
            source_stage=_EBPF_SOURCE_STAGE,
            time=make_time_info(
                time_ns,
                common_pb2.EBPF_MONOTONIC_CORRECTED,
                uncertainty_ns=self._uncertainty_ns,
            ),
            ebpf=rec,
            ebpf_derived=derived,
            completeness=completeness,
            normalizer_version=NORMALIZER_VERSION,
            context_version=CONTEXT_VERSION,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
        )
        # Acting process by executable (PROCESS, or HOST_PROCESS outside any
        # Pod). emit.py puts the primary entity in front of it.
        exe = self._process_executable(proc_state)
        if exe:
            ne.entities.add(
                type=(common_pb2.HOST_PROCESS if rec.reader_class == ebpf_pb2.READER_HOST_PROCESS
                      else common_pb2.PROCESS),
                name=exe,
                strength_class=common_pb2.STRENGTH_MEDIUM,
            )
        return ne

    def _process_executable(self, proc_state: dict) -> str:
        """Executable the process runs: an explicit one, its latest exec, else
        its world state."""
        if proc_state.get("executable"):
            return proc_state["executable"]
        key = proc_state.get("process_key", "")
        if key in self._exec_of:
            return self._exec_of[key]
        proc = self._proc_map.get(key)
        return getattr(proc, "executable", "") or ""


# ---------------------------------------------------------------------------
# Internal utility functions
# ---------------------------------------------------------------------------

def _sha256_str(s: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(s.encode()).hexdigest()


def _path_hash(path: str) -> int:
    """Stable integer derived from a path (for simulated dev/ino values)."""
    digest = hashlib.sha256(path.encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _ephemeral_port(process_key: str, time_ns: int, remote_ip: str, remote_port: int) -> int:
    """Stable ephemeral source port (Linux range 32768-60999) for one connect."""
    return 32768 + _path_hash(f"{process_key}|{time_ns}|{remote_ip}|{remote_port}") % 28232


def _cgroup_hash(cgroup: str) -> int:
    """Simulated cgroup_id (uint63) from a cgroup path."""
    digest = hashlib.sha256(cgroup.encode()).digest()
    return int.from_bytes(digest[:8], "big") % (2 ** 63)
