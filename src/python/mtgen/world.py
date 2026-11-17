"""Kubernetes world model and lifetime timeline.

Builds a coherent generated world from a world-size name and a resolved
generator spec. UIDs are allocated deterministically from the seed; all
churn (Pod delete/recreate, IP reuse, PID reuse, token rotation) is
derived from the same seed. The history store uses knowledge time (actual
change time + a generated watch delay) so that lookups at a reuse boundary
return Ambiguous when the deletion event has not yet been observed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import rng as _rng_mod
from .ids import UIDAllocator
from .history import WorldHistory, ContextHistoryRow, FOREVER, Ambiguous
from .simtime import ns_to_timestamp

# Default run epoch: 2024-01-01 00:00:00 UTC in nanoseconds
_DEFAULT_RUN_START_NS: int = 1_704_067_200_000_000_000
# Default run duration: 3600 seconds
_DEFAULT_RUN_DURATION_NS: int = 3_600_000_000_000_000  # 3600 * 10^12

# Watch delays: how long after the actual change the watcher knows about it
_WATCH_DELAY_CREATE_NS: int = 50_000_000          # 50 ms
_WATCH_DELAY_DELETE_NS: int = 100_000_000          # 100 ms
# Large deletion lag used on the first churn event to guarantee IP and PID
# reuse ambiguity. Must exceed reuse_delay (5 s recreate gap + 50 ms).
_WATCH_DELAY_DELETE_LARGE_NS: int = 60_000_000_000  # 60 s

# Gap between old pod deletion and new pod creation (5 seconds)
_POD_RECREATE_GAP_NS: int = 5_000_000_000

_HISTORY_VERSION: str = "context.v0"


# ---------------------------------------------------------------------------
# Entity state dataclasses
# ---------------------------------------------------------------------------

@dataclass
class NodeState:
    """A logical Kubernetes worker node."""
    uid: str
    name: str
    boot_id: str
    init_mnt_ns: int    # Linux mnt namespace ID of the node's init namespace
    init_pid_ns: int    # Linux pid namespace ID of the node's init namespace
    valid_from: int     # actual start time (ns)
    valid_to: int       # actual end time (ns); FOREVER if alive at run end


@dataclass
class NamespaceState:
    """A Kubernetes Namespace."""
    uid: str
    name: str
    valid_from: int
    valid_to: int


@dataclass
class ServiceAccountState:
    """A Kubernetes ServiceAccount."""
    uid: str
    namespace: str
    name: str
    valid_from: int
    valid_to: int


@dataclass
class RoleState:
    """A Kubernetes Role or ClusterRole."""
    uid: str
    namespace: str
    name: str
    kind: str           # "Role" or "ClusterRole"
    valid_from: int
    valid_to: int


@dataclass
class RoleBindingState:
    """A Kubernetes RoleBinding or ClusterRoleBinding."""
    uid: str
    namespace: str
    name: str
    kind: str           # "RoleBinding" or "ClusterRoleBinding"
    role_ref_kind: str
    role_ref_name: str
    subjects: list      # [{"kind": str, "name": str, "namespace": str}]
    valid_from: int
    valid_to: int


@dataclass
class PodState:
    """One Pod lifetime (a distinct UID, not a reused name)."""
    uid: str
    namespace: str
    name: str
    node_name: str
    node_uid: str
    pod_ips: list       # [str]
    service_account: str
    service_name: str
    generation: int     # 0 = initial; 1+ = recreated
    valid_from: int
    valid_to: int


@dataclass
class ContainerState:
    """One container lifetime (runtime container ID changes on recreation)."""
    uid: str            # runtime container ID (e.g. "ctr-<hex>")
    name: str
    pod_uid: str
    image_digest: str   # "sha256:<64hex>"
    image_signed: bool
    is_sidecar: bool
    cgroup: str         # cgroup v2 path (eBPF lookup key)
    valid_from: int
    valid_to: int


@dataclass
class ProcessState:
    """One process lifetime on a node, identified by (node, boot, tgid, start)."""
    process_key: str    # compact encoded key
    container_uid: str
    pod_uid: str
    node_uid: str
    boot_id: str
    tgid: int
    start_time_ns: int
    executable: str
    parent_process_key: str  # "" for container init process
    valid_from: int
    valid_to: int


@dataclass
class TokenVolumeState:
    """A projected ServiceAccount token volume (one version per rotation)."""
    uid: str
    pod_uid: str
    container_name: str
    service_account: str
    version: int        # increments on rotation
    jti: str            # JWT ID (opaque)
    valid_from: int
    valid_to: int


@dataclass
class FileState:
    """A tracked file or artifact in a container."""
    uid: str
    path: str
    container_uid: str
    pod_uid: str
    valid_from: int
    valid_to: int


@dataclass
class InfraState:
    """An infrastructure element (gateway, database, broker, etc.)."""
    kind: str   # "gateway" | "database" | "broker" | "api_server" |
                # "admission_controller" | "off_node_observer"
    uid: str
    name: str
    node_uid: str   # "" for the off-node observer
    valid_from: int
    valid_to: int


# ---------------------------------------------------------------------------
# Process key encoding
# ---------------------------------------------------------------------------

def _process_key(node_uid: str, boot_id: str, tgid: int, start_ns: int) -> str:
    """Encode a process key as a compact string.

    Format: <node_uid_prefix8>:<boot_id_prefix8>:<tgid>:<start_ns_hex>
    """
    return f"{node_uid[:8]}:{boot_id[:8]}:{tgid}:{start_ns:x}"


# ---------------------------------------------------------------------------
# World builder
# ---------------------------------------------------------------------------

class World:
    """Coherent Kubernetes world with a time-indexed lifetime timeline.

    Build a world from a world_size name ("Small", "Reference", or "Large"),
    a resolved generator spec dict, and a seed string. All UIDs, IPs, TGIDs,
    and churn events are deterministic from the seed.

    After construction the following are available:
      world.nodes, world.namespaces, world.service_accounts, world.roles,
      world.role_bindings, world.pods, world.containers, world.processes,
      world.token_volumes, world.files, world.infra, world.history,
      world.context_observations, world.watch_gaps, world.context_history_rows
    """

    INFRA_KINDS = [
        "gateway", "database", "broker",
        "api_server", "admission_controller", "off_node_observer",
    ]

    def __init__(
        self,
        world_size: str,
        spec: dict,
        seed: str,
        run_id: str = "",
        run_start_ns: int = _DEFAULT_RUN_START_NS,
        run_duration_ns: int = _DEFAULT_RUN_DURATION_NS,
    ):
        """
        Args:
            world_size: "Small", "Reference", or "Large"
            spec: resolved generator spec (from specs.load_generator_spec())
            seed: deterministic seed string
            run_id: run identifier (defaults to seed)
            run_start_ns: run start time in nanoseconds since epoch
            run_duration_ns: run duration in nanoseconds
        """
        self.world_size = world_size
        self.spec = spec
        self.seed = seed
        self.run_id = run_id or seed
        self.run_start_ns = run_start_ns
        self.run_duration_ns = run_duration_ns
        self._run_end_ns = run_start_ns + run_duration_ns

        self._streams = _rng_mod.Streams(seed)
        self._history = WorldHistory()

        # UID allocators — each uses its own independent stream
        self._node_uid = UIDAllocator(self._streams, "world.nodes")
        self._boot_uid = UIDAllocator(self._streams, "world.boots")
        self._ns_uid = UIDAllocator(self._streams, "world.namespaces")
        self._sa_uid = UIDAllocator(self._streams, "world.service_accounts")
        self._role_uid = UIDAllocator(self._streams, "world.roles")
        self._binding_uid = UIDAllocator(self._streams, "world.bindings")
        self._pod_uid = UIDAllocator(self._streams, "world.pods")
        self._ctr_uid = UIDAllocator(self._streams, "world.containers")
        self._token_uid = UIDAllocator(self._streams, "world.tokens")
        self._file_uid = UIDAllocator(self._streams, "world.files")
        self._infra_uid = UIDAllocator(self._streams, "world.infra")

        # Entity lists — hold ALL lifetimes including recreated ones
        self._nodes: list = []
        self._namespaces: list = []
        self._service_accounts: list = []
        self._roles: list = []
        self._role_bindings: list = []
        self._pods: list = []
        self._containers: list = []
        self._processes: list = []
        self._token_volumes: list = []
        self._files: list = []
        self._infra: dict = {}
        self._service_names: list = []
        self._ip_pool: list = []

        # Context stream records
        self._context_obs: list = []  # ObjectObservation protos
        self._watch_gaps: list = []   # WatchGap protos

        self._build()

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def nodes(self) -> list:
        return list(self._nodes)

    @property
    def namespaces(self) -> list:
        return list(self._namespaces)

    @property
    def service_accounts(self) -> list:
        return list(self._service_accounts)

    @property
    def roles(self) -> list:
        return list(self._roles)

    @property
    def role_bindings(self) -> list:
        return list(self._role_bindings)

    @property
    def service_names(self) -> list:
        return list(self._service_names)

    @property
    def pods(self) -> list:
        """All pod lifetimes including recreated pods."""
        return list(self._pods)

    @property
    def containers(self) -> list:
        """All container lifetimes including containers of recreated pods."""
        return list(self._containers)

    @property
    def processes(self) -> list:
        return list(self._processes)

    @property
    def token_volumes(self) -> list:
        return list(self._token_volumes)

    @property
    def files(self) -> list:
        return list(self._files)

    @property
    def infra(self) -> dict:
        return dict(self._infra)

    @property
    def history(self) -> WorldHistory:
        return self._history

    @property
    def context_observations(self) -> list:
        """ObjectObservation proto messages (knowledge-time observations)."""
        return list(self._context_obs)

    @property
    def watch_gaps(self) -> list:
        """WatchGap proto messages."""
        return list(self._watch_gaps)

    @property
    def context_history_rows(self) -> list:
        """ContextHistoryRow list for the context_history export table."""
        return self._history.history_rows

    # ------------------------------------------------------------------
    # Build pipeline (two-pass: build then commit to history)
    # ------------------------------------------------------------------

    def _build(self):
        cfg = self.spec["worlds"][self.world_size]
        n_workers = int(cfg["logical_kubernetes_workers"])
        n_services = int(cfg["application_services"])
        n_pods = int(cfg["concurrent_pods"])
        n_containers = int(cfg["concurrent_containers"])
        n_transitions = int(cfg["pod_delete_recreate_transitions"])
        # Derive sidecar pod count from the design-table concurrent container
        # number rather than sidecar_containers (the latter is inconsistent
        # with the design table for Small and Large worlds).
        n_sidecars = n_containers - n_pods

        # Pass 1: allocate structure (valid_to = FOREVER for survivors)
        self._build_nodes(n_workers)
        self._build_ip_pool(n_pods)
        self._build_namespaces_and_rbac(n_services)
        self._build_initial_pods(n_pods, n_sidecars)

        # Pass 2: apply churn — truncates old entities, creates new ones
        self._churn_deletion_lags: dict = {}  # pod_uid -> deletion_lag_ns
        self._apply_churn(n_transitions)

        # Pass 3: resolve FOREVER → run_end for surviving entities
        self._finalize_lifetimes()

        # Pass 4: commit everything to the history store
        self._commit_to_history()

        # Pass 5: supplementary objects
        self._build_tokens()
        self._build_files()
        self._build_infra()

        # Pass 6: watch observations of the final object lifetimes
        self._generate_context_observations()

    # ------------------------------------------------------------------
    # Pass 1 helpers
    # ------------------------------------------------------------------

    def _build_nodes(self, n_workers: int):
        for i in range(n_workers):
            uid = self._node_uid.next()
            boot_id = self._boot_uid.next()
            name = f"worker-{i + 1:02d}"
            rng = self._streams.get(f"world.node.ns.{i}")
            init_mnt = int(rng.integers(4026531000, 4026532000))
            init_pid = int(rng.integers(4026531000, 4026532000))
            self._nodes.append(NodeState(
                uid=uid, name=name, boot_id=boot_id,
                init_mnt_ns=init_mnt, init_pid_ns=init_pid,
                valid_from=self.run_start_ns, valid_to=FOREVER,
            ))

    def _build_ip_pool(self, n_pods: int):
        # Pre-allocate unique IPs; +20 extras for potential reuse
        for i in range(n_pods + 20):
            b = (i // 254) + 1
            c = (i % 254) + 1
            self._ip_pool.append(f"10.{b}.{c}.1")

    def _build_namespaces_and_rbac(self, n_services: int):
        for i in range(n_services):
            svc = f"svc-{i + 1:02d}"
            self._service_names.append(svc)
            ns_name = f"ns-{svc}"

            # Namespace
            ns_uid = self._ns_uid.next()
            self._namespaces.append(NamespaceState(
                uid=ns_uid, name=ns_name,
                valid_from=self.run_start_ns, valid_to=FOREVER,
            ))

            # ServiceAccount
            sa_uid = self._sa_uid.next()
            self._service_accounts.append(ServiceAccountState(
                uid=sa_uid, namespace=ns_name, name=svc,
                valid_from=self.run_start_ns, valid_to=FOREVER,
            ))

            # Role
            role_uid = self._role_uid.next()
            self._roles.append(RoleState(
                uid=role_uid, namespace=ns_name, name=f"role-{svc}",
                kind="Role", valid_from=self.run_start_ns, valid_to=FOREVER,
            ))

            # RoleBinding
            binding_uid = self._binding_uid.next()
            self._role_bindings.append(RoleBindingState(
                uid=binding_uid, namespace=ns_name, name=f"rb-{svc}",
                kind="RoleBinding", role_ref_kind="Role",
                role_ref_name=f"role-{svc}",
                subjects=[{"kind": "ServiceAccount", "name": svc,
                           "namespace": ns_name}],
                valid_from=self.run_start_ns, valid_to=FOREVER,
            ))

    def _build_initial_pods(self, n_pods: int, n_sidecars: int):
        """Allocate n_pods initial pods; first n_sidecars get a sidecar."""
        for i in range(n_pods):
            node = self._nodes[i % len(self._nodes)]
            svc = self._service_names[i % len(self._service_names)]
            ns_name = f"ns-{svc}"
            ip = self._ip_pool[i]

            pod_uid = self._pod_uid.next()
            pod_name = f"{svc}-pod-{i:04d}"
            pod = PodState(
                uid=pod_uid, namespace=ns_name, name=pod_name,
                node_name=node.name, node_uid=node.uid,
                pod_ips=[ip], service_account=svc, service_name=svc,
                generation=0, valid_from=self.run_start_ns, valid_to=FOREVER,
            )
            self._pods.append(pod)

            # Main container
            self._alloc_container(pod, f"{svc}-main", False, node)
            # Sidecar container for first n_sidecars pods
            if i < n_sidecars:
                self._alloc_container(pod, f"{svc}-sidecar", True, node)

    def _alloc_container(
        self,
        pod: PodState,
        name: str,
        is_sidecar: bool,
        node: NodeState,
    ) -> ContainerState:
        raw = self._ctr_uid.next()
        ctr_id = f"ctr-{raw.replace('-', '')[:24]}"
        image_digest = f"sha256:{raw.replace('-', '')}"
        cgroup = f"/kubepods/pod{pod.uid}/{ctr_id}"
        ctr = ContainerState(
            uid=ctr_id, name=name, pod_uid=pod.uid,
            image_digest=image_digest, image_signed=True,
            is_sidecar=is_sidecar, cgroup=cgroup,
            valid_from=pod.valid_from, valid_to=FOREVER,
        )
        self._containers.append(ctr)
        self._alloc_processes(ctr, node, reuse_tgid=None)
        return ctr

    def _alloc_processes(
        self,
        ctr: ContainerState,
        node: NodeState,
        reuse_tgid: Optional[int],
    ):
        """Allocate init + app processes for a container.

        If reuse_tgid is given the init process uses that TGID (PID reuse).
        """
        rng = self._streams.get(f"world.proc.{ctr.uid}")

        init_tgid = reuse_tgid if reuse_tgid is not None else int(
            rng.integers(1000, 55000)
        )
        init_start = ctr.valid_from + int(rng.integers(0, 50_000_000))
        pk_init = _process_key(node.uid, node.boot_id, init_tgid, init_start)

        self._processes.append(ProcessState(
            process_key=pk_init, container_uid=ctr.uid, pod_uid=ctr.pod_uid,
            node_uid=node.uid, boot_id=node.boot_id,
            tgid=init_tgid, start_time_ns=init_start, executable="/sbin/init",
            parent_process_key="", valid_from=init_start, valid_to=FOREVER,
        ))

        app_tgid = int(rng.integers(init_tgid + 1, min(init_tgid + 500, 65000)))
        app_start = init_start + int(rng.integers(10_000_000, 100_000_000))
        pk_app = _process_key(node.uid, node.boot_id, app_tgid, app_start)

        self._processes.append(ProcessState(
            process_key=pk_app, container_uid=ctr.uid, pod_uid=ctr.pod_uid,
            node_uid=node.uid, boot_id=node.boot_id,
            tgid=app_tgid, start_time_ns=app_start, executable="/app/server",
            parent_process_key=pk_init, valid_from=app_start, valid_to=FOREVER,
        ))

    # ------------------------------------------------------------------
    # Pass 2: churn
    # ------------------------------------------------------------------

    def _apply_churn(self, n_transitions: int):
        """Delete and recreate n_transitions pods during the run.

        The first churn event uses a large watch delay for the deletion so
        that the IP and PID reuse create an observable ambiguity boundary in
        the history store (required by the Reuse test).
        """
        if n_transitions == 0 or not self._pods:
            return

        # Select pods for churn: prefer main-only pods (no sidecar) so the
        # container lifetime count stays predictable at +1 per transition.
        sidecar_pod_uids = {
            c.pod_uid for c in self._containers if c.is_sidecar
        }
        candidates = [
            p for p in self._pods
            if p.generation == 0 and p.uid not in sidecar_pod_uids
        ]
        if len(candidates) < n_transitions:
            candidates = [p for p in self._pods if p.generation == 0]

        rng = self._streams.get("world.churn")
        indices = rng.choice(len(candidates), size=n_transitions, replace=False)

        for churn_idx, raw_idx in enumerate(indices):
            old_pod = candidates[int(raw_idx)]
            node = next(n for n in self._nodes if n.uid == old_pod.node_uid)

            # Deletion time: evenly spaced across the run
            frac = (churn_idx + 1) / (n_transitions + 1)
            t_delete = self.run_start_ns + int(self.run_duration_ns * frac)
            t_recreate = t_delete + _POD_RECREATE_GAP_NS

            # Large deletion lag on churn_idx==0 to force IP/PID ambiguity
            del_lag = (
                _WATCH_DELAY_DELETE_LARGE_NS if churn_idx == 0
                else _WATCH_DELAY_DELETE_NS
            )
            self._churn_deletion_lags[old_pod.uid] = del_lag

            # Truncate old pod and its containers/processes
            old_pod.valid_to = t_delete
            for ctr in self._containers:
                if ctr.pod_uid == old_pod.uid and ctr.valid_to == FOREVER:
                    ctr.valid_to = t_delete
            for proc in self._processes:
                if proc.pod_uid == old_pod.uid and proc.valid_to == FOREVER:
                    proc.valid_to = t_delete

            # For churn_idx==0: reuse the old init TGID in the new container
            reuse_tgid = None
            if churn_idx == 0:
                old_main = next(
                    (c for c in self._containers
                     if c.pod_uid == old_pod.uid and not c.is_sidecar),
                    None,
                )
                if old_main:
                    old_init = next(
                        (p for p in self._processes
                         if p.container_uid == old_main.uid
                         and p.parent_process_key == ""),
                        None,
                    )
                    if old_init:
                        reuse_tgid = old_init.tgid

            # Create replacement pod — reuse the IP for all churn events
            old_ip = old_pod.pod_ips[0]
            new_uid = self._pod_uid.next()
            new_name = old_pod.name  # same name, new UID
            new_pod = PodState(
                uid=new_uid, namespace=old_pod.namespace, name=new_name,
                node_name=old_pod.node_name, node_uid=old_pod.node_uid,
                pod_ips=[old_ip],
                service_account=old_pod.service_account,
                service_name=old_pod.service_name,
                generation=old_pod.generation + 1,
                valid_from=t_recreate, valid_to=FOREVER,
            )
            self._pods.append(new_pod)
            self._churn_deletion_lags[new_pod.uid] = 0  # not deleted

            # Main container for the new pod
            self._alloc_container(
                new_pod, f"{old_pod.service_name}-main", False, node,
                # override process allocation to use reuse_tgid
            )
            if reuse_tgid is not None:
                # Replace the just-allocated init process with one that
                # reuses the old TGID (the container's valid_from is t_recreate)
                new_ctr = self._containers[-1]
                # Remove the two processes just allocated for new_ctr
                self._processes = [
                    p for p in self._processes if p.container_uid != new_ctr.uid
                ]
                self._alloc_processes(new_ctr, node, reuse_tgid=reuse_tgid)

    # ------------------------------------------------------------------
    # Pass 3: finalize lifetimes
    # ------------------------------------------------------------------

    def _finalize_lifetimes(self):
        run_end = self._run_end_ns
        for p in self._pods:
            if p.valid_to == FOREVER:
                p.valid_to = run_end
        for c in self._containers:
            if c.valid_to == FOREVER:
                c.valid_to = run_end
        for p in self._processes:
            if p.valid_to == FOREVER:
                p.valid_to = run_end
        for n in self._nodes:
            if n.valid_to == FOREVER:
                n.valid_to = run_end
        for ns in self._namespaces:
            if ns.valid_to == FOREVER:
                ns.valid_to = run_end
        for sa in self._service_accounts:
            if sa.valid_to == FOREVER:
                sa.valid_to = run_end
        for r in self._roles:
            if r.valid_to == FOREVER:
                r.valid_to = run_end
        for rb in self._role_bindings:
            if rb.valid_to == FOREVER:
                rb.valid_to = run_end

    # ------------------------------------------------------------------
    # Pass 4: commit to history store
    # ------------------------------------------------------------------

    def _commit_to_history(self):
        """Register all entities into the WorldHistory with knowledge-time intervals."""
        run_end = self._run_end_ns

        # Nodes
        for n in self._nodes:
            obs_from = n.valid_from + _WATCH_DELAY_CREATE_NS
            obs_to = run_end  # nodes don't churn within a run
            self._history.add("Node", n.uid, obs_from, obs_to, n)
            self._history.add("Node:name", n.name, obs_from, obs_to, n)
            self._history.add_history_row(ContextHistoryRow(
                run_id=self.run_id, entity_type="Node", entity_uid=n.uid,
                valid_from=n.valid_from, valid_to=n.valid_to,
                observed_from=obs_from, parent_uid="",
                attributes={"name": n.name, "boot_id": n.boot_id,
                             "init_mnt_ns": n.init_mnt_ns,
                             "init_pid_ns": n.init_pid_ns},
                history_version=_HISTORY_VERSION, ambiguity_reason="",
            ))

        # Namespaces
        for ns in self._namespaces:
            obs_from = ns.valid_from + _WATCH_DELAY_CREATE_NS
            self._history.add("Namespace", ns.uid, obs_from, run_end, ns)
            self._history.add("Namespace:name", ns.name, obs_from, run_end, ns)
            self._history.add_history_row(ContextHistoryRow(
                run_id=self.run_id, entity_type="Namespace", entity_uid=ns.uid,
                valid_from=ns.valid_from, valid_to=ns.valid_to,
                observed_from=obs_from, parent_uid="",
                attributes={"name": ns.name},
                history_version=_HISTORY_VERSION, ambiguity_reason="",
            ))

        # ServiceAccounts
        for sa in self._service_accounts:
            obs_from = sa.valid_from + _WATCH_DELAY_CREATE_NS
            self._history.add("ServiceAccount", sa.uid, obs_from, run_end, sa)
            self._history.add_history_row(ContextHistoryRow(
                run_id=self.run_id, entity_type="ServiceAccount",
                entity_uid=sa.uid, valid_from=sa.valid_from, valid_to=sa.valid_to,
                observed_from=obs_from, parent_uid="",
                attributes={"name": sa.name, "namespace": sa.namespace},
                history_version=_HISTORY_VERSION, ambiguity_reason="",
            ))

        # Roles
        for r in self._roles:
            obs_from = r.valid_from + _WATCH_DELAY_CREATE_NS
            self._history.add("Role", r.uid, obs_from, run_end, r)

        # RoleBindings
        for rb in self._role_bindings:
            obs_from = rb.valid_from + _WATCH_DELAY_CREATE_NS
            self._history.add("RoleBinding", rb.uid, obs_from, run_end, rb)

        # Pods and their IP/name keys
        ip_reuse_set: set = set()
        for pod in self._pods:
            obs_from = pod.valid_from + _WATCH_DELAY_CREATE_NS
            del_lag = self._churn_deletion_lags.get(pod.uid, 0)
            if pod.valid_to < self._run_end_ns:
                # Churned pod: valid_to in history = actual_to + del_lag
                obs_to = pod.valid_to + del_lag
            else:
                obs_to = run_end

            self._history.add("Pod", pod.uid, obs_from, obs_to, pod)
            self._history.add("Pod:name", pod.name, obs_from, obs_to, pod)

            ip = pod.pod_ips[0]
            self._history.add("PodIP", ip, obs_from, obs_to, pod)
            if ip in ip_reuse_set:
                ambiguity_note = "ip_reuse"
            else:
                ambiguity_note = ""
            ip_reuse_set.add(ip)

            self._history.add_history_row(ContextHistoryRow(
                run_id=self.run_id, entity_type="Pod", entity_uid=pod.uid,
                valid_from=pod.valid_from, valid_to=pod.valid_to,
                observed_from=obs_from, parent_uid=pod.node_uid,
                attributes={"name": pod.name, "namespace": pod.namespace,
                             "pod_ips": pod.pod_ips, "node": pod.node_name,
                             "service_account": pod.service_account,
                             "generation": pod.generation},
                history_version=_HISTORY_VERSION,
                ambiguity_reason=ambiguity_note,
            ))

        # Containers
        pid_reuse_set: set = set()
        for ctr in self._containers:
            obs_from = ctr.valid_from + _WATCH_DELAY_CREATE_NS
            del_lag = self._churn_deletion_lags.get(ctr.pod_uid, 0)
            if ctr.valid_to < self._run_end_ns:
                obs_to = ctr.valid_to + del_lag
            else:
                obs_to = run_end

            self._history.add("Container", ctr.uid, obs_from, obs_to, ctr)
            self._history.add("Cgroup", ctr.cgroup, obs_from, obs_to, ctr)
            self._history.add_history_row(ContextHistoryRow(
                run_id=self.run_id, entity_type="Container", entity_uid=ctr.uid,
                valid_from=ctr.valid_from, valid_to=ctr.valid_to,
                observed_from=obs_from, parent_uid=ctr.pod_uid,
                attributes={"name": ctr.name, "cgroup": ctr.cgroup,
                             "is_sidecar": ctr.is_sidecar,
                             "image_digest": ctr.image_digest},
                history_version=_HISTORY_VERSION, ambiguity_reason="",
            ))

        # Processes — key by (node_uid, tgid) for PID reuse detection
        for proc in self._processes:
            del_lag = self._churn_deletion_lags.get(proc.pod_uid, 0)
            if proc.valid_to < self._run_end_ns:
                proc_obs_to = proc.valid_to + del_lag
            else:
                proc_obs_to = run_end
            proc_obs_from = proc.valid_from + _WATCH_DELAY_CREATE_NS

            self._history.add("Process", proc.process_key,
                               proc_obs_from, proc_obs_to, proc)
            pid_key = f"{proc.node_uid}:{proc.tgid}"
            self._history.add("ProcessPID", pid_key,
                               proc_obs_from, proc_obs_to, proc)

    # ------------------------------------------------------------------
    # Pass 5: supplementary objects
    # ------------------------------------------------------------------

    def _build_tokens(self):
        """Build projected token volumes — one per container (initial pods only)."""
        initial_pods = [p for p in self._pods if p.generation == 0]
        for pod in initial_pods:
            for ctr in self._containers:
                if ctr.pod_uid != pod.uid:
                    continue
                tok_uid = self._token_uid.next()
                rng = self._streams.get(f"world.token.{tok_uid}")
                jti = tok_uid.replace("-", "")
                self._token_volumes.append(TokenVolumeState(
                    uid=tok_uid, pod_uid=pod.uid, container_name=ctr.name,
                    service_account=pod.service_account, version=1, jti=jti,
                    valid_from=pod.valid_from, valid_to=pod.valid_to,
                ))

    def _build_files(self):
        """Build a representative tracked file per initial-pod container."""
        initial_pods = {p.uid for p in self._pods if p.generation == 0}
        for ctr in self._containers:
            if ctr.pod_uid not in initial_pods:
                continue
            f_uid = self._file_uid.next()
            self._files.append(FileState(
                uid=f_uid, path=f"/app/data/{f_uid[:8]}.dat",
                container_uid=ctr.uid, pod_uid=ctr.pod_uid,
                valid_from=ctr.valid_from, valid_to=ctr.valid_to,
            ))

    def _build_infra(self):
        """Build fixed infrastructure elements (one of each kind)."""
        ctrl_node = self._nodes[0]
        for kind in self.INFRA_KINDS:
            uid = self._infra_uid.next()
            node_uid = "" if kind == "off_node_observer" else ctrl_node.uid
            self._infra[kind] = InfraState(
                kind=kind, uid=uid, name=kind,
                node_uid=node_uid,
                valid_from=self.run_start_ns,
                valid_to=self._run_end_ns,
            )

    # ------------------------------------------------------------------
    # Context observation generation (ObjectObservation / WatchGap)
    # ------------------------------------------------------------------

    def _emit_context_obs(
        self,
        api_group: str,
        kind: str,
        namespace: str,
        name: str,
        uid: str,
        change_type_val: int,
        observed_time_ns: int,
        watch_stream_id: str,
        watch_seq: int,
        pod_summary=None,
    ):
        """Build and store an ObjectObservation proto."""
        try:
            from microtrace.v0 import context_pb2
            from microtrace.v0.common_pb2 import EvidenceRef, ORDINARY
            from google.protobuf.timestamp_pb2 import Timestamp
        except ImportError:
            return  # Skip if proto not available (shouldn't happen)

        sec = observed_time_ns // 1_000_000_000
        nanos = observed_time_ns % 1_000_000_000
        ts = Timestamp(seconds=sec, nanos=nanos)

        obs = context_pb2.ObjectObservation(
            api_group=api_group,
            kind=kind,
            namespace=namespace,
            name=name,
            uid=uid,
            resource_version=f"rv-{watch_seq}",
            change_type=change_type_val,
            observed_time=ts,
            watch_stream_id=watch_stream_id,
            watch_stream_seq=watch_seq,
        )
        if pod_summary is not None:
            obs.pod.CopyFrom(pod_summary)
        self._context_obs.append(obs)

    def observe_admitted_pod(self, uid: str, name: str, namespace: str, admitted_ns: int):
        """Watch observation (ADDED) of a Pod a scenario admits after the
        world is built. It has no world containers, so only identity is
        observed (a bare Pod: no controller owner); without it the agents
        never see the Pod exist."""
        from microtrace.v0 import context_pb2
        seq = 1 + max((o.watch_stream_seq for o in self._context_obs
                       if o.watch_stream_id == "watch-pods"), default=0)
        self._emit_context_obs(
            "", "Pod", namespace, name, uid, context_pb2.ADDED,
            admitted_ns + _WATCH_DELAY_CREATE_NS, "watch-pods", seq,
            pod_summary=context_pb2.PodSummary(),
        )

    def _generate_context_observations(self):
        """Generate ObjectObservation records for all state changes."""
        try:
            from microtrace.v0 import context_pb2
        except ImportError:
            return

        ADDED = context_pb2.ADDED
        DELETED = context_pb2.DELETED

        seq_pod = 0
        seq_node = 0

        for node in self._nodes:
            seq_node += 1
            obs_t = node.valid_from + _WATCH_DELAY_CREATE_NS
            self._emit_context_obs(
                "", "Node", "", node.name, node.uid, ADDED, obs_t,
                "watch-nodes", seq_node,
            )

        ctrs_by_pod: dict = {}
        for ctr in self._containers:
            ctrs_by_pod.setdefault(ctr.pod_uid, []).append(ctr)

        for pod in self._pods:
            seq_pod += 1
            obs_from = pod.valid_from + _WATCH_DELAY_CREATE_NS
            summary = context_pb2.PodSummary(
                node_name=pod.node_name,
                pod_ips=list(pod.pod_ips),
                service_account=pod.service_account,
                containers=[
                    context_pb2.ContainerStatusSummary(
                        name=ctr.name,
                        container_id=ctr.uid,
                        restart_count=0,
                        started_at=ns_to_timestamp(ctr.valid_from),
                        image_id=ctr.image_digest,
                    )
                    for ctr in sorted(ctrs_by_pod.get(pod.uid, []),
                                      key=lambda c: (c.valid_from, c.name))
                ],
            )
            # Controller owner: the service's Deployment. Named at the
            # Deployment level so the workload survives churn and rollouts;
            # no UID, since a UID is never fabricated (common.proto EntityRef).
            summary.owners.add(namespace=pod.namespace, name=pod.service_name)
            self._emit_context_obs(
                "", "Pod", pod.namespace, pod.name, pod.uid, ADDED, obs_from,
                "watch-pods", seq_pod, pod_summary=summary,
            )
            if pod.valid_to < self._run_end_ns:
                seq_pod += 1
                del_lag = self._churn_deletion_lags.get(pod.uid, _WATCH_DELAY_DELETE_NS)
                obs_del = pod.valid_to + del_lag
                self._emit_context_obs(
                    "", "Pod", pod.namespace, pod.name, pod.uid, DELETED, obs_del,
                    "watch-pods", seq_pod,
                )
