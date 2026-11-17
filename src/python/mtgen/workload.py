"""Benign workload engine.

Generates Activity records covering all services, graph edges, container
processes, control-plane operations, and scheduled jobs for the run duration.

At this phase activities are driven by scripted Poisson distributions
(ScriptedSource).  Phase 3 will supply a TemplateSource backed by
public-data templates; no other code changes are required.

Rate modes
----------
``fixed_per_service``  (default)
    Each service independently draws events at the profile rate.
``fixed_total``
    The profile rate applies to the whole cluster; each service gets
    rate / n_services.
"""
from __future__ import annotations

import abc
from typing import Dict, List, Optional, Tuple

import numpy as np

from .activity import Activity
from .netmodel import accept_delay_ns
from .rng import Streams
from .world import World


# ---------------------------------------------------------------------------
# DistributionSource interface
# ---------------------------------------------------------------------------

class DistributionSource(abc.ABC):
    """Interface for activity timing and parameter sampling.

    All randomness flows through the caller-supplied numpy Generator so that
    the engine controls stream naming and determinism.
    """

    @abc.abstractmethod
    def rate_per_ns(self, kind: str, service: str) -> float:
        """Mean event rate for (kind, service) in events per nanosecond."""

    @abc.abstractmethod
    def inter_arrival_ns(
        self, kind: str, service: str, rng: "np.random.Generator"
    ) -> int:
        """Sample one inter-arrival time (ns) from the distribution."""

    @abc.abstractmethod
    def sample_parameters(
        self,
        kind: str,
        service: str,
        rng: "np.random.Generator",
        context: dict,
    ) -> dict:
        """Sample action parameters for (kind, service) with optional context."""


# ---------------------------------------------------------------------------
# ScriptedSource
# ---------------------------------------------------------------------------

class ScriptedSource(DistributionSource):
    """DistributionSource backed by the generator spec's background_profiles.

    Rates come from the resolve_params()-resolved background_profiles dict.
    """

    def __init__(
        self,
        profile: dict,
        rate_mode: str = "fixed_per_service",
        n_services: int = 1,
    ):
        """
        Args:
            profile:    background_profiles section from the resolved spec.
            rate_mode:  ``"fixed_per_service"`` or ``"fixed_total"``.
            n_services: total services in the world (used for fixed_total).
        """
        if rate_mode not in ("fixed_per_service", "fixed_total"):
            raise ValueError(f"Unknown rate_mode: {rate_mode!r}")
        self._profile = profile
        self._rate_mode = rate_mode
        self._n_services = max(1, n_services)

    # ------------------------------------------------------------------
    # DistributionSource implementation
    # ------------------------------------------------------------------

    def rate_per_ns(self, kind: str, service: str) -> float:
        rate_s = self._base_rate_per_second(kind)
        if self._rate_mode == "fixed_total":
            rate_s = rate_s / self._n_services
        return rate_s / 1_000_000_000.0

    def inter_arrival_ns(
        self, kind: str, service: str, rng: "np.random.Generator"
    ) -> int:
        rate = self.rate_per_ns(kind, service)
        if rate <= 0:
            return int(1e18)
        return max(1, int(rng.exponential(1.0 / rate)))

    def sample_parameters(
        self,
        kind: str,
        service: str,
        rng: "np.random.Generator",
        context: dict,
    ) -> dict:
        if kind == "http_request":
            return self._http_params(service, rng, context)
        if kind == "api_request":
            return self._api_params(service, rng, context)
        if kind in ("read_token_file", "read_sensitive_file"):
            path = context.get(
                "file_path",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            )
            return {"file_path": path}
        if kind == "connect_internal":
            return {
                "protocol": "tcp",
                "target_port": int(context.get("port", 8080)),
            }
        if kind == "process_exec":
            exes = ["/app/server", "/usr/bin/python3", "/bin/sh", "/app/worker"]
            exe = exes[int(rng.integers(len(exes)))]
            return {"executable": exe, "argv": [exe]}
        if kind == "admit_pod":
            return {
                "policy_verdict": "PASS",
                "policy_enforcement": "enforce",
                "pod_name": context.get("pod_name", ""),
                "namespace": context.get("namespace", ""),
            }
        if kind == "file_write":
            return {
                "file_path": context.get("file_path", "/app/data/out.dat"),
                "create_if_missing": True,
            }
        return {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_rate_per_second(self, kind: str) -> float:
        """Spec-defined mean events per second for the given kind."""
        rr = self._profile.get("request_rates", {})
        pa = self._profile.get("process_activity", {})
        aa = self._profile.get("audit_activity", {})

        if kind == "http_request":
            return float(rr.get("baseline_requests_per_second", 10))
        if kind == "process_exec":
            return float(
                pa.get("process_spawn_rate_per_container_per_minute", 0.5)
            ) / 60.0
        if kind in ("read_token_file", "read_sensitive_file"):
            return float(
                pa.get("file_open_rate_per_process_per_minute", 10)
            ) / 60.0
        if kind == "file_write":
            return float(
                pa.get("file_open_rate_per_process_per_minute", 10)
            ) / 60.0 * 0.3   # writes are ~30% of file ops
        if kind == "connect_internal":
            return float(
                pa.get("network_connection_rate_per_process_per_minute", 2)
            ) / 60.0
        if kind == "external_egress":
            return float(
                pa.get("external_egress_rate_per_container_per_minute", 0.3)
            ) / 60.0
        if kind == "api_request":
            return float(
                aa.get("audit_events_per_minute_baseline", 100)
            ) / 60.0
        if kind == "admit_pod":
            return float(aa.get("admission_reviews_per_service_per_minute", 0.2)) / 60.0
        # Scheduled jobs: once per hour per service
        return 1.0 / 3600.0

    def _http_params(
        self, service: str, rng: "np.random.Generator", context: dict
    ) -> dict:
        rr = self._profile.get("request_rates", {})
        mix = rr.get("request_mix", [
            {"method": "GET",    "percentage": 70},
            {"method": "POST",   "percentage": 20},
            {"method": "PUT",    "percentage": 7},
            {"method": "DELETE", "percentage": 3},
        ])
        methods = [m["method"] for m in mix]
        weights = np.array([m["percentage"] for m in mix], dtype=float)
        weights /= weights.sum()
        idx = int(rng.choice(len(methods), p=weights))
        paths = [
            "/api/v1/items", "/api/v1/search", "/api/v1/health",
            "/api/v1/status", f"/api/v1/{service}/data",
        ]
        path = paths[int(rng.integers(len(paths)))]
        return {
            "method": methods[idx],
            "path": path,
            "target_service": context.get("target_service", service),
        }

    def _api_params(
        self, service: str, rng: "np.random.Generator", context: dict
    ) -> dict:
        aa = self._profile.get("audit_activity", {})
        verbs = aa.get(
            "event_types",
            ["list", "get", "watch", "create", "patch", "delete"],
        )
        resources = [
            "pods", "services", "configmaps", "endpoints",
            "secrets", "namespaces", "deployments",
        ]
        verb = verbs[int(rng.integers(len(verbs)))]
        resource = resources[int(rng.integers(len(resources)))]
        return {
            "verb": verb,
            "resource": resource,
            "api_group": "",
            "namespace": context.get("namespace", f"ns-{service}"),
        }


# ---------------------------------------------------------------------------
# WorkloadEngine
# ---------------------------------------------------------------------------

# Generator flags (exp2-conflict-origin-cases-plan D-31): off in PILOT.
# gateway_internal_listener: service-to-service calls go through the gateway's
# internal listener, which keeps the caller's x-request-id (G3).
# ebpf_accept: the server accepts every in-cluster connect to a Pod, rendered
# as a net.accept by a per-connection handler process (G1).
GATEWAY_INTERNAL_LISTENER = "gateway_internal_listener"
EBPF_ACCEPT = "ebpf_accept"
GENERATOR_FLAGS = (GATEWAY_INTERNAL_LISTENER, EBPF_ACCEPT)
# Share of internal calls that propagate the caller's current edge request
# ID; the rest send an ID of their own.
PROPAGATE_SHARE = 0.8


class WorkloadEngine:
    """Generates benign background Activities from background_profiles.

    Call generate() once; the returned list is sorted by time_ns and
    contains all activity kinds for the full run duration.  Calling
    generate() again returns the same cached list.
    """

    def __init__(
        self,
        world: "World",
        spec: dict,
        source: Optional[DistributionSource] = None,
        rate_mode: str = "fixed_per_service",
        flags: tuple = (),
    ):
        """
        Args:
            world:     built World instance
            spec:      resolved generator spec (from specs.load_generator_spec())
            source:    DistributionSource; if None, a ScriptedSource is built
                       from spec's background_profiles.
            rate_mode: "fixed_per_service" or "fixed_total"; ignored when
                       source is supplied explicitly.
            flags:     generator flags of the run (GENERATOR_FLAGS); none by
                       default, which keeps PILOT's activities unchanged.
        """
        self._world = world
        self._spec = spec
        self._flags = frozenset(flags)
        n_svc = len(world.service_names)
        profile = spec.get("background_profiles", {})
        self._source = source or ScriptedSource(
            profile=profile,
            rate_mode=rate_mode,
            n_services=n_svc,
        )
        self._streams = Streams(f"{world.seed}:workload")
        self._cache: Optional[List[Activity]] = None
        # Pre-computed indices (built lazily in _build)
        self._pods_by_svc: Dict[str, List[Tuple[int, int, str]]] = {}
        self._procs_by_ctr: Dict[str, List[Tuple[int, int, str]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> List[Activity]:
        """Return all benign activities for the run, sorted by time_ns.

        The result is deterministic: same World and spec always produce the
        same list in the same order.
        """
        if self._cache is not None:
            return list(self._cache)
        self._cache = self._build()
        return list(self._cache)

    def accepts(self, activities: List[Activity]) -> List[Activity]:
        """The server's accept of each successful in-cluster connect, under
        the flag ebpf_accept (G1); none otherwise.

        Background and scenario connects alike, or the accept would mark
        background traffic. A scenario connect's accept belongs to its
        step's action, unless a step of its own accepts it (accept_of: the
        connect step's action_seq). A connect to infrastructure (no Pod)
        gets none. Each connect gets a connection_id the accept names.

        An accept that would fall at or after the run end is not made (the
        server has not accepted yet when the run stops); the delay is drawn
        anyway, so the other accepts keep their times. The accept is on the
        server, so it does not take the connect step's `unobserved` sources:
        those describe a probe gap at the client's node.
        """
        if EBPF_ACCEPT not in self._flags:
            return []
        own = {str(a.parameters.get("accept_of")) for a in activities if a.kind == "accept_internal"}
        rng = self._streams.get("workload.net.accept")
        end = self._end_ns()
        out: List[Activity] = []
        for a in sorted(activities, key=lambda a: a.time_ns):
            if (a.kind != "connect_internal" or a.outcome != "success"
                    or a.target_type == "InfraService"
                    or (a.action_seq is not None and str(a.action_seq) in own)):
                continue
            t = a.time_ns + accept_delay_ns(rng)
            if t >= end:
                continue
            cid = f"auto{len(out) + 1}"
            a.parameters["connection_id"] = cid
            out.append(Activity(
                time_ns=t, kind="accept_internal",
                actor_uid=a.target_uid, actor_type=a.target_type,
                target_uid=a.actor_uid, target_type=a.actor_type,
                parameters={"accept_of": cid},
                action_seq=a.action_seq,
            ))
        return out

    # ------------------------------------------------------------------
    # Build pipeline
    # ------------------------------------------------------------------

    def _build(self) -> List[Activity]:
        self._pods_by_svc = self._build_pods_by_svc()
        self._procs_by_ctr = self._build_procs_by_ctr()

        acts: List[Activity] = []
        acts.extend(self._gen_requests())
        acts.extend(self._gen_process_activity())
        acts.extend(self._gen_external_egress())
        acts.extend(self._gen_control_plane())
        acts.extend(self._gen_scheduled_jobs())
        acts.sort(key=lambda a: a.time_ns)
        return acts

    # ------------------------------------------------------------------
    # Index builders
    # ------------------------------------------------------------------

    def _build_pods_by_svc(self) -> Dict[str, List[Tuple[int, int, str]]]:
        """Map service_name -> sorted list of (valid_from, valid_to, pod_uid)."""
        result: Dict[str, List[Tuple[int, int, str]]] = {}
        for pod in self._world.pods:
            svc = pod.service_name
            if svc not in result:
                result[svc] = []
            result[svc].append((pod.valid_from, pod.valid_to, pod.uid))
        for svc in result:
            result[svc].sort()
        return result

    def _build_procs_by_ctr(self) -> Dict[str, List[Tuple[int, int, str]]]:
        """Map container_uid -> sorted list of (valid_from, valid_to, proc_key)."""
        result: Dict[str, List[Tuple[int, int, str]]] = {}
        for proc in self._world.processes:
            cuid = proc.container_uid
            if cuid not in result:
                result[cuid] = []
            result[cuid].append(
                (proc.valid_from, proc.valid_to, proc.process_key)
            )
        for cuid in result:
            result[cuid].sort()
        return result

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _end_ns(self) -> int:
        return self._world.run_start_ns + self._world.run_duration_ns

    def _poisson_times(
        self,
        start_ns: int,
        end_ns: int,
        rate_per_ns: float,
        rng: "np.random.Generator",
    ) -> List[int]:
        """All event times for a Poisson process in [start_ns, end_ns).

        Uses the batch method: draw count from Poisson(λT), then place
        arrivals uniformly.  Equivalent to exponential inter-arrivals.
        """
        duration_ns = end_ns - start_ns
        if duration_ns <= 0 or rate_per_ns <= 0:
            return []
        expected = duration_ns * rate_per_ns
        if expected < 1e-12:
            return []
        n = int(rng.poisson(expected))
        if n == 0:
            return []
        offsets = rng.random(n) * duration_ns
        return sorted(start_ns + int(o) for o in offsets)

    @staticmethod
    def _pick_pod(
        pods_for_svc: List[Tuple[int, int, str]], time_ns: int
    ) -> Optional[str]:
        """Return a pod_uid whose actual lifetime covers time_ns, or None."""
        for vf, vt, uid in pods_for_svc:
            if vf <= time_ns < vt:
                return uid
        return None

    @staticmethod
    def _pick_process(
        procs_for_ctr: List[Tuple[int, int, str]], time_ns: int
    ) -> Optional[str]:
        """Return a process_key alive at time_ns, or None."""
        for vf, vt, pk in procs_for_ctr:
            if vf <= time_ns < vt:
                return pk
        return None

    def _service_edges(self) -> List[Tuple[str, str]]:
        """Deterministic caller→callee edges covering every service.

        Builds a ring (svc-i → svc-(i+1)%n) plus every-third skip-ahead
        shortcuts so every service is both a caller and a callee.  The set
        includes edges used by attack scenarios (H2, G1a, A1) because the
        gateway→all and ring→any-service structure mirrors them.
        """
        svcs = self._world.service_names
        n = len(svcs)
        if n == 0:
            return []
        seen: set = set()
        edges: List[Tuple[str, str]] = []
        for i in range(n):
            e = (svcs[i], svcs[(i + 1) % n])
            if e not in seen:
                seen.add(e)
                edges.append(e)
        # Skip-one shortcuts for cross-tier diversity
        for i in range(0, n, 3):
            e = (svcs[i], svcs[(i + 2) % n])
            if e not in seen:
                seen.add(e)
                edges.append(e)
        return edges

    # ------------------------------------------------------------------
    # Activity generators
    # ------------------------------------------------------------------

    def _internal_call(self, src_svc: str, dst_svc: str) -> dict:
        """Gateway parameters of a service-to-service call on the internal
        listener: most calls propagate the request src_svc is serving."""
        rng = self._streams.get(f"workload.http.propagate.{src_svc}.{dst_svc}")
        if rng.random() < PROPAGATE_SHARE:
            return {"listener": "internal", "propagate_from": src_svc}
        return {"listener": "internal"}

    def _gen_requests(self) -> List[Activity]:
        """HTTP inbound, interservice, DB queries, and broker traffic."""
        acts: List[Activity] = []
        start = self._world.run_start_ns
        end = self._end_ns()
        svcs = self._world.service_names
        infra = self._world.infra

        # --- Inbound HTTP to every service (from external) ---
        for svc in svcs:
            rng = self._streams.get(f"workload.http.inbound.{svc}")
            rate = self._source.rate_per_ns("http_request", svc)
            for t in self._poisson_times(start, end, rate, rng):
                params = self._source.sample_parameters(
                    "http_request", svc, rng, {"target_service": svc}
                )
                acts.append(Activity(
                    time_ns=t, kind="http_request",
                    actor_uid="external", actor_type="External",
                    target_uid=svc, target_type="Service",
                    parameters=params,
                ))

        # --- Interservice calls along graph edges ---
        for src_svc, dst_svc in self._service_edges():
            rng = self._streams.get(f"workload.http.edge.{src_svc}.{dst_svc}")
            rate = self._source.rate_per_ns("http_request", src_svc) * 0.5
            pods = self._pods_by_svc.get(src_svc, [])
            for t in self._poisson_times(start, end, rate, rng):
                pod_uid = self._pick_pod(pods, t)
                if pod_uid is None:
                    continue
                params = self._source.sample_parameters(
                    "http_request", src_svc, rng,
                    {"target_service": dst_svc},
                )
                if GATEWAY_INTERNAL_LISTENER in self._flags:
                    params.update(self._internal_call(src_svc, dst_svc))
                acts.append(Activity(
                    time_ns=t, kind="http_request",
                    actor_uid=pod_uid, actor_type="Pod",
                    target_uid=dst_svc, target_type="Service",
                    parameters=params,
                ))

        # --- DB queries: connect_internal from pods to database infra ---
        db_uid = infra["database"].uid if "database" in infra else "database"
        for svc in svcs:
            rng = self._streams.get(f"workload.db.{svc}")
            rate = self._source.rate_per_ns("connect_internal", svc) * 2.0
            pods = self._pods_by_svc.get(svc, [])
            for t in self._poisson_times(start, end, rate, rng):
                pod_uid = self._pick_pod(pods, t)
                if pod_uid is None:
                    continue
                acts.append(Activity(
                    time_ns=t, kind="connect_internal",
                    actor_uid=pod_uid, actor_type="Pod",
                    target_uid=db_uid, target_type="InfraService",
                    parameters={"protocol": "tcp", "target_port": 5432},
                ))

        # --- Broker traffic: connect_internal from pods to broker infra ---
        broker_uid = infra["broker"].uid if "broker" in infra else "broker"
        for svc in svcs:
            rng = self._streams.get(f"workload.broker.{svc}")
            rate = self._source.rate_per_ns("connect_internal", svc)
            pods = self._pods_by_svc.get(svc, [])
            for t in self._poisson_times(start, end, rate, rng):
                pod_uid = self._pick_pod(pods, t)
                if pod_uid is None:
                    continue
                acts.append(Activity(
                    time_ns=t, kind="connect_internal",
                    actor_uid=pod_uid, actor_type="Pod",
                    target_uid=broker_uid, target_type="InfraService",
                    parameters={"protocol": "tcp", "target_port": 9092},
                ))

        return acts

    def _gen_process_activity(self) -> List[Activity]:
        """Process starts, file reads/writes, and connects per container."""
        acts: List[Activity] = []
        start = self._world.run_start_ns
        end = self._end_ns()

        for ctr in self._world.containers:
            ctr_start = max(start, ctr.valid_from)
            ctr_end = min(end, ctr.valid_to)
            if ctr_start >= ctr_end:
                continue
            procs = self._procs_by_ctr.get(ctr.uid, [])
            if not procs:
                continue

            # Guaranteed startup: one process_exec when the first process
            # in this container launches (models the app-server start).
            first_vf, _first_vt, first_pk = procs[0]
            startup_t = first_vf + 1_000_000  # 1 ms after process valid_from
            if ctr_start <= startup_t < ctr_end:
                acts.append(Activity(
                    time_ns=startup_t, kind="process_exec",
                    actor_uid=first_pk, actor_type="Process",
                    target_uid="/app/server", target_type="File",
                    parameters={"executable": "/app/server",
                                "argv": ["/app/server"], "source": "startup"},
                ))

            # Additional Poisson-sampled process spawns (in-container forks)
            rng_exec = self._streams.get(f"workload.proc.exec.{ctr.uid}")
            for t in self._poisson_times(
                ctr_start, ctr_end,
                self._source.rate_per_ns("process_exec", ctr.uid),
                rng_exec,
            ):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                params = self._source.sample_parameters(
                    "process_exec", ctr.uid, rng_exec, {}
                )
                acts.append(Activity(
                    time_ns=t, kind="process_exec",
                    actor_uid=pk, actor_type="Process",
                    target_uid=params.get("executable", "/app/server"),
                    target_type="File",
                    parameters=params,
                ))

            # Token file reads (projected SA token, per app process)
            rng_tok = self._streams.get(f"workload.file.tok.{ctr.uid}")
            for t in self._poisson_times(
                ctr_start, ctr_end,
                self._source.rate_per_ns("read_token_file", ctr.uid),
                rng_tok,
            ):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                tok_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
                acts.append(Activity(
                    time_ns=t, kind="read_token_file",
                    actor_uid=pk, actor_type="Process",
                    target_uid=tok_path, target_type="File",
                    parameters={"file_path": tok_path},
                ))

            # File writes (application data)
            rng_fw = self._streams.get(f"workload.file.write.{ctr.uid}")
            for t in self._poisson_times(
                ctr_start, ctr_end,
                self._source.rate_per_ns("file_write", ctr.uid),
                rng_fw,
            ):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                out_path = f"/app/data/{ctr.uid[:6]}.out"
                acts.append(Activity(
                    time_ns=t, kind="file_write",
                    actor_uid=pk, actor_type="Process",
                    target_uid=out_path, target_type="File",
                    parameters={"file_path": out_path, "create_if_missing": True},
                ))

            # Intra-cluster connects from processes
            rng_net = self._streams.get(f"workload.net.{ctr.uid}")
            # Pick a neighbour service as target for process-level connects
            pod = next(
                (p for p in self._world.pods if p.uid == ctr.pod_uid), None
            )
            if pod is not None:
                svcs = self._world.service_names
                i = svcs.index(pod.service_name) if pod.service_name in svcs else 0
                neighbour = svcs[(i + 1) % len(svcs)] if len(svcs) > 1 else svcs[0]
            else:
                neighbour = "svc-01"
            for t in self._poisson_times(
                ctr_start, ctr_end,
                self._source.rate_per_ns("connect_internal", ctr.uid),
                rng_net,
            ):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                acts.append(Activity(
                    time_ns=t, kind="connect_internal",
                    actor_uid=pk, actor_type="Process",
                    target_uid=neighbour, target_type="Service",
                    parameters={"protocol": "tcp", "target_port": 8080},
                ))

        return acts

    # Benign external endpoints (documentation ranges, as the scenarios use),
    # so the remote range does not separate benign from attack transfers.
    _EGRESS_ENDPOINTS = (
        "203.0.113.10", "203.0.113.25", "203.0.113.77",
        "198.51.100.20", "198.51.100.44", "192.0.2.80",
    )

    def _gen_external_egress(self) -> List[Activity]:
        """Benign outbound transfers: a connect, then a flow with bytes out.

        Without them only attack scenarios would produce net.flow_bytes and
        path-flow records, so the presence of those sources would mark a run.
        """
        acts: List[Activity] = []
        start = self._world.run_start_ns
        end = self._end_ns()
        pods = {p.uid: p for p in self._world.pods}
        for ctr in self._world.containers:
            ctr_start = max(start, ctr.valid_from)
            ctr_end = min(end, ctr.valid_to)
            procs = self._procs_by_ctr.get(ctr.uid, [])
            pod = pods.get(ctr.pod_uid)
            if ctr_start >= ctr_end or not procs or pod is None:
                continue
            src_ip = pod.pod_ips[0] if pod.pod_ips else ""
            rng = self._streams.get(f"workload.egress.{ctr.uid}")
            for t in self._poisson_times(
                ctr_start, ctr_end,
                self._source.rate_per_ns("external_egress", ctr.uid),
                rng,
            ):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                remote = self._EGRESS_ENDPOINTS[int(rng.integers(len(self._EGRESS_ENDPOINTS)))]
                port = 443
                src_port = int(rng.integers(32768, 61000))
                acts.append(Activity(
                    time_ns=t, kind="connect_external",
                    actor_uid=pk, actor_type="Process",
                    target_uid=remote, target_type="Endpoint",
                    parameters={"remote_ip": remote, "remote_port": port,
                                "local_ip": src_ip, "local_port": src_port,
                                "protocol": "tcp"},
                ))
                t_xfer = t + int(rng.integers(500_000_000, 3_000_000_000))
                if t_xfer >= ctr_end:
                    continue
                bytes_out = int(rng.lognormal(mean=9.0, sigma=1.0))  # ~8 KB median
                acts.append(Activity(
                    time_ns=t_xfer, kind="egress_transfer",
                    actor_uid=pk, actor_type="Process",
                    target_uid=remote, target_type="Endpoint",
                    parameters={"remote_ip": remote, "remote_port": port,
                                "dst_ip": remote, "dst_port": port,
                                "src_ip": src_ip, "src_port": src_port,
                                "bytes_out": bytes_out,
                                "bytes_in": int(bytes_out * rng.uniform(0.1, 0.5)),
                                "protocol": "tcp"},
                ))
        return acts

    def _gen_control_plane(self) -> List[Activity]:
        """Controller/operator API calls, kubelet token refresh, admissions."""
        acts: List[Activity] = []
        start = self._world.run_start_ns
        end = self._end_ns()

        # --- Controller and operator API calls (per ServiceAccount) ---
        for sa in self._world.service_accounts:
            rng = self._streams.get(f"workload.api.{sa.uid}")
            rate = self._source.rate_per_ns("api_request", sa.name)
            ns = sa.namespace
            for t in self._poisson_times(start, end, rate, rng):
                params = self._source.sample_parameters(
                    "api_request", sa.name, rng, {"namespace": ns}
                )
                resource = params.get("resource", "pods")
                verb = params.get("verb", "list")
                acts.append(Activity(
                    time_ns=t, kind="api_request",
                    actor_uid=sa.uid, actor_type="ServiceAccount",
                    target_uid=f"{verb}:{resource}",
                    target_type="APIResource",
                    parameters=params,
                ))

        # --- Kubelet token refresh reads (per container, ~every 10 min) ---
        # The container's own app process reads the projected token; the
        # kubelet triggers the refresh by updating the projected volume.
        kubelet_rate = 1.0 / (600.0 * 1_000_000_000.0)  # 10-min interval in ns
        for ctr in self._world.containers:
            ctr_start = max(start, ctr.valid_from)
            ctr_end = min(end, ctr.valid_to)
            if ctr_start >= ctr_end:
                continue
            procs = self._procs_by_ctr.get(ctr.uid, [])
            if not procs:
                continue
            rng = self._streams.get(f"workload.kubelet.tok.{ctr.uid}")
            tok_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            for t in self._poisson_times(ctr_start, ctr_end, kubelet_rate, rng):
                pk = self._pick_process(procs, t)
                if pk is None:
                    continue
                acts.append(Activity(
                    time_ns=t, kind="read_token_file",
                    actor_uid=pk, actor_type="Process",
                    target_uid=tok_path, target_type="File",
                    parameters={"file_path": tok_path, "reader": "kubelet_refresh"},
                ))

        # --- Admissions for churn-created (generation > 0) Pods ---
        infra = self._world.infra
        admission_uid = (
            infra["admission_controller"].uid
            if "admission_controller" in infra
            else "admission_controller"
        )
        for pod in self._world.pods:
            if pod.generation == 0:
                continue
            t = pod.valid_from + 1_000_000  # 1 ms after Pod creation
            if t >= end:
                continue
            rng = self._streams.get(f"workload.admit.{pod.uid}")
            params = self._source.sample_parameters(
                "admit_pod", pod.service_name, rng,
                {"pod_name": pod.name, "namespace": pod.namespace},
            )
            acts.append(Activity(
                time_ns=t, kind="admit_pod",
                actor_uid=admission_uid, actor_type="InfraService",
                target_uid=pod.uid, target_type="Pod",
                parameters=params,
            ))

        # --- Admission reviews of live Pods (UPDATE patches), per service ---
        for svc in self._world.service_names:
            pods = [p for p in self._world.pods if p.service_name == svc]
            rng = self._streams.get(f"workload.admit.update.{svc}")
            for t in self._poisson_times(
                start, end, self._source.rate_per_ns("admit_pod", svc), rng,
            ):
                alive = [p for p in pods if p.valid_from <= t < p.valid_to]
                if not alive:
                    continue
                pod = alive[int(rng.integers(len(alive)))]
                params = self._source.sample_parameters(
                    "admit_pod", svc, rng,
                    {"pod_name": pod.name, "namespace": pod.namespace},
                )
                params["operation"] = "UPDATE"
                acts.append(Activity(
                    time_ns=t, kind="admit_pod",
                    actor_uid=admission_uid, actor_type="InfraService",
                    target_uid=pod.uid, target_type="Pod",
                    parameters=params,
                ))

        return acts

    def _gen_scheduled_jobs(self) -> List[Activity]:
        """Periodic process_exec events modelling scheduled / cron jobs."""
        acts: List[Activity] = []
        start = self._world.run_start_ns
        end = self._end_ns()

        for svc in self._world.service_names:
            rng = self._streams.get(f"workload.job.{svc}")
            rate = self._source.rate_per_ns("scheduled_job", svc)
            pods = self._pods_by_svc.get(svc, [])
            for t in self._poisson_times(start, end, rate, rng):
                pod_uid = self._pick_pod(pods, t)
                if pod_uid is None:
                    continue
                acts.append(Activity(
                    time_ns=t, kind="process_exec",
                    actor_uid=pod_uid, actor_type="Pod",
                    target_uid="/app/cron-job",
                    target_type="File",
                    parameters={
                        "executable": "/app/cron-job",
                        "argv": ["/app/cron-job", "--run"],
                        "source": "cronjob",
                    },
                ))

        return acts
