"""Builders for agent test streams: NormalizedEvent envelopes, context and
completeness records, routed to agent topics as the restreamer does.

Every UID and time is invented for tests. Times are seconds after T0.
"""
import itertools
import zlib

from google.protobuf import timestamp_pb2

from mtcore.agents import routing
from mtcore.agents.events import Ev
from microtrace.v0 import (common_pb2, context_pb2, dataset_pb2, ebpf_pb2, envelope_pb2,
                           gateway_pb2, kyverno_pb2, normalized_pb2, offnode_pb2, stream_pb2)

T0 = 1_791_460_800  # 2026-10-08T12:00:00Z
NS = 1_000_000_000
NODE, BOOT = "node-1", "boot-1"   # read at call time, so a test may give each run its own node
_seq = itertools.count(1)
_ids = itertools.count(1)


def ts(sec):
    t = timestamp_pb2.Timestamp()
    t.FromNanoseconds(int((T0 + sec) * NS))
    return t


def ns(sec):
    return int((T0 + sec) * NS)


def _envelope(ne, run_split="PILOT"):
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="generator",
                                kind=envelope_pb2.RecordKind.Value("NORMALIZED_EVENT"),
                                logical_id=ne.event_id, source=ne.source)
    env.run.run_id = "run-test"
    env.run.split = dataset_pb2.DataSplit.Value(run_split)
    env.normalized_event.CopyFrom(ne)
    return env


def _ne(source, t, event_id=None, unc_ns=1000, entities=(), gaps=(), action_id=None):
    ne = normalized_pb2.NormalizedEvent(event_id=event_id or f"ev-{next(_ids):05d}",
                                        source=common_pb2.Source.Value(source))
    ne.time.event_time.CopyFrom(ts(t))
    ne.time.clock_uncertainty_ns = unc_ns
    ne.evidence_ref.archive_id, ne.evidence_ref.object_key = "test-archive", f"obj/{ne.event_id}"
    for etype, name in entities:
        ne.entities.add(type=common_pb2.EntityType.Value(etype), name=name,
                        strength_class=common_pb2.StrengthClass.Value("STRENGTH_MEDIUM"))
    for reason in gaps:
        ne.completeness.gaps.add(reason=common_pb2.GapReason.Value(reason), scope="test")
    if action_id:
        ne.action_id = action_id
    return ne


# --- gateway ----------------------------------------------------------------
def gateway(t, request_id="req-1", matches=(), indicators=(), status=200, truncated=False,
            loss=False, origin="SENSOR"):
    ne = _ne("GATEWAY", t)
    g = ne.gateway
    g.request_id, g.response_status, g.body_truncated, g.observer_loss = request_id, status, truncated, loss
    g.request_id_origin = common_pb2.KeyOrigin.Value(origin)
    for pid, loc in matches:
        g.matches.add(pattern_id=pid, pattern_set_version="P_A-test", location=gateway_pb2.MatchLocation.Value(loc))
    for ind in indicators:
        g.response_indicators.add(indicator_id=ind, indicator_set_version="I_A2-test")
    return _envelope(ne)


# --- audit ------------------------------------------------------------------
def audit(t, verb="get", resource="pods", group="", namespace="shop", name="", code=200,
          principal="system:serviceaccount:shop:checkout", stage="ResponseComplete", audit_id=None,
          subresource="", request_uri="", observed_source="10.0.0.5", failed=False, uid="",
          resource_version="", used_jti=None, bound_pod=None, caller_routes=None, target_pod=None,
          user_agent="kubectl/v1.35"):
    ne = _ne("AUDIT", t)
    a = ne.audit
    a.audit_id = audit_id or f"aud-{next(_ids):05d}"
    a.stage, a.verb, a.response_code, a.user_agent = stage, verb, code, user_agent
    a.request_uri = request_uri
    a.source_ips.append(observed_source)
    o = a.object_ref
    o.api_group, o.resource, o.subresource, o.namespace, o.name = group, resource, subresource, namespace, name
    o.uid, o.resource_version = uid, resource_version
    a.request_received_timestamp.CopyFrom(ts(t))
    a.stage_timestamp.CopyFrom(ts(t))
    ad = ne.audit_derived
    ad.observed_source, ad.authentication_failed = observed_source, failed
    if principal and not failed:
        ad.principal.type = common_pb2.EntityType.Value("SERVICE_ACCOUNT" if principal.startswith("system:serviceaccount") else "USER")
        ad.principal.name = principal
        ad.principal.strength_class = common_pb2.StrengthClass.Value("STRENGTH_HIGH")
        a.user.username = principal
    if used_jti:
        ad.used_credential_id = used_jti
    if bound_pod:
        ad.bound_pod_uid = bound_pod
    if caller_routes:
        if caller_routes[0]:
            ad.attributed_caller_pod_uid = caller_routes[0]
        if caller_routes[1]:
            ad.peer_caller_pod_uid = caller_routes[1]
    if target_pod:
        ad.resolved_target_pod_uid = target_pod
    return _envelope(ne)


# --- eBPF -------------------------------------------------------------------
def ebpf(t, family, pod="pod-checkout-1", container="checkout", lineage="ln-1", node=None, boot=BOOT,
         seq=None, result="SUCCESS", reader="READER_POD_PROCESS", process=None, host_process=None,
         gaps=(), remote_class="", remote_pod=None, data_class="", token=None, host_ns_after=False,
         container_id="containerd://c1", tgid=None, parent_tgid=None, root_tgid=None):
    """tgid: the acting process (default: one process per lineage, which is
    also its lineage root); parent_tgid: its parent as the sensor reports it;
    root_tgid: the lineage root (default: the process itself)."""
    ents = []
    if process:
        ents.append(("PROCESS", process))
    if host_process:
        ents.append(("HOST_PROCESS", host_process))
    ne = _ne("EBPF", t, entities=ents, gaps=gaps)
    e = ne.ebpf
    e.node_id, e.boot_id, e.node_seq = node or NODE, boot, seq if seq is not None else next(_seq)
    e.event_family, e.result = family, ebpf_pb2.OpResult.Value(result)
    e.reader_class = ebpf_pb2.ReaderClass.Value(reader)
    e.container.container_id, e.container.container_name = container_id, container
    if tgid is None:
        tgid = 100 + zlib.crc32((lineage or "").encode()) % 30000
    for field_, value in (("process", tgid), ("parent", parent_tgid),
                          ("lineage_root", root_tgid if root_tgid is not None else tgid)):
        if value is not None:
            k = getattr(e, field_)
            k.node_id, k.boot_id, k.tgid, k.start_time_ns = e.node_id, boot, value, 1
    ed = ne.ebpf_derived
    if pod:
        ed.pod_uid = pod
    ed.container_name, ed.lineage_id = container, lineage
    ed.remote_class, ed.data_class, ed.host_namespace_after = remote_class, data_class, host_ns_after
    if remote_pod:
        ed.remote_pod_uid = remote_pod
    if token:
        ed.token_file.CopyFrom(token)
    return ne


def done(ne):
    return _envelope(ne)


def token_version(owner="pod-checkout-1", volume="kube-api-access-1", vdir="..2026_10_08_12_00_00.1"):
    return ebpf_pb2.ProjectedVersion(owner_pod_uid=owner, volume_name=volume, version_dir=vdir, file_name="token")


# --- Kyverno ------------------------------------------------------------------
def kyverno(t, pod="pod-checkout-1", container="checkout", verdict="FAIL", audit_mode=True, dry_run=False,
            resource_uid="pod-checkout-1"):
    ne = _ne("KYVERNO", t)
    k = ne.kyverno
    k.admission_request_uid, k.policy, k.rule = f"adm-{next(_ids)}", "verify-images", "check-signature"
    k.verdict, k.enforcement_audit_mode, k.dry_run = kyverno_pb2.AdmissionVerdict.Value(verdict), audit_mode, dry_run
    k.image_digests.append("sha256:" + "a" * 64)
    if resource_uid:
        k.resource_uid = resource_uid
    md = ne.admission_derived
    if pod:
        md.pod_uid = pod
    md.container_name = container
    return _envelope(ne)


# --- off-node -----------------------------------------------------------------
def db_read(t, source="10.1.0.7", klass="POD_ADDRESS", bytes_returned=1000, succeeded=True, statement="SELECT"):
    ne = _ne("DB_AUDIT", t)
    d = ne.db_audit
    d.record_id, d.statement_class, d.succeeded = f"db-{next(_ids)}", statement, succeeded
    d.client.ip = source
    if bytes_returned is not None:
        d.bytes_returned = bytes_returned
    d.server_time.CopyFrom(ts(t))
    od = ne.offnode_derived
    od.source_address, od.source_address_class = source, offnode_pb2.SourceAddressClass.Value(klass)
    od.pod_uid = "pod-orders-1"
    return _envelope(ne)


def path_flow(t, end, source="10.1.0.7", dst="198.51.100.9", port=443, octets=900, sampled=False,
              remote_class="external", host_match=""):
    ne = _ne("PATH_FLOW", t)
    f = ne.path_flow
    f.observer_id, f.exporter_flow_id = "obs-1", f"fl-{next(_ids)}"
    f.src.ip, f.dst.ip, f.dst.port, f.octets, f.sampled = source, dst, port, octets, sampled
    f.flow_start.CopyFrom(ts(t))
    f.flow_end.CopyFrom(ts(end))
    od = ne.offnode_derived
    od.source_address, od.remote_class, od.host_component_match = source, remote_class, host_match
    od.source_address_class = offnode_pb2.SourceAddressClass.Value("POD_ADDRESS")
    return _envelope(ne)


# --- context ------------------------------------------------------------------
def _ctx_env(o):
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="context-collector",
                                kind=envelope_pb2.RecordKind.Value("CONTEXT_OBSERVATION"),
                                source=common_pb2.Source.Value("CLUSTER_CONTEXT"),
                                logical_id=f"ctx-{o.uid}-{o.resource_version}-{o.change_type}")
    env.context_observation.CopyFrom(o)
    return ("context.cluster.v0", env)


def pod(t, uid="pod-checkout-1", owner="checkout", namespace="shop", containers=(("checkout", 0, "containerd://c1", -100),)):
    o = context_pb2.ObjectObservation(api_group="", kind="Pod", namespace=namespace, name=f"{owner}-x",
                                      uid=uid, resource_version=f"rv-{next(_ids)}",
                                      change_type=context_pb2.ChangeType.Value("ADDED"))
    o.observed_time.CopyFrom(ts(t))
    o.pod.owners.add(type=common_pb2.EntityType.Value("POD"), name=owner)
    for name, restarts, cid, started in containers:
        c = o.pod.containers.add(name=name, container_id=cid, restart_count=restarts)
        c.started_at.CopyFrom(ts(started))
    return _ctx_env(o)


def rbac_obj(t, kind, name, uid, namespace="", rules=(), subjects=(), role_ref=None, labels=None,
             selectors=(), rv="1", change="ADDED"):
    o = context_pb2.ObjectObservation(api_group="rbac.authorization.k8s.io", kind=kind, namespace=namespace,
                                      name=name, uid=uid, resource_version=rv,
                                      change_type=context_pb2.ChangeType.Value(change))
    o.observed_time.CopyFrom(ts(t))
    r = o.rbac
    for groups, resources, verbs, *names in rules:
        r.rules.add(api_groups=groups, resources=resources, verbs=verbs, resource_names=names[0] if names else [])
    for skind, sname, sns in subjects:
        r.subjects.add(kind=skind, name=sname, namespace=sns)
    if role_ref:
        r.role_ref_kind, r.role_ref_name = role_ref
    for k, v in (labels or {}).items():
        r.labels[k] = v
    r.aggregation_selectors.extend(selectors)
    return _ctx_env(o)


def watch_gap(start, end, group="rbac.authorization.k8s.io", resource="rolebindings"):
    g = context_pb2.WatchGap(api_group=group, resource=resource, reason=context_pb2.WatchGapReason.Value("GONE_410"))
    g.gap_start.CopyFrom(ts(start))
    g.gap_end.CopyFrom(ts(end))
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="context-collector",
                                kind=envelope_pb2.RecordKind.Value("CONTEXT_WATCH_GAP"))
    env.context_watch_gap.CopyFrom(g)
    return ("context.cluster.v0", env)


# --- completeness ---------------------------------------------------------------
def loss(start, end, source="EBPF", node=None, reason="DROPPED_BEFORE"):
    sc = stream_pb2.SourceCompleteness(source=common_pb2.Source.Value(source),
                                       scope=f"node={node or NODE}/boot={BOOT}/lane=NORMAL",
                                       status=stream_pb2.CompletenessStatus.Value("INCOMPLETE"))
    if start is not None:
        sc.interval_start.CopyFrom(ts(start))
    if end is not None:
        sc.interval_end.CopyFrom(ts(end))
    g = sc.gaps.add(reason=common_pb2.GapReason.Value(reason), scope="transport", detail="test loss")
    if start is not None:
        getattr(g, "from").CopyFrom(ts(start))
    if end is not None:
        g.to.CopyFrom(ts(end))
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="ingest-receiver",
                                kind=envelope_pb2.RecordKind.Value("SOURCE_COMPLETENESS"),
                                source=sc.source, logical_id=f"sc-{next(_ids)}")
    env.source_completeness.CopyFrom(sc)
    return ("source.completeness.v0", env)


# --- routing ------------------------------------------------------------------
def routed(env):
    """[(topic, env)] for every agent topic the restreamer would write env to."""
    return [(topic, env) for topic, key in routing.routes(Ev(env)) if key is not None]


def stream(*items):
    """Flatten envelopes (routed to agent topics) and (topic, env) records."""
    out = []
    for it in items:
        if isinstance(it, tuple):
            out.append(it)
        elif isinstance(it, list):
            out.extend(it)
        else:
            out.extend(routed(it))
    return out
