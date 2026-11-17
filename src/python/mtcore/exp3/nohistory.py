"""No-History identity variant of a run's readable stream (Exp. 3 ablation No-History).

evaluation-plan.md "Exp. 3 by fault": "No-History: a second identity variant built once by the
generator ('latest mapping' instead of history)"; D3_v28.tex: the ablation disables historical
workload identity resolution (eq. identity-resolution: time-indexed IP-to-Pod mappings).

In the generator the normalization tier resolves identities against the world's time-indexed
history (mtgen.history.WorldHistory.at, knowledge-time intervals; two holders at once give
Ambiguous and a JOIN_UNCERTAIN gap). The resolution sites are exactly:

  eBPF     ebpf_derived.remote_class / remote_pod_uid from the remote IP   (render/ebpf.py _wrap)
  audit    audit_derived.peer_caller_pod_uid from observed_source           (render/audit.py _derive_audit)
           audit_derived.resolved_target_pod_uid from object_ref name       (same)
  off-node offnode_derived.source_address_class / pod_uid from the source IP,
           path_flow remote_class from the destination IP                   (render/offnode.py)

Under the latest-mapping model each lookup key resolves, for the whole run, to its latest
mapping: the Pod with the latest observation start among all Pods that ever held the key
(ties: the larger UID). There is no time index, so no Ambiguous and no JOIN_UNCERTAIN gap,
and a key that has any Pod mapping always resolves. Everything else the generator does
(world, activities, which records exist, their times, lanes, IDs, order, truth) is unchanged.

This module produces exactly those records from the readable stream alone: the mappings come
from the run's own context.cluster.v0 Pod observations (the generator emits one ADDED
observation per world Pod, carrying pod_ips and name, at its history start; no profile drops
them), and each changed record is re-serialized the way mtgen.emit writes shipper lines.
Records that do not change are kept byte for byte. Truth and detector output are never read.
Deterministic: the same input gives the same bytes.
"""
import json

VARIANT = "no_history"
CONTEXT_TOPIC = "context.cluster.v0"
NORM_TOPIC = "norm.events.v0"
JOIN_SCOPES = {
    "EBPF": "field=remote_pod_uid",
    "AUDIT": "field=peer_caller_pod_uid",
    "DB_AUDIT": "field=pod_uid",
    "PATH_FLOW": "field=pod_uid",
}


def _ts_ns(s):
    from mtcore.exp3.base import ts_ns
    return ts_ns(s)


class LatestMap:
    """key -> latest Pod mapping, built from context.cluster.v0 Pod observations."""

    def __init__(self):
        self.ip = {}       # pod IP -> (observed ns, uid)
        self.name = {}     # pod name -> (observed ns, uid, namespace)

    def add_line(self, obj):
        if obj.get("topic") != CONTEXT_TOPIC:
            return
        o = (obj.get("envelope") or {}).get("context_observation")
        if not o or o.get("kind") != "Pod" or o.get("change_type") != "ADDED":
            return
        ips = (o.get("pod") or {}).get("pod_ips") or []
        uid = o.get("uid") or ""
        if not ips or not uid:
            return                  # a scenario-admitted bare Pod: not in the generator's Pod/PodIP history
        t = _ts_ns(o.get("observed_time"))
        ip = ips[0]                 # world.py keys PodIP history by pod_ips[0]
        if ip not in self.ip or (t, uid) > self.ip[ip]:
            self.ip[ip] = (t, uid)
        name = o.get("name") or ""
        if name and (name not in self.name or (t, uid) > self.name[name][:2]):
            self.name[name] = (t, uid, o.get("namespace") or "")

    def pod_of_ip(self, ip):
        v = self.ip.get(ip) if ip else None
        return v[1] if v else None

    def pod_of_name(self, name):
        v = self.name.get(name) if name else None
        return (v[1], v[2]) if v else None

    def summary(self):
        return {"pod_ips": len(self.ip), "pod_names": len(self.name)}


def build_map(paths, keep=None):
    """LatestMap over every line of the given node files (keep(obj) filters lines, e.g. no truth)."""
    m = LatestMap()
    for p in paths:
        with open(p, "rb") as fh:
            for raw in fh:
                if not raw.strip() or b'"context.cluster.v0"' not in raw:
                    continue
                obj = json.loads(raw)
                if keep is None or keep(obj):
                    m.add_line(obj)
    return m


def _drop_join_gap(ne, scope):
    from microtrace.v0 import common_pb2
    gaps = list(ne.completeness.gaps)
    kept = [g for g in gaps if not (g.reason == common_pb2.JOIN_UNCERTAIN and g.scope == scope)]
    if len(kept) != len(gaps):
        del ne.completeness.gaps[:]
        ne.completeness.gaps.extend(kept)


def _apply(ne, m):
    """Rewrite the identity fields of one NormalizedEvent in place; returns a new key component
    pair when the primary entity changed (off-node records), else None."""
    from microtrace.v0 import common_pb2, offnode_pb2
    src = ne.source
    if src == common_pb2.EBPF:
        d = ne.ebpf_derived
        if not ne.HasField("ebpf_derived") or not d.remote_class:
            return None                         # no remote IP was resolved for this record
        det = ne.ebpf.WhichOneof("detail")
        ip = ne.ebpf.socket.remote.ip if det == "socket" else (
            ne.ebpf.flow_counter.remote.ip if det == "flow_counter" else "")
        uid = m.pod_of_ip(ip)
        if uid is not None:
            d.remote_class = "cluster_pod"
            d.remote_pod_uid = uid
            _drop_join_gap(ne, JOIN_SCOPES["EBPF"])
        return None
    if src == common_pb2.AUDIT:
        if not ne.HasField("audit_derived"):
            return None
        d = ne.audit_derived
        ref = ne.audit.object_ref
        if ref.resource == "pods" and ref.namespace and ref.name:
            hit = m.pod_of_name(ref.name)
            if hit is not None and hit[1] == ref.namespace:
                d.resolved_target_pod_uid = hit[0]
            else:
                d.ClearField("resolved_target_pod_uid")
        uid = m.pod_of_ip(d.observed_source)
        if uid is not None:
            d.peer_caller_pod_uid = uid
            _drop_join_gap(ne, JOIN_SCOPES["AUDIT"])
        return None
    if src in (common_pb2.DB_AUDIT, common_pb2.PATH_FLOW):
        if not ne.HasField("offnode_derived"):
            return None
        d = ne.offnode_derived
        if src == common_pb2.PATH_FLOW and ne.path_flow.dst.ip and m.pod_of_ip(ne.path_flow.dst.ip) is not None:
            d.remote_class = "cluster_pod"
        uid = m.pod_of_ip(d.source_address)
        if uid is None:
            return None
        d.source_address_class = offnode_pb2.POD_ADDRESS
        d.pod_uid = uid
        _drop_join_gap(ne, JOIN_SCOPES["DB_AUDIT"])
        # mtgen.emit._set_entities: the primary entity of an off-node record is its Pod when
        # offnode_derived.pod_uid is set; the shipper key is that entity.
        secondary = [e for e in ne.entities[1:]]
        del ne.entities[:]
        ne.entities.add(type=common_pb2.POD, uid=uid, strength_class=common_pb2.STRENGTH_HIGH)
        ne.entities.extend(secondary)
        return ["POD", uid]
    return None


def transform_line(obj, m):
    """The no-history version of one shipper line (a dict), or None when it does not change."""
    if obj.get("topic") != NORM_TOPIC:
        return None
    env_d = obj.get("envelope") or {}
    ne_d = env_d.get("normalized_event")
    if not ne_d or ne_d.get("source") not in JOIN_SCOPES:
        return None
    from google.protobuf import json_format
    from microtrace.v0 import envelope_pb2
    env = json_format.ParseDict(env_d, envelope_pb2.Envelope())
    before = env.SerializeToString(deterministic=True)
    key = _apply(env.normalized_event, m)
    if env.SerializeToString(deterministic=True) == before:
        return None
    # As mtgen.emit._shipper_line: protojson with proto field names, keys sorted.
    new_env = json.loads(json.dumps(json_format.MessageToDict(env, preserving_proto_field_name=True),
                                    sort_keys=True))
    out = dict(obj)
    out["envelope"] = new_env
    if key is not None:
        out["key_components"] = key
    return out


def dump_line(obj):
    """One shipper line as mtgen.emit writes it."""
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
