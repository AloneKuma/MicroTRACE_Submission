"""Observed edges: one extractor per NormalizedEvent record type
(tgs-contract.md section 3, "Observed edges").

Source records already name who acted on what in their typed fields, so each
extractor reads the actor and object fields and copies the record's own
label. No edge is built from entities that merely appear together, and a node
is never given a UID its record does not carry.

A node is NodeRef(type, uid, namespace, name, status). Status is the identity
status of the contract: resolved (instance UID, high strength), weak
(collision-prone instance key), class_only (namespace and name only).
`unresolved` is decided per event in apply.py from the event's own gaps.
"""
from dataclasses import dataclass, field

import mtcodec
from microtrace.v0 import common_pb2, context_pb2, ebpf_pb2, kyverno_pb2

RESOLVED, WEAK, CLASS_ONLY, UNRESOLVED = "resolved", "weak", "class_only", "unresolved"
RANK = {RESOLVED: 0, WEAK: 1, CLASS_ONLY: 2, UNRESOLVED: 3}
ET = common_pb2.EntityType
SC = common_pb2.StrengthClass

# Kubernetes resources with their own entity type; any other API object is
# K8S_OBJECT (resource kept in the edge attributes).
RESOURCE_TYPE = {"pods": "POD", "nodes": "NODE", "namespaces": "NAMESPACE", "serviceaccounts": "SERVICE_ACCOUNT",
                 "roles": "RBAC_OBJECT", "rolebindings": "RBAC_OBJECT", "clusterroles": "RBAC_OBJECT",
                 "clusterrolebindings": "RBAC_OBJECT"}
KIND_TYPE = {"Pod": "POD", "Node": "NODE", "Namespace": "NAMESPACE", "ServiceAccount": "SERVICE_ACCOUNT",
             "Role": "RBAC_OBJECT", "RoleBinding": "RBAC_OBJECT", "ClusterRole": "RBAC_OBJECT",
             "ClusterRoleBinding": "RBAC_OBJECT", "User": "USER", "Group": "GROUP"}
# eBPF details that are coverage or control records, or carry no object.
NO_EDGE_DETAILS = {"privilege", "loss", "clock", "projected_index", "syscall", None}


@dataclass(frozen=True)
class NodeRef:
    type: str
    uid: str = ""
    namespace: str = ""
    name: str = ""
    status: str = CLASS_ONLY

    @property
    def id(self):
        """(type, uid) when a UID is present, else the class key (type,
        namespace, name) (tgs-contract.md section 3). On a UID node, name and
        namespace are labels, so sources that name one instance differently
        still reach one node."""
        if self.uid:
            key = {"node_type": self.type, "uid": self.uid, "namespace": "", "name": ""}
        else:
            key = {"node_type": self.type, "uid": "", "namespace": self.namespace, "name": self.name}
        return mtcodec.logical_id("graph_node", key)


@dataclass
class Observation:
    actor: NodeRef
    obj: NodeRef
    label: str
    attrs: dict = field(default_factory=dict)


def node(type_, uid="", namespace="", name="", status=None):
    """A NodeRef; status defaults to resolved with a UID, class_only without."""
    return NodeRef(type_, uid or "", namespace or "", name or "", status or (RESOLVED if uid else CLASS_ONLY))


def from_entity(e):
    """common_pb2.EntityRef -> NodeRef (findings name their entities this way)."""
    uid = e.uid if e.HasField("uid") else ""
    if not uid:
        status = CLASS_ONLY
    elif e.strength_class == SC.Value("STRENGTH_MEDIUM"):
        status = WEAK
    else:
        status = RESOLVED
    return node(ET.Name(e.type), uid, e.namespace, e.name, status)


def finding_node(fid):
    """A finding as a graph node (resolved: the finding ID is an instance ID).
    The ID depends on the finding ID only, so the finding record and the
    witnesses naming it reach one node; the type stays in `findings`."""
    return node("FINDING", fid)


def weakest(*statuses):
    return max(statuses, key=RANK.__getitem__)


# --- eBPF ------------------------------------------------------------------------------
def _process(k):
    if not k.node_id or not (k.tgid or k.start_time_ns):
        return None
    return node("PROCESS", f"{k.node_id}/{k.boot_id}/{k.tgid}/{k.start_time_ns}")


def _file(rec, f):
    path = f.resolved_path or f.path_as_opened
    if f.dev or f.ino:     # inode identity without a version index: collision-prone (STRENGTH_MEDIUM)
        return node("FILE_OBJECT", f"{rec.node_id}:{f.dev}:{f.ino}", name=path, status=WEAK)
    return node("FILE_OBJECT", name=path) if path else None


def endpoint(ep):
    """An address is not an instance: always class_only."""
    if ep.unix_path:
        return node("NETWORK_ENDPOINT", name=f"unix:{ep.unix_path}")
    if not ep.ip:
        return None
    return node("NETWORK_ENDPOINT", name=f"{ep.ip}:{ep.port}/{ep.protocol}")


def _node_host(rec):
    return node("NODE", name=rec.node_id) if rec.node_id else None


def ebpf(ne):
    rec = ne.ebpf
    detail = rec.WhichOneof("detail")
    if detail in NO_EDGE_DETAILS:
        return []
    actor = _process(rec.process)
    attrs = {"result": ebpf_pb2.OpResult.Name(rec.result)} if rec.result else {}
    if detail == "exec":
        actor, obj = _process(rec.parent), actor
        attrs["filename"] = rec.exec.filename
    elif detail in ("file_access", "file_mutation"):
        d = getattr(rec, detail)
        obj = _file(rec, d.file)
        if d.bytes:
            attrs["bytes"] = d.bytes
    elif detail == "socket":
        obj = endpoint(rec.socket.remote)
        attrs["op"] = ebpf_pb2.SocketOp.Name(rec.socket.op)
    elif detail == "flow_counter":
        obj = endpoint(rec.flow_counter.remote)
        attrs.update(bytes_out=rec.flow_counter.bytes_out, bytes_in=rec.flow_counter.bytes_in)
    elif detail == "ptrace":
        obj = _process(rec.ptrace.target)
    elif detail in ("namespace_change", "bpf"):
        obj = _node_host(rec)
    else:
        return []
    if actor is None or obj is None:
        return []
    return [Observation(actor, obj, rec.event_family or detail, attrs)]


# --- audit -----------------------------------------------------------------------------
def principal(ne):
    a = ne.audit
    d = ne.audit_derived if ne.HasField("audit_derived") else None
    if (d is not None and d.authentication_failed) or not a.user.username:
        src = (d.observed_source if d is not None else "") or (a.source_ips[0] if a.source_ips else "")
        return node("UNAUTHENTICATED_SOURCE", name=src) if src else None
    name = a.user.username
    if name.startswith("system:serviceaccount:"):
        parts = name.split(":")
        if len(parts) == 4:
            return node("SERVICE_ACCOUNT", a.user.uid, parts[2], parts[3])
    return node("USER", a.user.uid, name=name)


def audit(ne):
    a = ne.audit
    actor = principal(ne)
    o = a.object_ref
    if actor is None or not o.resource:
        return []
    obj = node(RESOURCE_TYPE.get(o.resource, "K8S_OBJECT"), o.uid, o.namespace, o.name or f"{o.resource}/*")
    label = a.verb + (f"/{o.subresource}" if o.subresource else "")
    return [Observation(actor, obj, label, {"resource": o.resource, "stage": a.stage})]


# --- gateway, database, path flow ------------------------------------------------------
def gateway(ne):
    g = ne.gateway
    out = []
    req = node("HTTP_REQUEST", g.request_id, name=f"{g.method} {g.path or g.route}") if g.request_id else None
    peer = node("NETWORK_ENDPOINT", name=g.peer_ip) if g.peer_ip else None
    if peer and req:
        out.append(Observation(peer, req, g.method, {"status": g.response_status}))
    if req and g.route:
        out.append(Observation(req, node("K8S_OBJECT", name=g.route), "routed_to", {"authority": g.authority}))
    return out


def db_audit(ne):
    d = ne.db_audit
    actor = endpoint(d.client)
    if actor is None or not d.object_name:
        return []
    obj = node("DB_OBJECT", name=f"{d.database}.{d.object_name}" if d.database else d.object_name)
    attrs = {"succeeded": d.succeeded, "db_user": d.db_user}
    if d.HasField("bytes_returned"):
        attrs["bytes_returned"] = d.bytes_returned
    return [Observation(actor, obj, d.statement_class or "query", attrs)]


def path_flow(ne):
    f = ne.path_flow
    src, dst = endpoint(f.src), endpoint(f.dst)
    if src is None or dst is None:
        return []
    return [Observation(src, dst, "flow", {"octets": f.octets, "packets": f.packets})]


# --- admission and context -------------------------------------------------------------
def kyverno(ne):
    k = ne.kyverno
    res = node(KIND_TYPE.get(k.resource_kind, "K8S_OBJECT"), k.resource_uid if k.HasField("resource_uid") else "",
               k.namespace, k.resource_name)
    verdict = "admission:" + kyverno_pb2.AdmissionVerdict.Name(k.verdict)
    attrs = {"policy": k.policy, "rule": k.rule, "dry_run": k.dry_run}
    # An image digest is instance-scoped but collision-prone (STRENGTH_MEDIUM).
    return [Observation(res, node("IMAGE", dg, status=WEAK), verdict, attrs) for dg in k.image_digests]


def context(ne):
    o = ne.context
    s = o.WhichOneof("summary")
    attrs = {"change_type": context_pb2.ChangeType.Name(o.change_type)}
    out = []
    if s == "pod":
        pod = node("POD", o.uid, o.namespace, o.name)
        p = o.pod
        if p.node_name:
            out.append(Observation(pod, node("NODE", name=p.node_name), "runs_on", attrs))
        if p.service_account:
            out.append(Observation(pod, node("SERVICE_ACCOUNT", namespace=o.namespace, name=p.service_account),
                                   "runs_as", attrs))
        for c in p.containers:
            if c.image_id:
                out.append(Observation(pod, node("IMAGE", c.image_id, status=WEAK), "uses_image", attrs))
        for own in p.owners:
            out.append(Observation(pod, from_entity(own), "owned_by", attrs))
    elif s == "rbac" and o.rbac.role_ref_name:
        r = o.rbac
        role = node("RBAC_OBJECT", namespace=o.namespace if r.role_ref_kind == "Role" else "", name=r.role_ref_name)
        for sub in r.subjects:
            subj = node(KIND_TYPE.get(sub.kind, "K8S_OBJECT"), namespace=sub.namespace, name=sub.name)
            out.append(Observation(subj, role, "bound_to", dict(attrs, binding=o.name)))
    return out


EXTRACTORS = {"ebpf": ebpf, "audit": audit, "gateway": gateway, "db_audit": db_audit,
              "path_flow": path_flow, "kyverno": kyverno, "context": context}


def observations(ne):
    """[Observation] for one NormalizedEvent; [] when its record names no
    actor and object."""
    kind = ne.WhichOneof("record")
    fn = EXTRACTORS.get(kind)
    return fn(ne) if fn else []
