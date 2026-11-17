"""Index keys (kappa_w) of a finding, per witness type, from its input events.

Each key is built only from sensor-originated fields (rulebook.v0.yaml
`witnesses`, key_origin), so a workload cannot forge a match. Every event
that carries a key is recorded with its role: a *source* event can open a
witness (the earlier end), a *target* event can close it. The direction comes
from the evidence (node_seq, connect -> accept), never from timestamps.

Types built here (build step 5b; the specified direct types):
- PROCESS_ANCESTRY: shared lineage on one node and boot; key (node, boot,
  lineage_id). Every eBPF event with a lineage is both source and target;
  node_seq orders them.
- HOST_TRANSITION: the same key; target events are those whose process is in
  the host namespaces after the operation (ebpf_derived.host_namespace_after).
- NETWORK_FLOW: the connection's client/server tuple. A CONNECT event (source)
  gives (local, remote), an ACCEPT event (target) gives (remote, local), so
  both ends of one TCP connection share the key across nodes. A Service
  address rewritten by DNAT does not match (gap2 NODE-SOCKET-FLOW).
- REQUEST_IDENTITY: the gateway's x-request-id (GatewayObservation.request_id).
  The key's origin is the observation's request_id_origin: SENSOR when the
  gateway minted the ID, WORKLOAD when it kept a client-supplied one (a
  non-edge listener). A minted ID is where the request starts, so a SENSOR
  event is both source and target; a WORKLOAD event carries an ID set
  upstream of it and is a target only. SensorKey (admit.py) refuses the
  WORKLOAD key unless No-Origin is on. One event is never both ends.

Enabling type (build step 5d), never a link:
- IMAGE_CLASS: an image digest. Source events are admission decisions
  (not dry-run) naming the digest; target events are eBPF events whose own
  evidence names the image (an IMAGE entity, e.g. a write to a file of the
  image) and whose container, per the Pod context known at the event, runs
  that digest. The context observation is the target-side evidence. An event
  that merely runs in the container (a token read) is not about the image.
"""
from dataclasses import dataclass, field

from microtrace.v0 import common_pb2, ebpf_pb2, witness_pb2

WT = witness_pb2.WitnessType
PROCESS_ANCESTRY, HOST_TRANSITION, NETWORK_FLOW = (WT.Value(n) for n in
                                                   ("PROCESS_ANCESTRY", "HOST_TRANSITION", "NETWORK_FLOW"))
IMAGE_CLASS, REQUEST_IDENTITY = WT.Value("IMAGE_CLASS"), WT.Value("REQUEST_IDENTITY")
# No-Witness ablation (A2): entity/time compatibility instead of a witness.
# It has no WitnessType of its own; the unspecified value stands for it.
ENTITY_COMPAT = WT.Value("WITNESS_TYPE_UNSPECIFIED")
IMAGE_ENTITY = common_pb2.EntityType.Value("IMAGE")
ENABLING = (IMAGE_CLASS,)
CONNECT, ACCEPT = ebpf_pb2.SocketOp.Value("CONNECT"), ebpf_pb2.SocketOp.Value("ACCEPT")
SENSOR, WORKLOAD = common_pb2.KeyOrigin.Value("SENSOR"), common_pb2.KeyOrigin.Value("WORKLOAD")
JOIN_KEY_TYPE = {PROCESS_ANCESTRY: "lineage_id", HOST_TRANSITION: "lineage_id", NETWORK_FLOW: "flow_tuple",
                 REQUEST_IDENTITY: "request_id", IMAGE_CLASS: "image_digest", ENTITY_COMPAT: "shared_entity"}
BUILT = (PROCESS_ANCESTRY, HOST_TRANSITION, NETWORK_FLOW, REQUEST_IDENTITY, IMAGE_CLASS)


@dataclass
class KeyEvents:
    join_key: str                                   # Witness.join_key
    sources: list = field(default_factory=list)     # Ev that can open a witness
    targets: list = field(default_factory=list)     # Ev that can close one
    context: dict = field(default_factory=dict)     # target event ID -> context observation ID (enabling)
    origin: int = SENSOR                            # common_pb2.KeyOrigin of the key's value


def _lineage_key(ev):
    e, ed = ev.ebpf, ev.ed
    if e is None or ed is None or not ed.lineage_id or not e.node_id or not e.boot_id:
        return None
    return (e.node_id, e.boot_id, ed.lineage_id)


def compat_keys(ev):
    """Entities an event names, for No-Witness: its Pod, principal, remote IP
    and process lineage (exp2-gaps-plan D-15)."""
    out = []
    if ev.pod_uid:
        out.append(("pod", ev.pod_uid))
    if ev.principal is not None:
        out.append(("principal",) + ev.principal)
    if ev.ebpf is not None and ev.ebpf.WhichOneof("detail") == "socket" and ev.ebpf.socket.remote.ip:
        out.append(("ip", ev.ebpf.socket.remote.ip))
    lk = _lineage_key(ev)
    if lk is not None:
        out.append(("lineage",) + lk)
    return out


def flow_key(ev):
    """(key, role) for a socket event, or (None, None)."""
    if ev.ebpf is None or ev.ebpf.WhichOneof("detail") != "socket":
        return None, None
    d = ev.ebpf.socket
    if not d.local.ip or not d.remote.ip:
        return None, None
    if d.op == CONNECT:
        client, server, role = d.local, d.remote, "source"
    elif d.op == ACCEPT:
        client, server, role = d.remote, d.local, "target"
    else:
        return None, None
    return (client.ip, client.port, server.ip, server.port, server.protocol or client.protocol), role


def loss_keys(ev):
    """Loss keys of an event (2026-11-17, scoped loss): the witness keys a lost copy of it could have
    fed or contradicted. Its process lineage (PROCESS_ANCESTRY, HOST_TRANSITION; a container change
    on a lineage is read from that lineage's own events) and its connection tuple (NETWORK_FLOW; a
    port-reuse contradiction is another CONNECT on the same tuple). An event with neither has no
    loss key: a gap made only of such records cannot hide a lineage or flow contradiction, but it
    still blocks every query that names no keys. Values never hold "/" or "|" (scope separators)."""
    out = set()
    lk = _lineage_key(ev)
    if lk is not None:
        out.add("L:{}:{}:{}".format(*lk))
    fk, _role = flow_key(ev)
    if fk is not None:
        out.add("F:{}:{}:{}:{}:{}".format(*fk))
    return frozenset(k for k in out if "/" not in k and "|" not in k)


def pair_loss_keys(wtype, src, tgt):
    """Loss keys a pair's coverage depends on: its own witness key (lineage or flow tuple)."""
    if wtype in (PROCESS_ANCESTRY, HOST_TRANSITION):
        lk = _lineage_key(src) or _lineage_key(tgt)
        return frozenset({"L:{}:{}:{}".format(*lk)}) if lk is not None else None
    if wtype == NETWORK_FLOW:
        fk, _ = flow_key(src)
        if fk is None:
            fk, _ = flow_key(tgt)
        return frozenset({"F:{}:{}:{}:{}:{}".format(*fk)}) if fk is not None else None
    return None


def request_key(ev):
    """(request ID, origin) for a gateway event, or (None, None)."""
    g = ev.gateway
    if g is None or not g.request_id:
        return None, None
    return g.request_id, (SENSOR if g.request_id_origin == SENSOR else WORKLOAD)


def finding_keys(events, enabled=BUILT, images=None):
    """{(witness type, key): KeyEvents} over a finding's input events (Ev).
    images: context.PodImages, needed for IMAGE_CLASS targets."""
    keys = {}

    def slot(w, k, join_key):
        if (w, k) not in keys:
            keys[(w, k)] = KeyEvents(join_key)
        return keys[(w, k)]

    for ev in events:
        lk = _lineage_key(ev)
        if lk is not None:
            if PROCESS_ANCESTRY in enabled:
                s = slot(PROCESS_ANCESTRY, lk, lk[2])
                s.sources.append(ev)
                s.targets.append(ev)
            if HOST_TRANSITION in enabled:
                s = slot(HOST_TRANSITION, lk, lk[2])
                s.sources.append(ev)
                if ev.ed.host_namespace_after:
                    s.targets.append(ev)
        if NETWORK_FLOW in enabled:
            fk, role = flow_key(ev)
            if fk is not None:
                s = slot(NETWORK_FLOW, fk, "{}:{}->{}:{}/{}".format(*fk))
                (s.sources if role == "source" else s.targets).append(ev)
        if REQUEST_IDENTITY in enabled:
            rk, origin = request_key(ev)
            if rk is not None:
                s = slot(REQUEST_IDENTITY, rk, rk)
                if origin == SENSOR:
                    s.sources.append(ev)
                else:
                    s.origin = WORKLOAD
                s.targets.append(ev)
        if ENTITY_COMPAT in enabled:
            for ck in compat_keys(ev):
                s = slot(ENTITY_COMPAT, ck, ":".join(map(str, ck)))
                s.sources.append(ev)
                s.targets.append(ev)
        if IMAGE_CLASS in enabled:
            k = ev.kyverno
            if k is not None and not k.dry_run:
                for digest in sorted(set(k.image_digests)):
                    slot(IMAGE_CLASS, digest, digest).sources.append(ev)
            elif ev.ebpf is not None and ev.pod_uid and ev.ed is not None and images is not None:
                hit = images.image_at(ev.pod_uid, ev.ed.container_name, ev.t)
                named = ev.entity(IMAGE_ENTITY)
                if hit is not None and named is not None and named.uid == hit[0]:
                    s = slot(IMAGE_CLASS, hit[0], hit[0])
                    s.targets.append(ev)
                    s.context[ev.id] = hit[1]
    return keys
