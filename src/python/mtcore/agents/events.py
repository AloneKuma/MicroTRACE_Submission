"""Typed access to the records the agents consume.

Ev wraps one NormalizedEvent from an agent topic. Absent optional fields read
as None, never as an invented default, so a rule can abstain with
FIELD_ABSENT instead of treating silence as a value.
"""
from microtrace.v0 import common_pb2

R = common_pb2  # enum namespace shortcut for rules

NS = 1_000_000_000


def ts_ns(ts):
    """Timestamp -> Unix ns, or None when unset."""
    if ts is None or (ts.seconds == 0 and ts.nanos == 0):
        return None
    return ts.seconds * NS + ts.nanos


def opt(msg, field):
    """Value of an optional/message field, or None when not present."""
    return getattr(msg, field) if msg.HasField(field) else None


class Ev:
    """One normalized event as seen by an agent."""

    __slots__ = ("env", "ne", "topic", "partition", "offset", "_t")

    def __init__(self, env, topic="", partition=0, offset=0):
        self.env = env
        self.ne = env.normalized_event
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self._t = ts_ns(self.ne.time.event_time) if self.ne.HasField("time") else None

    # identity and time ------------------------------------------------
    @property
    def id(self):
        return self.ne.event_id or self.env.logical_id

    @property
    def logical_id(self):
        return self.env.logical_id or self.ne.event_id

    @property
    def t(self):
        return self._t

    @property
    def unc(self):
        return self.ne.time.clock_uncertainty_ns if self.ne.HasField("time") else 0

    @property
    def source(self):
        return self.ne.source or self.env.source

    @property
    def action_id(self):
        return opt(self.ne, "action_id")

    # typed record -----------------------------------------------------
    @property
    def kind(self):
        return self.ne.WhichOneof("record")

    @property
    def rec(self):
        k = self.kind
        return getattr(self.ne, k) if k else None

    @property
    def derived(self):
        k = self.ne.WhichOneof("derived")
        return getattr(self.ne, k) if k else None

    @property
    def ebpf(self):
        return self.ne.ebpf if self.kind == "ebpf" else None

    @property
    def audit(self):
        return self.ne.audit if self.kind == "audit" else None

    @property
    def gateway(self):
        return self.ne.gateway if self.kind == "gateway" else None

    @property
    def kyverno(self):
        return self.ne.kyverno if self.kind == "kyverno" else None

    @property
    def db(self):
        return self.ne.db_audit if self.kind == "db_audit" else None

    @property
    def flow(self):
        return self.ne.path_flow if self.kind == "path_flow" else None

    @property
    def ad(self):
        return self.ne.audit_derived if self.ne.WhichOneof("derived") == "audit_derived" else None

    @property
    def ed(self):
        return self.ne.ebpf_derived if self.ne.WhichOneof("derived") == "ebpf_derived" else None

    @property
    def md(self):
        return self.ne.admission_derived if self.ne.WhichOneof("derived") == "admission_derived" else None

    @property
    def od(self):
        return self.ne.offnode_derived if self.ne.WhichOneof("derived") == "offnode_derived" else None

    @property
    def family(self):
        return self.ne.ebpf.event_family if self.kind == "ebpf" else ""

    @property
    def detail(self):
        e = self.ebpf
        if e is None:
            return None
        k = e.WhichOneof("detail")
        return getattr(e, k) if k else None

    # eBPF ordering ----------------------------------------------------
    @property
    def node(self):
        e = self.ebpf
        return e.node_id if e is not None else None

    @property
    def node_order(self):
        """(node_id, boot_id, node_seq) for eBPF records (KAFKA-RESTREAM-ORDER)."""
        e = self.ebpf
        return (e.node_id, e.boot_id, e.node_seq) if e is not None else None

    # attribution helpers ---------------------------------------------
    @property
    def pod_uid(self):
        if self.ed is not None:
            return opt(self.ed, "pod_uid")
        if self.md is not None:
            return opt(self.md, "pod_uid")
        if self.od is not None:
            return opt(self.od, "pod_uid")
        return None

    @property
    def principal(self):
        """(kind, id) of the authenticated principal, or None."""
        ad = self.ad
        if ad is None or not ad.HasField("principal"):
            return None
        p = ad.principal
        pid = p.uid if p.HasField("uid") else p.name
        if not pid:
            return None
        return common_pb2.EntityType.Name(p.type), pid

    def entity(self, etype):
        """First entity of the given EntityType on the event, or None."""
        for e in self.ne.entities:
            if e.type == etype:
                return e
        return None

    def record_gaps(self):
        """Gaps declared on the record itself (envelope and event)."""
        return list(self.env.completeness.gaps) + list(self.ne.completeness.gaps)

    def __repr__(self):
        return f"Ev({self.id} {self.kind} t={self.t})"
