"""Helpers shared by the rule modules."""
import hashlib

from microtrace.v0 import common_pb2, ebpf_pb2

from mtcore.agents.engine import FindingSpec, Rule, abstain, fired, not_fired  # noqa: F401
from mtcore.agents.events import opt  # noqa: F401

SRC = common_pb2.Source
GATEWAY, AUDIT, EBPF, KYVERNO = (SRC.Value(n) for n in ("GATEWAY", "AUDIT", "EBPF", "KYVERNO"))
CONTEXT, DB_AUDIT, PATH_FLOW = (SRC.Value(n) for n in ("CLUSTER_CONTEXT", "DB_AUDIT", "PATH_FLOW"))
ET = common_pb2.EntityType
ST = common_pb2.StrengthClass
GR = common_pb2.GapReason
SUCCESS = ebpf_pb2.OpResult.Value("SUCCESS")
FAILURE = ebpf_pb2.OpResult.Value("FAILURE")
HOST_READER = ebpf_pb2.ReaderClass.Value("READER_HOST_PROCESS")
UNATTRIBUTED = ebpf_pb2.ReaderClass.Value("READER_UNATTRIBUTED")

EXTERNAL = "external"


def entity(etype, uid=None, name="", namespace="", strength="STRENGTH_HIGH"):
    e = common_pb2.EntityRef(type=ET.Value(etype), name=name or "", namespace=namespace or "",
                             strength_class=ST.Value(strength))
    if uid:
        e.uid = uid
    return e


def pod_entity(uid):
    return entity("POD", uid=uid)


def lineage_entity(lineage_id):
    return entity("PROCESS_LINEAGE", uid=lineage_id)


def process_name(ev):
    """Executable of the acting process, from the event's PROCESS/HOST_PROCESS entity."""
    for t in ("PROCESS", "HOST_PROCESS"):
        e = ev.entity(ET.Value(t))
        if e is not None and e.name:
            return e.name
    return None


def has_gap(ev, reason):
    return any(g.reason == GR.Value(reason) for g in ev.record_gaps())


def ok_2xx(code):
    return 200 <= code < 300


def unique_audits(evs, stages=None):
    """One event per audit ID (the last stage seen), optionally by stage."""
    by_id = {}
    for ev in sorted(evs, key=lambda e: (e.t, e.id)):
        a = ev.audit
        if a is None or (stages and a.stage not in stages):
            continue
        by_id[a.audit_id or ev.id] = ev
    return [by_id[k] for k in sorted(by_id)]


def argv_hash(argv):
    """argv_sha256 convention: SHA-256 hex of the arguments joined by NUL."""
    return hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest()


def endpoint(ep):
    return f"{ep.ip}:{ep.port}"
