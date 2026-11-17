"""Apply one batch of Kafka records to a store in one transaction
(tgs-contract.md sections 2-3).

- norm.events.v0: the event row (full envelope), then one OBSERVED edge per
  extractor observation. Repeats merge into one edge (merge rules 1-7): the
  edge ID hashes (type, actor, object, label, identity status, trust), and
  every event keeps its own edge_events row.
- findings.v0: the finding row, a FINDING node and one `involves` edge per
  entity it names.
- witness.decisions.v0: one row per distinct witness record; a CONFIRMED
  witness is a CONFIRMED_WITNESS edge (never merged) that a later other status
  closes.
- incidents.v0: one row per distinct record (an open incident changes without
  a version bump), its aliases (incidents merged into it), its speculative
  paths as GO hypotheses (hypotheses.py), and a snapshot at the batch's
  applied offsets (snapshot.py). Its node epochs are kept; a new
  or earlier epoch moves the node's trusted events received at or after the
  onset to degraded edges (rule 3), so arrival order never changes the result.
- source.completeness.v0: one row per distinct record (coverage, 6c).
Heartbeats and other kinds are ignored. Every write is keyed by a stable ID,
so a record applied twice changes nothing. The failpoint tgs.mid_transaction
(Exp. 5) fires after a batch's rows are written, before its offsets and the
commit.
"""
import hashlib

from microtrace.v0 import common_pb2, incident_pb2, witness_pb2

from mtcore import failpoint
from mtcore.agents.events import ts_ns
from mtcore.tgs import EXTRACTOR_VERSION
from mtcore.tgs.extract import UNRESOLVED, finding_node, from_entity, observations, weakest
from mtcore.tgs.hypotheses import copy_speculative_paths
from mtcore.tgs.snapshot import record_snapshot

import mtcodec

OBSERVED, CONFIRMED_WITNESS = "OBSERVED", "CONFIRMED_WITNESS"
TRUSTED, DEGRADED = "trusted", "degraded"
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
JOIN_UNCERTAIN = common_pb2.GapReason.Value("JOIN_UNCERTAIN")


def edge_id(edge_type, src, dst, label, identity_status, trust):
    return mtcodec.logical_id("graph_edge", {"edge_type": edge_type, "source_node": src, "target_node": dst,
                                             "label": label, "identity_status": identity_status, "trust": trust})


def sha256(msg):
    return hashlib.sha256(msg.SerializeToString(deterministic=True)).hexdigest()


def apply_batch(store, records):
    """records: [(topic, partition, offset, Envelope)]. One transaction; on
    any error nothing of the batch (offsets included) is kept. Returns seq."""
    store.begin()
    try:
        seq = store.next_seq()
        last, incidents = {}, []
        for topic, partition, offset, env in records:
            applied = _apply(store, seq, topic, partition, offset, env)
            if applied is not None:
                incidents.append(applied)
            last[(topic, partition)] = max(last.get((topic, partition), -1), offset)
        # Exp. 5 part A: the batch's rows are written; offsets, snapshots and
        # the commit are not.
        failpoint.hit("tgs.mid_transaction", state=lambda: {"seq": seq, "records": len(records),
                                                            "applied": len(records)},
                      require=bool(records))
        for (topic, partition), offset in sorted(last.items()):
            store.set_offset(topic, partition, offset, seq)
        for incident_id, sha, version in incidents:      # snapshots at the batch's applied offsets
            record_snapshot(store, seq, incident_id, sha, version)
        store.log_apply(seq, len(records))
        store.commit()
    except BaseException:
        store.rollback()
        raise
    return seq


def _apply(store, seq, topic, partition, offset, env):
    kind = env.WhichOneof("payload")
    pos = {"topic": topic, "kafka_partition": partition, "kafka_offset": offset, "seq": seq}
    if kind == "normalized_event":
        _event(store, pos, env)
    elif kind == "finding":
        _finding(store, pos, env)
    elif kind == "witness":
        _witness(store, pos, env)
    elif kind == "incident":
        return _incident(store, pos, env)
    elif kind == "source_completeness":
        _completeness(store, pos, env)


# --- normalized events ---------------------------------------------------------------
def _event(store, pos, env):
    ne = env.normalized_event
    eid = ne.event_id or env.logical_id
    if not eid or store.has_event(eid):
        return
    t = ts_ns(ne.time.event_time) if ne.HasField("time") else None
    ing = ts_ns(ne.time.ingest_time) if ne.HasField("time") else None
    node_id, boot_id = (ne.ebpf.node_id, ne.ebpf.boot_id) if ne.HasField("ebpf") else ("", "")
    store.insert_event(dict(pos, event_id=eid, source=common_pb2.Source.Name(ne.source or env.source),
                            event_time=t, ingest_time=ing, node_id=node_id, boot_id=boot_id,
                            envelope=env.SerializeToString()))
    unresolved = any(g.reason == JOIN_UNCERTAIN for g in ne.completeness.gaps)
    trust = _trust(store, node_id, boot_id, ing)
    for ob in observations(ne):
        status = UNRESOLVED if unresolved else weakest(ob.actor.status, ob.obj.status)
        e = _merge_into(store, pos["seq"], ob.actor, ob.obj, ob.label, status, trust, ob.attrs)
        _count(e, t)
        store.upsert_edge(e)
        store.insert_edge_event(dict(pos, event_id=eid, edge_id=e["edge_id"], event_time=t, ingest_time=ing,
                                     node_id=node_id, boot_id=boot_id, attributes=ob.attrs))


def _trust(store, node_id, boot_id, ingest_ns):
    """Degraded when the event's node and boot have an epoch and the event was
    received off-node at or after its onset; an unknown receipt time counts
    as degraded (as in the GO, epochs.py)."""
    if not node_id:
        return TRUSTED
    ep = store.epoch(node_id, boot_id)
    if ep is None:
        return TRUSTED
    return DEGRADED if ingest_ns is None or ingest_ns >= ep["tau_n"] else TRUSTED


def _merge_into(store, seq, actor, obj, label, status, trust, attrs):
    """The edge this observation merges into, created if new (counts not yet
    raised). Nodes are written here."""
    for n in (actor, obj):
        _node(store, seq, n)
    eid = edge_id(OBSERVED, actor.id, obj.id, label, status, trust)
    e = store.edge(eid)
    if e is None:
        e = _new_edge(eid, OBSERVED, actor.id, obj.id, label, status, trust, seq, attrs)
    return e


def _new_edge(eid, edge_type, src, dst, label, status, trust, seq, attrs, **extra):
    row = {"edge_id": eid, "edge_type": edge_type, "src": src, "dst": dst, "label": label,
           "identity_status": status, "trust": trust, "count": 0, "first_t": None, "last_t": None,
           "witness_id": None, "finding_id": None, "extractor_version": EXTRACTOR_VERSION,
           "attributes": dict(attrs), "created_seq": seq, "closed_seq": None}
    row.update(extra)
    return row


def _count(e, t):
    e["count"] += 1
    e["closed_seq"] = None
    if t is not None:
        e["first_t"] = t if e["first_t"] is None else min(e["first_t"], t)
        e["last_t"] = t if e["last_t"] is None else max(e["last_t"], t)


def _node(store, seq, n):
    store.insert_node({"node_id": n.id, "node_type": n.type, "uid": n.uid, "namespace": n.namespace,
                       "name": n.name, "identity_status": n.status, "first_seq": seq})


# --- findings and witnesses ------------------------------------------------------------
def _finding(store, pos, env):
    f = env.finding
    if not f.finding_id or store.has_record("findings", f.finding_id):
        return
    store.insert_record("findings", dict(pos, finding_id=f.finding_id, finding_type=f.finding_type,
                                         event_start=ts_ns(f.event_start) if f.HasField("event_start") else None,
                                         agent_id=f.agent_id, envelope=env.SerializeToString()))
    fn = finding_node(f.finding_id)
    _node(store, pos["seq"], fn)
    start = ts_ns(f.event_start) if f.HasField("event_start") else None
    end = ts_ns(f.event_end) if f.HasField("event_end") else start
    for ent in f.entities:
        n = from_entity(ent)
        _node(store, pos["seq"], n)
        eid = edge_id(OBSERVED, fn.id, n.id, "involves", weakest(fn.status, n.status), "")
        if store.edge(eid) is not None:
            continue
        e = _new_edge(eid, OBSERVED, fn.id, n.id, "involves", weakest(fn.status, n.status), "", pos["seq"], {},
                      finding_id=f.finding_id, count=1, first_t=start, last_t=end)
        store.upsert_edge(e)


def _witness(store, pos, env):
    w = env.witness
    sha = sha256(w)
    if not w.witness_id or store.has_record("witnesses", w.witness_id, sha):
        return
    status = witness_pb2.WitnessStatus.Name(w.status)
    store.insert_record("witnesses", dict(
        pos, witness_id=w.witness_id, record_sha256=sha, status=status, source_finding_id=w.source_finding_id,
        target_finding_id=w.target_finding_id,
        source_event_time=ts_ns(w.source_event_time) if w.HasField("source_event_time") else None,
        envelope=env.SerializeToString()))
    src, dst = finding_node(w.source_finding_id), finding_node(w.target_finding_id)
    eid = edge_id(CONFIRMED_WITNESS, src.id, dst.id, w.witness_id, "", "")
    e = store.edge(eid)
    if w.status == CONFIRMED:
        for n in (src, dst):
            _node(store, pos["seq"], n)
        if e is None:
            s = ts_ns(w.source_event_time) if w.HasField("source_event_time") else None
            t = ts_ns(w.target_event_time) if w.HasField("target_event_time") else None
            e = _new_edge(eid, CONFIRMED_WITNESS, src.id, dst.id, w.witness_id, "", "", pos["seq"],
                          {"relationship_type": witness_pb2.WitnessType.Name(w.relationship_type)},
                          witness_id=w.witness_id, count=1, first_t=s, last_t=t)
        e["closed_seq"] = None
        store.upsert_edge(e)
    elif e is not None and e["closed_seq"] is None:
        e["closed_seq"] = pos["seq"]          # no longer CONFIRMED: the link leaves the graph
        store.upsert_edge(e)


# --- incidents, epochs, completeness ---------------------------------------------------
def _incident(store, pos, env):
    """Returns (incident_id, record_sha256, version) of a newly applied record."""
    inc = env.incident
    sha = sha256(inc)
    if not inc.incident_id or store.has_record("incident_records", inc.incident_id, sha):
        return None
    store.insert_record("incident_records", dict(
        pos, incident_id=inc.incident_id, record_sha256=sha, version=inc.version,
        status=incident_pb2.IncidentStatus.Name(inc.status), input_frontier=dict(inc.input_frontier),
        envelope=env.SerializeToString()))
    for alias in inc.aliases:
        store.upsert_alias(alias, inc.incident_id, pos["seq"])
    copy_speculative_paths(store, pos["seq"], inc, sha)
    for ep in inc.node_epochs:
        _epoch(store, pos["seq"], ep)
    return inc.incident_id, sha, inc.version


def _epoch(store, seq, ep):
    tau = ts_ns(ep.tau_n)
    if tau is None or not ep.node_id:
        return
    cur = store.epoch(ep.node_id, ep.boot_id)
    if cur is not None and cur["tau_n"] <= tau:
        return
    store.upsert_epoch({"node_id": ep.node_id, "boot_id": ep.boot_id, "tau_n": tau,
                        "trigger_finding_id": ep.trigger_finding_id,
                        "kind": incident_pb2.NodeEpochKind.Name(ep.kind), "seq": seq})
    resplit(store, seq, ep.node_id, ep.boot_id, tau)


def resplit(store, seq, node_id, boot_id, tau):
    """Move every trusted edge event of (node, boot) received at or after tau
    to the degraded twin of its edge (merge rule 3)."""
    moved = {}
    for r in store.trusted_edge_events_on(node_id, boot_id, tau):
        old = store.edge(r["edge_id"])
        new_id = edge_id(old["edge_type"], old["src"], old["dst"], old["label"], old["identity_status"], DEGRADED)
        new = store.edge(new_id) or _new_edge(new_id, old["edge_type"], old["src"], old["dst"], old["label"],
                                              old["identity_status"], DEGRADED, seq, old["attributes"])
        _count(new, r["event_time"])
        store.upsert_edge(new)
        store.move_edge_event(r["event_id"], old["edge_id"], new_id)
        moved[old["edge_id"]] = old
    for old_id, old in moved.items():
        n, lo, hi = store.edge_event_span(old_id)
        old["count"], old["first_t"], old["last_t"] = n, lo, hi
        if n == 0:
            old["closed_seq"] = seq
        store.upsert_edge(old)


def _completeness(store, pos, env):
    sc = env.source_completeness
    sha = sha256(sc)
    if store.has_record("completeness", sha):
        return
    store.insert_record("completeness", dict(
        pos, record_sha256=sha, source=common_pb2.Source.Name(sc.source), scope=sc.scope,
        interval_start=ts_ns(sc.interval_start) if sc.HasField("interval_start") else None,
        interval_end=ts_ns(sc.interval_end) if sc.HasField("interval_end") else None,
        envelope=env.SerializeToString()))
