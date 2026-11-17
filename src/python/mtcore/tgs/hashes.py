"""Canonical graph hashes for the rebuild check (tgs-contract.md sections 4, 9).

A hash covers content only: never `seq`, Kafka positions or apply times,
which depend on batching. A full replay of the same records, in any batch
size, must give the same hashes; so must a replay in another arrival order
(merged edge IDs are stable, and late epochs re-split).

- graph_hash: every node, edge (summary and closed state), edge event,
  epoch, alias and stored record (by the SHA-256 of its envelope bytes).
- incident_hash: an incident's latest record, its member findings, the
  witness records it lists, and the edges touching its findings or citing
  their input events.
- integrity_hash: the correlation result only (incident records and
  confirmed edges), for the Table 5 checks that nothing in the TGS feeds
  back into it.
- edge_hash: the OBSERVED and CONFIRMED_WITNESS edges only (summary and
  closed state), for the Exp. 5 equality of two live runs. graph_hash also
  covers every stored record, and how many intermediate open-incident and
  completeness records a live run writes depends on timing.
"""
import hashlib
import json

from microtrace.v0 import envelope_pb2

from mtcore.tgs.extract import finding_node


def _sha(b):
    return hashlib.sha256(bytes(b)).hexdigest()


def _edge(e):
    return [e["edge_id"], e["edge_type"], e["src"], e["dst"], e["label"], e["identity_status"], e["trust"],
            e["count"], e["first_t"], e["last_t"], e["witness_id"], e["finding_id"], e["closed_seq"] is None]


def _digest(parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def graph_hash(store):
    parts = {
        "nodes": sorted([n["node_id"], n["node_type"], n["uid"], n["namespace"], n["name"], n["identity_status"]]
                        for n in store.rows("nodes")),
        "edges": sorted(_edge(e) for e in store.rows("edges")),
        "edge_events": sorted([r["event_id"], r["edge_id"], r["event_time"]] for r in store.rows("edge_events")),
        "events": sorted([r["event_id"], _sha(r["envelope"])] for r in store.rows("events")),
        "findings": sorted([r["finding_id"], _sha(r["envelope"])] for r in store.rows("findings")),
        "witnesses": sorted([r["witness_id"], r["record_sha256"]] for r in store.rows("witnesses")),
        "incidents": sorted([r["incident_id"], r["record_sha256"]] for r in store.rows("incident_records")),
        "completeness": sorted(r["record_sha256"] for r in store.rows("completeness")),
        "epochs": sorted([r["node_id"], r["boot_id"], r["tau_n"], r["trigger_finding_id"]]
                         for r in store.rows("node_epochs")),
        "aliases": sorted([r["alias_id"], r["incident_id"]] for r in store.rows("incident_aliases")),
    }
    return _digest(parts)


def edge_hash(store):
    return _digest(sorted(_edge(e) for e in store.rows("edges")
                          if e["edge_type"] in ("OBSERVED", "CONFIRMED_WITNESS")))


def _envelope(row):
    env = envelope_pb2.Envelope()
    env.ParseFromString(bytes(row["envelope"]))
    return env


def incident_hash(store, incident_id):
    latest = store.latest_incident_record(incident_id)
    if latest is None:
        return None
    inc = _envelope(latest).incident
    members = set(inc.finding_ids)
    findings = {r["finding_id"]: r for r in store.rows("findings") if r["finding_id"] in members}
    inputs = {eid for r in findings.values() for eid in _envelope(r).finding.input_event_ids}
    fnodes = {finding_node(f).id for f in members}
    wanted = set(inc.link_witness_ids)
    cited = {r["edge_id"] for r in store.rows("edge_events") if r["event_id"] in inputs}
    edges = [e for e in store.rows("edges")
             if e["edge_id"] in cited or e["src"] in fnodes or e["dst"] in fnodes or e["witness_id"] in wanted]
    parts = {
        "record": latest["record_sha256"],
        "findings": sorted([f, _sha(r["envelope"])] for f, r in findings.items()),
        "witnesses": sorted([r["witness_id"], r["record_sha256"]] for r in store.rows("witnesses")
                            if r["witness_id"] in wanted),
        "edges": sorted(_edge(e) for e in edges),
    }
    return _digest(parts)


def integrity_hash(store):
    """What the TGS must never change (tgs-contract.md sections 8 and 9; P1,
    P4): every incident record's (incident_id, version, finding_ids,
    link_witness_ids) and every confirmed-witness edge. Observed edges,
    hypotheses, snapshots and reads never enter it."""
    incidents = []
    for r in store.rows("incident_records"):
        inc = _envelope(r).incident
        incidents.append([inc.incident_id, inc.version, sorted(inc.finding_ids), sorted(inc.link_witness_ids)])
    confirmed = sorted([e["src"], e["dst"], e["witness_id"], e["closed_seq"] is None]
                       for e in store.rows("edges") if e["edge_type"] == "CONFIRMED_WITNESS")
    return _digest({"incidents": sorted(incidents), "confirmed": confirmed})
