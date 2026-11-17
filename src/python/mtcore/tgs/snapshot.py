"""Snapshots, snapshot status and the GRE approval check (build step 6b;
tgs-contract.md section 4; design-spec.md section 9).

- v_C = (incident_id, version, record_sha256): an open incident changes under
  one version, so the record hash is what tells two of its states apart.
- A snapshot <v_C, o_t, status_t> is recorded whenever a batch applies an
  incident record (and on request): o_t holds the applied offset of every
  input partition after that batch, sid = SHA-256(v_C, o_t).
- Status, re-evaluated on every read:
    stale    a different record of the incident has been applied since, or
             the incident was merged into another (its ID is an alias);
    lagging  some partition of the record's input_frontier is not yet
             applied that far, or a witness the record lists is not applied;
    current  otherwise.
  Coverage freshness is separate: completeness records are not part of the
  input frontier.
"""
import hashlib
import json

from microtrace.v0 import envelope_pb2

CURRENT, LAGGING, STALE = "current", "lagging", "stale"


def offsets_map(store):
    """{"topic/partition": last applied offset}, the input_frontier format."""
    return {f"{t}/{p}": o for (t, p), o in store.offsets().items()}


def sid_of(v_c, offsets):
    incident_id, version, sha = v_c
    canon = json.dumps({"incident_id": incident_id, "version": version, "record_sha256": sha,
                        "offsets": dict(sorted(offsets.items()))}, sort_keys=True, separators=(",", ":"))
    return "sn_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]


def _incident(row):
    env = envelope_pb2.Envelope()
    env.ParseFromString(bytes(row["envelope"]))
    return env.incident


def status(store, v_c, offsets=None):
    """(status, [reasons]) of the incident state v_c against the store now
    (or against `offsets`, the applied offsets of a snapshot)."""
    incident_id, version, sha = v_c
    latest = store.latest_incident_record(incident_id)
    if latest is None:
        return STALE, [f"incident {incident_id} is unknown to the graph store"]
    merged = store.alias(incident_id)
    if merged is not None and merged["seq"] >= latest["seq"]:
        return STALE, [f"incident {incident_id} was merged into {merged['incident_id']}"]
    if latest["record_sha256"] != sha or latest["version"] != version:
        why = (f"version {version} -> {latest['version']}" if latest["version"] != version
               else f"open incident revised under version {version}")
        return STALE, [f"incident changed since review ({why})"]
    applied = offsets_map(store) if offsets is None else offsets
    reasons = []
    for tp, need in sorted(dict(latest["input_frontier"]).items()):
        have = applied.get(tp, -1)
        if have < need:
            reasons.append(f"{tp} applied to {have}, needs {need}")
    inc = _incident(latest)
    missing = sorted(set(inc.link_witness_ids) - store.witnesses_present(inc.link_witness_ids))
    if missing:
        reasons.append(f"witnesses not yet applied: {', '.join(missing)}")
    return (LAGGING, reasons) if reasons else (CURRENT, [])


def record_snapshot(store, seq, incident_id, sha, version):
    """Inside a transaction: record the snapshot of (incident, record) at the
    store's applied offsets now. Returns the snapshot row."""
    offsets = offsets_map(store)
    v_c = (incident_id, version, sha)
    st, _why = status(store, v_c, offsets)
    row = {"sid": sid_of(v_c, offsets), "incident_id": incident_id, "version": version,
           "record_sha256": sha, "offsets": offsets, "status": st, "seq": seq}
    store.insert_snapshot(row)
    return row


def take_snapshot(store, incident_id):
    """On request: a snapshot of the incident's latest record at the current
    offsets, in its own transaction. Returns the row, or None if unknown."""
    store.begin()
    try:
        latest = store.latest_incident_record(incident_id)
        if latest is None:
            store.rollback()
            return None
        row = record_snapshot(store, store.next_seq() - 1, incident_id, latest["record_sha256"], latest["version"])
        store.commit()
        return row
    except BaseException:
        store.rollback()
        raise


def check_approval(store, v_c, sid):
    """The GRE's graph check (P3): (accepted, reason). Accepted only if the
    snapshot exists for exactly v_c, was current when issued, and v_c is still
    the incident's latest applied record (not revised, not merged away)."""
    snap = store.snapshot(sid)
    if snap is None:
        return False, f"unknown snapshot {sid}"
    if (snap["incident_id"], snap["version"], snap["record_sha256"]) != tuple(v_c):
        return False, "snapshot belongs to another incident state than the approval"
    if snap["status"] != CURRENT:
        return False, f"snapshot was {snap['status']} when issued"
    st, why = status(store, v_c)
    if st == STALE:
        return False, why[0]
    return True, "approval matches the latest reviewed incident state"
