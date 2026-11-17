"""The two Exp. 5 read interfaces (build step 6d; tgs-contract.md section 6;
docs/plans/exp5-automated-investigation.md section 3).

Both read the same tables; only the access path differs.

- List interface (baseline): findings in event-time order with filters, one
  finding with its evidence references, one event, coverage records,
  witness records. No traversal, no versions.
- Graph interface: an incident with its snapshot status, the neighbours of
  a node, the confirmed path between two findings, an incident's gaps and
  contradictions, and an incident's subgraph as of one of its versions.

Every call goes through Session._call: arguments are checked against the
call's JSON schema, the call runs on a read-only store, and one log entry
{function, arguments, records, duration_ms, error} is written. One call is
one retrieval operation; each page is one call; PAGE = 50. That log is the
Exp. 5 effort measurement. Results carry payload messages only, never
Envelope.run (run ID, split), and ground truth is not in the store.
"""
import json
import os
import time
from datetime import datetime, timezone

import jsonschema
from google.protobuf import json_format
from microtrace.v0 import envelope_pb2

from mtcore.tgs.apply import DEGRADED, TRUSTED, edge_id
from mtcore.tgs.extract import finding_node
from mtcore.tgs.snapshot import status as snapshot_status
from mtcore.tgs.store import ReadOnlyStore
from mtcore.tgs.templates import gap_report, load_rulebook, load_templates, min_overlap, select as select_template

PAGE = 50
MAX_PATH = 16
_TS = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$", "maxLength": 40}
_ID = {"type": "string", "minLength": 1, "maxLength": 200}
_TEXT = {"type": "string", "minLength": 1, "maxLength": 253}
_PAGE = {"type": "integer", "minimum": 0, "maximum": 100000}
_VERSION = {"type": "integer", "minimum": 1, "maximum": 1000000}


def _obj(props, required=()):
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


SCHEMAS = {
    # list interface
    "list_findings": _obj({"time_from": _TS, "time_to": _TS, "namespace": _TEXT, "pod_uid": _TEXT,
                           "identity": _TEXT, "agent": _TEXT,
                           "finding_type": {"type": "string", "pattern": r"^[A-H][0-9][a-z]?$"}, "page": _PAGE}),
    "get_finding": _obj({"finding_id": _ID}, ["finding_id"]),
    "get_event": _obj({"event_id": _ID}, ["event_id"]),
    "list_coverage": _obj({"time_from": _TS, "time_to": _TS, "page": _PAGE}),
    "list_witnesses": _obj({"ids": {"type": "array", "items": _ID, "maxItems": PAGE, "uniqueItems": True},
                            "time_from": _TS, "time_to": _TS, "page": _PAGE}),
    # graph interface
    "get_incident": _obj({"incident_id": _ID, "as_of_version": _VERSION}, ["incident_id"]),
    "neighbours": _obj({"node": _ID,
                        "edge_types": {"type": "array", "uniqueItems": True, "maxItems": 3,
                                       "items": {"enum": ["OBSERVED", "CONFIRMED_WITNESS", "HYPOTHESIS"]}},
                        "time_from": _TS, "time_to": _TS, "page": _PAGE}, ["node"]),
    "confirmed_path": dict(_obj({"finding_a": _ID, "finding_b": _ID, "incident_id": _ID,
                                 "as_of_version": _VERSION}, ["finding_a", "finding_b"]),
                           dependentRequired={"as_of_version": ["incident_id"]}),
    "gaps_and_contradictions": _obj({"incident_id": _ID, "template_id": _ID}, ["incident_id"]),
    "graph_as_of": _obj({"incident_id": _ID, "version": _VERSION}, ["incident_id", "version"]),
}
LIST_CALLS = ("list_findings", "get_finding", "get_event", "list_coverage", "list_witnesses")
GRAPH_CALLS = ("get_incident", "neighbours", "confirmed_path", "gaps_and_contradictions", "graph_as_of")


class BudgetExceeded(RuntimeError):
    """The per-task call budget is spent."""


class InvalidArgument(ValueError):
    """An argument the schema accepts but the call cannot use (an impossible
    date)."""


def _query_canceled():
    """The Postgres statement-timeout error, or an empty tuple without
    psycopg."""
    try:
        from psycopg.errors import QueryCanceled
    except ImportError:
        return ()
    return QueryCanceled


class Session:
    """One investigator's access: a read-only store, argument checks, the
    call log and an optional call budget. `calls` limits it to one interface
    (LIST_CALLS or GRAPH_CALLS)."""

    def __init__(self, store, log_path=None, max_calls=None, calls=LIST_CALLS + GRAPH_CALLS):
        self.store = store if isinstance(store, ReadOnlyStore) else ReadOnlyStore(store)
        self.log_path, self.max_calls, self.allowed = log_path, max_calls, tuple(calls)
        self.log = []

    @property
    def operations(self):
        return len(self.log)

    @property
    def records(self):
        return sum(e["records"] for e in self.log)

    def call(self, name, args=None):
        """Run one interface call by name (the tool wrapper's entry)."""
        args = dict(args or {})
        if self.max_calls is not None and self.operations >= self.max_calls:
            raise BudgetExceeded(f"call budget of {self.max_calls} spent")
        if name not in self.allowed:
            return self._record(name, args, None, 0.0, f"{name} is not part of this interface")
        try:
            jsonschema.validate(args, SCHEMAS[name])
        except jsonschema.ValidationError as e:
            return self._record(name, args, None, 0.0, f"invalid arguments: {e.message}")
        t0 = time.perf_counter()
        result, error = None, None
        try:
            result = CALLS[name](self.store, **args)
        except InvalidArgument as e:
            error = f"invalid arguments: {e}"
        except LookupError as e:
            error = str(e)
        except _query_canceled():
            error = "query exceeded the time limit"
        except Exception as e:
            # Logged, then raised: a broken store or a bug is never an answer.
            self._record(name, args, None, time.perf_counter() - t0, f"internal error: {type(e).__name__}")
            try:
                self.store.end_call()
            except Exception:
                pass
            raise
        self.store.end_call()           # one call, one read transaction
        return self._record(name, args, result, time.perf_counter() - t0, error)

    def __getattr__(self, name):
        if name in CALLS:
            return lambda **kw: self.call(name, kw)
        raise AttributeError(name)

    def _record(self, name, args, result, seconds, error):
        entry = {"op": len(self.log) + 1, "function": name, "arguments": args, "records": count(result),
                 "duration_ms": round(seconds * 1000, 3), "error": error}
        self.log.append(entry)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return {"error": error} if error else result


def count(result):
    """Records returned by one call."""
    if not result or result.get("found") is False:
        return 0
    if "items" in result:
        return len(result["items"])
    if "nodes" in result:
        return len(result["nodes"]) + len(result["edges"])
    if "gaps" in result:
        return len(result["gaps"]) + len(result["contradictions"]) + len(result["hypotheses"])
    return 1


def open_session(dsn=None, **kw):
    """A Session on the read-only role (default $MT_TGS_READER_DSN) with a
    5 s statement timeout. Each call is one read-only REPEATABLE READ
    transaction, so it sees one state of the store."""
    import psycopg
    from mtcore.tgs.store import PgStore
    conn = psycopg.connect(dsn or os.environ["MT_TGS_READER_DSN"], options="-c statement_timeout=5000")
    conn.read_only = True
    conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
    return Session(PgStore(conn), **kw)


# --- helpers ---------------------------------------------------------------------------
def _ns(ts):
    if ts is None:
        return None
    try:
        if not ts.endswith("Z") or "\n" in ts:
            raise ValueError(ts)
        dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        frac = ts[19:-1]
        if frac and not (frac.startswith(".") and frac[1:].isdigit()):
            raise ValueError(ts)
        return int(dt.timestamp()) * 10**9 + (int(frac[1:].ljust(9, "0")) if frac else 0)
    except ValueError:
        raise InvalidArgument(f"{ts!r} is not a valid time") from None


def _ts(ns):
    if ns is None:
        return None
    secs, rem = divmod(int(ns), 10**9)
    base = datetime.fromtimestamp(secs, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return base + (f".{rem:09d}".rstrip("0") if rem else "") + "Z"


def _payload(row, kind):
    env = envelope_pb2.Envelope()
    env.ParseFromString(bytes(row["envelope"]))
    return getattr(env, kind)       # the payload only: Envelope.run never leaves the store


def _dict(msg):
    return json_format.MessageToDict(msg, preserving_proto_field_name=True)


def _page(rows, page, key=None):
    rows = sorted(rows, key=key) if key else rows
    chunk = rows[page * PAGE:(page + 1) * PAGE + 1]
    return chunk[:PAGE], len(chunk) > PAGE


def _node_view(r):
    return {"node_id": r["node_id"], "type": r["node_type"], "uid": r["uid"], "namespace": r["namespace"],
            "name": r["name"], "identity_status": r["identity_status"]}


def _edge_view(e, direction=None, other=None):
    v = {"edge_id": e["edge_id"], "edge_type": e["edge_type"], "label": e["label"], "count": e["count"],
         "span_first": _ts(e["first_t"]), "span_last": _ts(e["last_t"]), "trust": e["trust"] or None,
         "identity_status": e["identity_status"] or None, "witness_id": e["witness_id"], "src": e["src"],
         "dst": e["dst"]}
    if direction:
        v["direction"] = direction
    if other is not None:
        v["other"] = other
    return v


def _latest_by_id(rows, key):
    out = {}
    for r in sorted(rows, key=lambda r: (r["seq"], r["kafka_offset"])):
        out[r[key]] = r
    return out


def _record_for(store, incident_id, version=None):
    eq = {"incident_id": incident_id}
    if version is not None:
        eq["version"] = version
    rows = store.select("incident_records", equals=eq, order_by=["-seq", "-kafka_offset"], limit=1)
    if not rows:
        raise LookupError(f"no record of incident {incident_id}" + (f" version {version}" if version else ""))
    return rows[0]


# --- list interface --------------------------------------------------------------------
def _findings_naming(store, nodes):
    ids = [n["node_id"] for n in nodes]
    if not ids:
        return set()
    edges = store.select("edges", equals={"label": "involves"}, any_of={"dst": ids})
    return {e["finding_id"] for e in edges}


def list_findings(store, time_from=None, time_to=None, namespace=None, pod_uid=None, identity=None, agent=None,
                  finding_type=None, page=0):
    principals = {"node_type": ["SERVICE_ACCOUNT", "USER"]}
    entity_filters = []                 # node sets; a finding must name a node of every set
    if pod_uid is not None:
        entity_filters.append(store.select("nodes", equals={"node_type": "POD", "uid": pod_uid}))
    if namespace is not None:
        entity_filters.append(store.select("nodes", equals={"namespace": namespace}))
    if identity is not None:
        entity_filters.append(store.select("nodes", any_of=principals, equals={"name": identity})
                              + store.select("nodes", any_of=principals, equals={"uid": identity}))
    keep = None
    for nodes in entity_filters:
        ids = _findings_naming(store, nodes)
        keep = ids if keep is None else keep & ids
    if keep is not None and not keep:
        return {"items": [], "page": page, "more": False}
    eq = {}
    if agent is not None:
        eq["agent_id"] = agent
    if finding_type is not None:
        eq["finding_type"] = finding_type
    ranges = {"event_start": (_ns(time_from), _ns(time_to))} if time_from or time_to else None
    rows = store.select("findings", equals=eq, ranges=ranges, any_of={"finding_id": sorted(keep)} if keep else None,
                        order_by=["event_start", "finding_id"], limit=PAGE + 1, offset=page * PAGE)
    items = []
    for r in rows[:PAGE]:
        f = _payload(r, "finding")
        items.append({"finding_id": f.finding_id, "finding_type": f.finding_type, "agent_id": f.agent_id,
                      "event_start": _ts(r["event_start"]),
                      "primary_tactic": _dict(f).get("primary_tactic"),
                      "entities": [_dict(e) for e in f.entities]})
    return {"items": items, "page": page, "more": len(rows) > PAGE}


def get_finding(store, finding_id):
    rows = store.select("findings", equals={"finding_id": finding_id})
    if not rows:
        raise LookupError(f"no finding {finding_id}")
    f = _payload(rows[0], "finding")
    return {"finding": _dict(f), "evidence_event_ids": list(f.input_event_ids)}


def get_event(store, event_id):
    rows = store.select("events", equals={"event_id": event_id})
    if not rows:
        raise LookupError(f"no event {event_id}")
    return {"event": _dict(_payload(rows[0], "normalized_event"))}


def list_coverage(store, time_from=None, time_to=None, page=0):
    """Records meeting the range; a record without an interval bound meets
    every range on that side (as completeness_for and the gap report)."""
    lo, hi = _ns(time_from), _ns(time_to)
    rows = [r for r in store.select("completeness", order_by=["interval_start", "record_sha256"])
            if (lo is None or r["interval_end"] is None or r["interval_end"] >= lo)
            and (hi is None or r["interval_start"] is None or r["interval_start"] <= hi)]
    chunk, more = _page(rows, page)
    return {"items": [_dict(_payload(r, "source_completeness")) for r in chunk], "page": page, "more": more}


def list_witnesses(store, ids=None, time_from=None, time_to=None, page=0):
    """The latest record of each witness, then filtered by its source event
    time: a superseded record never stands in for the current decision."""
    lo, hi = _ns(time_from), _ns(time_to)
    rows = store.select("witnesses", any_of={"witness_id": ids} if ids is not None else None)
    latest = [r for r in _latest_by_id(rows, "witness_id").values()
              if (lo is None and hi is None) or (r["source_event_time"] is not None
                                                 and (lo is None or r["source_event_time"] >= lo)
                                                 and (hi is None or r["source_event_time"] <= hi))]
    chunk, more = _page(latest, page, key=lambda r: (r["source_event_time"] is None, r["source_event_time"] or 0,
                                                     r["witness_id"]))
    return {"items": [_dict(_payload(r, "witness")) for r in chunk], "page": page, "more": more}


# --- graph interface -------------------------------------------------------------------
def get_incident(store, incident_id, as_of_version=None):
    rec = _record_for(store, incident_id, as_of_version)
    v_c = (incident_id, rec["version"], rec["record_sha256"])
    st, why = snapshot_status(store, v_c)
    snaps = store.select("snapshots", equals={"incident_id": incident_id, "record_sha256": rec["record_sha256"]},
                         order_by=["-seq"], limit=1)
    return {"incident": _dict(_payload(rec, "incident")),
            "v_c": {"incident_id": incident_id, "version": rec["version"], "record_sha256": rec["record_sha256"]},
            "status": st, "reasons": why, "sid": snaps[0]["sid"] if snaps else None,
            "snapshot_status_when_issued": snaps[0]["status"] if snaps else None}


def _node_id(node):
    """A node ID as given, or a finding ID turned into its node ID."""
    return node if node.startswith("gn_") else finding_node(node).id


def neighbours(store, node, edge_types=None, time_from=None, time_to=None, page=0):
    nid = _node_id(node)
    types = set(edge_types or ["OBSERVED", "CONFIRMED_WITNESS"])
    lo, hi = _ns(time_from), _ns(time_to)
    out = []
    graph_types = sorted(types - {"HYPOTHESIS"})
    if graph_types:
        for direction, col in (("out", "src"), ("in", "dst")):
            for e in store.select("edges", equals={col: nid, "closed_seq": None}, any_of={"edge_type": graph_types}):
                if lo is not None and e["last_t"] is not None and e["last_t"] < lo:
                    continue
                if hi is not None and e["first_t"] is not None and e["first_t"] > hi:
                    continue
                out.append((e, direction, e["dst"] if direction == "out" else e["src"]))
    hyps = []
    if "HYPOTHESIS" in types:
        for direction, col in (("out", "src"), ("in", "dst")):
            for h in store.select("hypothesis_edges", equals={col: nid}):
                hyps.append({"edge_type": "HYPOTHESIS", "hypothesis_origin": h["origin"], "hyp_id": h["hyp_id"],
                             "label": h["label"], "direction": direction, "src": h["src"], "dst": h["dst"],
                             "unverified": True})
    others = {o for _e, _d, o in out}
    known = {r["node_id"]: _node_view(r) for r in store.select("nodes", any_of={"node_id": sorted(others)})} \
        if others else {}
    out.sort(key=lambda x: (x[0]["first_t"] is None, x[0]["first_t"] or 0, x[0]["edge_id"], x[1]))
    items = [_edge_view(e, d, known.get(o, {"node_id": o})) for e, d, o in out]
    items += sorted(hyps, key=lambda v: (v["hyp_id"], v["src"], v["dst"]))
    chunk, more = _page(items, page)
    return {"node_id": nid, "items": chunk, "page": page, "more": more}


def _as_of_seq(store, incident_id, version):
    return _record_for(store, incident_id, version)["seq"] if incident_id else None


def _edge_then(e, seq):
    """The edge an event of e sat on at seq. A degraded edge created after seq
    holds events an epoch moved off its trusted twin (apply.resplit keeps
    their seq), so as of seq they belong to that twin."""
    if e["trust"] == DEGRADED and e["created_seq"] > seq:
        return edge_id(e["edge_type"], e["src"], e["dst"], e["label"], e["identity_status"], TRUSTED)
    return e["edge_id"]


def _alive(e, seq):
    if seq is None:
        return e["closed_seq"] is None
    return e["created_seq"] <= seq and (e["closed_seq"] is None or e["closed_seq"] > seq)


def confirmed_path(store, finding_a, finding_b, incident_id=None, as_of_version=None):
    """Shortest path over CONFIRMED_WITNESS edges, a to b, else b to a; as of
    the incident version's apply point when given."""
    seq = _as_of_seq(store, incident_id, as_of_version) if as_of_version else None
    for start, goal in ((finding_a, finding_b), (finding_b, finding_a)):
        s, g = finding_node(start).id, finding_node(goal).id
        prev, frontier = {s: None}, [s]
        for _depth in range(MAX_PATH):
            if g in prev or not frontier:
                break
            edges = store.select("edges", equals={"edge_type": "CONFIRMED_WITNESS"}, any_of={"src": frontier},
                                 order_by=["src", "dst", "edge_id"])
            nxt = []
            for e in edges:
                if _alive(e, seq) and e["dst"] not in prev:
                    prev[e["dst"]] = e
                    nxt.append(e["dst"])
            frontier = nxt
        if g in prev:
            hops, n = [], g
            while prev[n] is not None:
                hops.append(prev[n])
                n = prev[n]["src"]
            hops.reverse()
            uid = {r["node_id"]: r["uid"] for r in store.select("nodes", any_of={"node_id": [s] + [h["dst"] for h in hops]})}
            return {"found": True, "direction": f"{start} -> {goal}",
                    "finding_ids": [uid.get(s, start)] + [uid.get(h["dst"], h["dst"]) for h in hops],
                    "witness_ids": [h["witness_id"] for h in hops]}
    return {"found": False, "direction": None, "finding_ids": [], "witness_ids": []}


def gaps_and_contradictions(store, incident_id, template_id=None):
    """Read-only: the gap report (selection rule, or the named template), the
    contradictions on witnesses among the incident's findings, and the
    hypotheses already recorded for this incident state."""
    rec = _record_for(store, incident_id)
    inc = _payload(rec, "incident")
    v_c = (incident_id, rec["version"], rec["record_sha256"])
    st, why = snapshot_status(store, v_c)
    types = store.finding_types(inc.finding_ids)
    library = load_templates()
    if template_id is not None:
        template = next((t for t in library if t.id == template_id), None)
        if template is None:
            raise LookupError(f"no template {template_id}")
        scores, reason = {}, "named by the caller"
    else:
        template, scores, reason = select_template(library, types.values(), min_overlap())
    gaps = gap_report(store, template, inc, types.values(), load_rulebook()) if template else []
    members = sorted(inc.finding_ids)
    rows = store.select("witnesses", any_of={"source_finding_id": members}) if members else []
    contradictions = []
    for r in sorted(_latest_by_id([r for r in rows if r["target_finding_id"] in set(members)],
                                  "witness_id").values(), key=lambda r: r["witness_id"]):
        w = _payload(r, "witness")
        if w.contradictions:
            contradictions.append({"witness_id": w.witness_id, "status": r["status"],
                                   "source_finding_id": w.source_finding_id, "target_finding_id": w.target_finding_id,
                                   "contradictions": [{"contradiction_id": c.contradiction_id, "decisive": c.decisive,
                                                       "detail": c.detail} for c in w.contradictions]})
    hyps = [{"hyp_id": h["hyp_id"], "origin": h["origin"], "template_id": h["template_id"] or None,
             "stage_id": h["stage_id"] or None, "detail": h["detail"], "unverified": True}
            for h in store.select("hypotheses", equals={"incident_id": incident_id,
                                                        "record_sha256": rec["record_sha256"]},
                                  order_by=["origin", "hyp_id"])]
    return {"incident_id": incident_id,
            "v_c": {"incident_id": incident_id, "version": rec["version"], "record_sha256": rec["record_sha256"]},
            "status": st, "reasons": why, "template": template.id if template else None, "reason": reason,
            "scores": scores, "gaps": gaps, "contradictions": contradictions, "hypotheses": hyps}


def graph_as_of(store, incident_id, version):
    """The incident's subgraph as the store knew it when that version was
    applied: its findings, their involves and witness edges, and the observed
    edges citing their input events, with counts recomputed at that point."""
    rec = _record_for(store, incident_id, version)
    seq = rec["seq"]
    inc = _payload(rec, "incident")
    members = sorted(inc.finding_ids)
    fnodes = [finding_node(f).id for f in members]
    edges = {}
    if fnodes:
        for e in store.select("edges", any_of={"src": fnodes, "edge_type": ["OBSERVED"]}, equals={"label": "involves"}):
            if _alive(e, seq):
                edges[e["edge_id"]] = dict(e)
    wanted = sorted(inc.link_witness_ids)
    if wanted:
        for e in store.select("edges", equals={"edge_type": "CONFIRMED_WITNESS"}, any_of={"witness_id": wanted}):
            if _alive(e, seq):
                edges[e["edge_id"]] = dict(e)
    inputs = sorted({eid for r in (store.select("findings", any_of={"finding_id": members}) if members else [])
                     for eid in _payload(r, "finding").input_event_ids})
    cited = {r["edge_id"] for r in store.select("edge_events", any_of={"event_id": inputs}, ranges={"seq": (None, seq)})} \
        if inputs else set()
    then = {}                           # edge as of seq -> its edge events applied by then
    for e in (store.select("edges", any_of={"edge_id": sorted(cited)}) if cited else []):
        evs = store.select("edge_events", equals={"edge_id": e["edge_id"]}, ranges={"seq": (None, seq)})
        if evs:
            then.setdefault(_edge_then(e, seq), []).extend(evs)
    for e in (store.select("edges", any_of={"edge_id": sorted(then)}) if then else []):
        if e["created_seq"] > seq:
            continue
        times = [r["event_time"] for r in then[e["edge_id"]] if r["event_time"] is not None]
        edges[e["edge_id"]] = dict(e, count=len(then[e["edge_id"]]), first_t=min(times) if times else None,
                                   last_t=max(times) if times else None)
    ids = sorted({x for e in edges.values() for x in (e["src"], e["dst"])} | set(fnodes))
    nodes = [_node_view(r) for r in store.select("nodes", any_of={"node_id": ids}, order_by=["node_id"])] if ids else []
    return {"incident_id": incident_id, "version": version, "record_sha256": rec["record_sha256"], "as_of_seq": seq,
            "nodes": nodes, "edges": [_edge_view(e) for e in sorted(edges.values(), key=lambda e: e["edge_id"])]}


CALLS = {f.__name__: f for f in (list_findings, get_finding, get_event, list_coverage, list_witnesses,
                                  get_incident, neighbours, confirmed_path, gaps_and_contradictions, graph_as_of)}
