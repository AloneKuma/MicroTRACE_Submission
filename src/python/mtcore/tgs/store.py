"""Where TGS rows live: MemoryStore (tests, no Postgres) and PgStore.

apply.py talks only to the methods below, so the two stores make the same
writes. Each batch runs between begin() and commit(); rollback() undoes every
write of the batch, offsets included (tgs-contract.md section 2).

PgStore writes the two high-volume tables (events, edge_events) and nodes with
COPY, and edges with one upsert per edge, at flush(); flush() runs before any
query that must see the batch's own writes and before COMMIT.
"""
import copy
import json
import os

SCHEMA_VERSION = "tgs-schema-5"
SCHEMA_SQL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

EVENT_COLS = ("event_id", "source", "event_time", "ingest_time", "node_id", "boot_id", "topic",
              "kafka_partition", "kafka_offset", "seq", "envelope")
EDGE_EVENT_COLS = ("event_id", "edge_id", "event_time", "ingest_time", "node_id", "boot_id", "topic",
                   "kafka_partition", "kafka_offset", "seq", "attributes")
NODE_COLS = ("node_id", "node_type", "uid", "namespace", "name", "identity_status", "first_seq")
EDGE_COLS = ("edge_id", "edge_type", "src", "dst", "label", "identity_status", "trust", "count", "first_t",
             "last_t", "witness_id", "finding_id", "extractor_version", "attributes", "created_seq", "closed_seq")
RECORD_COLS = {
    "findings": ("finding_id", "finding_type", "event_start", "agent_id", "topic", "kafka_partition",
                 "kafka_offset", "seq", "envelope"),
    "witnesses": ("witness_id", "record_sha256", "status", "source_finding_id", "target_finding_id",
                  "source_event_time", "topic", "kafka_partition", "kafka_offset", "seq", "envelope"),
    "incident_records": ("incident_id", "record_sha256", "version", "status", "input_frontier", "topic",
                         "kafka_partition", "kafka_offset", "seq", "envelope"),
    "completeness": ("record_sha256", "source", "scope", "interval_start", "interval_end", "topic",
                     "kafka_partition", "kafka_offset", "seq", "envelope"),
}
RECORD_KEY = {"findings": ("finding_id",), "witnesses": ("witness_id", "record_sha256"),
              "incident_records": ("incident_id", "record_sha256"), "completeness": ("record_sha256",)}
SNAPSHOT_COLS = ("sid", "incident_id", "version", "record_sha256", "offsets", "status", "seq")
HYP_COLS = ("hyp_id", "incident_id", "record_sha256", "origin", "template_id", "template_sha256", "stage_id",
            "detail", "seq")
HYP_EDGE_COLS = ("hyp_id", "src", "dst", "label", "origin", "seq")
JSON_COLS = {"attributes", "input_frontier", "offsets", "detail"}
# Every column select() may name: names come from here, never from a caller.
TABLE_COLS = {
    "events": EVENT_COLS, "edge_events": EDGE_EVENT_COLS, "nodes": NODE_COLS, "edges": EDGE_COLS,
    **RECORD_COLS, "snapshots": SNAPSHOT_COLS, "hypotheses": HYP_COLS, "hypothesis_edges": HYP_EDGE_COLS,
    "node_epochs": ("node_id", "boot_id", "tau_n", "trigger_finding_id", "kind", "seq"),
    "incident_aliases": ("alias_id", "incident_id", "seq"),
}
DATA_TABLES = ("apply_log", "applied_offsets", "nodes", "events", "edges", "edge_events", "node_epochs",
               "findings", "witnesses", "incident_records", "completeness", "snapshots", "incident_aliases",
               "hypotheses", "hypothesis_edges")


_STATUS_RANK = {"resolved": 0, "weak": 1, "class_only": 2, "unresolved": 3}   # extract.RANK


def merge_node(old, new):
    """One node seen by several sources (tgs-contract.md section 3): the
    smallest non-empty namespace and name, the weakest identity status and
    the first seq, so the row is the same in any arrival order."""
    out = dict(old)
    for c in ("namespace", "name"):
        seen = [v for v in (old[c], new[c]) if v]
        out[c] = min(seen) if seen else ""
    out["identity_status"] = max(old["identity_status"], new["identity_status"], key=_STATUS_RANK.__getitem__)
    out["first_seq"] = min(old["first_seq"], new["first_seq"])
    return out


def _check_cols(table, *names):
    cols = TABLE_COLS.get(table)
    if cols is None:
        raise ValueError(f"unknown table {table}")
    bad = [n for n in names if n not in cols]
    if bad:
        raise ValueError(f"unknown columns {bad} in {table}")


def _select_args(table, equals, ranges, any_of, order_by):
    equals, ranges, any_of, order_by = equals or {}, ranges or {}, any_of or {}, order_by or []
    _check_cols(table, *equals, *ranges, *any_of, *(c.lstrip("-") for c in order_by))
    return equals, ranges, any_of, order_by


class MemoryStore:
    """Dict tables with the same semantics as PgStore."""

    TABLES = DATA_TABLES

    def __init__(self):
        self.t = {name: {} for name in self.TABLES}
        self._saved = None

    # transactions ---------------------------------------------------------------
    def begin(self):
        self._saved = copy.deepcopy(self.t)

    def commit(self):
        self._saved = None

    def rollback(self):
        if self._saved is not None:
            self.t, self._saved = self._saved, None

    def end_call(self):
        """End one read-interface call (nothing to release in memory)."""

    # bookkeeping ----------------------------------------------------------------
    def next_seq(self):
        return max(self.t["apply_log"], default=0) + 1

    def log_apply(self, seq, records):
        self.t["apply_log"][seq] = {"seq": seq, "records": records}

    def offsets(self):
        return {k: r["last_offset"] for k, r in self.t["applied_offsets"].items()}

    def set_offset(self, topic, partition, offset, seq):
        k = (topic, partition)
        old = self.t["applied_offsets"].get(k)
        if old is None or offset > old["last_offset"]:
            self.t["applied_offsets"][k] = {"topic": topic, "kafka_partition": partition,
                                            "last_offset": offset, "seq": seq}

    # records --------------------------------------------------------------------
    def has_event(self, event_id):
        return event_id in self.t["events"]

    def insert_event(self, row):
        self.t["events"][row["event_id"]] = dict(row)

    def has_record(self, table, *key):
        return tuple(key) in self.t[table]

    def insert_record(self, table, row):
        self.t[table][tuple(row[c] for c in RECORD_KEY[table])] = dict(row)

    def latest_witness(self, witness_id):
        rows = [r for (w, _s), r in self.t["witnesses"].items() if w == witness_id]
        return max(rows, key=lambda r: r["seq"]) if rows else None

    # graph ----------------------------------------------------------------------
    def insert_node(self, row):
        old = self.t["nodes"].get(row["node_id"])
        self.t["nodes"][row["node_id"]] = merge_node(old, row) if old else dict(row)

    def edge(self, edge_id):
        r = self.t["edges"].get(edge_id)
        return dict(r) if r is not None else None

    def upsert_edge(self, row):
        self.t["edges"][row["edge_id"]] = dict(row)

    def insert_edge_event(self, row):
        self.t["edge_events"].setdefault((row["event_id"], row["edge_id"]), dict(row))

    def epoch(self, node_id, boot_id):
        r = self.t["node_epochs"].get((node_id, boot_id))
        return dict(r) if r is not None else None

    def upsert_epoch(self, row):
        self.t["node_epochs"][(row["node_id"], row["boot_id"])] = dict(row)

    def trusted_edge_events_on(self, node_id, boot_id, since_ns):
        """edge_events from (node, boot) received at or after since_ns (or with
        no receipt time) whose edge is trusted, sorted by (edge, event)."""
        out = []
        for r in self.t["edge_events"].values():
            if (r["node_id"], r["boot_id"]) != (node_id, boot_id):
                continue
            if r["ingest_time"] is not None and r["ingest_time"] < since_ns:
                continue
            if self.t["edges"][r["edge_id"]]["trust"] == "trusted":
                out.append(dict(r))
        return sorted(out, key=lambda r: (r["edge_id"], r["event_id"]))

    def move_edge_event(self, event_id, old_edge_id, new_edge_id):
        r = self.t["edge_events"].pop((event_id, old_edge_id))
        r["edge_id"] = new_edge_id
        self.t["edge_events"][(event_id, new_edge_id)] = r

    def edge_event_span(self, edge_id):
        ts = [r["event_time"] for r in self.t["edge_events"].values() if r["edge_id"] == edge_id]
        known = [t for t in ts if t is not None]
        return len(ts), (min(known) if known else None), (max(known) if known else None)

    # incidents and snapshots (6b) ----------------------------------------------
    def latest_incident_record(self, incident_id):
        rows = [r for (i, _s), r in self.t["incident_records"].items() if i == incident_id]
        return dict(max(rows, key=lambda r: (r["seq"], r["kafka_offset"]))) if rows else None

    def witnesses_present(self, witness_ids):
        have = {w for w, _s in self.t["witnesses"]}
        return {w for w in witness_ids if w in have}

    def insert_snapshot(self, row):
        self.t["snapshots"].setdefault(row["sid"], dict(row))

    def snapshot(self, sid):
        r = self.t["snapshots"].get(sid)
        return dict(r) if r is not None else None

    def upsert_alias(self, alias_id, incident_id, seq):
        self.t["incident_aliases"][alias_id] = {"alias_id": alias_id, "incident_id": incident_id, "seq": seq}

    def alias(self, alias_id):
        r = self.t["incident_aliases"].get(alias_id)
        return dict(r) if r is not None else None

    def reset(self):
        self.t = {name: {} for name in self.TABLES}

    # hypotheses and gap reports (6c) ---------------------------------------------
    def insert_hypothesis(self, row):
        self.t["hypotheses"].setdefault(row["hyp_id"], dict(row))

    def insert_hypothesis_edge(self, row):
        self.t["hypothesis_edges"].setdefault((row["hyp_id"], row["src"], row["dst"], row["label"]), dict(row))

    def finding_types(self, finding_ids):
        want = set(finding_ids)
        return {f: r["finding_type"] for f, r in ((k[0], v) for k, v in self.t["findings"].items()) if f in want}

    def completeness_for(self, source, lo, hi):
        """Completeness rows of `source` whose interval meets [lo, hi] (None:
        unbounded; a record without an interval always meets it)."""
        out = []
        for r in self.t["completeness"].values():
            if r["source"] != source:
                continue
            if lo is not None and r["interval_end"] is not None and r["interval_end"] < lo:
                continue
            if hi is not None and r["interval_start"] is not None and r["interval_start"] > hi:
                continue
            out.append(dict(r))
        return sorted(out, key=lambda r: r["record_sha256"])

    # generic read (6d) ------------------------------------------------------------
    def select(self, table, equals=None, ranges=None, any_of=None, order_by=None, limit=None, offset=0):
        """Rows matching every condition: equals {col: value} (None matches
        NULL), ranges {col: (lo, hi)} inclusive with None open (a NULL value
        never matches a bounded range), any_of {col: [values]}; ordered by
        order_by (a leading "-" is descending; NULLs last), then sliced."""
        equals, ranges, any_of, order_by = _select_args(table, equals, ranges, any_of, order_by)
        out = []
        for r in self.t[table].values():
            if any(r[c] != v for c, v in equals.items()):
                continue
            if any(not _in_range(r[c], lo, hi) for c, (lo, hi) in ranges.items()):
                continue
            if any(r[c] not in set(vs) for c, vs in any_of.items()):
                continue
            out.append(dict(r))
        for c in reversed(order_by):
            col, desc = c.lstrip("-"), c.startswith("-")
            known = [r for r in out if r[col] is not None]
            known.sort(key=lambda r: r[col], reverse=desc)
            out = known + [r for r in out if r[col] is None]
        return out[offset:offset + limit if limit is not None else None]

    # reads used by tests and later steps ----------------------------------------
    def rows(self, table):
        return [dict(r) for r in self.t[table].values()]


class PgStore:
    """psycopg 3 connection; the caller owns it. Uses the connection's
    search_path, so tests can run in a private schema."""

    def __init__(self, conn):
        self.conn = conn
        self._reset()

    def _reset(self):
        self._events, self._edge_events, self._nodes, self._edges = {}, {}, {}, {}
        self._node_updates = {}

    # schema -----------------------------------------------------------------------
    def apply_schema(self, rebuilding=False):
        """Create or upgrade the tables. Rows written under an older schema
        version are refused unless the caller is about to delete them
        (rebuilding): an upgrade never leaves old rows to be misread."""
        with open(SCHEMA_SQL, encoding="utf-8") as fh:
            ddl = fh.read()
        with self.conn.cursor() as cur:
            cur.execute(ddl)
            cur.execute("SELECT version FROM schema_version WHERE version <> %s ORDER BY version", (SCHEMA_VERSION,))
            old = [r[0] for r in cur.fetchall()]
            cur.execute("SELECT EXISTS (SELECT 1 FROM apply_log)")
            if old and cur.fetchone()[0] and not rebuilding:
                self.conn.rollback()
                raise RuntimeError(f"the TGS store holds rows written under {', '.join(old)}, not "
                                   f"{SCHEMA_VERSION}; rebuild it with --reset")
            cur.execute("DELETE FROM schema_version WHERE version <> %s", (SCHEMA_VERSION,))
            cur.execute("INSERT INTO schema_version VALUES (%s) ON CONFLICT DO NOTHING", (SCHEMA_VERSION,))
        self.conn.commit()

    # transactions -------------------------------------------------------------------
    def begin(self):
        self._reset()

    def commit(self):
        self.flush()
        self.conn.commit()
        self._reset()

    def rollback(self):
        self.conn.rollback()
        self._reset()

    def end_call(self):
        """End one read-interface call: close its read transaction, so a
        failed or timed-out query never poisons the next call."""
        self.rollback()

    def flush(self):
        with self.conn.cursor() as cur:
            for table, cols, buf in (("events", EVENT_COLS, self._events), ("nodes", NODE_COLS, self._nodes),
                                     ("edge_events", EDGE_EVENT_COLS, self._edge_events)):
                if not buf:
                    continue
                with cur.copy(f"COPY {table} ({', '.join(cols)}) FROM STDIN") as cp:
                    for row in buf.values():
                        cp.write_row([_db(c, row[c]) for c in cols])
                buf.clear()
            if self._node_updates:
                cur.executemany("UPDATE nodes SET namespace = %s, name = %s, identity_status = %s, first_seq = %s "
                                "WHERE node_id = %s",
                                [[r["namespace"], r["name"], r["identity_status"], r["first_seq"], r["node_id"]]
                                 for r in self._node_updates.values()])
                self._node_updates.clear()
            if self._edges:
                sets = ", ".join(f"{c} = EXCLUDED.{c}" for c in EDGE_COLS[1:])
                cur.executemany(
                    f"INSERT INTO edges ({', '.join(EDGE_COLS)}) VALUES ({', '.join(['%s'] * len(EDGE_COLS))}) "
                    f"ON CONFLICT (edge_id) DO UPDATE SET {sets}",
                    [[_db(c, r[c]) for c in EDGE_COLS] for r in self._edges.values()])
                self._edges.clear()

    def _one(self, sql, args=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()

    def _all(self, sql, args=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            names = [d.name for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    # bookkeeping ----------------------------------------------------------------------
    def next_seq(self):
        return self._one("SELECT COALESCE(MAX(seq), 0) + 1 FROM apply_log")[0]

    def log_apply(self, seq, records):
        self._one("INSERT INTO apply_log (seq, records) VALUES (%s, %s) RETURNING seq", (seq, records))

    def offsets(self):
        return {(r["topic"], r["kafka_partition"]): r["last_offset"]
                for r in self._all("SELECT topic, kafka_partition, last_offset FROM applied_offsets")}

    def set_offset(self, topic, partition, offset, seq):
        self._one("INSERT INTO applied_offsets VALUES (%s, %s, %s, %s) ON CONFLICT (topic, kafka_partition) "
                  "DO UPDATE SET last_offset = EXCLUDED.last_offset, seq = EXCLUDED.seq "
                  "WHERE applied_offsets.last_offset < EXCLUDED.last_offset RETURNING 1",
                  (topic, partition, offset, seq))

    # records ----------------------------------------------------------------------------
    def has_event(self, event_id):
        return event_id in self._events or self._one("SELECT 1 FROM events WHERE event_id = %s",
                                                     (event_id,)) is not None

    def insert_event(self, row):
        self._events[row["event_id"]] = dict(row)

    def has_record(self, table, *key):
        cond = " AND ".join(f"{c} = %s" for c in RECORD_KEY[table])
        return self._one(f"SELECT 1 FROM {table} WHERE {cond}", key) is not None

    def insert_record(self, table, row):
        cols = RECORD_COLS[table]
        self._one(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                  f"ON CONFLICT DO NOTHING RETURNING 1", [_db(c, row[c]) for c in cols])

    def latest_witness(self, witness_id):
        rows = self._all("SELECT witness_id, status, seq FROM witnesses WHERE witness_id = %s "
                         "ORDER BY seq DESC LIMIT 1", (witness_id,))
        return rows[0] if rows else None

    # graph ------------------------------------------------------------------------------
    def insert_node(self, row):
        """New nodes go out by COPY; a stored node whose labels change is
        updated (merge_node)."""
        nid = row["node_id"]
        for buf in (self._nodes, self._node_updates):
            if nid in buf:
                buf[nid] = merge_node(buf[nid], row)
                return
        stored = self._all(f"SELECT {', '.join(NODE_COLS)} FROM nodes WHERE node_id = %s", (nid,))
        if not stored:
            self._nodes[nid] = dict(row)
        elif merge_node(stored[0], row) != stored[0]:
            self._node_updates[nid] = merge_node(stored[0], row)

    def edge(self, edge_id):
        if edge_id in self._edges:
            return dict(self._edges[edge_id])
        rows = self._all(f"SELECT {', '.join(EDGE_COLS)} FROM edges WHERE edge_id = %s", (edge_id,))
        return rows[0] if rows else None

    def upsert_edge(self, row):
        self._edges[row["edge_id"]] = dict(row)

    def insert_edge_event(self, row):
        self._edge_events.setdefault((row["event_id"], row["edge_id"]), dict(row))

    def epoch(self, node_id, boot_id):
        rows = self._all("SELECT * FROM node_epochs WHERE node_id = %s AND boot_id = %s", (node_id, boot_id))
        return rows[0] if rows else None

    def upsert_epoch(self, row):
        self._one("INSERT INTO node_epochs VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (node_id, boot_id) DO UPDATE "
                  "SET tau_n = EXCLUDED.tau_n, trigger_finding_id = EXCLUDED.trigger_finding_id, "
                  "kind = EXCLUDED.kind, seq = EXCLUDED.seq RETURNING 1",
                  (row["node_id"], row["boot_id"], row["tau_n"], row["trigger_finding_id"], row["kind"], row["seq"]))

    def trusted_edge_events_on(self, node_id, boot_id, since_ns):
        self.flush()
        return self._all(
            f"SELECT {', '.join('ee.' + c for c in EDGE_EVENT_COLS)} FROM edge_events ee "
            "JOIN edges e ON e.edge_id = ee.edge_id WHERE ee.node_id = %s AND ee.boot_id = %s "
            "AND (ee.ingest_time IS NULL OR ee.ingest_time >= %s) AND e.trust = 'trusted' "
            "ORDER BY ee.edge_id, ee.event_id", (node_id, boot_id, since_ns))

    def move_edge_event(self, event_id, old_edge_id, new_edge_id):
        self.flush()
        self._one("UPDATE edge_events SET edge_id = %s WHERE event_id = %s AND edge_id = %s RETURNING 1",
                  (new_edge_id, event_id, old_edge_id))

    def edge_event_span(self, edge_id):
        self.flush()
        return tuple(self._one("SELECT COUNT(*), MIN(event_time), MAX(event_time) FROM edge_events "
                               "WHERE edge_id = %s", (edge_id,)))

    # incidents and snapshots (6b) ------------------------------------------------------
    def latest_incident_record(self, incident_id):
        rows = self._all("SELECT * FROM incident_records WHERE incident_id = %s "
                         "ORDER BY seq DESC, kafka_offset DESC LIMIT 1", (incident_id,))
        return rows[0] if rows else None

    def witnesses_present(self, witness_ids):
        ids = sorted(set(witness_ids))
        if not ids:
            return set()
        return {r["witness_id"] for r in self._all("SELECT DISTINCT witness_id FROM witnesses "
                                                   "WHERE witness_id = ANY(%s)", (ids,))}

    def insert_snapshot(self, row):
        self._one(f"INSERT INTO snapshots ({', '.join(SNAPSHOT_COLS)}) VALUES "
                  f"({', '.join(['%s'] * len(SNAPSHOT_COLS))}) ON CONFLICT DO NOTHING RETURNING 1",
                  [_db(c, row[c]) for c in SNAPSHOT_COLS])

    def snapshot(self, sid):
        rows = self._all("SELECT * FROM snapshots WHERE sid = %s", (sid,))
        return rows[0] if rows else None

    def upsert_alias(self, alias_id, incident_id, seq):
        self._one("INSERT INTO incident_aliases VALUES (%s, %s, %s) ON CONFLICT (alias_id) DO UPDATE "
                  "SET incident_id = EXCLUDED.incident_id, seq = EXCLUDED.seq RETURNING 1",
                  (alias_id, incident_id, seq))

    def alias(self, alias_id):
        rows = self._all("SELECT * FROM incident_aliases WHERE alias_id = %s", (alias_id,))
        return rows[0] if rows else None

    # hypotheses and gap reports (6c) ---------------------------------------------------
    def insert_hypothesis(self, row):
        self._one(f"INSERT INTO hypotheses ({', '.join(HYP_COLS)}) VALUES ({', '.join(['%s'] * len(HYP_COLS))}) "
                  "ON CONFLICT DO NOTHING RETURNING 1", [_db(c, row[c]) for c in HYP_COLS])

    def insert_hypothesis_edge(self, row):
        self._one(f"INSERT INTO hypothesis_edges ({', '.join(HYP_EDGE_COLS)}) VALUES "
                  f"({', '.join(['%s'] * len(HYP_EDGE_COLS))}) ON CONFLICT DO NOTHING RETURNING 1",
                  [_db(c, row[c]) for c in HYP_EDGE_COLS])

    def finding_types(self, finding_ids):
        ids = sorted(set(finding_ids))
        if not ids:
            return {}
        return {r["finding_id"]: r["finding_type"] for r in
                self._all("SELECT finding_id, finding_type FROM findings WHERE finding_id = ANY(%s)", (ids,))}

    def completeness_for(self, source, lo, hi):
        return self._all("SELECT * FROM completeness WHERE source = %s "
                         "AND (%s::bigint IS NULL OR interval_end IS NULL OR interval_end >= %s) "
                         "AND (%s::bigint IS NULL OR interval_start IS NULL OR interval_start <= %s) "
                         "ORDER BY record_sha256", (source, lo, lo, hi, hi))

    def reset(self):
        """Delete every row (a rebuild replays from the start); the schema stays."""
        self._reset()
        with self.conn.cursor() as cur:
            cur.execute(f"TRUNCATE {', '.join(DATA_TABLES)}")
        self.conn.commit()

    def select(self, table, equals=None, ranges=None, any_of=None, order_by=None, limit=None, offset=0):
        """As MemoryStore.select; parameterized SQL, column names from
        TABLE_COLS only."""
        equals, ranges, any_of, order_by = _select_args(table, equals, ranges, any_of, order_by)
        where, args = [], []
        for c, v in equals.items():
            if v is None:
                where.append(f"{c} IS NULL")
            else:
                where.append(f"{c} = %s")
                args.append(_db(c, v))
        for c, (lo, hi) in ranges.items():
            if lo is not None:
                where.append(f"{c} >= %s")
                args.append(lo)
            if hi is not None:
                where.append(f"{c} <= %s")
                args.append(hi)
        for c, vs in any_of.items():
            where.append(f"{c} = ANY(%s)")
            args.append(list(vs))
        sql = f"SELECT {', '.join(TABLE_COLS[table])} FROM {table}"
        if where:
            sql += " WHERE " + " AND ".join(where)
        if order_by:
            sql += " ORDER BY " + ", ".join(f"{c.lstrip('-')} {'DESC' if c.startswith('-') else 'ASC'} NULLS LAST"
                                            for c in order_by)
        if limit is not None:
            sql += " LIMIT %s"
            args.append(limit)
        if offset:
            sql += " OFFSET %s"
            args.append(offset)
        self.flush()
        return self._all(sql, args)

    def rows(self, table):
        self.flush()
        return self._all(f"SELECT * FROM {table}")


def _db(col, value):
    if col in JSON_COLS:
        return json.dumps(value, sort_keys=True)
    return value


def _in_range(v, lo, hi):
    if v is None:
        return lo is None and hi is None
    return (lo is None or v >= lo) and (hi is None or v <= hi)


class ReadOnlyStore:
    """What the Exp. 5 interfaces and the GRE may call: reads only. A second
    line behind the read-only Postgres role (tgs_reader)."""

    READS = ("select", "latest_incident_record", "alias", "snapshot", "witnesses_present", "offsets",
             "completeness_for", "finding_types", "next_seq", "end_call")

    def __init__(self, store):
        self._store = store

    def __getattr__(self, name):
        if name in self.READS:
            return getattr(self._store, name)
        raise AttributeError(f"{name} is not available on a read-only store")
