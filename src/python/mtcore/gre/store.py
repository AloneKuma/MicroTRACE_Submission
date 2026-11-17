"""GRE durable state: the nonce store and the attempt records A_resp.

MemoryGreStore and PgGreStore have the same semantics; the GRE tests run on
both, the Postgres ones only when it is reachable. consume_nonce is the one
atomic step: of any number of concurrent calls with one nonce, exactly one
returns True.
"""
import json
import os
import threading

SCHEMA_VERSION = "gre-schema-3"
SCHEMA_SQL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
ATTEMPT_COLS = ("attempt_id", "rid", "gid", "act", "uid", "ts", "status", "reason", "ref_audit", "ref_verify",
                "request")
STATUSES = ("Rejected", "Submitted", "Verified", "Failed", "Unresolved")
INTENT_COLS = ("intent_id", "rid", "nonce", "act", "service_account", "path", "user_agent", "planned_at", "request",
               "postcondition", "resolved_attempt_id", "verified_attempt_id")
JSON_COLS = ("request", "postcondition")


class MemoryGreStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.nonces, self._attempts, self._intents = {}, [], []

    def consume_nonce(self, nonce, rid, keep_until, now, request=None):
        with self._lock:
            if nonce in self.nonces:
                return False
            self.nonces[nonce] = {"nonce": nonce, "rid": rid, "keep_until": keep_until, "consumed_at": now,
                                  "request": request, "closed_attempt_id": None}
            return True

    def close_nonce(self, nonce, attempt_id):
        with self._lock:
            if nonce in self.nonces:
                self.nonces[nonce]["closed_attempt_id"] = attempt_id

    def unclosed_nonces(self, consumed_before):
        """Accepted requests with no outcome row and no intent: their GRE
        stopped before it could have written anything."""
        with self._lock:
            planned = {i["nonce"] for i in self._intents}
            return [dict(n) for n in sorted(self.nonces.values(), key=lambda n: n["consumed_at"])
                    if n["closed_attempt_id"] is None and n["nonce"] not in planned
                    and n["consumed_at"] < consumed_before]

    def record_intent(self, row):
        with self._lock:
            out = dict(row, intent_id=len(self._intents) + 1, resolved_attempt_id=None, verified_attempt_id=None)
            out.setdefault("postcondition", None)
            self._intents.append(out)
            return dict(out)

    def resolve_intent(self, intent_id, attempt_id):
        with self._lock:
            self._intents[intent_id - 1]["resolved_attempt_id"] = attempt_id

    def open_intents(self):
        """Intents not closed, or closed only as Unresolved."""
        with self._lock:
            status = {a["attempt_id"]: a["status"] for a in self._attempts}
            return [dict(i) for i in self._intents
                    if i["resolved_attempt_id"] is None or status.get(i["resolved_attempt_id"]) == "Unresolved"]

    def pending_verification(self):
        """Intents whose write was Submitted and whose effect is not yet
        Verified or Failed, each with the Submitted row's ref_audit."""
        with self._lock:
            by_id = {a["attempt_id"]: a for a in self._attempts}
            out = []
            for i in self._intents:
                sub, ver = by_id.get(i["resolved_attempt_id"]), by_id.get(i["verified_attempt_id"])
                if sub and sub["status"] == "Submitted" and (ver is None or ver["status"] == "Unresolved"):
                    out.append(dict(i, ref_audit=sub["ref_audit"],
                                    verified_status=ver["status"] if ver else None))
            return out

    def finish_verification(self, row, intent_id):
        """Append a verification's A_resp row and point the intent at it."""
        with self._lock:
            out = dict(row, attempt_id=len(self._attempts) + 1)
            self._attempts.append(out)
            self._intents[intent_id - 1]["verified_attempt_id"] = out["attempt_id"]
            return dict(out)

    def purge_nonces(self, now):
        """Delete nonces whose keep_until has passed and whose request has an
        outcome row; an unreconciled one stays. Returns how many."""
        with self._lock:
            old = [n for n, r in self.nonces.items() if r["keep_until"] < now and r["closed_attempt_id"] is not None]
            for n in old:
                del self.nonces[n]
            return len(old)

    def record_attempt(self, row):
        return self.finish_attempt(row)

    def finish_attempt(self, row, intent_id=None, nonce=None):
        """Append one A_resp row and, in the same step, close the intent and
        the nonce it answers, so a crash never leaves one without the other."""
        with self._lock:
            out = dict(row, attempt_id=len(self._attempts) + 1)
            self._attempts.append(out)
            if intent_id is not None:
                self._intents[intent_id - 1]["resolved_attempt_id"] = out["attempt_id"]
            if nonce is not None and nonce in self.nonces:
                self.nonces[nonce]["closed_attempt_id"] = out["attempt_id"]
            return dict(out)

    def attempts(self, rid=None):
        with self._lock:
            return [dict(a) for a in self._attempts if rid is None or a["rid"] == rid]


class PgGreStore:
    """On a connection whose search_path reaches the GRE tables (schema gre
    for role gre_exec; a private schema in tests). Every method commits."""

    def __init__(self, conn):
        self.conn = conn

    def apply_schema(self):
        with open(SCHEMA_SQL, encoding="utf-8") as fh:
            ddl = fh.read()
        with self.conn.cursor() as cur:
            cur.execute(ddl)
            cur.execute("INSERT INTO gre_schema_version VALUES (%s) ON CONFLICT DO NOTHING", (SCHEMA_VERSION,))
        self.conn.commit()

    def consume_nonce(self, nonce, rid, keep_until, now, request=None):
        try:
            with self.conn.cursor() as cur:
                cur.execute("INSERT INTO gre_nonces (nonce, rid, keep_until, consumed_at, request) "
                            "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (nonce) DO NOTHING RETURNING 1",
                            (nonce, rid, keep_until, now, _json(request)))
                won = cur.fetchone() is not None
            self.conn.commit()
            return won
        except BaseException:
            self.conn.rollback()
            raise

    def close_nonce(self, nonce, attempt_id):
        self._exec("UPDATE gre_nonces SET closed_attempt_id = %s WHERE nonce = %s", (attempt_id, nonce))

    def unclosed_nonces(self, consumed_before):
        return self._rows("SELECT nonce, rid, keep_until, consumed_at, request, closed_attempt_id FROM gre_nonces n "
                          "WHERE closed_attempt_id IS NULL AND consumed_at < %s "
                          "AND NOT EXISTS (SELECT 1 FROM gre_intents i WHERE i.nonce = n.nonce) "
                          "ORDER BY consumed_at", (consumed_before,))

    def record_intent(self, row):
        cols = [c for c in INTENT_COLS if c not in ("intent_id", "resolved_attempt_id", "verified_attempt_id")]
        vals = [_json(row.get(c)) if c in JSON_COLS else row[c] for c in cols]
        [(iid,)] = self._exec(f"INSERT INTO gre_intents ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                              "RETURNING intent_id", vals, fetch=True)
        return dict(row, intent_id=iid, resolved_attempt_id=None, verified_attempt_id=None,
                    postcondition=row.get("postcondition"))

    def resolve_intent(self, intent_id, attempt_id):
        self._exec("UPDATE gre_intents SET resolved_attempt_id = %s WHERE intent_id = %s", (attempt_id, intent_id))

    def open_intents(self):
        return self._rows(f"SELECT {', '.join('i.' + c for c in INTENT_COLS)} FROM gre_intents i "
                          "LEFT JOIN gre_attempts a ON a.attempt_id = i.resolved_attempt_id "
                          "WHERE i.resolved_attempt_id IS NULL OR a.status = 'Unresolved' ORDER BY i.intent_id")

    def pending_verification(self):
        return self._rows(f"SELECT {', '.join('i.' + c for c in INTENT_COLS)}, s.ref_audit, "
                          "v.status AS verified_status FROM gre_intents i "
                          "JOIN gre_attempts s ON s.attempt_id = i.resolved_attempt_id "
                          "LEFT JOIN gre_attempts v ON v.attempt_id = i.verified_attempt_id "
                          "WHERE s.status = 'Submitted' AND (v.attempt_id IS NULL OR v.status = 'Unresolved') "
                          "ORDER BY i.intent_id")

    def finish_verification(self, row, intent_id):
        """As MemoryGreStore.finish_verification, in one transaction."""
        cols = [c for c in ATTEMPT_COLS if c != "attempt_id"]
        vals = [_json(row.get(c)) if c == "request" else row.get(c, "") for c in cols]
        try:
            with self.conn.cursor() as cur:
                cur.execute(f"INSERT INTO gre_attempts ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                            "RETURNING attempt_id", vals)
                aid = cur.fetchone()[0]
                cur.execute("UPDATE gre_intents SET verified_attempt_id = %s WHERE intent_id = %s", (aid, intent_id))
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        return dict(row, attempt_id=aid)

    def _exec(self, sql, args=(), fetch=False):
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, args)
                out = cur.fetchall() if fetch else None
            self.conn.commit()
            return out
        except BaseException:
            self.conn.rollback()
            raise

    def _rows(self, sql, args=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            names = [d.name for d in cur.description]
            rows = [dict(zip(names, r)) for r in cur.fetchall()]
        self.conn.commit()
        return rows

    def purge_nonces(self, now):
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM gre_nonces WHERE keep_until < %s AND closed_attempt_id IS NOT NULL", (now,))
            n = cur.rowcount
        self.conn.commit()
        return n

    def record_attempt(self, row):
        return self.finish_attempt(row)

    def finish_attempt(self, row, intent_id=None, nonce=None):
        """As MemoryGreStore.finish_attempt, in one transaction."""
        cols = [c for c in ATTEMPT_COLS if c != "attempt_id"]
        vals = [_json(row.get(c)) if c == "request" else row.get(c, "") for c in cols]
        try:
            with self.conn.cursor() as cur:
                cur.execute(f"INSERT INTO gre_attempts ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                            "RETURNING attempt_id", vals)
                aid = cur.fetchone()[0]
                if intent_id is not None:
                    cur.execute("UPDATE gre_intents SET resolved_attempt_id = %s WHERE intent_id = %s",
                                (aid, intent_id))
                if nonce is not None:
                    cur.execute("UPDATE gre_nonces SET closed_attempt_id = %s WHERE nonce = %s", (aid, nonce))
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        return dict(row, attempt_id=aid)

    def attempts(self, rid=None):
        sql = f"SELECT {', '.join(ATTEMPT_COLS)} FROM gre_attempts"
        args = ()
        if rid is not None:
            sql, args = sql + " WHERE rid = %s", (rid,)
        with self.conn.cursor() as cur:
            cur.execute(sql + " ORDER BY attempt_id", args)
            rows = [dict(zip(ATTEMPT_COLS, r)) for r in cur.fetchall()]
        self.conn.commit()
        return rows


def _json(v):
    return json.dumps(v, sort_keys=True, default=str) if v is not None else None
