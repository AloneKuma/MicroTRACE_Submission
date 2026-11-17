"""Fail-closed validation of a response request (evaluation-plan.md section 5,
step 7; paper Phase 4, Step 3).

Checks, in order; the first failure rejects:
1. shape: a well-formed R_resp with the action's exact parameters;
2. signature: Ed25519 by a trusted approval key over the whole request;
3. expiry: now < exp, and exp no further ahead than max_ttl + max_skew;
4. scope: the configured cluster, a permitted action, and for namespaced
   actions an application namespace (never a protected one);
5. binding: gid is the incident of v_C;
6. graph: TGS check_approval(v_C, sid): the snapshot was current when issued
   and v_C is still the incident's latest record. A TGS that cannot answer
   rejects;
7. nonce: consumed atomically in durable storage; a nonce already consumed,
   by this or any other GRE instance, rejects.

Guard ablation (7.5; Exp. 5 part B, "each guard is then removed in turn"):
GreConfig.ablate names the guards switched off for one run. Here "nonce"
skips step 7 (a replay executes again) and "snapshot" skips step 6 (a stale
approval executes); "revalidation" and "permissions" act in the executor,
"postcondition" in the choice of verifier. A deployment never sets it.

Any exception inside a check rejects. Every rejection is one A_resp row with
status Rejected and its reason. An accepted request has consumed its nonce;
the executor (7.2) records Submitted and later states. Target revalidation
against the live object is part of execution (7.2), immediately before the
write.
"""
import time
from dataclasses import dataclass, field

from mtcore.gre import request as R
from mtcore.tgs.snapshot import check_approval
from mtcore.tgs.store import ReadOnlyStore

NS = 10**9
GUARDS = ("nonce", "snapshot", "revalidation", "postcondition", "permissions")
PROTECTED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "microtrace",
                                  "microtrace-system"})


@dataclass(frozen=True)
class GreConfig:
    cluster: str
    app_namespaces: frozenset            # the only namespaces namespaced actions may touch
    trusted_keys: dict                   # approval key_id -> Ed25519PublicKey
    actions: frozenset = frozenset(R.ACTIONS)
    max_skew_s: int = 30                 # largest clock difference between approver and GRE instances
    max_ttl_s: int = 900                 # longest approval lifetime accepted
    ablate: frozenset = frozenset()      # guards switched off (7.5); empty outside ablation runs

    def __post_init__(self):
        unknown = set(self.ablate) - set(GUARDS)
        if unknown:
            raise ValueError(f"unknown guards: {sorted(unknown)}")


@dataclass
class Decision:
    accepted: bool
    reason: str
    attempt: dict = field(default=None)


class TgsGraph:
    """The GRE's view of the TGS: check_approval on a read-only store (the
    tgs_reader role in deployment). Each check closes its read transaction,
    so the next one sees the store as it is then."""

    def __init__(self, store):
        self.store = store if isinstance(store, ReadOnlyStore) else ReadOnlyStore(store)

    def check(self, v_c, sid):
        try:
            return check_approval(self.store, v_c, sid)
        finally:
            self.store.end_call()


class Gre:
    def __init__(self, config, graph, store, clock=time.time_ns):
        self.config, self.graph, self.store, self.clock = config, graph, store, clock

    def validate(self, req):
        """Decision for one request; a rejection is recorded as A_resp."""
        now = self.clock()
        try:
            reason = self._check(req, now)
        except Exception as e:                       # fail closed
            reason = f"internal error: {type(e).__name__}"
        if reason is None:
            return Decision(True, "accepted")
        return Decision(False, reason, self._reject(req, now, reason))

    def _check(self, req, now):
        try:
            R.check_shape(req)
        except R.Malformed as e:
            return f"malformed request: {e}"
        ok, why = R.verify(req, self.config.trusted_keys)
        if not ok:
            return why
        exp = req["exp"] * NS
        if now >= exp:
            return "approval expired"
        if exp - now > (self.config.max_ttl_s + self.config.max_skew_s) * NS:
            return "approval expiry too far ahead"
        why = self._scope(req)
        if why:
            return why
        v_c = (req["v_c"]["incident_id"], req["v_c"]["version"], req["v_c"]["record_sha256"])
        if req["gid"] != v_c[0]:
            return "evidence group does not match v_C"
        if "snapshot" not in self.config.ablate:
            try:
                ok, why = self.graph.check(v_c, req["sid"])
            except Exception as e:
                return f"TGS unreachable: {type(e).__name__}"
            if not ok:
                return f"graph check failed: {why}"
        if "nonce" not in self.config.ablate:
            keep_until = exp + self.config.max_skew_s * NS
            if not self.store.consume_nonce(req["nonce"], req["rid"], keep_until, now, request=req):
                return "nonce already used"
        return None

    def _scope(self, req):
        c = self.config
        if req["cluster"] != c.cluster:
            return f"cluster {req['cluster']} is not this GRE's cluster"
        if req["act"] not in c.actions:
            return f"action {req['act']} is not permitted"
        if R.ACTIONS[req["act"]]["namespaced"] and (req["ns"] in PROTECTED_NAMESPACES
                                                    or req["ns"] not in c.app_namespaces):
            return f"namespace {req['ns']} is out of scope"
        return None

    def _reject(self, req, now, reason):
        d = req if isinstance(req, dict) else {}
        row = {"rid": str(d.get("rid", "")), "gid": str(d.get("gid", "")), "act": str(d.get("act", "")),
               "uid": str(d.get("uid", "")), "ts": now, "status": "Rejected", "reason": reason,
               "ref_audit": "", "ref_verify": "", "request": d or None}
        try:
            return self.store.record_attempt(row)
        except Exception:
            return None                                # a lost record never turns a rejection into acceptance


def open_gre(config, gre_dsn=None, reader_dsn=None, **kw):
    """A Gre on the deployment roles: gre_exec for its own tables
    ($MT_GRE_DSN, search_path gre) and tgs_reader for the graph check
    ($MT_TGS_READER_DSN, read-only transactions, 5 s statement timeout)."""
    import os

    import psycopg

    from mtcore.gre.store import PgGreStore
    from mtcore.tgs.store import PgStore
    own = psycopg.connect(gre_dsn or os.environ["MT_GRE_DSN"])
    store = PgGreStore(own)
    store.apply_schema()
    reader = psycopg.connect(reader_dsn or os.environ["MT_TGS_READER_DSN"], options="-c statement_timeout=5000")
    reader.read_only = True
    return Gre(config, TgsGraph(PgStore(reader)), store, **kw)
