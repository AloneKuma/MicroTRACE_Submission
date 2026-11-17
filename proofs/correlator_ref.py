#!/usr/bin/env python3
"""Reference correlator: an executable transcription of MicroTRACE Phase 3.

This is NOT the production pipeline (experiments/slice/ has no multi-finding correlation).
It exists to test the Section IV claims of the paper (Props. 1-3, Lemma 1) on
randomized scenarios. Each predicate below names the paper equation it encodes.

Abstractions:
  * One supporting event per (finding, witness type). The finding record carries
    its index keys (kappa_w); the event record carries the evidence (time,
    source, direction rank, receipt time) and may be missing or deleted.
  * Every evidence item has an event time `t` and an off-node receipt time
    `recv` (data). The GO arrival time `arr` is NOT data: it only orders the
    stream and is varied to test order invariance.
  * Sources: agent@<node> (on-node, can be degraded), audit, admission, ctx,
    offnode (off-node, never degraded).
Stdlib only; Python >= 3.10.
"""

import math
from dataclasses import dataclass, field

TYPES = ("request", "process", "api", "credential", "artifact", "host")
AGENT_TYPES = ("request", "process")
TYPE_SRC = {"api": "audit", "credential": "audit", "artifact": "admission", "host": "offnode"}
LINK_SRC = ("ctx",)  # sources able to carry a decisive link-level contradiction


@dataclass
class Params:
    W: dict = field(default_factory=lambda: {"request": 30.0, "process": 60.0, "api": 40.0,
                                             "credential": 120.0, "artifact": 300.0, "host": 90.0})
    eps_bar: float = 5.0          # per-type uncertainty cap (same for all types here)
    A: float = 10.0               # finding ordering time vs supporting events
    lateness: float = 20.0        # Lambda
    beta: float = 8.0             # max receipt delay
    beta_onset: float = 8.0       # ship-latency bound under which a trigger's own evidence stays trusted
    eps_unknown: float = 1e6      # uncertainty with no clock record
    drift: float = 0.05           # uncertainty growth per second since last clock record
    eps_conv: float = 0.1
    cover_end: float = 1000.0
    lam: float = 1.0
    K: int = 2
    L: int = 6
    T: float = 10_000.0
    q_w: dict = field(default_factory=lambda: {"request": 0.9, "process": 0.95, "api": 0.9,
                                               "credential": 0.85, "artifact": 0.8, "host": 0.7})
    q_unmapped: float = 0.6
    pair_window: float = 30.0     # only used by the superseded tactic_pair_window variant

    def H(self, w):               # Lemma 1 posting horizon
        return self.W[w] + self.eps_bar + 2 * self.A


@dataclass
class Variant:
    """Flags reproducing weaker designs. All False/None = the paper's design."""
    no_origin: bool = False             # workload keys may confirm; workload contradictions decisive
    no_eps_cap: bool = False            # TimeValid without eps_w <= eps_bar
    covered_witness_only: bool = False  # Covered ignores link-level contradiction sources
    single_eval: bool = False           # each pair evaluated once, at retrieval
    first_arrival_dedup: bool = False   # duplicate keeps the first-ingested (arrival-order) finding
    horizon_scale: float = 1.0          # < 1 shortens H_w
    truncate: int | None = None         # cap postings per key
    evict_by_watermark: bool = False    # evict by raw watermark instead of processing frontier
    tactic_pair_window: bool = False    # superseded spec gate
    distinct_no_coverage: bool = False  # DistinctAction falls back without action-ID coverage (D3_v1 text)
    covered_epoch_event_time: bool = False  # Covered checks epochs only to the interval end (D3_v1 text)
    no_trigger_exemption: bool = False  # Covered counts the epoch the target's own trigger opened (D3_v5 text)


# ---------------------------------------------------------------- evidence
def src_node(src):
    return src.split("@", 1)[1] if src.startswith("agent@") else None


class Evidence:
    """Evidence set E. Lists of dicts; deletion = removal + a loss record."""

    def __init__(self, findings, events, actions, contras, clocks, losses, triggers, C):
        self.findings = findings    # fid -> dict(t,node,inst,tactic,keys{w:k},wkeys{w:k})
        self.events = events        # list dict(id,fid,w,t,src,dirrank,recv)
        self.actions = actions      # list dict(id,fid,kind:'aid'|'opsig',val,t,src,recv)
        self.contras = contras      # list dict(id,a,b,w|None,origin,src,t,recv,producer)
        self.clocks = clocks        # list dict(id,src,t,eps,recv)
        self.losses = losses        # list dict(id,src,lo,hi,tau,t,recv)   (not deletable)
        self.triggers = triggers    # list dict(id,node,t,eps,recv,src[,fid]); fid: the finding it is evidence of
        self.C = C                  # adversary-controlled instances
        self._index()

    def _index(self):
        self.ev = {(e["fid"], e["w"]): e for e in self.events}
        self.act = {}
        for a in self.actions:
            self.act[(a["fid"], a["kind"])] = a["val"]
        self.ctr = {}
        for c in self.contras:
            self.ctr.setdefault(frozenset((c["a"], c["b"])), []).append(c)
        self.clk = {}
        # Clock records of one source at the same time: the largest uncertainty
        # sorts last, so eps_of is conservative and does not depend on the order
        # in which the records arrived (seed 105 found an arrival-order tie).
        for c in sorted(self.clocks, key=lambda c: (c["t"], c["eps"], c["id"])):
            self.clk.setdefault(c["src"], []).append(c)

    def items(self):
        for kind in ("events", "actions", "contras", "clocks", "triggers"):
            for it in getattr(self, kind):
                yield kind, it

    def copy(self, **over):
        d = dict(findings=self.findings, events=list(self.events), actions=list(self.actions),
                 contras=list(self.contras), clocks=list(self.clocks), losses=list(self.losses),
                 triggers=list(self.triggers), C=self.C)
        d.update(over)
        return Evidence(**d)


def eps_of(E, e, P):
    """Phase 1 eq. time-normalization: clock + conversion uncertainty of one event."""
    recs = [c for c in E.clk.get(e["src"], []) if c["t"] <= e["t"]]
    if not recs:
        return P.eps_unknown
    c = recs[-1]
    return c["eps"] + P.drift * (e["t"] - c["t"]) + P.eps_conv


def epochs(E):
    """Node-trust epoch onsets tau_N: confirmed (trigger) and suspected (agent gap)."""
    tau = {}
    for g in E.triggers:
        tau[g["node"]] = min(tau.get(g["node"], math.inf), g["t"] - g["eps"])
    for l in E.losses:
        n = src_node(l["src"])
        if n is not None:
            tau[n] = min(tau.get(n, math.inf), l["tau"])
    return tau


def degraded(rec, tau):
    n = src_node(rec["src"])
    return n is not None and rec["recv"] >= tau.get(n, math.inf)


def trigger_own(cx, rec):
    """rec is evidence of a trigger's own finding on the trigger's node, received
    within beta_onset of its event time: it stays trusted after the onset."""
    n = src_node(rec["src"])
    return n is not None and "fid" in rec and rec["recv"] <= rec["t"] + cx.P.beta_onset and any(
        g.get("fid") == rec["fid"] and g["node"] == n for g in cx.E.triggers)


def degraded_ev(cx, rec):
    return degraded(rec, cx.tau) and not trigger_own(cx, rec)


def self_triggered(cx, j, n):
    """Node n's onset is set by a trigger of finding j alone: no other trigger
    and no suspected epoch (loss) opens at or before it."""
    tau = cx.tau.get(n, math.inf)
    own = [g for g in cx.E.triggers if g["node"] == n and g.get("fid") == j and g["t"] - g["eps"] == tau]
    other = [g for g in cx.E.triggers if g["node"] == n and g.get("fid") != j and g["t"] - g["eps"] <= tau]
    lost = [l for l in cx.E.losses if src_node(l["src"]) == n and l["tau"] <= tau]
    return bool(own) and not other and not lost


class Ctx:
    """Per-evaluation context; eps_E / tau_E allow freezing clocks/epochs from another E."""

    def __init__(self, E, P, V, eps_E=None, tau_E=None):
        self.E, self.P, self.V = E, P, V
        self.eps_E = eps_E or E
        self.tau = epochs(tau_E or E)


# ---------------------------------------------------------------- predicates
def witness_src(E, f, w):
    return f"agent@{E.findings[f]['node']}" if w in AGENT_TYPES else TYPE_SRC[w]


def instance_match(cx, i, j, w):
    fi, fj = cx.E.findings[i], cx.E.findings[j]
    ki, kj = fi["keys"].get(w), fj["keys"].get(w)
    if ki is not None and ki == kj:
        return "sensor"
    if cx.V.no_origin:
        wi, wj = fi["wkeys"].get(w), fj["wkeys"].get(w)
        if wi is not None and wi == wj:
            return "workload"
    return None


def supported(cx, i, j, w):
    """eq. witness-support: EvidenceValid & InstanceMatch & SensorKey & DirectionValid."""
    ei, ej = cx.E.ev.get((i, w)), cx.E.ev.get((j, w))
    if ei is None or ej is None:                       # EvidenceValid
        return False
    origin = instance_match(cx, i, j, w)               # InstanceMatch
    if origin is None:
        return False
    if degraded_ev(cx, ei) or degraded_ev(cx, ej):     # SensorKey: non-degraded evidence
        return False
    return ei["dirrank"] < ej["dirrank"]               # DirectionValid (sensor-derived)


def time_gap(cx, i, j, w):
    ei, ej = cx.E.ev[(i, w)], cx.E.ev[(j, w)]
    d = ej["t"] - ei["t"]
    eps = eps_of(cx.eps_E, ei, cx.P) + eps_of(cx.eps_E, ej, cx.P)
    return d, eps


def time_valid(cx, i, j, w):
    """eq. witness-time (+ eps cap)."""
    d, eps = time_gap(cx, i, j, w)
    delta = max(0.0, d - eps)
    ok = (d + eps >= 0) and (delta <= cx.P.W[w])
    if not cx.V.no_eps_cap:
        ok = ok and eps <= cx.P.eps_bar
    if ok and cx.V.tactic_pair_window:
        ti, tj = cx.E.findings[i]["tactic"], cx.E.findings[j]["tactic"]
        if ti is not None and tj is not None:
            ok = delta <= cx.P.pair_window
    return ok


def decisive(cx, c):
    return (c["origin"] == "sensor" or cx.V.no_origin) and not degraded(c, cx.tau)


def conflict_w(cx, i, j, w):
    return any(c["w"] == w and decisive(cx, c) for c in cx.E.ctr.get(frozenset((i, j)), []))


def conflict_L(cx, i, j):
    return any(c["w"] is None and decisive(cx, c) for c in cx.E.ctr.get(frozenset((i, j)), []))


def contra_interval(cx, i, j):
    ti, tj = cx.E.findings[i]["t"], cx.E.findings[j]["t"]
    pad = cx.P.A + cx.P.eps_bar
    return min(ti, tj) - pad, max(ti, tj) + pad


def contra_sources(cx, i, j, w):
    if w in AGENT_TYPES:
        s = {f"agent@{cx.E.findings[i]['node']}", f"agent@{cx.E.findings[j]['node']}"}
    else:
        s = {TYPE_SRC[w]}
    if not cx.V.covered_witness_only:
        s |= set(LINK_SRC)
    return s


def covered(cx, i, j, w):
    """Covered(w): every contradiction-capable source reports no loss/idle/epoch over the interval."""
    lo, hi = contra_interval(cx, i, j)
    for s in contra_sources(cx, i, j, w):
        if hi > cx.P.cover_end:                        # beyond heartbeat frontier = unknown loss
            return False
        if any(l["src"] == s and l["lo"] <= hi and l["hi"] >= lo for l in cx.E.losses):
            return False
        n = src_node(s)
        # A record with event time in [lo, hi] is received by hi + beta, so an epoch that
        # opens before then can degrade a contradiction drawn from the interval.
        horizon = hi if cx.V.covered_epoch_event_time else hi + cx.P.beta
        if n is not None and cx.tau.get(n, math.inf) <= horizon:
            # The target's own trigger opened the epoch: the epoch degrades nothing
            # the pair depends on unless it degrades a contradiction for the pair
            # that would otherwise be decisive (sensor-originated; workload ones never are).
            if not cx.V.no_trigger_exemption and self_triggered(cx, j, n) and not any(
                    c["src"] == s and (c["origin"] == "sensor" or cx.V.no_origin) and degraded(c, cx.tau)
                    for c in cx.E.ctr.get(frozenset((i, j)), [])):
                continue
            return False
    return True


AID_SRC = "audit"


def aid_covered(cx, f):
    """The action-ID source reports no loss around f, so a missing ID means 'no ID', not 'lost ID'."""
    t = cx.E.findings[f]["t"]
    lo, hi = t - cx.P.A, t + cx.P.A + cx.P.beta
    return not any(l["src"] == AID_SRC and l["lo"] <= hi and l["hi"] >= lo for l in cx.E.losses)


def distinct_action(cx, i, j):
    a = cx.E.act
    ai, aj = a.get((i, "aid")), a.get((j, "aid"))
    if ai is not None and aj is not None:
        return ai != aj
    if not cx.V.distinct_no_coverage and not (aid_covered(cx, i) and aid_covered(cx, j)):
        return False                                   # equal IDs may have been suppressed
    oi, oj = a.get((i, "opsig")), a.get((j, "opsig"))
    return oi is not None and oj is not None and oi != oj


def admissible(cx, i, j):
    """eq. admissible-witnesses: D_ij."""
    return [w for w in TYPES
            if supported(cx, i, j, w) and time_valid(cx, i, j, w)
            and not conflict_w(cx, i, j, w) and covered(cx, i, j, w)]


def link(cx, i, j):
    """eq. link-admissibility."""
    if i == j or not distinct_action(cx, i, j) or conflict_L(cx, i, j):
        return False
    return bool(admissible(cx, i, j))


def score(cx, i, j):
    """eq. link-score."""
    ti, tj = cx.E.findings[i]["tactic"], cx.E.findings[j]["tactic"]
    q_ab = cx.P.q_unmapped if ti is None or tj is None else (0.9 if ti != tj else 0.7)
    nondec = sum(1 for c in cx.E.ctr.get(frozenset((i, j)), []) if not decisive(cx, c))
    best = 0.0
    for w in admissible(cx, i, j):
        d, eps = time_gap(cx, i, j, w)
        delta = max(0.0, d - eps)
        best = max(best, cx.P.q_w[w] * q_ab * (0.8 ** nondec) * math.exp(-cx.P.lam * delta / cx.P.W[w]))
    return best


# ---------------------------------------------------------------- dedup, groups, paths
def representatives(E, fids):
    """Canonical dedup: among findings with the same verified action ID, keep the min fid."""
    rep = {}
    for f in sorted(fids):
        aid = E.act.get((f, "aid"))
        if aid is None or aid not in rep:
            rep[aid if aid is not None else ("solo", f)] = f
    return set(rep.values())


def groups(links, t_of=None):
    """Weakly connected components with their canonical anchor: the earliest
    finding by event time, then finding ID (paper eq. group-anchor; design-spec
    "anchor"). Without t_of the smallest ID is used (equal times)."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in links:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    comp = {}
    for x in list(parent):
        comp.setdefault(find(x), set()).add(x)
    key = (lambda f: (t_of[f], f)) if t_of is not None else (lambda f: f)
    return frozenset((min(m, key=key), frozenset(m)) for m in comp.values())


def path_score(p, s):
    m = len(p) - 1
    return math.prod(s[(p[k], p[k + 1])] for k in range(m)) ** (1.0 / m)


def topk_paths(commits, s, t_of, P):
    """Bounded prefix-suffix reconstruction (Step 4) over links in commit order."""
    store, parent = [], {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            x = parent[x]
        return x

    for (u, v) in commits:
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[max(ru, rv)] = min(ru, rv)
        pre = [p for p in store if p[-1] == u] + [(u,)]
        suf = [q for q in store if q[0] == v] + [(v,)]
        for p in pre:
            for q in suf:
                r = p + q
                if len(set(r)) == len(r) and len(r) <= P.L and t_of[r[-1]] - t_of[r[0]] <= P.T:
                    store.append(r)
        store = list(dict.fromkeys(store))
        by = {}
        for p in store:
            by.setdefault(find(p[0]), []).append(p)
        store = [p for g in by.values()
                 for p in sorted(g, key=lambda p: (-path_score(p, s), p))[:P.K]]
    return frozenset(store)


# ---------------------------------------------------------------- exhaustive and streaming
def exhaustive(E, P, V=Variant(), dedup=True, **cxkw):
    cx = Ctx(E, P, V, **cxkw)
    fids = representatives(E, E.findings) if dedup else set(E.findings)
    return {(i, j) for i in fids for j in fids if i != j and link(cx, i, j)}


def stream(E, P, V, arr):
    """Algorithm 2 (CorrelateStream). `arr` maps ('finding', fid) / (kind, id) -> arrival time."""
    items = [("finding", f, E.findings[f]) for f in E.findings]
    items += [(k, it["id"], it) for k, it in E.items()]
    items += [("losses", l["id"], l) for l in E.losses]
    items.sort(key=lambda x: (arr[(x[0], x[1])], x[0], str(x[1])))

    avail = {k: [] for k in ("events", "actions", "contras", "clocks", "triggers", "losses")}
    cur = E.copy(events=[], actions=[], contras=[], clocks=[], triggers=[], losses=[])
    wm, maxt = -math.inf, -math.inf
    pending, processed, arrived = [], [], []   # awaiting watermark; processed; ingestion order
    postings = {w: {} for w in TYPES}     # w -> key -> list[(t, fid)]
    status, retrieved, first_confirm = {}, set(), {}
    tick = [0]

    def rebuild():
        nonlocal cur
        cur = E.copy(events=list(avail["events"]), actions=list(avail["actions"]),
                     contras=list(avail["contras"]), clocks=list(avail["clocks"]),
                     triggers=list(avail["triggers"]), losses=list(avail["losses"]))

    def reps_now():
        if V.first_arrival_dedup:
            seen, out = {}, set()
            for f in arrived:
                aid = cur.act.get((f, "aid"))
                if aid is None:
                    out.add(f)
                elif aid not in seen:
                    seen[aid] = f
                    out.add(f)
            return out
        return representatives(cur, processed)

    def evaluate(pairs):
        cx = Ctx(cur, P, V)
        for (i, j) in pairs:
            ok = link(cx, i, j)
            if ok and not status.get((i, j)):
                tick[0] += 1
                first_confirm[(i, j)] = tick[0]
            status[(i, j)] = ok

    def process(f):
        frontier = E.findings[f]["t"]
        horizon_now = wm if V.evict_by_watermark else frontier
        cands = set()
        for w in TYPES:
            keys = [E.findings[f]["keys"].get(w)]
            if V.no_origin:
                keys.append(("wk", E.findings[f]["wkeys"].get(w)))
            H = P.H(w) * V.horizon_scale
            for k in keys:
                if k is None or k == ("wk", None):
                    continue
                lst = postings[w].setdefault(k, [])
                lst[:] = [(tg, g) for (tg, g) in lst if tg + H >= horizon_now]
                view = lst[-V.truncate:] if V.truncate else lst
                cands |= {g for (_, g) in view}
                lst.append((E.findings[f]["t"], f))
        processed.append(f)
        new = set()
        for g in sorted(cands):
            new |= {(g, f), (f, g)}
        retrieved.update(new)
        evaluate(sorted(new))

    for kind, iid, it in items:
        if kind == "finding":
            pending.append(iid)
            arrived.append(iid)
            maxt = max(maxt, it["t"])
        else:
            avail[kind].append(it)
            rebuild()
            maxt = max(maxt, it["t"])
            if not V.single_eval:
                if kind in ("events", "actions"):
                    aff = {it["fid"]}
                elif kind == "contras":
                    aff = {it["a"], it["b"]}
                else:
                    aff = None          # clocks / triggers / losses affect every pair
                evaluate(sorted(p for p in retrieved if aff is None or p[0] in aff or p[1] in aff))
        wm = maxt - P.lateness
        for f in sorted((f for f in pending if E.findings[f]["t"] <= wm), key=lambda f: (E.findings[f]["t"], f)):
            pending.remove(f)
            process(f)
    wm = math.inf
    for f in sorted(pending, key=lambda f: (E.findings[f]["t"], f)):
        process(f)
    # Seal: no extra re-evaluation here; final status comes from the stream.
    reps = reps_now()
    links = {p for p, ok in status.items() if ok and p[0] in reps and p[1] in reps}
    commits = sorted(links, key=lambda p: first_confirm[p])
    return links, commits
