"""Groups, anchors, scores and paths (D3_v4.tex eqs. link-score, path-score,
group, Step 4; design-spec.md "Correlation"; proofs/correlator_ref.py).

- Canonical dedup: findings that record the same verified action ID are one
  action; the smallest finding ID represents it, whatever arrived first.
- Groups are the weakly connected components of CONFIRMED links between
  representatives. The anchor is the member with the earliest corrected
  event time, then the smallest finding ID (decided 2026-10-09).
- Link score: the strongest witness, never a sum:
  s_ij = max_w q_w * q_e * q_ab * q_c * exp(-lambda * delta_w / W_w), with
  q_e = 1 (no evidence-quality model yet), q_ab = q_unmapped when either end
  has no primary tactic, else the transition table's weight for the
  direction along the ATT&CK tactic order (params.q_ab; 1 under No-Tactic),
  and q_c = 0.8 per nondecisive contradiction.
- Paths: bounded prefix-suffix joins over links in commit order (the order
  in which each link was first CONFIRMED), at most L findings, span at most
  T, no finding twice, the K best per group by geometric-mean score then
  path. Top-K paths depend on commit order; the order is kept for replay.
- Speculative paths: one per ENABLING_ONLY witness touching the group; they
  never enter links, scores or ranked paths.
- Node epochs: every node-trust epoch on a (node, boot) that supplied eBPF
  input to a member.
- Input frontier: per "topic/partition", the largest offset the group cites:
  each member and its inputs, both ends of each speculative path, and the
  contradiction events of each link witness (design-spec.md section 9).
"""
import math
from dataclasses import dataclass, field

from microtrace.v0 import common_pb2, incident_pb2, witness_pb2

from mtcore.orchestrator.keys import ENABLING

ST = witness_pb2.WitnessStatus
CONFIRMED, ENABLING_ONLY = ST.Value("CONFIRMED"), ST.Value("ENABLING_ONLY")
POD = common_pb2.EntityType.Value("POD")


@dataclass
class GroupView:
    anchor_fid: str
    anchor_entity: object        # common_pb2.EntityRef or None
    finding_ids: list            # members, sorted by (order time, finding ID)
    link_witness_ids: list       # CONFIRMED DIRECT witness IDs inside the group
    ranked_paths: list           # incident_pb2.RankedPath (path_id unset)
    speculative_paths: list      # incident_pb2.RankedPath via ENABLING witnesses
    event_start: int             # ns
    event_end: int               # ns
    last_extension: int          # ns: latest event time at which a new finding could still join
    scores: dict = field(default_factory=dict)   # (source, target) -> link score
    node_epochs: list = field(default_factory=list)      # (node, boot, tau_N ns, trigger finding ID), sorted
    input_frontier: dict = field(default_factory=dict)   # "topic/partition" -> offset


def representatives(findings, fids):
    """Among findings with the same action ID keep the smallest finding ID."""
    rep = {}
    for f in sorted(fids):
        fd = findings[f]
        aid = fd.action_id if fd.HasField("action_id") and fd.action_id else None
        key = ("aid", aid) if aid is not None else ("solo", f)
        rep.setdefault(key, f)
    return set(rep.values())


def link_score(w, d, findings, oparams):
    """Score of one CONFIRMED witness w (decision d for its slack)."""
    fa, fb = findings[w.source_finding_id], findings[w.target_finding_id]
    q_ab = oparams.q_ab(fa.primary_tactic if fa.HasField("primary_tactic") else 0,
                        fb.primary_tactic if fb.HasField("primary_tactic") else 0)
    q_c = 0.8 ** sum(1 for c in w.contradictions if not c.decisive)
    slack = d.slack_ns or 0
    return oparams.q_w(w.relationship_type) * q_ab * q_c * math.exp(
        -oparams.lam * slack / oparams.window_ns(w.relationship_type))


def _find(parent, x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def _union(parent, a, b):
    ra, rb = _find(parent, a), _find(parent, b)
    if ra != rb:
        parent[max(ra, rb)] = min(ra, rb)


def path_score(p, s):
    m = len(p) - 1
    return math.prod(s[(p[k], p[k + 1])] for k in range(m)) ** (1.0 / m)


def topk_paths(commits, s, t_of, oparams):
    """Prefix-suffix reconstruction over links in commit order (proofs
    topk_paths). Returns the kept paths as tuples of finding IDs."""
    store, parent = [], {}
    for u, v in commits:
        _union(parent, u, v)
        pre = [p for p in store if p[-1] == u] + [(u,)]
        suf = [q for q in store if q[0] == v] + [(v,)]
        for p in pre:
            for q in suf:
                r = p + q
                if len(set(r)) == len(r) and len(r) <= oparams.L and t_of[r[-1]] - t_of[r[0]] <= oparams.T_ns:
                    store.append(r)
        store = list(dict.fromkeys(store))
        by = {}
        for p in store:
            by.setdefault(_find(parent, p[0]), []).append(p)
        store = [p for g in by.values() for p in sorted(g, key=lambda p: (-path_score(p, s), p))[:oparams.K]]
    return store


def compute(eng):
    """[GroupView] from an Engine's published witnesses, sorted by anchor."""
    p = eng.p
    findings, t_of = eng.findings, eng.order_t
    confirmed = {}                      # (a, b) -> [(witness, decision)]
    enabling = []
    for k, w in eng.published.items():
        if w.status == CONFIRMED:
            confirmed.setdefault(k[:2], []).append((w, eng.decisions[k]))
        elif w.status == ENABLING_ONLY:
            enabling.append(w)
    reps = representatives(findings, {f for pair in confirmed for f in pair})
    pairs = {pr: ws for pr, ws in confirmed.items() if pr[0] in reps and pr[1] in reps}
    s, best = {}, {}
    for pr, ws in pairs.items():
        scored = sorted(((link_score(w, d, findings, p), w.witness_id) for w, d in ws), key=lambda x: (-x[0], x[1]))
        s[pr], best[pr] = scored[0]
    commits = sorted(pairs, key=lambda pr: (eng.commit_seq[pr], pr))
    paths = topk_paths(commits, s, t_of, p)
    # A new finding can join only through an enabled direct type's window.
    window = max((p.window_ns(w) for w in eng.enabled if w not in ENABLING), default=0)
    parent = {}
    for a, b in pairs:
        _union(parent, a, b)
    comps = {}
    for f in list(parent):
        comps.setdefault(_find(parent, f), []).append(f)
    out = []
    for members in comps.values():
        members = sorted(members, key=lambda f: (t_of[f], f))
        mset = set(members)
        anchor = members[0]
        ranked = []
        for path in sorted((q for q in paths if q[0] in mset), key=lambda q: (-path_score(q, s), q)):
            ranked.append(incident_pb2.RankedPath(finding_ids=list(path),
                                                  witness_ids=[best[(path[i], path[i + 1])]
                                                               for i in range(len(path) - 1)],
                                                  score=path_score(path, s)))
        spec = sorted((w for w in enabling if w.source_finding_id in mset or w.target_finding_id in mset),
                      key=lambda w: (w.source_finding_id, w.target_finding_id, w.witness_id))
        speculative = [incident_pb2.RankedPath(finding_ids=[w.source_finding_id, w.target_finding_id],
                                               witness_ids=[w.witness_id]) for w in spec]
        link_ids = sorted(w.witness_id for pr, ws in pairs.items() if pr[0] in mset for w, _d in ws)
        frontier = {}
        for need in ([eng.need.get(f, {}) for f in members]
                     + [eng.need.get(f, {}) for w in spec for f in (w.source_finding_id, w.target_finding_id)]
                     + [eng.wit_need.get(w, {}) for w in link_ids]):
            for tp, off in need.items():
                frontier[tp] = max(frontier.get(tp, -1), off)
        epochs = [(n, b, eng.epochs.onset(n, b), eng.epochs.trigger[(n, b)])
                  for n, b in sorted({nb for f in members for nb in eng.nodes_of.get(f, ())})
                  if eng.epochs.onset(n, b) is not None]
        starts = [_ns(findings[f].event_start) for f in members]
        ends = [_ns(findings[f].event_end) or _ns(findings[f].event_start) for f in members]
        reach = max(t_of[f] for f in members) + window + p.eps_bar_ns
        out.append(GroupView(
            anchor_fid=anchor, anchor_entity=_pod(findings[anchor]), finding_ids=members,
            link_witness_ids=link_ids,
            ranked_paths=ranked, speculative_paths=speculative,
            event_start=min(x for x in starts if x is not None), event_end=max(x for x in ends if x is not None),
            last_extension=min(reach, t_of[anchor] + p.T_ns),
            scores={pr: v for pr, v in s.items() if pr[0] in mset},
            node_epochs=epochs, input_frontier=frontier))
    return sorted(out, key=lambda g: (t_of[g.anchor_fid], g.anchor_fid))


def _ns(ts):
    return ts.seconds * 10**9 + ts.nanos if ts.seconds or ts.nanos else None


def _pod(f):
    for e in f.entities:
        if e.type == POD:
            return e
    return None
