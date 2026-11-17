"""Link admission, part 1 (build step 5b): Supported and TimeValid for one
ordered finding pair (i, j) and one witness type w (D3_v4.tex eqs.
witness-support and witness-time; proofs/correlator_ref.py:166-197).

Supported(w) = EvidenceValid and InstanceMatch and SensorKey and DirectionValid
- EvidenceValid: i has a source event and j a target event under the key.
- InstanceMatch: both findings carry the same kappa_w (the index key).
- SensorKey: the key is sensor-originated and its evidence is not degraded
  (node-trust epochs: build step 5c). A workload-set key (KeyEvents.origin
  WORKLOAD; trace and request IDs a caller sets, B5) never supports a link;
  the No-Origin ablation treats it as sensor-set (A2).
- DirectionValid: process types need the source event before the target in
  node_seq on the same node and boot; NETWORK_FLOW needs i's CONNECT and j's
  ACCEPT (roles fixed by keys.py); REQUEST_IDENTITY needs i's event to carry
  the minted ID and j's a different event with that ID. Timestamps never set
  direction.
- Ancestry (A1): process types also need the source event's process to be
  the target's or an ancestor of it on the recorded parent chain
  (lineage.py); a chain broken by a lost birth leaves the pair UNPROVEN.

TimeValid(w): with D = t_j - t_i, eps = unc_i + unc_j, delta = max(0, D - eps):
D + eps >= 0 and delta <= W_w and eps <= eps_bar. Ablation no_uncertainty
(Exp. 3 No-Uncertainty) tests this on nominal timestamps (eps = 0).

Every ordered event pair the evidence allows is tested; the witness uses a
time-valid one if any exists (a finding may hold several events per key).

Part 2 (build step 5c) turns a decision into a witness status:
- Covered: every source able to carry a decisive contradiction for the type
  (eBPF on the pair's node or nodes) reports no loss or idle gap over
  I = [t_src - eps, t_tgt + eps], and no node-trust epoch on those nodes
  opens before max(I) + beta, except the epoch opened by the pair's own
  target event (a link into the compromise) when it degrades none of the
  pair's contradictions. Unknown loss is not no loss, so coverage is
  decided only once the watermark has passed max(I) + beta (engine). A gap
  scoped to eBPF families counts only if it names a family the check reads:
  the pair's own events and the families its contradictions show in
  (CHECK_FAMILIES).
  Ablation no_coverage (Exp. 3 No-Coverage) ignores every loss and idle
  record here and in DistinctAction: missing observations are taken as
  complete. Epochs still apply (No-Epoch, No-ContraCoverage are separate).
- DistinctAction: equal verified action IDs are one action; different ones
  are distinct. Without both IDs the findings' operation evidence decides
  (disjoint input events), but only when their sources report no loss within
  A (+ beta) of both findings (a family-scoped gap only on the findings' own
  input families); otherwise distinctness is unresolved.
- Status: evidence valid only without degradation -> POST_COMPROMISE; a
  decisive contradiction, the same action, or a time-invalid pair ->
  REJECTED; uncovered or unresolved distinctness -> UNPROVEN; else CONFIRMED.
"""
from dataclasses import dataclass

from microtrace.v0 import common_pb2, witness_pb2

from mtcore.agents.completeness import ABSTAIN_REASONS
from mtcore.orchestrator import keys as K
from mtcore.orchestrator import lineage
from mtcore.orchestrator.keys import (ENTITY_COMPAT, HOST_TRANSITION, NETWORK_FLOW, PROCESS_ANCESTRY, REQUEST_IDENTITY,
                                     SENSOR, WORKLOAD)

# eBPF families in which a type's contradictions show: a container-instance
# change on a lineage appears at exec; a reused client port at connect.
CHECK_FAMILIES = {PROCESS_ANCESTRY: frozenset({"proc.exec"}),
                  HOST_TRANSITION: frozenset({"proc.exec", "ns.change"}),
                  NETWORK_FLOW: frozenset({"net.connect"})}


@dataclass
class PairDecision:
    source_fid: str
    target_fid: str
    wtype: int
    key: tuple
    join_key: str
    source_ev: object = None
    target_ev: object = None
    delta_ns: int = None           # D = t_j - t_i
    eps_ns: int = None
    slack_ns: int = None           # delta = max(0, D - eps)
    supported: bool = False
    time_valid: bool = False
    chain_unresolved: bool = False     # process types: a birth on the target's chain was lost
    origin: int = 0                    # common_pb2.KeyOrigin of the key (WORKLOAD only under no_origin)
    reason: str = ""

    @property
    def passes(self):
        """Both gates built so far hold."""
        return self.supported and self.time_valid


def degraded(ev):
    """No epoch known: nothing is degraded (the engine passes EpochIndex.degraded)."""
    return False


def _seq(ev):
    return ev.ebpf.node_seq


def _pairs(wtype, src_ke, tgt_ke):
    """Every ordered (source Ev, target Ev) the evidence allows. Process types:
    each target with every source before it in node_seq (the latest may be a
    sibling's while an earlier one is the ancestor's; R7). NETWORK_FLOW:
    every CONNECT with every ACCEPT of the same tuple. REQUEST_IDENTITY:
    every event carrying the minted ID with every other event carrying it."""
    if wtype == NETWORK_FLOW:
        return [(s, t) for s in src_ke.sources for t in tgt_ke.targets]
    if wtype == REQUEST_IDENTITY:
        return [(s, t) for s in src_ke.sources for t in tgt_ke.targets if s.id != t.id]
    if wtype == ENTITY_COMPAT:                   # No-Witness: direction by time only
        return [(s, t) for t in tgt_ke.targets for s in src_ke.sources
                if s.id != t.id and s.t is not None and t.t is not None and s.t <= t.t]
    return [(s, t) for t in tgt_ke.targets for s in src_ke.sources if _seq(s) < _seq(t)]


def _on_chain(pairs, tree, src_ke, tgt_ke):
    """Process types (A1): the pairs whose source process is the target's or
    one of its ancestors; failing that, the pairs whose chain is unknown
    (a lost birth), flagged. Returns (pairs, unresolved)."""
    if tree is None:
        return pairs, False
    extra = list(src_ke.sources) + list(tgt_ke.targets)
    rel = [(p, tree.relation(p[0], p[1], extra)) for p in pairs]
    proven = [p for p, r in rel if r in (lineage.SAME, lineage.ANCESTOR)]
    if proven:
        return proven, False
    return [p for p, r in rel if r == lineage.UNKNOWN], True


def _timing(src, tgt, wtype, oparams):
    """(time-valid, D, eps, delta) for one ordered pair; None without times."""
    if src.t is None or tgt.t is None:
        return None
    delta = tgt.t - src.t
    eps = src.unc + tgt.unc
    # No-Uncertainty (Exp. 3): TimeValid on nominal timestamps, every clock
    # uncertainty 0. eps is still returned (the witness and the coverage
    # interval keep the declared uncertainty); only the validity test changes.
    eps_tv = 0 if oparams.ablated("no_uncertainty") else eps
    slack = max(0, delta - eps_tv)
    ok = delta + eps_tv >= 0 and slack <= oparams.window_ns(wtype)
    if not oparams.ablated("no_eps_cap"):          # proofs weakened variant, not a paper ablation
        ok = ok and eps_tv <= oparams.eps_bar_ns
    return ok, delta, eps, slack


def decide(i, j, wtype, key, keys_i, keys_j, oparams, is_degraded=degraded, tree=None):
    """PairDecision for source finding i and target finding j under (wtype, key).
    keys_*: the findings' {(type, key): KeyEvents} maps. tree: the process
    tree (lineage.ProcessTree) for the process types; None keeps the shared
    lineage as evidence (the pre-A1 rule, ablation no_ancestry_chain). Of all
    ordered event pairs, a time-valid one is chosen if any exists (smallest
    gap first), otherwise the closest one is reported."""
    src_ke, tgt_ke = keys_i.get((wtype, key)), keys_j.get((wtype, key))
    d = PairDecision(i, j, wtype, key, (src_ke or tgt_ke).join_key if (src_ke or tgt_ke) else "")
    if i == j or src_ke is None or tgt_ke is None:
        d.reason = "no shared key"
        return d
    d.origin = WORKLOAD if WORKLOAD in (src_ke.origin, tgt_ke.origin) else SENSOR
    if d.origin == WORKLOAD and not oparams.ablated("no_origin"):
        d.reason = "workload-set key: a workload can forge it (SensorKey)"
        return d
    pairs = _pairs(wtype, src_ke, tgt_ke)
    if not pairs:
        d.reason = "no source event ordered before a target event"
        return d
    if wtype in (PROCESS_ANCESTRY, HOST_TRANSITION):
        pairs, d.chain_unresolved = _on_chain(pairs, tree, src_ke, tgt_ke)
        if not pairs:
            d.reason = "source process is not the target's or an ancestor of it"
            return d
    pairs = [(s, t) for s, t in pairs if not (is_degraded(s) or is_degraded(t))]
    if not pairs:
        d.reason = "key evidence degraded"
        return d
    d.supported = True
    timed = [(p, _timing(p[0], p[1], wtype, oparams)) for p in pairs]
    timed = [(p, tm) for p, tm in timed if tm is not None]
    if not timed:
        d.source_ev, d.target_ev = pairs[0]
        d.reason = "event time absent"
        return d
    # valid pairs first, then the smallest gap |D|, then stable event IDs
    (src, tgt), (ok, delta, eps, slack) = min(
        timed, key=lambda pt: (not pt[1][0], abs(pt[1][1]), pt[0][0].id, pt[0][1].id))
    d.source_ev, d.target_ev = src, tgt
    d.delta_ns, d.eps_ns, d.slack_ns, d.time_valid = delta, eps, slack, ok
    if not ok:
        d.reason = "outside the witness window or uncertainty cap"
    return d


# ---------------------------------------------------------------- part 2 (5c)
ST = witness_pb2.WitnessStatus
EBPF = common_pb2.Source.Value("EBPF")
IDLE = common_pb2.GapReason.Value("SOURCE_IDLE")


def interval(d):
    """Contradiction interval I of a decision, as (lo, hi) in ns."""
    eps = d.eps_ns or 0
    return d.source_ev.t - eps, d.target_ev.t + eps


def coverage_due(d, oparams):
    """Watermark at which the loss and epoch records for I are known: records
    from I arrive by max(I) + beta, and an epoch trigger whose onset (event
    time minus uncertainty) falls before that is processed by then if its
    uncertainty is within eps_bar. A trigger with a larger uncertainty is
    caught by the engine re-checking published witnesses when an epoch opens."""
    return interval(d)[1] + oparams.beta_ns + oparams.eps_bar_ns


def _nodes(d):
    """(node, boot) of the contradiction-capable sources: the pair's eBPF nodes."""
    return sorted({(e.ebpf.node_id, e.ebpf.boot_id) for e in (d.source_ev, d.target_ev) if e.ebpf is not None})


def self_triggered(d, epochs, node, boot):
    """The epoch on (node, boot) opens at d's own target event: that event is a
    trigger event on this node and its onset is the epoch's onset."""
    tgt = d.target_ev
    return (tgt is not None and tgt.ebpf is not None and (tgt.ebpf.node_id, tgt.ebpf.boot_id) == (node, boot)
            and tgt.id in epochs.trigger_events and tgt.t is not None
            and tgt.t - tgt.unc == epochs.onset(node, boot))


def covered(d, gaps, epochs, oparams, contradictions=()):
    """(covered, [ContradictionCoverage]) for decision d. An epoch opened by d's
    own target event (a link into the compromise itself) leaves the interval
    covered unless it degrades one of d's contradictions: those are the only
    records the epoch could have made nondecisive (proofs/correlator_ref.py)."""
    lo, hi = interval(d)
    loss = idle = epoch = False
    families = CHECK_FAMILIES.get(d.wtype, frozenset()) | _families((d.source_ev, d.target_ev))
    use_gaps = not oparams.ablated("no_coverage")   # No-Coverage: loss and idle records ignored
    # Scoped loss (params scoped_loss): only loss of records on the pair's own witness key counts.
    keys = K.pair_loss_keys(d.wtype, d.source_ev, d.target_ev) if getattr(oparams, "scoped_loss", False) else None
    for node, boot in _nodes(d):
        for reason in (gaps.query({EBPF}, {node}, lo, hi, families=families, keys=keys) if use_gaps else ()):
            if reason == IDLE:
                idle = True
            elif reason in ABSTAIN_REASONS:
                loss = True
        tau = epochs.onset(node, boot)
        if tau is not None and tau <= hi + oparams.beta_ns:
            exempt = (not oparams.ablated("no_trigger_exemption") and self_triggered(d, epochs, node, boot)
                      and not any(c.degraded for c in contradictions))
            epoch = epoch or not exempt
    cov = witness_pb2.ContradictionCoverage(source=EBPF, loss_overlap=loss, idle_overlap=idle, epoch_overlap=epoch)
    return not (loss or idle or epoch), [cov]


def _families(events):
    """eBPF event families of the given events."""
    return frozenset(e.family for e in events if e is not None and e.ebpf is not None and e.family)


def _sources_of(events):
    """{(source, node or None)} that delivered a finding's input events."""
    return {(e.source, e.ebpf.node_id if e.ebpf is not None else None) for e in events}


def aid_covered(finding, events, t, gaps, oparams):
    """The finding's sources report no loss within A (+ beta) of it, so a
    missing action ID means "no ID", not "lost ID"."""
    if not events:
        return False
    if oparams.ablated("no_coverage"):             # No-Coverage: missing observations taken as complete
        return True
    lo, hi = t - oparams.A_ns, t + oparams.A_ns + oparams.beta_ns
    families = _families(events) or None
    # Scoped loss: only loss of records on the finding's own lineages or flows could have carried
    # its action ID (action IDs come from a finding's own input events); unkeyed gaps still count.
    keys = None
    if getattr(oparams, "scoped_loss", False):
        per = [K.loss_keys(e) for e in events]
        # an eBPF input without a lineage or flow key leaves the check node-wide, as before
        if all(k or e.ebpf is None for k, e in zip(per, events)):
            keys = frozenset().union(*per)
    for src, node in sorted(_sources_of(events), key=repr):
        if gaps.query({src}, {node} if node else None, lo, hi, families=families, keys=keys):
            return False
    return True


def distinct_action(fi, fj, ev_i, ev_j, t_i, t_j, gaps, oparams):
    """True, False, or None (unresolved)."""
    ai = fi.action_id if fi.HasField("action_id") and fi.action_id else None
    aj = fj.action_id if fj.HasField("action_id") and fj.action_id else None
    if ai is not None and aj is not None:
        return ai != aj
    if not (aid_covered(fi, ev_i, t_i, gaps, oparams) and aid_covered(fj, ev_j, t_j, gaps, oparams)):
        return None
    return not (set(fi.input_event_ids) & set(fj.input_event_ids))


def status(d_trusted, d_evidence, contradictions, is_covered, distinct, oparams):
    """Witness status from the trusted decision (epochs applied), the
    evidence-only decision (no epochs), and the remaining gates."""
    if not d_trusted.supported:
        return ST.Value("POST_COMPROMISE") if d_evidence.passes else ST.Value("REJECTED")
    if not d_trusted.time_valid:
        return ST.Value("REJECTED")
    if not oparams.ablated("no_conflict") and any(c.decisive for c in contradictions):
        return ST.Value("REJECTED")
    if not oparams.ablated("no_distinct"):
        if distinct is False:
            return ST.Value("REJECTED")
        if distinct is None:
            return ST.Value("UNPROVEN")
    if not oparams.ablated("no_contra_coverage") and not is_covered:
        return ST.Value("UNPROVEN")
    if d_trusted.chain_unresolved:
        return ST.Value("UNPROVEN")
    return ST.Value("CONFIRMED")


# ---------------------------------------------------------------- enabling (5d)
def decide_enabling(i, j, wtype, key, keys_i, keys_j):
    """PairDecision for an enabling witness (IMAGE_CLASS): i's admission names
    the digest that j's container runs. No window applies; the only order
    check is that the admission does not come after the run (within both
    uncertainties). Enabling witnesses never license a link."""
    src_ke, tgt_ke = keys_i.get((wtype, key)), keys_j.get((wtype, key))
    d = PairDecision(i, j, wtype, key, key if isinstance(key, str) else "")
    if i == j or src_ke is None or tgt_ke is None or not src_ke.sources or not tgt_ke.targets:
        d.reason = "no shared key"
        return d
    pairs = [(s, t) for s in src_ke.sources for t in tgt_ke.targets
             if s.t is not None and t.t is not None and s.t <= t.t + s.unc + t.unc]
    if not pairs:
        d.reason = "admission after the run"
        return d
    d.source_ev, d.target_ev = min(pairs, key=lambda p: (p[1].t - p[0].t, p[0].id, p[1].id))
    d.delta_ns = d.target_ev.t - d.source_ev.t
    d.eps_ns = d.source_ev.unc + d.target_ev.unc
    d.slack_ns = max(0, d.delta_ns - d.eps_ns)
    d.supported = d.time_valid = True
    return d
