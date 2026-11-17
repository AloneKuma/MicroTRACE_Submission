"""Score one run against its generated truth (build step 8; Exp. 1-4).

    python -m mtcore.harness.score --truth RUN/restricted --output out.jsonl [--fault-log faults.jsonl] [--out score.json]
        [--reference-output exhaustive.jsonl --k 2]

Truth: the generator's restricted files (mtgen.truth.write_restricted):
truth_actions.pb, truth_findings.pb, truth_links.pb, length-delimited
GroundTruthAction, FindingOpportunity and ActionLink. Output: JSON lines
{"topic", "record"} for findings.v0, witness.decisions.v0 and incidents.v0
(the agents' and the orchestrator's offline output, or `mtcore.harness.dump
--topics ... --events`); rule.evaluations.v0 lines are counted for the
abstention report, and {"topic", "event", "timestamp_ms"} lines for
norm.events.v0 give the input arrival times for latency. Repeated
deliveries collapse by ID; a witness keeps its last record. Joins are on
logical IDs only, never on offsets (dataset-generator-design.md section 6).

Exp. 1, findings (unit: FindingOpportunity). A finding matches an
opportunity when the types are equal and its input_event_ids intersect the
opportunity's evidence_event_ids. A PRESENT opportunity matched by some
finding is a true positive, unmatched a false negative. A finding is a false
positive when it matches no PRESENT and no UNOBSERVABLE opportunity: it
matches only ABSENT ones (a benign lookalike) or none at all (fired on
background). A finding matching an UNOBSERVABLE opportunity (and no PRESENT
one) is neither, and is reported. precision = TP / (TP + FP), recall =
TP / (TP + FN), per finding type and over all; a type with no PRESENT
opportunity is reported as unsupported (recall None).

Exp. 2, links (unit: directed action pair). Findings map to actions through
GroundTruthAction.rendered_event_ids (a finding maps to every action one of
its input events was rendered for). Each CONFIRMED witness proposes the pairs
(a, b), a an action of its source finding and b one of its target finding,
a != b. A proposed pair with a PRESENT ActionLink is a true positive; with
an UNOBSERVABLE one, neither; any other is a false link, and one with an
ABSENT row (a hard nonlink) is also counted as a violated nonlink. A
confirmed witness whose source or target finding maps to no action is a
false link of its own. A witness whose pairs are all within one action is
reported (intra_action), not scored. Recall = recovered PRESENT pairs /
PRESENT pairs. For true positives, whether some confirming witness has the
row's witness_type is reported (type_agreement).

Exp. 2 scores only links the GO can propose (D-20, exp2-gaps-plan B0a): a
link is scored when both its actions have a PRESENT FindingOpportunity in
the base truth. The GO links findings, so a link with no finding expected at
one end (no opportunity, or only ABSENT or UNOBSERVABLE ones) can never be
confirmed or refused. Unscored links stay in truth and are counted
apart (unscored_links by state): an unscored PRESENT link is not in recall,
a proposed pair on one is neither true nor false (unscored_proposed), and it
is not an edge of the reference paths. A proposed pair on an unscored ABSENT
link is a false link as before: it joins two actions with no PRESENT link.
Same-socket continuity links (bytes counted on the connect's own flow) are
scored: that no witness type of our correlator covers them is a miss, not a
reason to drop them (2026-10-31; D-24 had them unscored). Benign continuity
is unscored, marked by its catalogue reason (two findings of one
benign process, or of a benign process and its benign child, as when a decoy
fires two findings; linking them is neither an attack link nor a mistake).
Link precision and recall are also reported without same-process
continuity rows (without_same_process: their PRESENT links leave the
recall base and their true positives the count; false links stay), which
D-2 reports apart.

A finding can map to several actions (an H1 window over two egress
actions), so one confirmed witness proposes several pairs. When one of them
is PRESENT or UNOBSERVABLE, the witness's pairs with no truth row are
companions of that link (companion_pairs), not false links: the paper's
link F1 is over finding pairs (A3). A pair labelled ABSENT stays false.

Exp. 3, faults: a record the fault log lists as dropped (dropped_unreported,
dropped_reported) is never an observed negative. An opportunity with a
dropped evidence event becomes UNOBSERVABLE for that run (all
evidence_event_ids are treated as required). A PRESENT link becomes
UNOBSERVABLE when its from- or to-action has PRESENT opportunities and every
one of them became UNOBSERVABLE: no finding can be expected at that end. The
truth files are never rewritten. Findings whose inputs include a forged
record are counted (on_forged); they are scored like any other.

Exp. 2, paths (definitions chosen 2026-10-12). Reference paths: every
source-to-sink path of the graph whose edges are the PRESENT ActionLinks
(after the fault adjustment; an UNOBSERVABLE link breaks a chain), with at
least one link. Retained paths: the ranked_paths (top-K per anchor) of each
incident's latest record. A reference path is recovered when one retained
path contains, in order, a distinct finding for each of its actions (a
finding stands for the actions its input events were rendered for), and
every step of that path from the first matched finding to the last is a
supported step (not a false link, as for the false-chain rate below): the
retained path is cut at its false steps and one clean piece must hold the
match (rule A', 2026-11-04). False steps outside the matched stretch do not
count against it; a match that only holds across a false step does not count.
top-K path recall = recovered / reference paths. The rule of 2026-10-12
(in order anywhere in the path, false steps allowed between) is reported as
recovered_loose and top_k_path_recall_loose, a diagnostic. False-chain rate: a
retained path with at least two findings is a false chain when some
consecutive pair is a false link, judged as in the link score (no PRESENT
and no UNOBSERVABLE action pair, not intra-action, or an end that maps to no
action); FCR = false chains / retained paths with two or more findings.

Exp. 4, paths against a reference run (--reference-output): the reference
(an exhaustive, unbounded run on the same input) keeps its K best ranked
paths per incident by score; recall = the share of those, as finding-ID
sequences, that the scored run also retains.

Latency (needs records with timestamp_ms, i.e. a live run). A finding's
latency is its first Kafka timestamp minus the latest Kafka timestamp of its
input events in norm.events.v0 (LogAppendTime: when the receiver wrote
them); correlation latency is a witness's first CONFIRMED record minus the
later of its two findings' first records. Both are on the analysis host's
clock and include window waits and watermark delay, not sensor or network
transit. Reported as count, mean, p50, p95, p99 and max, in milliseconds,
per finding type and over all. Offline outputs have no timestamps; latency
is then None.
"""
import argparse
import json
import struct
import sys
from collections import Counter, defaultdict

from google.protobuf import json_format

from microtrace.v0 import dataset_pb2, finding_pb2, incident_pb2, witness_pb2

FINDINGS, WITNESSES, EVALUATIONS = "findings.v0", "witness.decisions.v0", "rule.evaluations.v0"
INCIDENTS, EVENTS = "incidents.v0", "norm.events.v0"
MAX_REFERENCE_PATHS = 100000
PRESENT = dataset_pb2.TruthExpectation.Value("PRESENT")
ABSENT = dataset_pb2.TruthExpectation.Value("ABSENT")
UNOBSERVABLE = dataset_pb2.TruthExpectation.Value("UNOBSERVABLE")
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
ABSTAINED = dataset_pb2.EvaluationOutcome.Value("ABSTAINED")
DROPPED = ("dropped_unreported", "dropped_reported")
PROCESS_CONTINUITY = "same-process continuity"
BENIGN_CONTINUITY = "benign continuity"
UNSCORED_REASONS = (BENIGN_CONTINUITY,)
FORGED = "forged"


# --- inputs ----------------------------------------------------------------------------
def read_ld(path, cls):
    """Length-delimited protobuf file (4-byte big-endian length per message)."""
    out = []
    with open(path, "rb") as fh:
        while True:
            head = fh.read(4)
            if not head:
                return out
            if len(head) < 4:
                raise ValueError(f"{path}: truncated length header")
            (n,) = struct.unpack(">I", head)
            data = fh.read(n)
            if len(data) < n:
                raise ValueError(f"{path}: truncated message")
            msg = cls()
            msg.ParseFromString(data)
            out.append(msg)


class Truth:
    def __init__(self, actions, opportunities, links, incidents=()):
        self.actions, self.opportunities, self.links = list(actions), list(opportunities), list(links)
        self.incidents = list(incidents)

    @classmethod
    def load(cls, directory):
        import os
        inc = os.path.join(directory, "truth_incidents.pb")
        return cls(read_ld(os.path.join(directory, "truth_actions.pb"), dataset_pb2.GroundTruthAction),
                   read_ld(os.path.join(directory, "truth_findings.pb"), dataset_pb2.FindingOpportunity),
                   read_ld(os.path.join(directory, "truth_links.pb"), dataset_pb2.ActionLink),
                   read_ld(inc, dataset_pb2.GroundTruthIncident) if os.path.exists(inc) else ())


def _first(d, key, ts):
    if ts is not None and (key not in d or ts < d[key]):
        d[key] = ts


class Output:
    """A run's findings (by ID), witnesses (last record by ID), incidents
    (latest version by ID), evaluation counts, and first Kafka timestamps
    (ms) of findings, of confirmed witness records and of input events."""

    def __init__(self, findings=None, witnesses=None, evaluations=0, abstained=0, incidents=None):
        self.findings = dict(findings or {})
        self.witnesses = dict(witnesses or {})
        self.incidents = dict(incidents or {})
        self.evaluations, self.abstained = evaluations, abstained
        self.finding_ts, self.confirmed_ts, self.event_ts = {}, {}, {}

    def _incident(self, inc):
        old = self.incidents.get(inc.incident_id)
        if old is None or inc.version >= old.version:      # equal version: the later record
            self.incidents[inc.incident_id] = inc

    @classmethod
    def parse(cls, lines):
        out, evals = cls(), {}
        for line in lines:
            if not line.strip():
                continue
            obj = json.loads(line)
            topic, rec, ts = obj.get("topic"), obj.get("record"), obj.get("timestamp_ms")
            if topic == EVENTS and "event" in obj:
                _first(out.event_ts, obj["event"], ts)
                continue
            if rec is None:
                continue
            if topic == FINDINGS:
                f = json_format.ParseDict(rec, finding_pb2.Finding(), ignore_unknown_fields=True)
                out.findings[f.finding_id] = f
                _first(out.finding_ts, f.finding_id, ts)
            elif topic == WITNESSES:
                w = json_format.ParseDict(rec, witness_pb2.Witness(), ignore_unknown_fields=True)
                out.witnesses[w.witness_id] = w
                if w.status == CONFIRMED:
                    _first(out.confirmed_ts, w.witness_id, ts)
            elif topic == INCIDENTS:
                out._incident(json_format.ParseDict(rec, incident_pb2.Incident(), ignore_unknown_fields=True))
            elif topic == EVALUATIONS:
                e = json_format.ParseDict(rec, dataset_pb2.RuleEvaluation(), ignore_unknown_fields=True)
                evals[e.evaluation_id] = e.outcome
        out.evaluations = len(evals)
        out.abstained = sum(1 for o in evals.values() if o == ABSTAINED)
        return out

    @classmethod
    def load(cls, *paths):
        merged = cls()
        for p in paths:
            with open(p, encoding="utf-8") as fh:
                o = cls.parse(fh)
            merged.findings.update(o.findings)
            merged.witnesses.update(o.witnesses)
            for inc in o.incidents.values():
                merged._incident(inc)
            for mine, theirs in ((merged.finding_ts, o.finding_ts), (merged.confirmed_ts, o.confirmed_ts),
                                 (merged.event_ts, o.event_ts)):
                for k, v in theirs.items():
                    _first(mine, k, v)
            merged.evaluations += o.evaluations
            merged.abstained += o.abstained
        return merged

    def retained_paths(self):
        """[(incident_id, RankedPath)] of each incident's latest record."""
        return [(iid, p) for iid, inc in sorted(self.incidents.items()) for p in inc.ranked_paths]


def read_fault_log(path):
    """(dropped logical IDs, forged logical IDs) from a fault log; the header
    line and other actions are skipped."""
    dropped, forged = set(), set()
    if path is None:
        return dropped, forged
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if "header" in e or not e.get("logical_id"):
                continue
            if e.get("action") in DROPPED:
                dropped.add(e["logical_id"])
            elif e.get("action") == FORGED:
                forged.add(e["logical_id"])
    return dropped, forged


# --- fault adjustment ------------------------------------------------------------------
def effective_states(truth, dropped):
    """opportunity_id -> expected state after the fault adjustment."""
    return {o.opportunity_id: UNOBSERVABLE if o.expected_state != UNOBSERVABLE and dropped
            and not dropped.isdisjoint(o.evidence_event_ids) else o.expected_state
            for o in truth.opportunities}


def effective_link_states(truth, opp_states):
    """link_id -> expected state after the fault adjustment (module doc)."""
    present = defaultdict(list)
    for o in truth.opportunities:
        if o.expected_state == PRESENT:
            present[o.action_seq].append(opp_states[o.opportunity_id])
    blind = {a for a, states in present.items() if all(s == UNOBSERVABLE for s in states)}
    return {lk.link_id: UNOBSERVABLE if lk.expected_state == PRESENT
            and (lk.from_action_seq in blind or lk.to_action_seq in blind) else lk.expected_state
            for lk in truth.links}


# --- Exp. 1 ----------------------------------------------------------------------------
def _ratio(a, b):
    return a / b if b else None


def _prf(tp, fp, fn):
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r > 0 else None
    return {"precision": p, "recall": r, "f1": f1}


def score_findings(truth, output, opp_states, forged=frozenset()):
    by_type_ev = defaultdict(lambda: defaultdict(list))     # type -> event -> [opportunity]
    for o in truth.opportunities:
        for ev in o.evidence_event_ids:
            by_type_ev[o.finding_type][ev].append(o)
    matched = set()                                          # PRESENT opportunity IDs matched
    rows = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "fp_absent": 0, "fp_background": 0,
                                "on_unobservable": 0, "present": 0})
    false_findings, on_forged = [], 0
    for fid, f in sorted(output.findings.items()):
        opps = {o.opportunity_id: o for ev in f.input_event_ids for o in by_type_ev[f.finding_type].get(ev, ())}
        states = {opp_states[k] for k in opps}
        on_forged += bool(forged) and not forged.isdisjoint(f.input_event_ids)
        r = rows[f.finding_type]
        if PRESENT in states:
            matched.update(k for k in opps if opp_states[k] == PRESENT)
        elif UNOBSERVABLE in states:
            r["on_unobservable"] += 1
        else:
            r["fp"] += 1
            r["fp_absent" if ABSENT in states else "fp_background"] += 1
            false_findings.append(fid)
    missed = []
    for o in truth.opportunities:
        if opp_states[o.opportunity_id] != PRESENT:
            continue
        r = rows[o.finding_type]
        r["present"] += 1
        if o.opportunity_id in matched:
            r["tp"] += 1
        else:
            r["fn"] += 1
            missed.append(o.opportunity_id)
    per_type = {}
    for t, r in sorted(rows.items()):
        per_type[t] = {**r, **_prf(r["tp"], r["fp"], r["fn"]), "unsupported": r["present"] == 0}
    tot = {k: sum(r[k] for r in rows.values()) for k in ("tp", "fn", "fp", "fp_absent", "fp_background",
                                                        "on_unobservable", "present")}
    by_scenario = _by_scenario(truth, opp_states, matched)
    return {"overall": {**tot, **_prf(tot["tp"], tot["fp"], tot["fn"])}, "per_type": per_type,
            "by_scenario": by_scenario, "false_findings": false_findings, "missed_opportunities": sorted(missed),
            "on_forged": on_forged,
            "unobservable_opportunities": sum(1 for s in opp_states.values() if s == UNOBSERVABLE),
            "evaluations": output.evaluations, "abstained": output.abstained}


def _by_scenario(truth, opp_states, matched):
    scen = {a.action_seq: a.scenario_id for a in truth.actions}
    out = defaultdict(lambda: {"present": 0, "tp": 0})
    for o in truth.opportunities:
        if opp_states[o.opportunity_id] == PRESENT:
            r = out[scen.get(o.action_seq, "")]
            r["present"] += 1
            r["tp"] += o.opportunity_id in matched
    return {s: {**r, "recall": _ratio(r["tp"], r["present"])} for s, r in sorted(out.items())}


# --- Exp. 2 ----------------------------------------------------------------------------
def finding_actions(truth, output):
    """finding_id -> set of action_seq its input events were rendered for."""
    ev_actions = defaultdict(set)
    for a in truth.actions:
        for ev in a.rendered_event_ids:
            ev_actions[ev].add(a.action_seq)
    return {fid: set().union(*(ev_actions.get(ev, set()) for ev in f.input_event_ids))
            for fid, f in output.findings.items()}


def scored_link_ids(truth):
    """link_ids of the links Exp. 2 scores: a PRESENT opportunity at both ends
    (D-20), and not a benign continuity link."""
    has_opp = {o.action_seq for o in truth.opportunities if o.expected_state == PRESENT}
    return {lk.link_id for lk in truth.links
            if lk.from_action_seq in has_opp and lk.to_action_seq in has_opp
            and not lk.reason.startswith(UNSCORED_REASONS)}


def score_links(truth, output, link_states):
    acts = finding_actions(truth, output)
    scored = scored_link_ids(truth)
    rows = {(lk.from_action_seq, lk.to_action_seq): lk for lk in truth.links}
    state = {pair: link_states[lk.link_id] for pair, lk in rows.items() if lk.link_id in scored}
    unscored = {pair: link_states[lk.link_id] for pair, lk in rows.items() if lk.link_id not in scored}
    proposed = defaultdict(list)                 # pair -> [witness]
    supported = set()                            # witness IDs with a PRESENT or UNOBSERVABLE pair
    unmapped, intra = [], []
    for wid, w in sorted(output.witnesses.items()):
        if w.status != CONFIRMED:
            continue
        a, b = acts.get(w.source_finding_id, set()), acts.get(w.target_finding_id, set())
        if not a or not b:
            unmapped.append(wid)
            continue
        pairs = {(x, y) for x in a for y in b if x != y}
        if not pairs:
            intra.append(wid)
            continue
        for p in pairs:
            proposed[p].append(w)
            if state.get(p, unscored.get(p)) in (PRESENT, UNOBSERVABLE):
                supported.add(wid)
    tp, fp, violated, agree, unscored_hit, companion = [], [], [], 0, [], []
    for pair, ws in sorted(proposed.items()):
        s = state.get(pair, unscored.get(pair))
        if pair in unscored and s != ABSENT:
            unscored_hit.append(pair)
        elif s == PRESENT:
            tp.append(pair)
            agree += any(w.relationship_type == rows[pair].witness_type for w in ws)
        elif s == UNOBSERVABLE:
            continue
        elif s is None and all(w.witness_id in supported for w in ws):
            companion.append(pair)                # another action of a true link's finding (A3)
        else:
            fp.append(pair)
            if s == ABSENT:
                violated.append(pair)
    present = [p for p, s in state.items() if s == PRESENT]
    n_fp = len(fp) + len(unmapped)
    missed = sorted(set(present) - set(tp))
    same = {p for p in present if rows[p].reason.startswith(PROCESS_CONTINUITY)}
    tp_x, fn_x = len(set(tp) - same), len(set(missed) - same)
    return {"tp": len(tp), "fp": n_fp, "fn": len(missed), "present": len(present),
            **_prf(len(tp), n_fp, len(missed)),
            "without_same_process": {"tp": tp_x, "fp": n_fp, "fn": fn_x, "present": len(present) - len(same),
                                     **_prf(tp_x, n_fp, fn_x)},
            "false_pairs": [list(p) for p in fp], "unmapped_witnesses": unmapped,
            "violated_nonlinks": [list(p) for p in violated], "intra_action_witnesses": intra,
            "missed_links": [rows[p].link_id for p in missed], "type_agreement": _ratio(agree, len(tp)),
            "unobservable_links": sum(1 for s in state.values() if s == UNOBSERVABLE),
            "scored_links": len(state),
            "companion_pairs": [list(p) for p in companion],
            "unscored_links": {dataset_pb2.TruthExpectation.Name(s): n
                               for s, n in sorted(Counter(unscored.values()).items())},
            "unscored_proposed": [list(p) for p in unscored_hit]}


# --- Exp. 2: paths ---------------------------------------------------------------------
def reference_paths(truth, link_states, limit=MAX_REFERENCE_PATHS, scored=None):
    """Every source-to-sink path (tuples of action_seq, two or more actions) of
    the PRESENT-link graph, restricted to the link_ids in scored when given;
    (paths, truncated). A cycle's nodes that no source reaches start a walk of
    their own, so no link is left out."""
    succ, indeg = defaultdict(set), defaultdict(int)
    for lk in truth.links:
        a, b = lk.from_action_seq, lk.to_action_seq
        if scored is not None and lk.link_id not in scored:
            continue
        if link_states[lk.link_id] == PRESENT and a != b and b not in succ[a]:
            succ[a].add(b)
            indeg[b] += 1
    nodes = set(succ) | set(indeg)
    paths, reached, truncated = set(), set(), False

    def walk(start):
        nonlocal truncated
        stack = [(start, (start,))]
        while stack:
            if len(paths) >= limit:
                truncated = True
                return
            node, path = stack.pop()
            reached.add(node)
            nxt = [n for n in sorted(succ.get(node, ())) if n not in path]
            if not nxt:
                if len(path) > 1:
                    paths.add(path)
                continue
            stack.extend((n, path + (n,)) for n in nxt)
    for n in sorted(x for x in nodes if indeg.get(x, 0) == 0):
        walk(n)
    for n in sorted(nodes):
        if n not in reached and not truncated:
            walk(n)
    return sorted(paths), truncated


def covers(actions, finding_ids, acts):
    """True if finding_ids holds, in order, a distinct finding for each action."""
    i = 0
    for f in finding_ids:
        if i < len(actions) and actions[i] in acts.get(f, ()):
            i += 1
    return i == len(actions)


def _step_ok(f, g, acts, state):
    """Is the step f -> g of a retained path a supported link (module doc, FCR)?"""
    a, b = acts.get(f, set()), acts.get(g, set())
    if not a or not b:
        return False
    pairs = {(x, y) for x in a for y in b if x != y}
    if not pairs:
        return True                                        # intra-action: not a false link
    states = {state.get(p) for p in pairs}
    return PRESENT in states or UNOBSERVABLE in states


def clean_segments(finding_ids, acts, state):
    """The retained path cut at its false steps: maximal runs of findings whose
    consecutive steps all pass _step_ok (rule A')."""
    segs, cur = [], []
    for f in finding_ids:
        if cur and not _step_ok(cur[-1], f, acts, state):
            segs.append(tuple(cur))
            cur = []
        cur.append(f)
    if cur:
        segs.append(tuple(cur))
    return segs


def score_paths(truth, output, link_states):
    acts = finding_actions(truth, output)
    refs, truncated = reference_paths(truth, link_states, scored=scored_link_ids(truth))
    retained = output.retained_paths()
    state = {(lk.from_action_seq, lk.to_action_seq): link_states[lk.link_id] for lk in truth.links}
    seqs = [tuple(p.finding_ids) for _iid, p in retained]
    segs = [s for q in seqs for s in clean_segments(q, acts, state)]
    recovered, loose, missed = 0, 0, []
    by_len = defaultdict(lambda: {"reference": 0, "recovered": 0, "recovered_loose": 0})
    for path in refs:
        ok = any(covers(path, s, acts) for s in segs)
        ok_loose = ok or any(covers(path, q, acts) for q in seqs)
        recovered += ok
        loose += ok_loose
        by_len[len(path)]["reference"] += 1
        by_len[len(path)]["recovered"] += ok
        by_len[len(path)]["recovered_loose"] += ok_loose
        if not ok:
            missed.append(list(path))
    multi = [(iid, p) for iid, p in retained if len(p.finding_ids) > 1]
    false = [{"incident_id": iid, "path_id": p.path_id, "finding_ids": list(p.finding_ids)} for iid, p in multi
             if not all(_step_ok(f, g, acts, state) for f, g in zip(p.finding_ids, p.finding_ids[1:]))]
    return {"reference_paths": len(refs), "recovered": recovered,
            "top_k_path_recall": _ratio(recovered, len(refs)), "reference_truncated": truncated,
            "recovered_loose": loose, "top_k_path_recall_loose": _ratio(loose, len(refs)),
            "missed_paths": missed[:100],
            "by_length": {str(n): {**r, "recall": _ratio(r["recovered"], r["reference"])}
                          for n, r in sorted(by_len.items())},
            "incidents": len(output.incidents), "retained_paths": len(retained), "retained_multi": len(multi),
            "false_chains": len(false), "false_chain_rate": _ratio(len(false), len(multi)),
            "false_chain_examples": false[:50]}


def reference_path_recall(reference, output, k):
    """Exp. 4: share of the reference run's K best paths per incident (by score,
    then finding IDs) that the scored run also retains."""
    want = set()
    for inc in reference.incidents.values():
        best = sorted(inc.ranked_paths, key=lambda p: (-(p.score if p.HasField("score") else 0.0),
                                                       tuple(p.finding_ids)))[:k]
        want.update(tuple(p.finding_ids) for p in best)
    have = {tuple(p.finding_ids) for _iid, p in output.retained_paths()}
    return {"k": k, "reference_paths": len(want), "retained": len(want & have),
            "recall": _ratio(len(want & have), len(want))}


# --- Exp. 2: incidents (B1) -------------------------------------------------------------
def score_incidents(truth, output):
    """Merges: correlator incidents whose findings map to actions of two or
    more truth incidents. Fragmentation: truth incidents whose findings lie in
    two or more correlator incidents. Each incident's latest record; None
    without incident truth (runs built before B1)."""
    if not truth.incidents:
        return None
    inc_of = {seq: i.incident_id for i in truth.incidents for seq in i.action_seqs}
    attack = {i.incident_id: i.is_attack for i in truth.incidents}
    acts = finding_actions(truth, output)
    go_to_truth, truth_to_go = {}, defaultdict(set)
    for iid, inc in sorted(output.incidents.items()):
        t = {inc_of[a] for f in inc.finding_ids for a in acts.get(f, ()) if a in inc_of}
        if t:
            go_to_truth[iid] = t
            for x in t:
                truth_to_go[x].add(iid)
    merged = sorted(i for i, t in go_to_truth.items() if len(t) > 1)
    fragmented = sorted(x for x, g in truth_to_go.items() if len(g) > 1)
    return {"go_incidents": len(go_to_truth), "truth_incidents_seen": len(truth_to_go),
            "merges": len(merged), "merge_rate": _ratio(len(merged), len(go_to_truth)),
            "attack_merges": sum(1 for i in merged if any(attack.get(x) for x in go_to_truth[i])),
            "fragmented": len(fragmented), "fragmentation_rate": _ratio(len(fragmented), len(truth_to_go)),
            "attack_fragmented": sum(1 for x in fragmented if attack.get(x)),
            "merged_examples": [{"incident_id": i, "truth_incidents": sorted(go_to_truth[i])} for i in merged[:20]],
            "fragmented_examples": [{"truth_incident": x, "incidents": sorted(truth_to_go[x])}
                                    for x in fragmented[:20]]}


# --- latency ---------------------------------------------------------------------------
def _stats(values):
    """count, mean, nearest-rank p50/p95/p99 and max (ms); None when empty."""
    if not values:
        return None
    v = sorted(values)

    def q(pct):
        return v[min(len(v), max(1, -(-pct * len(v) // 100))) - 1]
    return {"n": len(v), "mean_ms": sum(v) / len(v), "p50_ms": q(50), "p95_ms": q(95), "p99_ms": q(99),
            "max_ms": v[-1]}


def score_latency(output):
    per_type, overall, missing = defaultdict(list), [], 0
    for fid, f in sorted(output.findings.items()):
        ts = output.finding_ts.get(fid)
        ins = [output.event_ts[e] for e in f.input_event_ids if e in output.event_ts]
        if ts is None or not ins:
            missing += 1
            continue
        per_type[f.finding_type].append(ts - max(ins))
        overall.append(ts - max(ins))
    corr, corr_missing = [], 0
    for wid, t in sorted(output.confirmed_ts.items()):
        w = output.witnesses[wid]
        ends = [output.finding_ts.get(w.source_finding_id), output.finding_ts.get(w.target_finding_id)]
        if None in ends:
            corr_missing += 1
            continue
        corr.append(t - max(ends))
    return {"finding": {"overall": _stats(overall), "per_type": {t: _stats(v) for t, v in sorted(per_type.items())},
                        "without_timestamps": missing},
            "correlation": {"overall": _stats(corr), "without_timestamps": corr_missing}}


# --- entry -----------------------------------------------------------------------------
def score(truth, output, dropped=frozenset(), forged=frozenset(), reference=None, k=None):
    opp_states = effective_states(truth, set(dropped))
    link_states = effective_link_states(truth, opp_states)
    out = {"findings": score_findings(truth, output, opp_states, set(forged)),
           "links": score_links(truth, output, link_states),
           "paths": score_paths(truth, output, link_states),
           "incidents": score_incidents(truth, output),
           "latency": score_latency(output),
           "faults": {"dropped_records": len(dropped), "forged_records": len(forged)}}
    if reference is not None:
        out["paths"]["against_reference"] = reference_path_recall(reference, output, k)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score a run against its generated truth (Exp. 1-4).")
    ap.add_argument("--truth", required=True, help="the run's restricted/ directory")
    ap.add_argument("--output", required=True, action="append",
                    help="JSONL of findings.v0 / witness.decisions.v0 records (repeatable)")
    ap.add_argument("--fault-log", default=None, help="the injector's fault log (Exp. 3)")
    ap.add_argument("--out", default=None, help="write the score here (default stdout)")
    ap.add_argument("--reference-output", action="append", default=None,
                    help="Exp. 4: an exhaustive run's output on the same input (repeatable)")
    ap.add_argument("--k", type=int, default=None, help="Exp. 4: paths kept per incident (default the GO's K)")
    a = ap.parse_args(argv)
    dropped, forged = read_fault_log(a.fault_log)
    reference, k = None, a.k
    if a.reference_output:
        reference = Output.load(*a.reference_output)
        if k is None:
            from mtcore.orchestrator.params import OrchParams
            k = OrchParams.load().K
    result = score(Truth.load(a.truth), Output.load(*a.output), dropped, forged, reference, k)
    text = json.dumps(result, indent=2, sort_keys=True)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
