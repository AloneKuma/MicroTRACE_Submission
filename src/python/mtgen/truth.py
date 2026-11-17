"""Truth writer: restricted truth tables for a generated run.

Writes GroundTruthAction (with rendered_event_ids filled), FindingOpportunity,
and ActionLink as length-delimited protobuf files, plus a JSONL coverage table,
all under <run_dir>/restricted/.  No restricted value (action_seq, scenario_id,
step_label, expected state, or evidence event IDs) appears in any event in the
base stream.

Usage::

    from mtgen.truth import TruthWriter, RenderedEventInfo
    writer = TruthWriter(run_id, rendering_table, catalogue)
    result = writer.write(gt_records, rendered_by_seq)
    writer.write_restricted(result, Path(run_dir))
"""
from __future__ import annotations

import datetime
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import mtgen  # registers gen/ on sys.path
from microtrace.v0 import common_pb2, dataset_pb2, finding_pb2, witness_pb2
from mtgen.scenarios import GroundTruthRecord, is_attack_scenario
from mtgen.simtime import ns_to_timestamp

TRUTH_VERSION = "truth.v0"

# ---------------------------------------------------------------------------
# Enum lookup tables
# ---------------------------------------------------------------------------

_TACTIC_BY_NAME: Dict[str, int] = {
    "INITIAL_ACCESS": finding_pb2.INITIAL_ACCESS,
    "EXECUTION": finding_pb2.EXECUTION,
    "PERSISTENCE": finding_pb2.PERSISTENCE,
    "PRIVILEGE_ESCALATION": finding_pb2.PRIVILEGE_ESCALATION,
    "CREDENTIAL_ACCESS": finding_pb2.CREDENTIAL_ACCESS,
    "DISCOVERY": finding_pb2.DISCOVERY,
    "LATERAL_MOVEMENT": finding_pb2.LATERAL_MOVEMENT,
    "EXFILTRATION": finding_pb2.EXFILTRATION,
}

_WITNESS_BY_NAME: Dict[str, int] = {
    "NETWORK_FLOW": witness_pb2.NETWORK_FLOW,
    "REQUEST_IDENTITY": witness_pb2.REQUEST_IDENTITY,
    "CREDENTIAL_READ_TO_USE": witness_pb2.CREDENTIAL_READ_TO_USE,
    "PROCESS_ANCESTRY": witness_pb2.PROCESS_ANCESTRY,
    "HOST_TRANSITION": witness_pb2.HOST_TRANSITION,
    "ADMISSION_INSTANCE": witness_pb2.ADMISSION_INSTANCE,
    "CONTROL_PLANE_CAUSALITY_INSTANCE": witness_pb2.CONTROL_PLANE_CAUSALITY_INSTANCE,
    "HOST_CONTEXT": witness_pb2.HOST_CONTEXT,
    "CONTROL_PLANE_CAUSALITY_CLASS": witness_pb2.CONTROL_PLANE_CAUSALITY_CLASS,
    "IMAGE_CLASS": witness_pb2.IMAGE_CLASS,
}

# Record types (RenderedEventInfo.record_type) a link witness is read from.
_WITNESS_SOURCES: Dict[str, frozenset] = {
    "NETWORK_FLOW": frozenset({"ebpf", "path_flow"}),
    "REQUEST_IDENTITY": frozenset({"gateway"}),
    "CREDENTIAL_READ_TO_USE": frozenset({"ebpf", "audit"}),
    "PROCESS_ANCESTRY": frozenset({"ebpf"}),
    "HOST_TRANSITION": frozenset({"ebpf"}),
    "ADMISSION_INSTANCE": frozenset({"kyverno", "audit", "context"}),
    "CONTROL_PLANE_CAUSALITY_INSTANCE": frozenset({"audit"}),
    "HOST_CONTEXT": frozenset({"ebpf", "path_flow"}),
}

# What a declared gap hides from the agents and the correlator, mirrored here
# so truth and detector agree (exp2-gaps-plan B0c; mtcore.agents.completeness,
# mtcore.orchestrator.admit): the gap reasons they abstain on, and the eBPF
# families in which a witness type's contradictions show.
_ABSTAIN_REASONS = frozenset({
    common_pb2.DROPPED_BEFORE, common_pb2.TRUNCATED, common_pb2.SOURCE_IDLE,
    common_pb2.POLICY_EXCLUDED, common_pb2.DELIVERY_UNESTABLISHED,
})
_CHECK_FAMILIES: Dict[str, frozenset] = {
    "PROCESS_ANCESTRY": frozenset({"proc.exec"}),
    "HOST_TRANSITION": frozenset({"proc.exec", "ns.change"}),
    "NETWORK_FLOW": frozenset({"net.connect"}),
}
# Findings that open a node-trust epoch (mtcore.orchestrator.epochs.TRIGGERS).
_EPOCH_TRIGGERS = frozenset({"C1b"})
# Truth says what the data lost, not how a detector reads it: a gap blinds a
# finding only when it covers the finding's own evidence, never because it
# falls in some detector's window (2026-10-31, fix A review).
_RECORD_BY_SOURCE: Dict[int, str] = {
    common_pb2.EBPF: "ebpf", common_pb2.GATEWAY: "gateway", common_pb2.AUDIT: "audit",
    common_pb2.KYVERNO: "kyverno", common_pb2.CLUSTER_CONTEXT: "context",
    common_pb2.DB_AUDIT: "db_audit", common_pb2.PATH_FLOW: "path_flow",
}


@dataclass(frozen=True)
class DeclaredGap:
    """One abstaining gap of a SourceCompleteness record, as the agents read it."""
    record_type: str                 # "" = every source
    node: Optional[str]              # eBPF node, or None (every node)
    families: Optional[frozenset]    # eBPF families, or None (every family)
    lo: int
    hi: int

    def hits(self, record_type: str, node: str, families: Optional[frozenset],
             lo: int, hi: int) -> bool:
        """Does the gap stop a read of record_type (on node, of families) over [lo, hi]?"""
        if self.record_type and self.record_type != record_type:
            return False
        if record_type == "ebpf" and self.node is not None and node and node != self.node:
            return False
        if self.families is not None and families is not None and not (self.families & families):
            return False
        return self.lo <= hi and lo <= self.hi

    def describe(self) -> str:
        where = self.record_type or "every source"
        if self.node:
            where += f" node {self.node}"
        if self.families:
            where += " families " + ",".join(sorted(self.families))
        return where


def _ts(t) -> int:
    return t.seconds * 1_000_000_000 + t.nanos


def declared_gaps(completeness_records) -> List[DeclaredGap]:
    """The abstaining gaps the base stream declares: per record, its node
    (scope "node=<id>"), and per gap its families (gap scope "family=...")."""
    import re
    from microtrace.v0 import stream_pb2
    out: List[DeclaredGap] = []
    for sc in completeness_records or ():
        m = re.search(r"(?:^|/)node=([^/]+)", sc.scope)
        node = m.group(1) if m else None
        rec = _RECORD_BY_SOURCE.get(sc.source, "")
        lo = _ts(sc.interval_start) if sc.HasField("interval_start") else -(1 << 62)
        hi = _ts(sc.interval_end) if sc.HasField("interval_end") else 1 << 62
        if sc.status == stream_pb2.CompletenessStatus.Value("DELIVERY_UNKNOWN"):
            out.append(DeclaredGap(rec, node, None, lo, hi))
        for g in sc.gaps:
            if g.reason not in _ABSTAIN_REASONS:
                continue
            fm = re.search(r"(?:^|/)family=([^/]+)", g.scope)
            fams = frozenset(f for f in fm.group(1).split(",") if f) if fm else None
            out.append(DeclaredGap(rec, node, fams,
                                   _ts(getattr(g, "from")) if g.HasField("from") else lo,
                                   _ts(g.to) if g.HasField("to") else hi))
    return out



def _process_path(scenario: dict, to_label: str, from_label: str) -> set:
    """Step labels on the target's process chain, up to the link's source.

    Walks the "@step<N>.process" references from the target step (the
    process it acts as, that process's exec, its parent, ...). An exec on
    this chain that lost its proc.exec hides whether the target descends
    from the source; a lost exec of any other step, such as a decoy placed
    between the endpoints, does not.
    """
    steps = {str(s.get("step")): s for s in scenario.get("steps", [])}

    def refs(label):
        for v in steps.get(label, {}).get("params", {}).values():
            if isinstance(v, str) and v.startswith("@step") and v.endswith(".process"):
                yield v[len("@step"):].partition(".")[0]

    # The walk stops at the source and at the process the source acts as
    # (a same-process continuity link has no path).
    stop = {from_label, *refs(from_label)}
    path: set = set()
    todo = [to_label]
    while todo:
        for label in refs(todo.pop()):
            if label not in stop and label not in path:
                path.add(label)
                todo.append(label)
    return path


_TRUTH_EXPECTATION_BY_NAME: Dict[str, int] = {
    "PRESENT": dataset_pb2.PRESENT,
    "ABSENT": dataset_pb2.ABSENT,
    "UNOBSERVABLE": dataset_pb2.UNOBSERVABLE,
}

_SOURCE_ENUM_TO_NAME: Dict[int, str] = {
    common_pb2.GATEWAY: "GATEWAY",
    common_pb2.AUDIT: "AUDIT",
    common_pb2.EBPF: "EBPF",
    common_pb2.KYVERNO: "KYVERNO",
    common_pb2.CLUSTER_CONTEXT: "CLUSTER_CONTEXT",
    common_pb2.DB_AUDIT: "DB_AUDIT",
    common_pb2.PATH_FLOW: "PATH_FLOW",
}

_GAP_REASON_TO_NAME: Dict[int, str] = {
    common_pb2.SOURCE_IDLE: "SOURCE_IDLE",
    common_pb2.DROPPED_BEFORE: "DROPPED_BEFORE",
    common_pb2.WATCH_RELIST_GAP: "WATCH_RELIST_GAP",
    common_pb2.JOIN_UNCERTAIN: "JOIN_UNCERTAIN",
}

# Map derived type name -> base record type for evidence coverage checking
_DERIVED_TO_BASE_RECORD: Dict[str, str] = {
    "audit_derived": "audit",
    "ebpf_derived": "ebpf",
    "admission_derived": "kyverno",
    "offnode_derived": "db_audit",
}


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class RenderedEventInfo:
    """Minimal metadata about one rendered NormalizedEvent for the truth writer.

    Attributes:
        event_id:    NormalizedEvent.event_id (= Envelope.logical_id)
        record_type: record oneof alternative name: "gateway", "audit", "ebpf",
                     "kyverno", "context", "db_audit", or "path_flow"
        family:      eBPF record family (e.g. "file.read", "net.connect"); empty
                     string for non-eBPF sources
        time_ns:     event_time in nanoseconds; used for window computation
    """
    event_id: str
    record_type: str
    family: str = ""
    time_ns: int = 0
    node: str = ""          # eBPF node_id; empty for other sources
    record_gap: str = ""    # an abstaining gap declared on the record itself, by reason


@dataclass
class TruthResult:
    """Restricted truth output for one run, ready to write to disk.

    Attributes:
        actions:           GroundTruthAction protos (rendered_event_ids filled)
        opportunities:     FindingOpportunity protos
        links:             ActionLink protos
        coverage_rows:     JSONL-ready dicts for the coverage table
        downgrades:        list of (action_seq, finding_type, old, new, reason)
                           for each catalogue PRESENT or ABSENT downgraded to
                           UNOBSERVABLE
        consistency_errors: list of (action_seq, detail) for expected_finding_types
                           mismatches; empty means the run is consistent
        hollow_unobservable: list of (action_seq, finding_type, scenario_id) for
                           catalogue UNOBSERVABLE expectations of a degraded
                           scenario (degraded_by: source, the default) whose
                           evidence was all rendered: the scenario declares a
                           loss the data does not have
    """
    actions: List["dataset_pb2.GroundTruthAction"]
    opportunities: List["dataset_pb2.FindingOpportunity"]
    links: List["dataset_pb2.ActionLink"]
    coverage_rows: List[dict]
    downgrades: List[Tuple[int, str, str, str, str]] = field(default_factory=list)
    consistency_errors: List[Tuple[int, str]] = field(default_factory=list)
    hollow_unobservable: List[Tuple[int, str, str]] = field(default_factory=list)
    incidents: List["dataset_pb2.GroundTruthIncident"] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class TruthWriter:
    """Build restricted truth tables from rendered observations.

    Parameters
    ----------
    run_id : str
        Run identifier, written into every truth record.
    rendering_table : dict
        Loaded spec/generator/evidence-rendering.v0.yaml.
    catalogue : dict
        Loaded spec/scenarios/catalogue.v0.yaml.
    gen_spec : dict, optional
        Loaded spec/generator/generator-spec.v0.yaml; used to resolve window
        symbol values for findings with keyed windows (W_B1, W_B2, …).
        When None or a symbol has no value, falls back to action step times.
    truth_version : str
        Version tag written into every FindingOpportunity and ActionLink.
    """

    def __init__(
        self,
        run_id: str,
        rendering_table: dict,
        catalogue: dict,
        gen_spec: Optional[dict] = None,
        truth_version: str = TRUTH_VERSION,
    ) -> None:
        self._run_id = run_id
        self._truth_version = truth_version
        # finding_id -> entry from the rendering table
        self._rt_by_id: Dict[str, dict] = {
            f["id"]: f
            for f in rendering_table.get("findings", [])
        }
        # Findings the rendering table excludes (included: false) have no
        # opportunities and are dropped from expected_finding_types.
        self._excluded: frozenset = frozenset(
            fid for fid, f in self._rt_by_id.items()
            if f.get("included", True) is False
        )
        # scenario_id -> scenario dict from catalogue
        self._cat_by_id: Dict[str, dict] = {
            s["id"]: s
            for s in catalogue.get("scenarios", [])
        }
        # Build a symbol -> value_ns lookup from the declared_artifacts section
        self._window_ns_by_symbol: Dict[str, Optional[int]] = (
            _extract_window_values(gen_spec) if gen_spec else {}
        )
        # The correlator's A and beta (D-21: equal to the frozen orchestrator
        # values); None without a generator spec, and then no link is judged
        # by distinctness near a gap.
        timing = (gen_spec or {}).get("correlator_timing") or {}
        self._a_beta_ns: Optional[Tuple[int, int]] = (
            (int(float(timing["A_s"]) * 1e9), int(float(timing["beta_s"]) * 1e9))
            if "A_s" in timing and "beta_s" in timing else None)
        self._gaps: List[DeclaredGap] = []
        self._epochs: Dict[str, int] = {}          # node -> node-trust epoch onset (ns)
        self._epoch_events: Dict[str, set] = {}    # node -> the trigger's own event IDs at the onset

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(
        self,
        gt_records: List[GroundTruthRecord],
        rendered_by_seq: Dict[int, List[RenderedEventInfo]],
        completeness_records: Optional[List] = None,
        standing_by_seq: Optional[Dict[int, List[RenderedEventInfo]]] = None,
        dropped_by_seq: Optional[Dict[int, List[RenderedEventInfo]]] = None,
        own_dropped_by_seq: Optional[Dict[int, List[RenderedEventInfo]]] = None,
    ) -> TruthResult:
        """Build all truth tables from rendered observations.

        Parameters
        ----------
        gt_records :
            GroundTruthRecord list from ScenarioEngine.execute(), in
            action_seq order.
        rendered_by_seq :
            Mapping from action_seq to the RenderedEventInfo list for all
            events the renderers produced for that action.
        completeness_records :
            Optional list of SourceCompleteness protos (from
            CompletenessRenderer.render_completeness()) for the coverage
            table.  Pass None to omit coverage rows.
        standing_by_seq :
            Optional mapping from action_seq to earlier observations of the
            acting entity's own state that the step did not render (Pod watch
            event, lineage fork/exec). Counted as evidence; not used for the
            opportunity window.
        dropped_by_seq :
            Optional mapping from action_seq to evidence the degraded profile
            dropped (the step's own events and lost standing evidence). A
            lookalike missing a requirement that this evidence would have
            covered is UNOBSERVABLE.
        own_dropped_by_seq :
            Optional mapping from action_seq to the step's own events the
            profile dropped (no standing evidence). Link labels use it; see
            _build_links. Defaults to dropped_by_seq.

        Returns
        -------
        TruthResult
            All restricted truth messages and any diagnostic records.
        """
        downgrades: List[Tuple[int, str, str, str, str]] = []
        consistency_errors: List[Tuple[int, str]] = []
        hollow: List[Tuple[int, str, str]] = []
        self._gaps = declared_gaps(completeness_records)

        # Step 1: group records into scenario execution instances so that
        # (from_step, to_step) link references can be resolved to action_seqs.
        # A new execution starts whenever (scenario_id, variant_id) changes or
        # when a step_label repeats within the current (scenario_id, variant_id).
        exec_instances = self._group_executions(gt_records)
        # action_seq -> action_seqs of the same execution up to and including it
        scope_seqs: Dict[int, List[int]] = {}
        for _sid, _vid, step_map in exec_instances:
            seqs = sorted(step_map.values())
            for i, seq in enumerate(seqs):
                scope_seqs[seq] = seqs[: i + 1]

        # Step 2: build GroundTruthAction protos with rendered_event_ids.
        actions = [
            self._build_gta(rec, rendered_by_seq.get(rec.action_seq, []))
            for rec in gt_records
        ]

        # Step 3: build FindingOpportunity protos.
        opportunities: List[dataset_pb2.FindingOpportunity] = []
        opp_idx = 0
        # action_seq -> [(finding_type, state)] for consistency check
        finding_states_by_seq: Dict[int, List[Tuple[str, str]]] = {}

        for rec in gt_records:
            scenario = self._cat_by_id.get(rec.scenario_id)
            if scenario is None:
                continue
            step = self._find_step(scenario, rec.step_label)
            if step is None:
                continue

            step_states: List[Tuple[str, str]] = []

            for expects in step.get("expects", []):
                finding_type = expects.get("finding", "")
                catalogue_state = expects.get("state", "PRESENT")
                cat_reason = expects.get("reason", "")

                if not finding_type or finding_type in self._excluded:
                    continue

                # A keyed or global rule's evidence may span several steps
                # (read, then connect, then transfer): the events of this step
                # and of every earlier step of the same scenario execution. A
                # stateless rule reads one event at a time, so its evidence is
                # this step's own events; otherwise a finding on an earlier
                # step would be credited to this one (2026-10-24: step 2 of
                # a1_kube_ids0_sqli, which P_A does not match).
                span = (scope_seqs.get(rec.action_seq, [rec.action_seq])
                        if self._spans_steps(finding_type) else [rec.action_seq])
                event_infos = [ei for seq in span for ei in rendered_by_seq.get(seq, [])]
                # Standing evidence: earlier observations of the acting entity's
                # own state (its Pod's watch event, its lineage's fork and exec)
                # that the rule reads but this step did not render. It counts as
                # evidence but does not widen the opportunity window.
                seen_ids = {ei.event_id for ei in event_infos}
                evidence_infos = list(event_infos) + [
                    ei for ei in (standing_by_seq or {}).get(rec.action_seq, [])
                    if ei.event_id not in seen_ids
                ]
                event_ids = [ei.event_id for ei in evidence_infos]
                dropped_infos = [ei for seq in span for ei in (dropped_by_seq or {}).get(seq, [])]

                opp_idx += 1
                opp_id = (
                    f"opp-{rec.run_id[:8]}-{rec.action_seq:06d}-{opp_idx:04d}"
                )

                if catalogue_state == "ABSENT":
                    # Benign lookalike: evidence_requirements = all field paths.
                    # A dropped record is never an observed negative
                    # (fault-contract.md): when the profile dropped evidence
                    # a requirement needed, the absence cannot be confirmed.
                    # Evidence the lookalike never renders (no connect after
                    # a benign read) is part of the lookalike, not a loss.
                    missing = []
                    if dropped_infos:
                        still_missing = set(self._check_evidence(
                            finding_type, evidence_infos + dropped_infos))
                        missing = [
                            m for m in self._check_evidence(finding_type, evidence_infos)
                            if m not in still_missing
                        ]
                    if missing:
                        actual_state = "UNOBSERVABLE"
                        actual_reason = (
                            "Lookalike evidence dropped: " + ", ".join(missing)
                        )
                        evidence_reqs = missing
                        downgrades.append((
                            rec.action_seq, finding_type,
                            "ABSENT", "UNOBSERVABLE", actual_reason,
                        ))
                    else:
                        actual_state = "ABSENT"
                        actual_reason = cat_reason or f"Benign lookalike: {finding_type}"
                        evidence_reqs = self._all_requirements(finding_type)
                        blind = self._gap_blinds(finding_type, evidence_infos, step.get("params"))
                        if blind:
                            actual_state = "UNOBSERVABLE"
                            actual_reason = "Lookalike inside a declared gap: " + blind
                            downgrades.append((
                                rec.action_seq, finding_type,
                                "ABSENT", "UNOBSERVABLE", actual_reason,
                            ))

                elif catalogue_state == "UNOBSERVABLE":
                    # Declared degraded case: evidence_requirements = the ones
                    # that are missing (i.e. all, since the scenario declares this
                    # upfront without rendering full evidence).
                    actual_state = "UNOBSERVABLE"
                    actual_reason = cat_reason or f"Declared unobservable: {finding_type}"
                    evidence_reqs = self._all_requirements(finding_type)
                    # A degraded scenario that loses a source must actually
                    # lose evidence (step `unobserved`); field- or
                    # volume-degraded scenarios degrade by other means.
                    if (scenario.get("kind") == "degraded"
                            and scenario.get("degraded_by", "source") == "source"
                            and not self._check_evidence(finding_type, evidence_infos)):
                        hollow.append((rec.action_seq, finding_type, rec.scenario_id))

                else:  # PRESENT in catalogue
                    missing = self._check_evidence(finding_type, evidence_infos)
                    if missing:
                        actual_state = "UNOBSERVABLE"
                        actual_reason = (
                            "Missing required sources: " + ", ".join(missing)
                        )
                        evidence_reqs = missing  # name the missing requirements
                        downgrades.append((
                            rec.action_seq, finding_type,
                            "PRESENT", "UNOBSERVABLE", actual_reason,
                        ))
                    else:
                        actual_state = "PRESENT"
                        actual_reason = cat_reason
                        blind = self._gap_blinds(finding_type, evidence_infos, step.get("params"))
                        if blind:
                            actual_state = "UNOBSERVABLE"
                            actual_reason = "Evidence inside a declared gap: " + blind
                            evidence_reqs = self._all_requirements(finding_type)
                            downgrades.append((
                                rec.action_seq, finding_type,
                                "PRESENT", "UNOBSERVABLE", actual_reason,
                            ))
                        evidence_reqs = self._all_requirements(finding_type)

                step_states.append((finding_type, actual_state))
                opp = self._build_opportunity(
                    opp_id=opp_id,
                    rec=rec,
                    finding_type=finding_type,
                    expected_state=actual_state,
                    evidence_reqs=evidence_reqs,
                    reason=actual_reason,
                    evidence_event_ids=event_ids,
                    event_infos=event_infos,
                )
                opportunities.append(opp)

            finding_states_by_seq[rec.action_seq] = step_states

        # Step 4: expected_finding_types is what the run realised: the
        # catalogue expectations minus excluded findings and minus those
        # downgraded for missing evidence (reported in ``downgrades``). A
        # catalogue expectation with no opportunity at all is an error.
        gta_by_seq = {gta.action_seq: gta for gta in actions}
        for rec in gt_records:
            states = finding_states_by_seq.get(rec.action_seq, [])
            present_types = {ft for ft, st in states if st == "PRESENT"}
            labelled = {ft for ft, _st in states}
            declared = [
                ft for ft in rec.expected_finding_types
                if ft not in self._excluded
            ]
            # The record must declare exactly its catalogue step's PRESENT
            # expectations; a disagreement is a harness defect.
            scenario = self._cat_by_id.get(rec.scenario_id)
            step = self._find_step(scenario, rec.step_label) if scenario else None
            if step is not None:
                catalogue_present = sorted(
                    e.get("finding", "") for e in step.get("expects", [])
                    if e.get("state", "PRESENT") == "PRESENT"
                    and e.get("finding") and e.get("finding") not in self._excluded
                )
                if sorted(declared) != catalogue_present:
                    consistency_errors.append((
                        rec.action_seq,
                        f"expected_finding_types={sorted(declared)!r} != catalogue "
                        f"PRESENT expectations={catalogue_present!r}",
                    ))
            unlabelled = sorted(set(declared) - labelled)
            if unlabelled:
                consistency_errors.append((
                    rec.action_seq,
                    f"expected_finding_types {unlabelled!r} have no opportunity",
                ))
            gta = gta_by_seq.get(rec.action_seq)
            if gta is not None:
                del gta.expected_finding_types[:]
                gta.expected_finding_types.extend(
                    ft for ft in declared if ft in present_types)

        self._open_epochs(opportunities, rendered_by_seq)

        # Step 5: build ActionLink protos.
        links = self._build_links(
            exec_instances,
            own_dropped_by_seq if own_dropped_by_seq is not None else (dropped_by_seq or {}),
            downgrades, rendered_by_seq)

        # Step 6: coverage rows from SourceCompleteness records.
        coverage_rows = []
        if completeness_records:
            for sc in completeness_records:
                coverage_rows.append(self._completeness_to_row(sc))

        return TruthResult(
            actions=actions,
            opportunities=opportunities,
            links=links,
            coverage_rows=coverage_rows,
            downgrades=downgrades,
            consistency_errors=consistency_errors,
            hollow_unobservable=hollow,
            incidents=self._build_incidents(exec_instances),
        )

    def write_restricted(self, result: TruthResult, run_dir: Path) -> None:
        """Write all restricted truth to <run_dir>/restricted/.

        Creates the directory if it does not exist.  Writes:
          truth_actions.pb  — length-delimited GroundTruthAction protos
          truth_findings.pb — length-delimited FindingOpportunity protos
          truth_links.pb    — length-delimited ActionLink protos
          truth_incidents.pb — length-delimited GroundTruthIncident protos
          coverage.jsonl    — one JSON object per source × scope
        """
        restricted = Path(run_dir) / "restricted"
        restricted.mkdir(parents=True, exist_ok=True)
        write_ld_protos(restricted / "truth_actions.pb", result.actions)
        write_ld_protos(restricted / "truth_findings.pb", result.opportunities)
        write_ld_protos(restricted / "truth_links.pb", result.links)
        write_ld_protos(restricted / "truth_incidents.pb", result.incidents)
        with open(restricted / "coverage.jsonl", "w", newline="\n") as fh:
            for row in result.coverage_rows:
                fh.write(json.dumps(row) + "\n")

    # ------------------------------------------------------------------
    # Incidents (exp2-gaps-plan B1)
    # ------------------------------------------------------------------

    def _build_incidents(
        self, exec_instances: List[Tuple[str, str, Dict[str, int]]]
    ) -> List["dataset_pb2.GroundTruthIncident"]:
        """Incidents of each scenario execution: a step's catalogue
        `incident:` name, else its float group for a benign (decoy or twin)
        step, else the execution's main incident. An incident is an attack
        when its scenario is and it holds a non-benign step."""
        out: List[dataset_pb2.GroundTruthIncident] = []
        for scen_id, _var, step_map in exec_instances:
            scenario = self._cat_by_id.get(scen_id) or {}
            groups: Dict[str, List[int]] = {}
            attack: Dict[str, bool] = {}
            for label, seq in sorted(step_map.items(), key=lambda kv: kv[1]):
                step = self._find_step(scenario, label) or {}
                benign = bool(step.get("benign"))
                name = str(step.get("incident") or (
                    f"float:{step['float']}" if benign and step.get("float") else "main"))
                groups.setdefault(name, []).append(seq)
                attack[name] = attack.get(name, False) or (
                    is_attack_scenario(scenario) and not benign)
            # A catalogue PRESENT link never crosses incidents: merge the
            # groups it joins (a twin flow's connect and its transfer).
            of = {seq: name for name, seqs in groups.items() for seq in seqs}
            for lk in scenario.get("links", []):
                if lk.get("expected", "PRESENT") != "PRESENT":
                    continue
                a = of.get(step_map.get(str(lk.get("from"))))
                b = of.get(step_map.get(str(lk.get("to"))))
                if a is None or b is None or a == b:
                    continue
                keep, gone = sorted((a, b), key=lambda x: (x != "main", x))
                groups[keep] += groups.pop(gone)
                attack[keep] = attack[keep] or attack.pop(gone)
                of = {seq: name for name, seqs in groups.items() for seq in seqs}
            for name in sorted(groups, key=lambda n: min(groups[n])):
                out.append(dataset_pb2.GroundTruthIncident(
                    run_id=self._run_id,
                    incident_id=f"inc-{self._run_id[:8]}-{len(out) + 1:04d}",
                    action_seqs=sorted(groups[name]), is_attack=attack[name],
                    scenario_id=scen_id, truth_version=self._truth_version))
        return out

    # ------------------------------------------------------------------
    # Execution grouping
    # ------------------------------------------------------------------

    def _group_executions(
        self, gt_records: List[GroundTruthRecord]
    ) -> List[Tuple[str, str, Dict[str, int]]]:
        """Group records into scenario execution instances.

        Returns a list of (scenario_id, variant_id, {step_label: action_seq}).
        A new execution starts when scenario_id/variant_id changes or when
        a step_label repeats within the current pair.
        """
        instances: List[Tuple[str, str, Dict[str, int]]] = []
        cur_scen: Optional[str] = None
        cur_var: Optional[str] = None
        cur_map: Dict[str, int] = {}
        cur_seen: set = set()

        for rec in sorted(gt_records, key=lambda r: r.action_seq):
            if (rec.scenario_id != cur_scen
                    or rec.variant_id != cur_var
                    or rec.step_label in cur_seen):
                if cur_scen is not None:
                    instances.append((cur_scen, cur_var, cur_map))
                cur_scen = rec.scenario_id
                cur_var = rec.variant_id
                cur_map = {}
                cur_seen = set()
            cur_map[rec.step_label] = rec.action_seq
            cur_seen.add(rec.step_label)

        if cur_scen is not None:
            instances.append((cur_scen, cur_var, cur_map))

        return instances

    # ------------------------------------------------------------------
    # Proto builders
    # ------------------------------------------------------------------

    def _build_gta(
        self,
        rec: GroundTruthRecord,
        event_infos: List[RenderedEventInfo],
    ) -> "dataset_pb2.GroundTruthAction":
        gta = dataset_pb2.GroundTruthAction(
            run_id=rec.run_id,
            action_seq=rec.action_seq,
            scenario_id=rec.scenario_id,
            variant_id=rec.variant_id,
            step_label=rec.step_label,
            is_attack=rec.is_attack,
            harness_version=rec.harness_version,
            harness_outcome=rec.harness_outcome,
        )
        gta.expected_finding_types.extend(
            ft for ft in rec.expected_finding_types if ft not in self._excluded
        )
        gta.started_at.CopyFrom(ns_to_timestamp(rec.started_at_ns))
        gta.ended_at.CopyFrom(ns_to_timestamp(rec.ended_at_ns))
        if rec.intended_tactic:
            tval = _TACTIC_BY_NAME.get(rec.intended_tactic)
            if tval is not None:
                gta.intended_tactic = tval
        for er in rec.actors:
            ref = gta.actors.add()
            ref.type = _entity_type_str_to_enum(er.entity_type)
            if er.uid:
                ref.uid = er.uid
            if er.namespace:
                ref.namespace = er.namespace
            if er.name:
                ref.name = er.name
        for er in rec.targets:
            ref = gta.targets.add()
            ref.type = _entity_type_str_to_enum(er.entity_type)
            if er.uid:
                ref.uid = er.uid
            if er.namespace:
                ref.namespace = er.namespace
            if er.name:
                ref.name = er.name
        gta.rendered_event_ids.extend(ei.event_id for ei in event_infos)
        return gta

    def _build_opportunity(
        self,
        opp_id: str,
        rec: GroundTruthRecord,
        finding_type: str,
        expected_state: str,
        evidence_reqs: List[str],
        reason: str,
        evidence_event_ids: List[str],
        event_infos: Optional[List["RenderedEventInfo"]] = None,
    ) -> "dataset_pb2.FindingOpportunity":
        state_enum = _TRUTH_EXPECTATION_BY_NAME.get(
            expected_state, dataset_pb2.TRUTH_EXPECTATION_UNSPECIFIED
        )
        ws_ns, we_ns = self._compute_window(
            finding_type, expected_state, event_infos or [],
            rec.started_at_ns, rec.ended_at_ns,
        )
        opp = dataset_pb2.FindingOpportunity(
            run_id=rec.run_id,
            opportunity_id=opp_id,
            action_seq=rec.action_seq,
            finding_type=finding_type,
            expected_state=state_enum,
            reason=reason,
            truth_version=self._truth_version,
        )
        opp.window_start.CopyFrom(ns_to_timestamp(ws_ns))
        opp.window_end.CopyFrom(ns_to_timestamp(we_ns))
        opp.evidence_requirements.extend(evidence_reqs)
        opp.evidence_event_ids.extend(evidence_event_ids)
        return opp

    def _build_links(
        self,
        exec_instances: List[Tuple[str, str, Dict[str, int]]],
        dropped_by_seq: Optional[Dict[int, List[RenderedEventInfo]]] = None,
        downgrades: Optional[list] = None,
        rendered_by_seq: Optional[Dict[int, List[RenderedEventInfo]]] = None,
    ) -> List["dataset_pb2.ActionLink"]:
        """ActionLink rows from the catalogue links of each execution.

        A link (PRESENT or ABSENT) is UNOBSERVABLE when its witness can be
        neither confirmed nor ruled out (``dropped_by_seq``: the steps' own
        dropped events): an endpoint lost an event of a source the witness
        reads, or, for PROCESS_ANCESTRY, a step between the endpoints lost its
        proc.exec (the child on the path, such as the curl between a shell
        and the connect curl makes), or every step the link names in
        ``contradicted_by`` lost its net.connect (the reusing connects of a
        port-reuse nonlink, G2: one left is enough for the correlator to see
        the contradiction). A dropped proc.fork does not count when
        the step's proc.exec, which names the same child and parent, was
        kept. Applying this to both labels keeps a degraded profile from
        holding a link's negatives without its positives. Recorded in
        ``downgrades`` with finding type "link:<WITNESS>".
        """
        links: List[dataset_pb2.ActionLink] = []
        link_idx = 0

        for scen_id, var_id, step_map in exec_instances:
            scenario = self._cat_by_id.get(scen_id)
            if scenario is None:
                continue
            for link_def in scenario.get("links", []):
                from_label = str(link_def.get("from", ""))
                to_label = str(link_def.get("to", ""))
                from_seq = step_map.get(from_label)
                to_seq = step_map.get(to_label)
                if from_seq is None or to_seq is None:
                    continue  # step not executed in this run

                link_idx += 1
                link_id = f"link-{self._run_id[:8]}-{link_idx:06d}"
                witness_name = link_def.get("witness", "")
                expected_str = link_def.get("expected", "PRESENT")
                shared_keys = link_def.get("shared_keys", [])
                reason = link_def.get("reason", "")
                sources = _WITNESS_SOURCES.get(witness_name, frozenset())
                path = ({step_map[p] for p in _process_path(scenario, to_label, from_label)
                         if p in step_map}
                        if witness_name == "PROCESS_ANCESTRY" else set())
                contra = {step_map[str(c)] for c in link_def.get("contradicted_by", [])
                          if str(c) in step_map}
                if not all(any(ei.family == "net.connect"
                               for ei in (dropped_by_seq or {}).get(seq, [])) for seq in contra):
                    contra = set()          # a reusing connect is left: decidable

                def _counts(seq, ei):
                    if ei.record_type not in sources:
                        return False
                    if seq in contra and seq not in (from_seq, to_seq):
                        return ei.family == "net.connect"
                    if seq not in (from_seq, to_seq):
                        # Another step matters only as a process on the
                        # target's ancestry path: its exec.
                        return ei.family == "proc.exec"
                    return not (ei.family == "proc.fork" and any(
                        k.family == "proc.exec"
                        for k in (rendered_by_seq or {}).get(seq, [])))

                lost = sorted({
                    ei.record_type
                    for seq in {from_seq, to_seq} | path | contra
                    for ei in (dropped_by_seq or {}).get(seq, [])
                    if _counts(seq, ei)
                })
                if lost and expected_str != "UNOBSERVABLE":
                    new_reason = (f"Link witness evidence dropped ({', '.join(lost)}); "
                                  f"catalogue {expected_str}")
                    if downgrades is not None:
                        downgrades.append((to_seq, f"link:{witness_name}",
                                           expected_str, "UNOBSERVABLE", new_reason))
                    expected_str, reason = "UNOBSERVABLE", new_reason
                if expected_str != "UNOBSERVABLE":
                    why = self._link_gap(witness_name, (rendered_by_seq or {}).get(from_seq, []),
                                         (rendered_by_seq or {}).get(to_seq, []))
                    if why:
                        new_reason = f"Link {why}; catalogue {expected_str}"
                        if downgrades is not None:
                            downgrades.append((to_seq, f"link:{witness_name}",
                                               expected_str, "UNOBSERVABLE", new_reason))
                        expected_str, reason = "UNOBSERVABLE", new_reason

                expected_enum = _TRUTH_EXPECTATION_BY_NAME.get(
                    expected_str, dataset_pb2.TRUTH_EXPECTATION_UNSPECIFIED
                )
                witness_enum = _WITNESS_BY_NAME.get(
                    witness_name, witness_pb2.WITNESS_TYPE_UNSPECIFIED
                )

                lnk = dataset_pb2.ActionLink(
                    run_id=self._run_id,
                    link_id=link_id,
                    from_action_seq=from_seq,
                    to_action_seq=to_seq,
                    witness_type=witness_enum,
                    expected_state=expected_enum,
                    reason=reason,
                    truth_version=self._truth_version,
                )
                lnk.shared_keys.extend(shared_keys)
                links.append(lnk)

        return links

    def _gap_blinds(self, finding_type: str, infos: List[RenderedEventInfo],
                    params: Optional[dict] = None) -> str:
        """A declared gap that covers the finding's own evidence (a source
        and, for eBPF, a family the finding reads, at an evidence event's
        time), described; "" when none. What a detector does around a gap is
        not truth: a gap elsewhere in some rule's window does not blind it.

        A gap declared on the record itself is gateway observer loss, which
        loses the request body and the response but keeps the path and query.
        It blinds A2 (the response), and A1 only when the step's request
        carried a body (params: the catalogue step's)."""
        rt = self._rt_by_id.get(finding_type)
        if rt is None:
            return ""
        inputs = rt.get("inputs", [])
        records = {i["record"] for i in inputs if i.get("record")}
        families = frozenset(i["family"] for i in inputs
                             if i.get("record") == "ebpf" and i.get("family")) or None
        evs = [ei for ei in infos if ei.record_type in records]
        p = params or {}
        body = bool(p.get("body") or p.get("body_prefix_b64"))
        for ei in evs:
            if ei.record_gap and (finding_type != "A1" or body):
                return f"{ei.record_gap} declared on the {ei.record_type} record"
        for ei in evs:
            for g in self._gaps:
                if g.hits(ei.record_type, ei.node, families, ei.time_ns, ei.time_ns):
                    return g.describe()
        return ""

    def _open_epochs(self, opportunities, rendered_by_seq: Dict[int, List[RenderedEventInfo]]) -> None:
        """Node-trust epochs (D-23): a PRESENT trigger finding (C1b) opens one
        on its evidence's node; the correlator distrusts what follows.

        The onset comes from the trigger step's own events only, as the
        correlator's comes from the C1b finding's inputs (epochs.py). The
        opportunity's evidence also cites earlier steps and standing evidence
        (ancestry, node events from the run's start), which would open the
        epoch long before the escape."""
        self._epochs, self._epoch_events = {}, {}
        for opp in opportunities:
            if opp.finding_type not in _EPOCH_TRIGGERS or opp.expected_state != dataset_pb2.PRESENT:
                continue
            own = {ei.event_id: ei for ei in rendered_by_seq.get(opp.action_seq, [])}
            for eid in opp.evidence_event_ids:
                ei = own.get(eid)
                if ei is not None and ei.record_type == "ebpf" and ei.node:
                    tau = self._epochs.get(ei.node)
                    if tau is None or ei.time_ns < tau:
                        self._epochs[ei.node], self._epoch_events[ei.node] = ei.time_ns, {eid}
                    elif ei.time_ns == tau:
                        self._epoch_events[ei.node].add(eid)

    def _into_trigger(self, node: str, tau: int, from_infos: List[RenderedEventInfo],
                      to_infos: List[RenderedEventInfo]) -> bool:
        """A link into the compromise itself (D-23 narrowed 2026-10-24): its
        to-end holds the event that opened node's epoch and its from-end's
        events on node precede the onset. admit.covered does not count that
        epoch against the link, and the from-end evidence is not degraded."""
        own = self._epoch_events.get(node, set())
        return (any(e.event_id in own for e in to_infos if e.node == node)
                and all(e.time_ns < tau for e in from_infos if e.record_type == "ebpf" and e.node == node))

    def _link_gap(self, witness_name: str, from_infos: List[RenderedEventInfo],
                  to_infos: List[RenderedEventInfo]) -> str:
        """Why the correlator cannot decide the link for a declared gap, or "".

        As mtcore.orchestrator.admit: without action IDs, distinctness needs
        no gap within A (+ beta) of either end on its own sources; coverage
        needs no eBPF gap between the ends on their nodes (families: the
        ends' own and those the witness type's contradictions show in)."""
        ebpf_ends = [e for e in list(from_infos) + list(to_infos) if e.record_type == "ebpf" and e.node]
        if self._epochs and ebpf_ends and _CHECK_FAMILIES.get(witness_name) is not None:
            # A node-trust epoch opening before the link's end plus beta:
            # degraded evidence or an uncovered interval (admit.covered), D-23.
            beta = self._a_beta_ns[1] if self._a_beta_ns is not None else 0
            hi = max(e.time_ns for e in ebpf_ends)
            for node in sorted({e.node for e in ebpf_ends}):
                tau = self._epochs.get(node)
                if tau is not None and tau <= hi + beta:
                    if self._into_trigger(node, tau, from_infos, to_infos):
                        continue
                    return f"after a node-trust epoch onset on node {node} (C1b): evidence not trusted"
        if not self._gaps:
            return ""
        if self._a_beta_ns is not None:
            a, beta = self._a_beta_ns
            for infos in (from_infos, to_infos):
                fams = frozenset(e.family for e in infos if e.record_type == "ebpf" and e.family) or None
                for e in infos:
                    for g in self._gaps:
                        if g.hits(e.record_type, e.node, fams, e.time_ns - a, e.time_ns + a + beta):
                            return f"near a declared gap ({g.describe()}): within A + beta of an end"
        checks = _CHECK_FAMILIES.get(witness_name)
        ends = [e for e in list(from_infos) + list(to_infos) if e.record_type == "ebpf"]
        if checks is not None and ends:
            fams = checks | frozenset(e.family for e in ends if e.family)
            lo, hi = min(e.time_ns for e in ends), max(e.time_ns for e in ends)
            for node in sorted({e.node for e in ends}):
                for g in self._gaps:
                    if g.hits("ebpf", node, fams, lo, hi):
                        return f"crosses a declared gap ({g.describe()}): contradictions not covered"
        return ""

    # ------------------------------------------------------------------
    # Window computation
    # ------------------------------------------------------------------

    def _compute_window(
        self,
        finding_type: str,
        expected_state: str,
        event_infos: List["RenderedEventInfo"],
        step_start_ns: int,
        step_end_ns: int,
    ) -> Tuple[int, int]:
        """Return (window_start_ns, window_end_ns) for a FindingOpportunity.

        Rules (from evidence-rendering.v0.yaml state.window):
        - window: null  → span from first to last evidence event time; if no
                          events present, fall back to the action's step times.
        - window: W_X   → window ends at the last evidence event and spans the
                          declared W_X length backward; if W_X has no value in
                          the spec yet (UNFROZEN), fall back to step times.
        - UNOBSERVABLE with no events → both bounds equal step_start_ns.
        """
        event_times = [ei.time_ns for ei in event_infos if ei.time_ns > 0]

        if expected_state == "UNOBSERVABLE" and not event_times:
            return step_start_ns, step_start_ns

        window_symbol = self._get_window_symbol(finding_type)

        if window_symbol is None:
            # null window: first to last evidence event
            if event_times:
                return min(event_times), max(event_times)
            return step_start_ns, step_end_ns

        # Symbol window: look up the declared value
        window_ns = self._window_ns_by_symbol.get(window_symbol)
        if window_ns is not None and window_ns > 0:
            if event_times:
                we = max(event_times)
                ws = max(0, we - window_ns)
                return ws, we
            return step_start_ns, step_end_ns
        # Symbol present but no value yet (UNFROZEN): fall back to step times
        return step_start_ns, step_end_ns

    def _get_window_symbol(self, finding_type: str) -> Optional[str]:
        """Return the state.window symbol for this finding, or None if null."""
        rt = self._rt_by_id.get(finding_type)
        if rt is None:
            return None
        return rt.get("state", {}).get("window")  # None or e.g. "W_B1"

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------

    def _all_requirements(self, finding_type: str) -> List[str]:
        """Return all field path strings for this finding from the rendering table."""
        rt = self._rt_by_id.get(finding_type)
        if rt is None:
            return []
        return [inp["field"] for inp in rt.get("inputs", [])]

    def _check_evidence(
        self,
        finding_type: str,
        event_infos: List[RenderedEventInfo],
    ) -> List[str]:
        """Check which required (record_type, family) sources are absent.

        Inputs without an ``any_of`` group are all required. Inputs sharing
        an ``any_of`` group are alternatives: the group is covered when any
        one of them is rendered, and names all its members when none is.

        Returns a list of missing field paths; empty means the evidence is
        complete.
        """
        rt = self._rt_by_id.get(finding_type)
        if rt is None:
            return []

        # (record_type, family) -> first field path, per any_of group. Group
        # None holds the individually required inputs. Derived fields
        # (record=null) are checked via their base record type.
        groups: Dict[Optional[str], Dict[Tuple[str, str], str]] = {}
        for inp in rt.get("inputs", []):
            record = inp.get("record")
            derived = inp.get("derived")
            if record is not None:
                key = (record, inp.get("family") or "")
            elif derived is not None and derived in _DERIVED_TO_BASE_RECORD:
                key = (_DERIVED_TO_BASE_RECORD[derived], "")
            else:
                continue
            groups.setdefault(inp.get("any_of"), {}).setdefault(key, inp["field"])

        # Build the set of rendered (record_type, family) pairs.
        rendered: set = {(ei.record_type, ei.family) for ei in event_infos}

        def covered(rec: str, fam: str) -> bool:
            if fam:
                return (rec, fam) in rendered
            # Any family for this record type is acceptable
            return any(r == rec for r, _ in rendered)

        missing: List[str] = []
        for (rec, fam), field_path in sorted(groups.get(None, {}).items()):
            if not covered(rec, fam):
                missing.append(field_path)
        for name in sorted(g for g in groups if g is not None):
            alternatives = groups[name]
            if not any(covered(rec, fam) for rec, fam in alternatives):
                missing.extend(field_path for _, field_path in sorted(alternatives.items()))

        return missing

    # ------------------------------------------------------------------
    # Catalogue lookup helpers
    # ------------------------------------------------------------------

    def _spans_steps(self, finding_type: str) -> bool:
        """Whether a finding's evidence may come from earlier steps: its rule
        keeps state across events (rendering table state.kind keyed or
        global). Unknown findings keep the multi-step span."""
        kind = ((self._rt_by_id.get(finding_type) or {}).get("state") or {}).get("kind")
        return kind != "stateless"

    def _find_step(
        self, scenario: dict, step_label: str
    ) -> Optional[dict]:
        """Return the step dict matching step_label (as string or int)."""
        try:
            step_num = int(step_label)
        except (ValueError, TypeError):
            step_num = None

        for s in scenario.get("steps", []):
            if str(s.get("step", "")) == step_label:
                return s
            if step_num is not None and s.get("step") == step_num:
                return s
        return None

    # ------------------------------------------------------------------
    # Coverage table helper
    # ------------------------------------------------------------------

    def _completeness_to_row(self, sc) -> dict:
        """Convert a SourceCompleteness proto to a coverage table row dict."""
        from microtrace.v0 import stream_pb2
        source_name = _SOURCE_ENUM_TO_NAME.get(sc.source, "UNSPECIFIED")
        status_name = (
            "NO_KNOWN_GAP"
            if sc.status == stream_pb2.NO_KNOWN_GAP
            else "INCOMPLETE"
        )
        gap_reason = ""
        if sc.gaps:
            gap_reason = _GAP_REASON_TO_NAME.get(sc.gaps[0].reason, "UNKNOWN")

        return {
            "run_id": self._run_id,
            "source_family": source_name,
            "scope": sc.scope,
            "interval_start": _ts_to_iso(sc.interval_start),
            "interval_end": _ts_to_iso(sc.interval_end),
            "status": status_name,
            "gap_reason": gap_reason,
            "fault_id": "",
        }


# ---------------------------------------------------------------------------
# Length-delimited protobuf I/O (big-endian 4-byte header)
# ---------------------------------------------------------------------------

def write_ld_protos(path: Path, messages: List) -> None:
    """Serialize proto messages to a length-delimited binary file."""
    with open(path, "wb") as fh:
        for msg in messages:
            data = msg.SerializeToString(deterministic=True)   # map fields in key order
            fh.write(struct.pack(">I", len(data)))
            fh.write(data)


def read_ld_protos(path: Path, message_class) -> List:
    """Deserialize all messages from a length-delimited binary file."""
    messages = []
    with open(path, "rb") as fh:
        while True:
            header = fh.read(4)
            if not header:
                break
            (length,) = struct.unpack(">I", header)
            data = fh.read(length)
            msg = message_class()
            msg.ParseFromString(data)
            messages.append(msg)
    return messages


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _ts_to_iso(ts) -> str:
    """Convert a google.protobuf.Timestamp to an ISO 8601 UTC string."""
    dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + \
        datetime.timedelta(seconds=ts.seconds, microseconds=ts.nanos // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _extract_window_values(gen_spec: dict) -> Dict[str, Optional[int]]:
    """Build a symbol -> window_ns mapping from generator-spec declared_artifacts.

    A declared artifact's window_symbol or symbol field names a parameter
    symbol (e.g. "W_B1"). If the spec provides a numeric value (via
    pilot_default or frozen), convert it to nanoseconds (assuming seconds).
    Most symbols are UNFROZEN (no value yet); return None for those.
    """
    result: Dict[str, Optional[int]] = {}
    artifacts = gen_spec.get("declared_artifacts", {})
    for _name, art in artifacts.items():
        for sym_key in ("window_symbol", "symbol"):
            sym = art.get(sym_key)
            if sym is None:
                continue
            # Try to find a numeric value under the same artifact
            for val_key in ("window_seconds", "value_seconds", "seconds"):
                val = art.get(val_key)
                if val is not None:
                    val_s = _resolve_param(val)
                    if val_s is not None:
                        result[sym] = int(val_s * 1_000_000_000)
                        break
            else:
                result.setdefault(sym, None)  # declare symbol; value unknown
    return result


def _resolve_param(val) -> Optional[float]:
    """Extract a scalar from a possibly-unfrozen parameter dict."""
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, dict):
        frozen = val.get("frozen")
        if frozen is not None:
            return float(frozen)
        pd = val.get("pilot_default")
        if pd is not None:
            return float(pd)
    return None


def _entity_type_str_to_enum(entity_type: str) -> int:
    """Map an entity type string to the EntityType enum value."""
    mapping = {
        "POD": common_pb2.POD,
        "CONTAINER": common_pb2.CONTAINER,
        "PROCESS": common_pb2.PROCESS,
        "SERVICE_ACCOUNT": common_pb2.SERVICE_ACCOUNT,
        "NAMESPACE": common_pb2.NAMESPACE,
        "NODE": common_pb2.NODE,
        "UNAUTHENTICATED_SOURCE": common_pb2.UNAUTHENTICATED_SOURCE,
        "External": common_pb2.UNAUTHENTICATED_SOURCE,
        "InfraService": common_pb2.NODE,
    }
    return mapping.get(entity_type, common_pb2.ENTITY_TYPE_UNSPECIFIED)
