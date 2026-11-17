"""Scenario engine: execute catalogue scenarios in the world.

Selects scenarios and variants per a run specification, binds abstract roles
to concrete world entities with a seeded choice, places steps in time with
seeded offsets within the variant, and executes each step's action against the
world.

Each executed step:
  1. Emits one Activity carrying action_seq.
  2. Applies state changes to world.history when outcome is not
     "attempt_failed".
  3. Returns one GroundTruthRecord.

``rendered_event_ids`` in GroundTruthRecord is always empty; the truth
writer (phase 2.5) fills it after rendering.
"""
from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from .activity import Activity
from .degrade import UNOBSERVED_SOURCES
from .history import FOREVER, ContextHistoryRow
from .ids import child_process_key, pod_init_processes
from .netmodel import gap_ns
from .rng import Streams
from .world import (
    _HISTORY_VERSION, FileState, ProcessState, World,
)

HARNESS_VERSION: str = "scenarios.v0"

# Window allocated to each scenario (ns)
_SCENARIO_WINDOW_NS: int = 60_000_000_000   # 60 s
# Gap between consecutive scenario windows (ns)
_SCENARIO_SPACING_NS: int = 30_000_000_000  # 30 s
# Duration from step start to step end (ns)
_STEP_DURATION_NS: int = 5_000_000_000      # 5 s
# Least time between two placed steps of a scenario (ns)
_MIN_STEP_GAP_NS: int = 2_000_000_000       # 2 s

# A degraded scenario is an attack whose evidence was partly lost, so its
# non-benign steps are attacks (decision T-1, 2026-11-02). These two are not
# attacks: failures below the alert threshold, and an exec of unknown principal.
_DEGRADED_NOT_ATTACK = frozenset({"b2_auth_failure_below_threshold", "g2_exec_session_ambiguous"})


def is_attack_scenario(scenario: dict) -> bool:
    """True if the scenario's non-benign steps are attack steps."""
    kind = scenario.get("kind", "benign")
    return kind == "attack" or (kind == "degraded" and scenario.get("id") not in _DEGRADED_NOT_ATTACK)


# Map action id -> (actor_param_key, target_param_key)
_ACTION_ACTOR_TARGET: Dict[str, Tuple[str, str]] = {
    "http_request":                    ("source_pod",        "target_service"),
    "api_request":                     ("principal",         "resource"),
    "api_auth_failure":                ("source_ip",         "resource"),
    "secret_list":                     ("principal",         "namespace"),
    "secret_get":                      ("principal",         "name"),
    "read_token_file":                 ("reader_process",    "token_file_path"),
    "read_sensitive_file":             ("reader_process",    "file_path"),
    "shell_exec":                      ("parent_process",    "shell_binary"),
    "process_exec":                    ("parent_process",    "executable"),
    "ptrace_attach":                   ("attaching_process", "target_process"),
    "file_write":                      ("writer_process",    "file_path"),
    "make_executable":                 ("process",           "file_path"),
    "chmod":                           ("process",           "file_path"),
    "privilege_change":                ("process",           "process"),
    "euid_to_root":                    ("process",           "process"),
    "namespace_escape":                ("process",           "process"),
    "capability_gain":                 ("process",           "process"),
    "connect_external":                ("source_pod",        "remote_ip"),
    "connect_internal":                ("source_pod",        "target_service_or_pod"),
    "accept_internal":                 ("server_pod",        "source_pod"),
    "egress_transfer":                 ("source_pod",        "destination"),
    "admit_pod":                       ("",                  "resource_uid"),
    "rbac_change":                     ("principal",         "name"),
    "capability_privilege_annotation": ("pod_name",          "namespace"),
    "observe_state":                   ("entity_id",         "entity_id"),
    "delay":                           ("",                  ""),
    "set_baseline":                    ("principal",         "workload"),
    "expect_finding":                  ("finding_id",        "finding_id"),
}

# Map action id -> target_type string used in Activity.target_type
_ACTION_TARGET_TYPE: Dict[str, str] = {
    "http_request":                    "Service",
    "api_request":                     "APIResource",
    "api_auth_failure":                "APIResource",
    "secret_list":                     "APIResource",
    "secret_get":                      "APIResource",
    "read_token_file":                 "File",
    "read_sensitive_file":             "File",
    "shell_exec":                      "File",
    "process_exec":                    "File",
    "ptrace_attach":                   "Process",
    "file_write":                      "File",
    "make_executable":                 "File",
    "chmod":                           "File",
    "privilege_change":                "Process",
    "euid_to_root":                    "Process",
    "namespace_escape":                "Process",
    "capability_gain":                 "Process",
    "connect_external":                "Endpoint",
    "connect_internal":                "Service",
    "accept_internal":                 "Pod",
    "egress_transfer":                 "Endpoint",
    "admit_pod":                       "Pod",
    "rbac_change":                     "APIResource",
    "capability_privilege_annotation": "Pod",
    "observe_state":                   "Entity",
    "delay":                           "None",
    "set_baseline":                    "Entity",
    "expect_finding":                  "None",
}


# Catalogue steps sometimes name the actor with a generic parameter instead
# of the action's own actor parameter (source_process for file_write's
# writer_process, source_principal for shell_exec's parent_process).
_ACTOR_SYNONYMS: Tuple[str, ...] = (
    "source_process", "source_pod", "source_principal", "process", "principal",
)


def _actor_value(actor_key: str, resolved: dict) -> Optional[str]:
    """Return the step's actor UID: its actor parameter, else a synonym."""
    if not actor_key:
        return None
    if resolved.get(actor_key):
        return resolved[actor_key]
    for key in _ACTOR_SYNONYMS:
        if resolved.get(key):
            return resolved[key]
    return None


def _step_refs(params: dict) -> set:
    """Step numbers a step's parameters name with "@step<N>.<key>"."""
    refs = set()
    for v in params.values():
        if isinstance(v, str) and v.startswith("@step"):
            label = v[len("@step"):].partition(".")[0]
            refs.add(int(label) if label.isdigit() else label)
    return refs


def scenario_window_ns(scenario: dict) -> int:
    """Time a scenario's steps spread over: its ``window_s``, default 60 s."""
    return int(float(scenario.get("window_s", _SCENARIO_WINDOW_NS / 1e9)) * 1_000_000_000)


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class EntityRefRecord:
    """Python representation of dataset.proto EntityRef.

    entity_type is the EntityType enum name string, e.g. "POD", "PROCESS".
    uid is None when not established (not fabricated from a name or IP).
    """
    entity_type: str
    uid: Optional[str] = None
    namespace: str = ""
    name: str = ""


@dataclass
class GroundTruthRecord:
    """Python representation of dataset.proto GroundTruthAction.

    rendered_event_ids is always empty in phase 2.3; the truth writer
    (phase 2.5) populates it after rendering.
    harness_outcome is "effect_realized" or "attempt_failed".
    """
    run_id: str
    action_seq: int
    scenario_id: str
    variant_id: str
    step_label: str
    is_attack: bool
    expected_finding_types: List[str] = field(default_factory=list)
    intended_tactic: Optional[str] = None
    actors: List[EntityRefRecord] = field(default_factory=list)
    targets: List[EntityRefRecord] = field(default_factory=list)
    started_at_ns: int = 0
    ended_at_ns: int = 0
    harness_version: str = HARNESS_VERSION
    harness_outcome: str = "effect_realized"
    rendered_event_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scenario engine
# ---------------------------------------------------------------------------

class ScenarioEngine:
    """Execute catalogue scenarios inside a built World.

    Parameters
    ----------
    world : World
        Built and finalised world instance.
    catalogue : dict
        Loaded catalogue YAML as a dict with a "scenarios" list.
    run_spec : dict
        Which scenarios and variants to execute.  Format::

            {
                "scenarios": [
                    {"scenario_id": "...", "variant_id": "..."},
                    ...
                ],
                "scenario_spacing_ns": int,   # optional, default 30 s
            }

    seed : str
        Seed for all scenario randomness (role binding, step timing).
    """

    def __init__(
        self,
        world: World,
        catalogue: dict,
        run_spec: dict,
        seed: str,
    ) -> None:
        self._world = world
        self._catalogue = {s["id"]: s for s in catalogue.get("scenarios", [])}
        self._run_spec = run_spec
        self._seed = seed
        self._streams = Streams(f"{seed}:scenario")
        # A Pod-level actor acts through the Pod's init process (as the eBPF
        # renderer reads it); processes by key, world and scenario-forked.
        self._pod_init = pod_init_processes(world.processes)
        self._procs: Dict[str, ProcessState] = {p.process_key: p for p in world.processes}
        # Global action sequence counter
        self._action_seq: int = 0
        # Scenario IDs selected but not started because the run ended first
        self.dropped_scenarios: List[str] = []
        # Pod roles re-bound because the first pick died within the window
        self.repicked_roles: int = 0
        # Roles re-drawn because they drew an entity another role holds
        self.rebound_roles: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self) -> Tuple[List[Activity], List[GroundTruthRecord]]:
        """Execute all selected scenarios.

        Returns:
            (activities, ground_truth_records). Activities are sorted by
            time_ns. Records are in action_seq order.
        """
        activities: List[Activity] = []
        records: List[GroundTruthRecord] = []

        run_start = self._world.run_start_ns
        run_end = run_start + self._world.run_duration_ns
        spacing = int(self._run_spec.get("scenario_spacing_ns", _SCENARIO_SPACING_NS))

        rng_place = self._streams.get("scenario.placement")
        t_cursor = run_start + spacing

        # Seeded execution order: with a fixed (catalogue) order every run
        # puts each scenario at the same offset, so window time alone would
        # predict the label.
        entries = list(self._run_spec.get("scenarios", []))
        order = self._streams.get("scenario.order").permutation(len(entries))
        entries = [entries[int(i)] for i in order]

        for pos, entry in enumerate(entries):
            sid = entry["scenario_id"]
            vid = entry.get("variant_id", "v1")

            scenario = self._catalogue.get(sid)
            if scenario is None:
                raise ValueError(
                    f"scenario {sid!r} not found in catalogue "
                    f"(available: {list(self._catalogue)})"
                )

            # Small jitter within ±25% of spacing
            half = max(1, spacing // 4)
            jitter = int(rng_place.integers(-half, half + 1))
            window_ns = scenario_window_ns(scenario)
            scen_start = max(run_start + 1, t_cursor + jitter)
            scen_end = min(run_end, scen_start + window_ns)
            if scen_start >= run_end:
                self.dropped_scenarios = [e["scenario_id"] for e in entries[pos:]]
                break

            acts, recs = self._execute_scenario(scenario, vid, scen_start, scen_end)
            activities.extend(acts)
            records.extend(recs)

            t_cursor += spacing + window_ns

        activities.sort(key=lambda a: a.time_ns)
        return activities, records

    # ------------------------------------------------------------------
    # Scenario execution
    # ------------------------------------------------------------------

    def _execute_scenario(
        self,
        scenario: dict,
        variant_id: str,
        start_ns: int,
        end_ns: int,
    ) -> Tuple[List[Activity], List[GroundTruthRecord]]:
        sid = scenario["id"]
        is_attack = is_attack_scenario(scenario)
        tactic = scenario.get("intended_tactic")

        rng = self._streams.get(f"scenario.exec.{sid}.{variant_id}")

        # Resolve steps with variant-specific overrides
        steps = list(scenario.get("steps", []))
        variant = self._find_variant(scenario, variant_id)
        steps = self._apply_variant_changes(steps, variant)

        # Bind abstract roles to concrete world entities
        binding = self._bind_roles(scenario, start_ns, rng, until_ns=end_ns)

        # Determine step execution order
        sequential = True
        if variant is not None:
            sequential = variant.get("sequential", True)
        ordered_steps = self._order_steps(steps, sequential, rng)
        # A link with `ordering: false` is a truth row only: placement ignores it.
        placing = [lk for lk in scenario.get("links", []) if lk.get("ordering", True)]
        ordered_steps = self._float_groups(ordered_steps, placing, rng)

        # Assign a time to each step
        placed = self._place_steps(ordered_steps, start_ns, end_ns, rng)
        placed = self._match_gaps(placed, placing, start_ns, end_ns, rng)

        activities: List[Activity] = []
        gt_records: List[GroundTruthRecord] = []
        # step label -> entities the step acted with, for "@step<N>.<key>"
        # references in later steps: "process" (an exec step's child, else
        # the acting process), "pod" and "action_seq" (the build resolves
        # copy_request_id_of with it).
        outputs: Dict[str, Dict[str, str]] = {}

        for step, t in placed:
            self._action_seq += 1
            seq = self._action_seq
            step_label = str(step.get("step", seq))
            outcome = step.get("outcome", "success")
            action = step["action"]

            resolved = self._resolve_params(step.get("params", {}), binding, outputs, sid)
            if action == "admit_pod":
                resolved = self._mint_admitted_pod(resolved, sid, seq)
            if action in ("shell_exec", "process_exec") and outcome != "attempt_failed":
                # The exec forks a child: name it, so later steps can act as it.
                # The forking process is the step's actor (parent_process, or
                # a synonym such as source_principal for kubectl exec steps).
                parent = self._real_process(_actor_value("parent_process", resolved) or "")
                resolved["parent_process_key"] = parent
                resolved["process_key"] = self._child_of(parent, t)
            if action == "accept_internal" and outcome != "attempt_failed":
                # The server Pod's main process forks the connection's
                # handler, which accepts it (G1); later steps may act as it.
                parent = self._real_process(resolved.get("server_pod") or "")
                resolved["parent_process_key"] = parent
                resolved["process_key"] = self._child_of(parent, t)

            # repeat: N renders the step N times as a burst within the step
            # duration, all one action; "{i}" in a string parameter becomes
            # the copy number (1..N), e.g. distinct secret names. A step
            # placed near the window end compresses its burst to fit, so no
            # copy falls after the scenario window (or the run) ends.
            repeat = max(1, int(step.get("repeat", 1)))
            unobserved = tuple(step.get("unobserved", ()))
            bad = set(unobserved) - set(UNOBSERVED_SOURCES)
            if bad:
                raise ValueError(f"{sid} step {step_label}: unknown unobserved source(s) {sorted(bad)}")
            span = min(_STEP_DURATION_NS, max(0, end_ns - 1 - t))
            for i in range(repeat):
                params_i = resolved if repeat == 1 else {
                    k: v.replace("{i}", str(i + 1)) if isinstance(v, str) else v
                    for k, v in resolved.items()
                }
                t_i = t + i * (span // repeat)
                if i and "process_key" in params_i:
                    # Each copy of a repeated exec forks its own child.
                    params_i = dict(params_i, process_key=self._child_of(
                        params_i["parent_process_key"], t_i))
                act = self._make_activity(action, params_i, t_i, outcome, seq)
                act.unobserved = unobserved
                activities.append(act)
                if outcome != "attempt_failed":
                    self._apply_effect(action, params_i, t_i)

            actor_key, _ = _ACTION_ACTOR_TARGET.get(action, ("", ""))
            actor = _actor_value(actor_key, resolved) or ""
            outputs[step_label] = {
                "process": resolved.get("process_key") or self._real_process(
                    resolved.get("source_process") or actor),
                "pod": self._pod_of(actor),
                "action_seq": str(seq),
            }

            expected_findings = [
                e["finding"]
                for e in step.get("expects", [])
                if e.get("state") == "PRESENT"
            ]

            actor_ref, target_ref = self._build_refs(action, resolved, binding)

            gt_records.append(GroundTruthRecord(
                run_id=self._world.run_id,
                action_seq=seq,
                scenario_id=sid,
                variant_id=variant_id,
                step_label=step_label,
                # A benign step inside an attack scenario (a chain's decoy).
                is_attack=is_attack and not step.get("benign", False),
                expected_finding_types=expected_findings,
                # a step's own intended tactic (B4) wins over the scenario's
                intended_tactic=step.get("intended_tactic") or tactic,
                actors=[actor_ref] if actor_ref else [],
                targets=[target_ref] if target_ref else [],
                started_at_ns=t,
                ended_at_ns=t + _STEP_DURATION_NS,
                harness_version=HARNESS_VERSION,
                harness_outcome=(
                    "attempt_failed" if outcome == "attempt_failed"
                    else "effect_realized"
                ),
            ))

        return activities, gt_records

    # ------------------------------------------------------------------
    # Variant helpers
    # ------------------------------------------------------------------

    def _find_variant(self, scenario: dict, variant_id: str) -> Optional[dict]:
        for v in scenario.get("variants", []):
            if v.get("id") == variant_id:
                return v
        return None

    def _apply_variant_changes(
        self, steps: List[dict], variant: Optional[dict]
    ) -> List[dict]:
        """Apply parameter overrides declared in the variant."""
        if variant is None or not variant.get("changes"):
            return steps
        steps = copy.deepcopy(steps)
        for change in variant["changes"]:
            fpath = change.get("field", "")
            value = change.get("value")
            # Only "step.N.params.key" paths are supported here
            parts = fpath.split(".")
            if len(parts) == 4 and parts[0] == "step":
                try:
                    step_num = int(parts[1])
                    section = parts[2]
                    key = parts[3]
                except (ValueError, IndexError):
                    continue
                for s in steps:
                    if s.get("step") == step_num:
                        s.setdefault(section, {})[key] = value
        return steps

    # ------------------------------------------------------------------
    # Step ordering and placement
    # ------------------------------------------------------------------

    def _order_steps(
        self, steps: List[dict], sequential: bool, rng: "np.random.Generator"
    ) -> List[dict]:
        """Return steps in execution order."""
        if sequential:
            return sorted(steps, key=lambda s: s.get("step", 0))
        # Non-sequential: seeded shuffle
        ordered = list(steps)
        perm = rng.permutation(len(ordered))
        return [ordered[int(i)] for i in perm]

    def _float_groups(
        self, steps: List[dict], links: List[dict], rng: "np.random.Generator"
    ) -> List[dict]:
        """Insert ``float: <name>`` step groups at seeded random positions.

        A floating group (a decoy's exec and its action) keeps its own order
        but is not always before or after a given real step, so a decoy's
        position does not give its label away. A floating step stays after
        the steps it names ("@step<N>") and the source of any link into it,
        before the steps that name it and the target of any link out of it,
        and never between a step and its ``follows_within_s`` follower; a
        floating follower stays right after its group predecessor.
        """
        groups: Dict[str, List[dict]] = {}
        for s in steps:
            if s.get("float"):
                groups.setdefault(str(s["float"]), []).append(s)
        if not groups:
            return steps
        fixed = [s for s in steps if not s.get("float")]
        n = len(fixed)
        key: Dict[int, float] = {s.get("step"): float(i) for i, s in enumerate(fixed)}
        # Insertion gap g puts a step just before fixed[g]; a fixed follower
        # keeps its predecessor, so the gap before it is closed.
        open_gap = [g == n or fixed[g].get("follows_within_s") is None for g in range(n + 1)]
        before: Dict[int, set] = {s.get("step"): _step_refs(s.get("params", {})) for s in steps}
        after: Dict[int, set] = {s.get("step"): set() for s in steps}
        for num, refs in before.items():
            for r in refs:
                after.setdefault(r, set()).add(num)
        for lk in links:
            before.setdefault(lk.get("to"), set()).add(lk.get("from"))
            after.setdefault(lk.get("from"), set()).add(lk.get("to"))

        for name in sorted(groups):
            # Group order: a step after the group steps it names, else by
            # step number (a decoy's exec may be numbered after its action).
            rest, members = list(groups[name]), []
            while rest:
                nxt = next((s for s in rest if not (before.get(s.get("step"), set())
                                                    & {m.get("step") for m in rest}
                                                    - {s.get("step")})), rest[0])
                members.append(nxt)
                rest.remove(nxt)
            # A step's upper bound also holds the later steps of its group,
            # which must come after it.
            his = [min([key[q] for q in after.get(s.get("step"), ()) if q in key] + [float(n)])
                   for s in members]
            for j in range(len(his) - 2, -1, -1):
                his[j] = min(his[j], his[j + 1])
            prev: Optional[float] = None
            for s, hi in zip(members, his):
                num = s.get("step")
                if prev is not None and s.get("follows_within_s") is not None:
                    key[num] = prev + 1e-6
                    prev = key[num]
                    continue
                lo = max([key[p] for p in before.get(num, ()) if p in key]
                         + ([prev] if prev is not None else []) + [-1.0])
                gaps = [g for g in range(int(np.floor(lo)) + 1, int(np.ceil(hi)) + 1)
                        if open_gap[g]] if hi > lo else []
                if not gaps:
                    raise ValueError(f"floating step {num} ({name!r}) has no position "
                                     "that keeps its references and links in order")
                g = gaps[int(rng.integers(len(gaps)))]
                a, b = max(g - 1.0, lo), min(float(g), hi)
                key[num] = a + (b - a) * (0.05 + 0.9 * float(rng.random()))
                prev = key[num]

        ordered = sorted(steps, key=lambda s: key[s.get("step")])
        pos = {s.get("step"): i for i, s in enumerate(ordered)}
        for num, refs in before.items():
            if num in pos and any(r in pos and pos[r] > pos[num] for r in refs):
                raise ValueError(f"step {num} is placed before a step it depends on "
                                 "(floating groups that reference each other)")
        return ordered

    def _match_gaps(
        self,
        placed: List[Tuple[dict, int]],
        links: List[dict],
        start_ns: int,
        end_ns: int,
        rng: "np.random.Generator",
    ) -> List[Tuple[dict, int]]:
        """Re-time the floating endpoint of links that declare a gap.

        A twin link with ``gap_of: [a, b]`` places its floating endpoint so
        the link spans the time between steps a and b (x0.75-1.25); with
        ``gap_s: [lo, hi]`` it spans a uniform draw from that range. A real
        link and its twin then share one gap distribution, so the gap does
        not give the label away. A step with ``after: {step: N, gap_s: G}``
        is placed G after step N; G is ``[lo, hi]`` or ``accept_delay``
        (netmodel: a connect's accept, a fixed-port reconnect; G2). Steps
        that must stay in order (references, link directions) are then
        pushed apart by at least 0.5 s, moving floating steps only; an
        ``after`` step is placed last, its gap after its predecessor's final
        time (later only if another step it names needs it); the result is
        in time order.
        """
        timed = {s.get("step"): s["after"] for s, _ in placed if s.get("after")}
        if not timed and not any(lk.get("gap_of") or lk.get("gap_s") for lk in links):
            return placed
        t = {s.get("step"): ts for s, ts in placed}
        floating = {s.get("step") for s, _ in placed if s.get("float")} | set(timed)
        pinned: set = set()
        after_gap: Dict[int, int] = {}
        # after: in dependency order, each step at its predecessor's time
        # plus its gap (a chain c1 -> a1 -> c2 -> a2 resolves front to back).
        # The gap is kept: the passes below may move the predecessor, and the
        # final pass re-places the step from it.
        pending = [s.get("step") for s, _ in placed if s.get("step") in timed]
        while pending:
            ready = [n for n in pending if timed[n]["step"] not in pending]
            if not ready:
                raise ValueError(f"steps {pending}: after names each other in a cycle")
            for n in ready:
                ref = timed[n]["step"]
                if ref not in t:
                    raise ValueError(f"step {n}: after names step {ref}, which is not executed")
                after_gap[n] = max(gap_ns(timed[n]["gap_s"], rng), 1_000_000)
                t[n] = t[ref] + after_gap[n]
                pinned.add(n)
                pending.remove(n)
        for lk in links:
            a, b = lk.get("from"), lk.get("to")
            if a not in t or b not in t or not (lk.get("gap_of") or lk.get("gap_s")):
                continue
            if a in timed or b in timed:
                raise ValueError(f"link {a}->{b}: gap_of/gap_s on a step timed with after")
            if lk.get("gap_of"):
                x, y = lk["gap_of"]
                gap = abs(t[y] - t[x]) * (0.75 + 0.5 * float(rng.random()))
            else:
                gap = gap_ns(lk["gap_s"], rng)
            gap = max(int(gap), 1_000_000)
            if b in floating:
                t[b] = t[a] + gap
                pinned.add(b)
            elif a in floating:
                t[a] = t[b] - gap
                pinned.add(a)
            else:
                raise ValueError(f"link {a}->{b}: gap_of/gap_s needs a floating endpoint")
        # Order constraints: a step after the steps it names, a link's
        # target after its source. Push floating steps until all hold,
        # moving a step pinned to its gap only when nothing else can move.
        before: Dict[int, set] = {s.get("step"): set(_step_refs(s.get("params", {})))
                                  for s, _ in placed}
        for lk in links:
            if lk.get("from") in t and lk.get("to") in t:
                before.setdefault(lk["to"], set()).add(lk["from"])
        for num, a in timed.items():
            before.setdefault(num, set()).add(a["step"])
        for _ in range(len(t) + 1):
            moved = False
            for num, refs in before.items():
                if num in timed:
                    continue        # placed from its final predecessor below
                margin = 500_000_000
                for r in refs:
                    if r in t and num in t and t[num] < t[r] + margin:
                        if num in floating and num not in pinned:
                            t[num] = t[r] + margin
                        elif r in floating and r not in pinned:
                            t[r] = t[num] - margin
                        # Both pinned: move the earlier step back (a decoy's
                        # exec) rather than push its action onto its partner.
                        elif r in floating:
                            t[r] = t[num] - margin
                        elif num in floating:
                            t[num] = t[r] + margin
                        else:
                            continue
                        moved = True
            if not moved:
                break
        for num in t:
            t[num] = min(max(t[num], start_ns), end_ns - 1)
        # Clamping to the window can tie or invert two dependent steps: order
        # by dependencies first (earliest ready step next), then keep each
        # step at least 1 ms after its predecessors.
        step_of = {s.get("step"): s for s, _ in placed}
        deps = {num: {r for r in before.get(num, ()) if r in t and r != num} for num in t}
        done: List[int] = []
        while len(done) < len(t):
            ready = [n for n in t if n not in done and deps[n] <= set(done)]
            if not ready:
                raise ValueError("steps depend on each other in a cycle")
            n = min(ready, key=lambda k: t[k])
            if n in after_gap:
                # Its predecessor is final now: the drawn gap after it, unless
                # another dependency needs the step later.
                lo = max(t[r] for r in deps[n]) + 1_000_000
                t[n] = min(max(t[timed[n]["step"]] + after_gap[n], lo), end_ns - 1)
            elif deps[n]:
                # At the window end a tie stays: the list order (execution
                # order, kept by the stable time sort) still runs it later.
                t[n] = min(max(t[n], max(t[r] for r in deps[n]) + 1_000_000), end_ns - 1)
            done.append(n)
        # Stable: a tie keeps the dependency order.
        return [(step_of[n], t[n]) for n in sorted(done, key=t.get)]

    def _place_steps(
        self,
        steps: List[dict],
        start_ns: int,
        end_ns: int,
        rng: "np.random.Generator",
    ) -> List[Tuple[dict, int]]:
        """Assign one time per step: sorted uniform draws in [start_ns, end_ns).

        Steps keep their order and are at least ``_MIN_STEP_GAP_NS`` apart, so
        the time between two steps does not follow from their step numbers.
        A step with ``follows_within_s: S`` is placed 1 ms to S s after the
        previous step instead (a pair close in time); room for it is kept.
        """
        if not steps:
            return []
        # Blocks: a step and the followers placed right after it.
        blocks: List[List[Tuple[dict, int]]] = []
        for step in steps:
            gap = step.get("follows_within_s")
            if blocks and gap is not None:
                blocks[-1].append((step, int(float(gap) * 1_000_000_000)))
            else:
                blocks.append([(step, 0)])
        lengths = [sum(g for _, g in b) for b in blocks]
        window = max(0, end_ns - start_ns)
        nb = len(blocks)
        min_gap = _MIN_STEP_GAP_NS
        if nb > 1 and window - sum(lengths) < (nb - 1) * min_gap:
            min_gap = max(0, (window - sum(lengths)) // (nb - 1))
        slack = max(0, window - sum(lengths) - (nb - 1) * min_gap)
        offsets = np.sort(rng.integers(0, slack + 1, size=nb))
        result: List[Tuple[dict, int]] = []
        base = start_ns
        for block, length, off in zip(blocks, lengths, offsets):
            t = min(base + int(off), end_ns - 1)
            result.append((block[0][0], t))
            for step, gap in block[1:]:
                t = t + 1_000_000 + int(rng.integers(0, max(1, gap - 1_000_000)))
                result.append((step, min(t, end_ns - 1)))
            base += length + min_gap
        return result

    # ------------------------------------------------------------------
    # Role binding
    # ------------------------------------------------------------------

    def _bind_roles(
        self, scenario: dict, t_ns: int, rng: "np.random.Generator",
        until_ns: Optional[int] = None,
    ) -> Dict[str, dict]:
        """Map role names to concrete entity dicts."""
        binding: Dict[str, dict] = {}
        for role in scenario.get("roles", []):
            rname = role["name"]
            rkind = role.get("kind", "internal_pod")
            if rkind == "peer_pod":
                binding[rname] = self._peer_pod(binding[role["of"]], t_ns, rng, until_ns)
                continue
            ent = self._resolve_role(rkind, t_ns, rng, until_ns)
            used = {b["uid"] for b in binding.values()}
            if ent["uid"] in used and ent["uid"] != "external":
                # Two roles are two entities: a Pod drawn twice made a
                # "different Pod" nonlink one Pod, whose shared process then
                # showed the absent link. Re-pick only on a collision, so
                # every other binding is unchanged.
                self.rebound_roles += 1
                for _ in range(16):
                    ent = self._resolve_role(rkind, t_ns, rng, until_ns)
                    if ent["uid"] not in used:
                        break
            binding[rname] = ent
        return binding

    def _peer_pod(
        self, of: dict, t_ns: int, rng: "np.random.Generator",
        until_ns: Optional[int] = None,
    ) -> dict:
        """Another Pod of the same service as role ``of`` (``kind: peer_pod``).

        It runs as the same ServiceAccount, so its API requests carry the
        same principal but a different bound pod-uid: the twin of a stolen
        token's use. Alive for the whole window where possible.
        """
        pods = {p.uid: p for p in self._world.pods}
        ref = pods.get(of.get("uid", ""))
        if ref is None:
            raise ValueError(f"peer_pod: role {of!r} is not a Pod")
        peers = [p for p in self._world.pods
                 if p.service_name == ref.service_name and p.uid != ref.uid
                 and p.valid_from <= t_ns < p.valid_to]
        lasting = [p for p in peers if until_ns is None or p.valid_to >= until_ns]
        peers = lasting or peers
        if not peers:
            raise ValueError(f"peer_pod: no other Pod of service {ref.service_name!r}")
        pod = peers[int(rng.integers(len(peers)))]
        return {"uid": pod.uid, "entity_type": "POD",
                "namespace": pod.namespace, "name": pod.name}

    def _resolve_role(
        self, kind: str, t_ns: int, rng: "np.random.Generator",
        until_ns: Optional[int] = None,
    ) -> dict:
        """Resolve a role kind to a concrete entity descriptor."""
        if kind == "external_client":
            return {
                "uid": "external",
                "entity_type": "UNAUTHENTICATED_SOURCE",
                "namespace": "", "name": "external",
            }

        if kind in ("internal_pod", "attacker_pod"):
            pod = self._pick_pod(t_ns, rng)
            if pod is not None and until_ns is not None and pod.valid_to < until_ns:
                # The Pod is deleted before the scenario's last step: re-pick
                # among Pods alive for the whole window. Only this case draws
                # again, so every other binding is unchanged.
                lasting = [p for p in self._world.pods
                           if p.valid_from <= t_ns and p.valid_to >= until_ns]
                if lasting:
                    pod = lasting[int(rng.integers(len(lasting)))]
                    self.repicked_roles += 1
            if pod is None:
                return {"uid": "external", "entity_type": "POD",
                        "namespace": "", "name": ""}
            return {
                "uid": pod.uid, "entity_type": "POD",
                "namespace": pod.namespace, "name": pod.name,
            }

        if kind == "process":
            proc = self._pick_process(t_ns, rng)
            if proc is None:
                return {"uid": "proc-unknown", "entity_type": "PROCESS",
                        "namespace": "", "name": ""}
            return {
                "uid": proc.process_key, "entity_type": "PROCESS",
                "namespace": "", "name": proc.executable,
            }

        if kind == "service_account":
            sas = self._world.service_accounts
            if not sas:
                return {"uid": "sa-unknown", "entity_type": "SERVICE_ACCOUNT",
                        "namespace": "", "name": ""}
            sa = sas[int(rng.integers(len(sas)))]
            return {
                "uid": sa.uid, "entity_type": "SERVICE_ACCOUNT",
                "namespace": sa.namespace, "name": sa.name,
            }

        if kind == "namespace":
            nss = self._world.namespaces
            if not nss:
                return {"uid": "ns-unknown", "entity_type": "NAMESPACE",
                        "namespace": "", "name": ""}
            ns = nss[int(rng.integers(len(nss)))]
            return {
                "uid": ns.uid, "entity_type": "NAMESPACE",
                "namespace": "", "name": ns.name,
            }

        if kind == "infra_service":
            infra = self._world.infra
            if infra:
                keys = list(infra.keys())
                k = keys[int(rng.integers(len(keys)))]
                el = infra[k]
                return {
                    "uid": el.uid, "entity_type": "NODE",
                    "namespace": "", "name": el.name,
                }
            return {"uid": "infra-unknown", "entity_type": "NODE",
                    "namespace": "", "name": ""}

        # Unknown kind: fall back to internal_pod
        return self._resolve_role("internal_pod", t_ns, rng, until_ns)

    def _pick_pod(
        self, t_ns: int, rng: "np.random.Generator"
    ) -> Optional["PodState"]:
        alive = [p for p in self._world.pods if p.valid_from <= t_ns < p.valid_to]
        if not alive:
            return None
        return alive[int(rng.integers(len(alive)))]

    def _pick_process(
        self, t_ns: int, rng: "np.random.Generator"
    ) -> Optional[ProcessState]:
        alive = [
            p for p in self._world.processes
            if p.valid_from <= t_ns < p.valid_to
        ]
        if not alive:
            return None
        return alive[int(rng.integers(len(alive)))]

    # ------------------------------------------------------------------
    # Parameter resolution
    # ------------------------------------------------------------------

    def _resolve_params(
        self, params: dict, binding: Dict[str, dict],
        outputs: Optional[Dict[str, Dict[str, str]]] = None, sid: str = "",
    ) -> dict:
        """Replace role names with concrete UIDs, "<role>.namespace" with the
        role's namespace, and "@step<N>.<key>" with what step N of this
        execution acted with (see _execute_scenario)."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and v in binding:
                resolved[k] = binding[v]["uid"]
            elif (isinstance(v, str) and v.endswith(".namespace")
                  and v[:-len(".namespace")] in binding):
                resolved[k] = binding[v[:-len(".namespace")]]["namespace"]
            elif isinstance(v, str) and v.startswith("@step"):
                label, _, key = v[len("@step"):].partition(".")
                value = (outputs or {}).get(label, {}).get(key)
                if not value:
                    raise ValueError(
                        f"{sid}: {k}={v!r} names no {key!r} of an earlier step {label}")
                resolved[k] = value
            else:
                resolved[k] = v
        return resolved

    def _real_process(self, key: str) -> str:
        """A Pod UID names the Pod's init process; any other key is itself."""
        return self._pod_init.get(key, key)

    def _pod_of(self, key: str) -> str:
        """Pod UID of a Pod or process key; "" for anything else."""
        if any(p.uid == key for p in self._world.pods):
            return key
        proc = self._procs.get(self._real_process(key))
        return proc.pod_uid if proc is not None else ""

    def _child_of(self, parent_key: str, t_ns: int) -> str:
        """Key of the child ``parent_key`` forks at ``t_ns`` (as the renderer
        derives it); the child is registered so later steps may act as it."""
        parent = self._procs.get(parent_key)
        if parent is None:
            raise ValueError(f"exec parent {parent_key!r} is not a known process")
        key, tgid = child_process_key(parent_key, parent.node_uid, parent.boot_id, t_ns)
        if key not in self._procs:
            self._procs[key] = ProcessState(
                process_key=key,
                container_uid=parent.container_uid,
                pod_uid=parent.pod_uid,
                node_uid=parent.node_uid,
                boot_id=parent.boot_id,
                tgid=tgid,
                start_time_ns=t_ns,
                executable="",
                parent_process_key=parent_key,
                valid_from=t_ns,
                valid_to=self._world.run_start_ns + self._world.run_duration_ns,
            )
        return key

    # ------------------------------------------------------------------
    # Activity construction
    # ------------------------------------------------------------------

    def _make_activity(
        self,
        action: str,
        resolved: dict,
        time_ns: int,
        outcome: str,
        seq: int,
    ) -> Activity:
        actor_key, target_key = _ACTION_ACTOR_TARGET.get(action, ("", ""))
        actor_uid = _actor_value(actor_key, resolved) or "unknown"
        target_uid = resolved.get(target_key, "unknown") if target_key else "unknown"

        actor_type = self._infer_entity_type(actor_uid)
        target_type = _ACTION_TARGET_TYPE.get(action, "Entity")

        return Activity(
            time_ns=time_ns,
            kind=action,
            actor_uid=actor_uid,
            actor_type=actor_type,
            target_uid=target_uid,
            target_type=target_type,
            parameters=resolved,
            outcome=outcome,
            action_seq=seq,
        )

    @staticmethod
    def _infer_entity_type(uid: str) -> str:
        if uid == "external":
            return "External"
        if uid.startswith("ctr-"):
            return "Container"
        # Process keys have format "8hex:8hex:tgid:start_hex" — 3 colons
        if uid.count(":") >= 3:
            return "Process"
        return "Pod"

    # ------------------------------------------------------------------
    # EntityRef construction
    # ------------------------------------------------------------------

    def _build_refs(
        self,
        action: str,
        resolved: dict,
        binding: Dict[str, dict],
    ) -> Tuple[Optional[EntityRefRecord], Optional[EntityRefRecord]]:
        actor_key, target_key = _ACTION_ACTOR_TARGET.get(action, ("", ""))
        actor_uid = _actor_value(actor_key, resolved)
        target_uid = resolved.get(target_key) if target_key else None

        uid_to_ent: Dict[str, dict] = {e["uid"]: e for e in binding.values()}

        def _ref(uid: Optional[str], fallback_type: str) -> Optional[EntityRefRecord]:
            if not uid:
                return None
            ent = uid_to_ent.get(uid)
            if ent:
                return EntityRefRecord(
                    entity_type=ent.get("entity_type", fallback_type),
                    uid=ent["uid"],
                    namespace=ent.get("namespace", ""),
                    name=ent.get("name", ""),
                )
            return EntityRefRecord(
                entity_type=fallback_type,
                uid=uid,
            )

        actor_ref = _ref(actor_uid, self._infer_entity_type(actor_uid or ""))
        target_ref = _ref(target_uid, _ACTION_TARGET_TYPE.get(action, "Entity"))
        # Suppress target when it equals actor (e.g. privilege_change on self)
        if target_uid and target_uid == actor_uid:
            target_ref = None
        return actor_ref, target_ref

    # ------------------------------------------------------------------
    # State change application
    # ------------------------------------------------------------------

    def _apply_effect(
        self, action: str, resolved: dict, time_ns: int
    ) -> None:
        """Apply the world history change for a successful action step."""
        end_ns = self._world.run_start_ns + self._world.run_duration_ns

        if action in ("shell_exec", "process_exec"):
            self._effect_new_process(resolved, time_ns, end_ns)
        elif action == "file_write":
            self._effect_file_write(resolved, time_ns, end_ns)
        elif action in ("make_executable", "chmod"):
            self._effect_make_executable(resolved, time_ns, end_ns)
        elif action == "read_token_file":
            self._effect_token_read(resolved, time_ns)
        elif action in ("privilege_change", "euid_to_root", "capability_gain"):
            self._effect_privilege_change(resolved, time_ns)
        elif action == "namespace_escape":
            self._effect_namespace_escape(resolved, time_ns)
        elif action == "rbac_change":
            self._effect_rbac_change(resolved, time_ns, end_ns)
        elif action == "admit_pod":
            self._effect_admit_pod(resolved, time_ns, end_ns)
        # All other actions (http_request, api_request, connect_*, etc.)
        # are stateless from the world's perspective.

    def _effect_new_process(
        self, resolved: dict, time_ns: int, end_ns: int
    ) -> Optional[ProcessState]:
        """Record the child an exec step forked (``process_key``, named by
        _execute_scenario) in history under kind 'ScenarioProcess'."""
        proc = self._procs.get(resolved.get("process_key", ""))
        if proc is None:
            return None
        proc.executable = resolved.get(
            "executable", resolved.get("shell_binary", "/bin/sh"))
        hist = self._world.history
        hist.add("ScenarioProcess", proc.process_key, time_ns, end_ns, proc)
        hist.add(
            "ScenarioPID",
            f"{proc.node_uid}:{proc.tgid}",
            time_ns, end_ns, proc,
        )
        return proc

    def _effect_file_write(
        self, resolved: dict, time_ns: int, end_ns: int
    ) -> None:
        """Record a new FileState under kind 'ScenarioFile'."""
        file_path = resolved.get("file_path", "")
        writer_pk = resolved.get("writer_process", "")
        parent = next(
            (p for p in self._world.processes if p.process_key == writer_pk),
            None,
        )
        rng = self._streams.get(f"scenario.file.{file_path}.{time_ns}")
        uid_raw = format(int(rng.integers(0, 2**32)), "08x")
        new_file = FileState(
            uid=f"file-{uid_raw}",
            path=file_path,
            container_uid=parent.container_uid if parent else "",
            pod_uid=parent.pod_uid if parent else "",
            valid_from=time_ns,
            valid_to=end_ns,
        )
        self._world.history.add("ScenarioFile", file_path, time_ns, end_ns, new_file)

    def _effect_make_executable(
        self, resolved: dict, time_ns: int, end_ns: int
    ) -> None:
        """Record an executable-file change under kind 'ScenarioExecFile'."""
        file_path = resolved.get("file_path", "")
        proc_pk = resolved.get("process", "")
        parent = next(
            (p for p in self._world.processes if p.process_key == proc_pk),
            None,
        )
        rng = self._streams.get(f"scenario.execfile.{file_path}.{time_ns}")
        uid_raw = format(int(rng.integers(0, 2**32)), "08x")
        new_file = FileState(
            uid=f"file-{uid_raw}",
            path=file_path,
            container_uid=parent.container_uid if parent else "",
            pod_uid=parent.pod_uid if parent else "",
            valid_from=time_ns,
            valid_to=end_ns,
        )
        self._world.history.add(
            "ScenarioExecFile", file_path, time_ns, end_ns, new_file
        )

    def _effect_token_read(self, resolved: dict, time_ns: int) -> None:
        """Record a token-read event under kind 'TokenRead' (point interval)."""
        reader_pk = resolved.get("reader_process", "")
        token_path = resolved.get(
            "token_file_path", resolved.get("file_path", "")
        )
        self._world.history.add(
            "TokenRead", reader_pk,
            time_ns, time_ns + 1,
            {"reader_process": reader_pk, "token_path": token_path},
        )

    def _effect_privilege_change(self, resolved: dict, time_ns: int) -> None:
        """Record a privilege change under kind 'ProcessPrivilege' (point)."""
        proc_pk = resolved.get("process", "")
        euid = resolved.get("target_euid", 0)
        caps = resolved.get("caps_to_gain", resolved.get("caps", []))
        self._world.history.add(
            "ProcessPrivilege", proc_pk,
            time_ns, time_ns + 1,
            {"process": proc_pk, "euid": euid, "caps": caps},
        )

    def _effect_namespace_escape(self, resolved: dict, time_ns: int) -> None:
        """Record a namespace transition under kind 'ProcessNamespace' (point)."""
        proc_pk = resolved.get("process", "")
        namespaces = resolved.get("target_namespaces", [])
        ns_inum = resolved.get("target_ns_inum")
        self._world.history.add(
            "ProcessNamespace", proc_pk,
            time_ns, time_ns + 1,
            {"process": proc_pk, "namespaces": namespaces, "ns_inum": ns_inum},
        )

    def _effect_rbac_change(
        self, resolved: dict, time_ns: int, end_ns: int
    ) -> None:
        """Record an RBAC object mutation under kind 'ScenarioRBAC'."""
        name = resolved.get("name", "rbac-obj")
        namespace = resolved.get("namespace", "")
        obj_type = resolved.get("object_type", "RoleBinding")
        mutation = resolved.get("mutation_type", "create")
        rng = self._streams.get(f"scenario.rbac.{name}.{time_ns}")
        uid_raw = format(int(rng.integers(0, 2**32)), "08x")
        obj_uid = f"rbac-{uid_raw}"
        self._world.history.add(
            "ScenarioRBAC", obj_uid, time_ns, end_ns,
            {
                "uid": obj_uid, "namespace": namespace, "name": name,
                "kind": obj_type, "mutation_type": mutation,
            },
        )

    def _mint_admitted_pod(self, resolved: dict, sid: str, seq: int) -> dict:
        """Give a Pod admitted by a scenario a run-unique UID.

        The catalogue names the new Pod with a placeholder resource_uid. A
        placeholder that is not a world Pod UID is replaced by a UID derived
        from (run_id, scenario, action_seq), so repeated executions admit
        distinct Pods.
        """
        uid = resolved.get("resource_uid", "")
        if any(pod.uid == uid for pod in self._world.pods):
            return resolved
        resolved = dict(resolved)
        resolved["resource_uid"] = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"mtgen-admitted-pod:{self._world.run_id}|{sid}|{seq}|{uid}",
        ))
        return resolved

    def _effect_admit_pod(
        self, resolved: dict, time_ns: int, end_ns: int
    ) -> None:
        """Record a Pod admission; an admitted Pod enters the context history.

        A policy failure under enforce mode rejects the Pod, which then never
        exists. Any other outcome admits it from the admission time to the
        end of the run.
        """
        resource_uid = resolved.get("resource_uid", "")
        pod_name = resolved.get("pod_name", "")
        namespace = resolved.get("namespace", "")
        verdict = resolved.get("policy_verdict", "PASS")
        self._world.history.add(
            "ScenarioPod", resource_uid, time_ns, end_ns,
            {
                "uid": resource_uid, "name": pod_name,
                "namespace": namespace, "verdict": verdict,
            },
        )
        enforced = resolved.get("policy_enforcement", "enforce") == "enforce"
        if verdict == "FAIL" and enforced:
            return
        self._world.history.add_history_row(ContextHistoryRow(
            run_id=self._world.run_id, entity_type="Pod", entity_uid=resource_uid,
            valid_from=time_ns, valid_to=end_ns, observed_from=time_ns,
            parent_uid="",
            attributes={"name": pod_name, "namespace": namespace,
                        "admitted_by_scenario": True},
            history_version=_HISTORY_VERSION,
            ambiguity_reason="",
        ))
        self._world.observe_admitted_pod(resource_uid, pod_name, namespace, time_ns)
