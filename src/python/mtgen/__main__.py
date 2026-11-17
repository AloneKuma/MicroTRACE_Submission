"""Generator CLI entry point: python -m mtgen."""
import datetime
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

# Fixed manifest date (generated_at) when SOURCE_DATE_EPOCH is unset:
# 2026-10-25T00:00:00Z. Synthetic data, so any fixed date keeps builds
# byte-identical; epoch 0 read as 1970 (freeze proposal OQ-7).
BUILD_EPOCH = 1792886400

# ---------------------------------------------------------------------------
# spec-check (existing command)
# ---------------------------------------------------------------------------

def _cmd_spec_check():
    from . import specs
    gen_spec = specs.load_generator_spec()
    rendering = specs.load_evidence_rendering()
    catalogue = specs.load_scenario_catalogue()
    actions = specs.load_scenario_actions()
    patterns = specs.load_pattern_artifacts()
    indicators = specs.load_indicator_artifacts()

    print(f"generator-spec: {len(gen_spec['worlds'])} world sizes")
    findings = rendering.get("findings", {})
    print(f"evidence-rendering: {len(findings)} findings")
    scenarios = catalogue.get("scenarios", [])
    print(f"catalogue: {len(scenarios)} scenarios")
    action_list = actions.get("actions", [])
    print(f"actions: {len(action_list)} actions")
    pattern_list = patterns.get("patterns", [])
    print(f"patterns: {len(pattern_list)} patterns")
    indicator_list = indicators.get("indicators", [])
    print(f"indicators: {len(indicator_list)} indicators")


# ---------------------------------------------------------------------------
# build command
# ---------------------------------------------------------------------------

def _cmd_build(args):
    """Execute one full generator run."""
    import mtgen  # noqa: F401 – ensures gen/ and spec/tools/ are on sys.path

    from . import specs
    from .world import World
    from .workload import WorkloadEngine
    from .scenarios import ScenarioEngine
    from .evidence import EvidenceArchive
    from .render.gateway import GatewayRenderer
    from .render.audit import AuditRenderer
    from .render.ebpf import EbpfRenderer
    from .render.kyverno import KyvernoRenderer
    from .render.context import ContextRenderer
    from .render.offnode import OffNodeRenderer
    from .completeness import CompletenessRenderer
    from .degrade import Degrader
    from .truth import TruthWriter, RenderedEventInfo, TruthResult
    from .envelopes import build_run_context
    from .emit import (Emitter, write_manifest, compute_truth_sha256,
                       write_context_history)
    from microtrace.v0 import dataset_pb2

    # -----------------------------------------------------------------
    # 1. Parse CLI options
    # -----------------------------------------------------------------
    world_name = args.world          # "Small" | "Reference" | "Large"
    shape = args.shape               # observability profile name
    scenarios_arg = args.scenarios   # comma-separated IDs or "all"
    split_name = args.split          # "PILOT" | "RESEARCH" | "HELD_OUT"
    seed_int = args.seed             # integer seed
    out_dir = Path(args.out)
    duration_s = getattr(args, "duration_s", 3600)
    duration_ns = duration_s * 1_000_000_000
    seed_str = f"build:{seed_int}"
    overlays = list(getattr(args, "catalogue_overlay", None) or [])
    flags = [f for f in (getattr(args, "flags", "") or "").split(",") if f]

    # Split enum
    _SPLIT_MAP = {
        "PILOT": dataset_pb2.PILOT,
        "RESEARCH": dataset_pb2.RESEARCH,
        "HELD_OUT": dataset_pb2.HELD_OUT,
    }
    split_enum = _SPLIT_MAP.get(split_name, dataset_pb2.PILOT)
    t_start = time.perf_counter()

    # -----------------------------------------------------------------
    # 2. Load specs
    # -----------------------------------------------------------------
    gen_spec = specs.load_generator_spec()
    catalogue = specs.load_scenario_catalogue(overlays)
    rendering_table = specs.load_evidence_rendering()
    pa_artifact = specs.load_pattern_artifacts()
    ia2_artifact = specs.load_indicator_artifacts()

    # Observability profile
    obs_profiles = gen_spec.get("observability_profiles", {})
    profile = obs_profiles.get(shape, {})

    # -----------------------------------------------------------------
    # 3. Resolve scenarios and derive run_id
    # -----------------------------------------------------------------
    # run_id uses the resolved scenario list so --from-manifest rebuilds are
    # byte-identical (manifest stores scenario_ids, rebuild uses that list).
    all_scenario_ids = [s["id"] for s in catalogue.get("scenarios", [])]
    if scenarios_arg.strip().lower() == "all":
        selected_ids = all_scenario_ids
    else:
        selected_ids = [s.strip() for s in scenarios_arg.split(",") if s.strip()]

    # Variant per scenario: v1 unless --variants names another. A variant
    # other than v1 is part of the run_id; an all-v1 run keeps its old id.
    variant_per_scenario = {sid: "v1" for sid in selected_ids}
    for item in filter(None, (v.strip() for v in (getattr(args, "variants", "") or "").split(","))):
        sid, _, vid = item.partition("=")
        scen = next((s for s in catalogue.get("scenarios", []) if s["id"] == sid), None)
        if sid not in variant_per_scenario or scen is None or not any(
                v.get("id") == vid for v in scen.get("variants", [])):
            print(f"[build] ERROR: --variants {item!r}: no variant {vid!r} of a "
                  f"selected scenario {sid!r}", file=sys.stderr)
            sys.exit(2)
        variant_per_scenario[sid] = vid
    non_default = ",".join(f"{sid}={vid}" for sid, vid in variant_per_scenario.items()
                           if vid != "v1")

    run_id = str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"mtgen:{world_name}|{shape}|{','.join(selected_ids)}|{split_name}|{seed_int}"
        f"|{duration_s}" + (f"|{non_default}" if non_default else "")
        + (f"|flags={','.join(sorted(flags))}" if flags else ""),
    ))
    print(f"[build] run_id={run_id}  world={world_name}  shape={shape}"
          f"  split={split_name}  seed={seed_int}")

    # -----------------------------------------------------------------
    # 4. Build world
    # -----------------------------------------------------------------
    world = World(world_name, gen_spec, seed_str, run_id=run_id, run_duration_ns=duration_ns)
    print(f"[build] world built: {len(world.nodes)} nodes, "
          f"{len(world.pods)} pods, {len(world.processes)} procs")

    # -----------------------------------------------------------------
    # 5. Build scenario run_spec
    # -----------------------------------------------------------------
    run_spec = {
        "scenarios": [
            {"scenario_id": sid, "variant_id": variant_per_scenario[sid]}
            for sid in selected_ids
            if sid in all_scenario_ids
        ],
    }
    print(f"[build] scenario run_spec: {len(run_spec['scenarios'])} scenarios selected")

    # -----------------------------------------------------------------
    # 5. Benign workload activities
    # -----------------------------------------------------------------
    from .workload import GENERATOR_FLAGS
    unknown = sorted(set(flags) - set(GENERATOR_FLAGS))
    if unknown:
        print(f"[build] ERROR: unknown generator flag(s) {unknown}", file=sys.stderr)
        sys.exit(2)
    workload_engine = WorkloadEngine(world, gen_spec, flags=tuple(flags))
    benign_activities = workload_engine.generate()
    print(f"[build] benign activities: {len(benign_activities)}")

    # -----------------------------------------------------------------
    # 6. Scenario activities + GT records
    # -----------------------------------------------------------------
    scenario_engine = ScenarioEngine(world, catalogue, run_spec, seed_str)
    scenario_activities, gt_records = scenario_engine.execute()
    print(f"[build] scenario activities: {len(scenario_activities)}, "
          f"GT records: {len(gt_records)}")
    if scenario_engine.dropped_scenarios:
        print(f"[build] WARNING: {len(scenario_engine.dropped_scenarios)} of "
              f"{len(run_spec['scenarios'])} scenarios did not fit in "
              f"{duration_s} s and were not run", file=sys.stderr)

    # -----------------------------------------------------------------
    # 7. Evidence archive
    # -----------------------------------------------------------------
    archive = EvidenceArchive(archive_id=run_id)

    # -----------------------------------------------------------------
    # 8. Instantiate renderers
    # -----------------------------------------------------------------
    gateway_r = GatewayRenderer(pa_artifact, ia2_artifact, archive)
    audit_r = AuditRenderer(world.history, world=world)
    ebpf_r = EbpfRenderer(world, archive, c_h4=gen_spec["declared_artifacts"]
                          ["sensitive_data_class_h4"].get("paths", {}))
    kyverno_r = KyvernoRenderer(world)
    context_r = ContextRenderer(world)
    offnode_r = OffNodeRenderer(world.history)

    # -----------------------------------------------------------------
    # 9. Render all activities
    # -----------------------------------------------------------------
    all_ne: List = []
    rendered_by_seq: Dict[int, List[RenderedEventInfo]] = {}
    scenario_nes: Dict[int, List] = {}

    # Server accepts of in-cluster connects (generator flag ebpf_accept)
    accept_activities = workload_engine.accepts(benign_activities + scenario_activities)
    if accept_activities:
        print(f"[build] accept activities: {len(accept_activities)}")

    # Combine activities; scenario ones carry action_seq
    all_activities = sorted(
        benign_activities + scenario_activities + accept_activities,
        key=lambda a: a.time_ns,
    )

    # Events a degraded profile loses never reach the stream or the truth.
    degrader = Degrader(world, shape, profile, seed_str)

    # What the profile dropped, kept only to tell the truth writer which
    # evidence was lost (an ABSENT whose evidence was lost is UNOBSERVABLE):
    # each step's own dropped events, and dropped standing-evidence candidates.
    dropped_scenario_nes: Dict[int, List] = {}
    dropped_standing_nes: List = []

    # action_seq -> request ID a scenario step's request was sent with, for a
    # later step that copies it (copy_request_id_of: "@step<N>.action_seq")
    request_ids: Dict[int, str] = {}

    for activity in all_activities:
        activity = _bind_request_id(activity, request_ids)
        rendered = _render_activity(activity, gateway_r, audit_r, ebpf_r, kyverno_r, offnode_r)
        if activity.action_seq is not None:
            for ne in rendered:
                if ne.HasField("gateway"):
                    request_ids.setdefault(activity.action_seq, ne.gateway.request_id)
        if activity.unobserved:
            # The step's records from these sources are lost in a declared
            # gap (catalogue `unobserved`), not silently omitted.
            for ne in rendered:
                degrader.add_step_window(ne, activity.unobserved)
        nes = []
        for ne in rendered:
            if degrader.keep(ne):
                nes.append(ne)
            elif activity.action_seq is not None:
                dropped_scenario_nes.setdefault(activity.action_seq, []).append(ne)
            elif _is_standing_candidate(ne):
                dropped_standing_nes.append(ne)
        all_ne.extend(nes)
        if activity.action_seq is not None:
            infos = rendered_by_seq.setdefault(activity.action_seq, [])
            for ne in nes:
                infos.append(_make_rendered_event_info(ne))
            scenario_nes.setdefault(activity.action_seq, []).extend(nes)

    # Context NEs (from world observations)
    context_ne = []
    for ne in context_r.render_all():
        if degrader.keep(ne):
            context_ne.append(ne)
        elif _is_standing_candidate(ne):
            dropped_standing_nes.append(ne)
    all_ne.extend(context_ne)
    standing_by_seq = _standing_evidence(all_ne, scenario_nes)
    dropped_by_seq = _dropped_evidence(
        all_ne, scenario_nes, standing_by_seq,
        dropped_scenario_nes, dropped_standing_nes)

    print(f"[build] rendered {len(all_ne)} NormalizedEvents")

    # -----------------------------------------------------------------
    # 10. Completeness records
    # -----------------------------------------------------------------
    # Collect per-scope per-family event counts from all rendered NEs.
    event_counts: Dict[str, Dict[str, int]] = {}
    for _ne in all_ne:
        _scope, _family = _ne_scope_family(_ne)
        if _scope and _family:
            event_counts.setdefault(_scope, {})
            event_counts[_scope][_family] = event_counts[_scope].get(_family, 0) + 1

    completeness_r = CompletenessRenderer(world, profile_name=shape, profile=profile,
                                          degrader=degrader)
    sc_records = completeness_r.render_completeness(event_counts=event_counts)
    heartbeats = completeness_r.render_heartbeats()

    # -----------------------------------------------------------------
    # 11. Truth writer
    # -----------------------------------------------------------------
    truth_writer = TruthWriter(run_id, rendering_table, catalogue, gen_spec=gen_spec)
    truth_result = truth_writer.write(gt_records, rendered_by_seq, sc_records,
                                      standing_by_seq=standing_by_seq,
                                      dropped_by_seq=dropped_by_seq,
                                      own_dropped_by_seq={
                                          seq: [_make_rendered_event_info(ne) for ne in nes]
                                          for seq, nes in dropped_scenario_nes.items()})
    if truth_result.consistency_errors:
        print(f"[build] WARNING: {len(truth_result.consistency_errors)} "
              f"truth consistency errors", file=sys.stderr)
    if truth_result.hollow_unobservable:
        # A degraded scenario declares a loss its data does not have.
        print(f"[build] WARNING: {len(truth_result.hollow_unobservable)} catalogue "
              f"UNOBSERVABLE expectations with all evidence rendered: "
              f"{sorted({(h[2], h[1]) for h in truth_result.hollow_unobservable})}",
              file=sys.stderr)
    if degrader.windows or degrader.lost_families:
        print(f"[build] degradation: {len(degrader.windows)} gap windows, "
              f"{sum(degrader.dropped.values())} events dropped")
    # Nothing is lost in a clean run but a scenario's own declared step gaps
    # (catalogue `unobserved`), and a node-trust epoch a scenario's escape
    # opens is the correlator's rule, not a loss: a downgrade for any other
    # reason means a scenario does not render the evidence its catalogue
    # expectation needs.
    unexplained = [d for d in truth_result.downgrades if not any(k in d[4] for k in DETECTOR_RULES)]
    if shape == "clean" and unexplained:
        print(f"[build] WARNING: {len(unexplained)} catalogue PRESENT/ABSENT "
              f"expectations downgraded in a clean run: "
              f"{sorted({d[1] for d in unexplained})}", file=sys.stderr)

    # Write restricted truth files
    out_dir.mkdir(parents=True, exist_ok=True)
    truth_writer.write_restricted(truth_result, out_dir)
    truth_sha256 = compute_truth_sha256(out_dir)
    print(f"[build] truth: {len(truth_result.actions)} actions, "
          f"{len(truth_result.opportunities)} opportunities, "
          f"{len(truth_result.links)} links")

    # -----------------------------------------------------------------
    # 12. Build run context
    # -----------------------------------------------------------------
    run_context = build_run_context(
        run_id=run_id,
        split=split_enum,
        capture_profile="evaluated-v0",
        parameter_set_version="generator-spec.v0",
    )

    # -----------------------------------------------------------------
    # 13. Emitter: base stream + shipper files
    # -----------------------------------------------------------------
    emitter = Emitter(world, run_context)
    # Evidence archive and context history go into the run directory.
    archive_sha256 = archive.write_to(out_dir / "evidence")
    context_history_sha256 = write_context_history(
        world.context_history_rows, out_dir / "context_history.jsonl")

    emit_result = emitter.emit(
        ne_list=all_ne,
        context_obs=list(world.context_observations),
        sc_records=sc_records,
        heartbeats=heartbeats,
        gta_protos=list(truth_result.actions),
        out_dir=out_dir,
    )
    print(f"[build] base stream: {emit_result.total_envelopes} envelopes, "
          f"sha256={emit_result.base_stream_sha256[:16]}...")

    # -----------------------------------------------------------------
    # 14. Build and write manifest
    # -----------------------------------------------------------------
    t_elapsed = time.perf_counter() - t_start
    manifest = {
        "manifest_version": "build-manifest.v0",
        "run_id": run_id,
        "split": split_name,
        "world_name": world_name,
        "scenario_ids": selected_ids,
        "duration_s": duration_s,
        "variant_per_scenario": variant_per_scenario,
        "generator_version": _generator_version(),
        # Reproducible-builds convention: SOURCE_DATE_EPOCH, default
        # BUILD_EPOCH, so the manifest is byte-identical across builds.
        "generated_at": datetime.datetime.fromtimestamp(
            int(os.environ.get("SOURCE_DATE_EPOCH", str(BUILD_EPOCH))),
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observability_profile": shape,
        "completeness_guarantees": _build_completeness_guarantees(
            shape, profile, degrader.step_windows),
        "template_usage": {
            "scripted_distributions": [
                {
                    "source": "scripted",
                    "reason": (
                        "Phase 3 replay templates not implemented; "
                        "all benign traffic uses scripted distributions"
                    ),
                }
            ]
        },
        "generator_spec_version": "generator-spec.v0",
        "capture_profile": "evaluated-v0",
        "rule_evaluation_mode": "all",
        "scenario_catalogue_version": _file_sha256(
            "spec/scenarios/catalogue.v0.yaml"),
        # Add-on runs only (D-31), so PILOT's manifests keep their fields.
        **({"catalogue_overlays": {rel: _file_sha256(rel) for rel in overlays}} if overlays else {}),
        **({"generator_flags": flags} if flags else {}),
        "seeds": {
            "generator_seed": seed_int,
            "scenario_seed": seed_int,
        },
        "hashes": {
            "base_stream_sha256": emit_result.base_stream_sha256,
            "truth_sha256": truth_sha256,
            "evidence_archive_sha256": archive_sha256,
            "context_history_sha256": context_history_sha256,
        },
        "artifact_versions": {
            "P_A": _file_sha256("spec/artifacts/p_a.v0.yaml"),
            "I_A2": _file_sha256("spec/artifacts/i_a2.v0.yaml"),
        },
        "spec_file_sha256": {
            rel: _file_sha256(rel) for rel in _SPEC_FILES
        },
        "code_sha256": _code_sha256(),
        # Single-scenario convenience fields
        **({
            "scenario_id": selected_ids[0],
            "scenario_variant": 0,
        } if len(selected_ids) == 1 else {}),
        "archive_paths": {
            "base_stream": "base.pb",
            "truth_directory": "restricted",
            "archive_directory": "evidence",
            "context_history": "context_history.jsonl",
        },
        "stream_statistics": {
            "total_envelopes": emit_result.total_envelopes,
            "logical_id_count": emit_result.logical_id_count,
            "events_per_source_family": emit_result.events_per_source,
        },
        "truth_statistics": {
            "total_actions": len(truth_result.actions),
            "total_findings": len(truth_result.opportunities),
            "total_links": len(truth_result.links),
        },
    }

    manifest_path, manifest_sha256 = write_manifest(manifest, out_dir)
    print(f"[build] manifest: {manifest_path}")
    print(f"[build] done in {t_elapsed:.1f}s  "
          f"base={emit_result.base_stream_sha256[:16]}..."
          f"  truth={truth_sha256[:16]}...")

    return {
        "run_id": run_id,
        "base_stream_sha256": emit_result.base_stream_sha256,
        "truth_sha256": truth_sha256,
        "total_envelopes": emit_result.total_envelopes,
        "elapsed_s": t_elapsed,
    }


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _bind_request_id(activity, request_ids):
    """An http_request step naming copy_request_id_of sends, as its client
    x-request-id, the ID that earlier step's request carried (G3: a copied ID).
    Only the internal listener keeps a client's ID; on the edge listener the
    gateway mints a new one, so the copy would silently do nothing."""
    src = activity.parameters.get("copy_request_id_of")
    if activity.kind != "http_request" or src is None:
        return activity
    if activity.parameters.get("listener", "edge") != "internal":
        raise ValueError(f"copy_request_id_of={src!r} needs listener: internal (the edge listener mints its own ID)")
    rid = request_ids.get(int(src))
    if rid is None:
        raise ValueError(f"copy_request_id_of={src!r}: step rendered no gateway request before this one")
    import dataclasses
    return dataclasses.replace(activity, parameters=dict(activity.parameters, client_request_id=rid))


def _render_activity(activity, gateway_r, audit_r, ebpf_r, kyverno_r, offnode_r):
    """Dispatch one Activity to the appropriate renderer and return NE list."""
    kind = activity.kind

    if kind == "http_request":
        ne = gateway_r.render(activity)
        return [ne] if ne is not None else []

    if kind in ("api_request", "api_auth_failure", "exec_api_request",
                "secret_list", "secret_get", "rbac_change"):
        ne = audit_r.render(activity)
        return [ne] if ne is not None else []

    if kind == "admit_pod":
        return kyverno_r.render(activity)

    if kind in ("db_query",):
        return offnode_r.render(activity)

    if kind in ("path_flow", "egress_transfer"):
        # egress_transfer is handled by both eBPF (flow_counter) and offnode
        # (PathFlowRecord). In the base pipeline, eBPF handles egress_transfer
        # for the eBPF flow_counter record; offnode handles it for PathFlowRecord.
        ne_ebpf = ebpf_r.render(activity)
        ne_off = offnode_r.render(activity)
        return ne_ebpf + ne_off

    # eBPF families (default)
    return ebpf_r.render(activity)


def _standing_evidence(all_ne, scenario_nes):
    """Map action_seq -> earlier observations of the acting entity's state.

    For each eBPF event a scenario step rendered: the fork and exec events of
    the same lineage, and the watch event (with PodSummary) of the same Pod,
    observed at or before the step's event. These are what a rule reads for
    lineage continuity and container start time; the step itself does not
    render them.
    """
    from microtrace.v0 import common_pb2

    def _t(ne):
        return ne.time.event_time.seconds * 1_000_000_000 + ne.time.event_time.nanos

    lineage_events: Dict[str, List] = {}
    pod_watch: Dict[str, List] = {}
    for ne in all_ne:
        if ne.source == common_pb2.EBPF:
            if ne.ebpf.event_family in ("proc.fork", "proc.exec"):
                lid = ne.ebpf_derived.lineage_id
                if lid:
                    lineage_events.setdefault(lid, []).append(ne)
        elif ne.source == common_pb2.CLUSTER_CONTEXT:
            obs = ne.context
            if obs.kind == "Pod" and obs.HasField("pod"):
                pod_watch.setdefault(obs.uid, []).append(ne)

    standing: Dict[int, List] = {}
    for seq, nes in scenario_nes.items():
        own = {ne.event_id for ne in nes}
        picked: Dict[str, object] = {}
        for ne in nes:
            if ne.source != common_pb2.EBPF:
                continue
            t = _t(ne)
            der = ne.ebpf_derived
            candidates = list(lineage_events.get(der.lineage_id, []))
            if der.HasField("pod_uid"):
                candidates += pod_watch.get(der.pod_uid, [])
            for c in candidates:
                if c.event_id not in own and _t(c) <= t:
                    picked.setdefault(c.event_id, c)
        if picked:
            standing[seq] = [
                _make_rendered_event_info(c)
                for c in sorted(picked.values(), key=lambda c: (_t(c), c.event_id))
            ]
    return standing


def _is_standing_candidate(ne) -> bool:
    """True for events _standing_evidence can pick: fork/exec and Pod watch events."""
    from microtrace.v0 import common_pb2

    if ne.source == common_pb2.EBPF:
        return ne.ebpf.event_family in ("proc.fork", "proc.exec")
    if ne.source == common_pb2.CLUSTER_CONTEXT:
        return ne.context.kind == "Pod" and ne.context.HasField("pod")
    return False


def _dropped_evidence(all_ne, scenario_nes, standing_by_seq,
                      dropped_scenario_nes, dropped_standing_nes):
    """Map action_seq -> evidence the degraded profile dropped.

    A step's own dropped events, plus the standing evidence it would have had
    without degradation but lost: computed by re-running _standing_evidence
    over kept + dropped events and removing what the kept run already has.
    """
    if not dropped_scenario_nes and not dropped_standing_nes:
        return {}
    full_scenario = {
        seq: list(scenario_nes.get(seq, [])) + dropped_scenario_nes.get(seq, [])
        for seq in set(scenario_nes) | set(dropped_scenario_nes)
    }
    full_standing = _standing_evidence(
        list(all_ne) + dropped_standing_nes
        + [ne for nes in dropped_scenario_nes.values() for ne in nes],
        full_scenario,
    )
    dropped: Dict[int, List] = {}
    for seq in set(full_standing) | set(dropped_scenario_nes):
        kept_ids = {ei.event_id for ei in standing_by_seq.get(seq, [])}
        lost = [_make_rendered_event_info(ne) for ne in dropped_scenario_nes.get(seq, [])]
        lost += [ei for ei in full_standing.get(seq, []) if ei.event_id not in kept_ids]
        if lost:
            dropped[seq] = lost
    return dropped


# Downgrade reasons that follow a detector rule, expected in any profile.
DETECTOR_RULES = ("declared gap", "node-trust epoch")


def _make_rendered_event_info(ne):
    """Build a RenderedEventInfo from a NormalizedEvent."""
    from .truth import RenderedEventInfo
    from microtrace.v0 import common_pb2

    # Determine record_type from the source
    _source_to_record = {
        common_pb2.EBPF: "ebpf",
        common_pb2.GATEWAY: "gateway",
        common_pb2.AUDIT: "audit",
        common_pb2.KYVERNO: "kyverno",
        common_pb2.CLUSTER_CONTEXT: "context",
        common_pb2.DB_AUDIT: "db_audit",
        common_pb2.PATH_FLOW: "path_flow",
    }
    record_type = _source_to_record.get(ne.source, "ebpf")
    family = ne.ebpf.event_family if ne.source == common_pb2.EBPF else ""
    node = ne.ebpf.node_id if ne.source == common_pb2.EBPF else ""
    et = ne.time.event_time
    time_ns = et.seconds * 1_000_000_000 + et.nanos
    from .truth import _ABSTAIN_REASONS, _GAP_REASON_TO_NAME
    record_gap = next((_GAP_REASON_TO_NAME.get(g.reason, "GAP") for g in ne.completeness.gaps
                       if g.reason in _ABSTAIN_REASONS), "")
    return RenderedEventInfo(
        event_id=ne.event_id, record_type=record_type, family=family, time_ns=time_ns, node=node,
        record_gap=record_gap,
    )


def _ne_scope_family(ne):
    """Return (scope, family) for completeness counter bucketing.

    Returns (None, None) for record types with no fixed scope.
    """
    from microtrace.v0 import common_pb2
    src = ne.source
    if src == common_pb2.EBPF:
        node_id = ne.ebpf.node_id
        if not node_id:
            return None, None
        return f"node={node_id}", ne.ebpf.event_family or "ebpf"
    elif src == common_pb2.GATEWAY:
        return "gateway=1", "gateway"
    elif src == common_pb2.AUDIT:
        return "audit-collector=1", "audit"
    elif src == common_pb2.KYVERNO:
        return "kyverno=1", "kyverno"
    elif src == common_pb2.CLUSTER_CONTEXT:
        return "context-collector=1", "context"
    elif src == common_pb2.DB_AUDIT:
        return "db-audit-collector=1", "db_audit"
    elif src == common_pb2.PATH_FLOW:
        return "path-flow-collector=1", "path_flow"
    return None, None


def _build_completeness_guarantees(profile_name: str, profile: dict,
                                   step_windows=()) -> dict:
    """Build completeness_guarantees from the observability profile.

    A source with gap windows from unobserved scenario steps is not complete
    in any profile (clean included); scenario_gap_windows counts them.
    """
    from .completeness import _param_val
    result = {}
    for src in ("gateway", "audit", "ebpf", "context"):
        if profile_name == "degraded_gateway" and src == "gateway":
            pct = float(_param_val(profile, "observer_loss_percentage", 15))
            result[src] = {"expected_complete": False, "loss_percentage": pct}
        elif profile_name == "degraded_audit" and src == "audit":
            pct = float(_param_val(profile, "event_loss_percentage", 10))
            result[src] = {"expected_complete": False, "loss_percentage": pct}
        elif profile_name == "degraded_ebpf" and src == "ebpf":
            result[src] = {"expected_complete": False, "loss_percentage": 0.0}
        elif profile_name == "degraded_context" and src == "context":
            result[src] = {"expected_complete": False, "loss_percentage": 0.0}
        else:
            result[src] = {"expected_complete": True, "loss_percentage": 0.0}
    for w in step_windows:
        entry = result.setdefault(w.source, {"expected_complete": True, "loss_percentage": 0.0})
        entry["expected_complete"] = False
        entry["scenario_gap_windows"] = entry.get("scenario_gap_windows", 0) + 1
    return result


_SPEC_FILES = (
    "spec/generator/generator-spec.v0.yaml",
    "spec/generator/evidence-rendering.v0.yaml",
    "spec/scenarios/catalogue.v0.yaml",
    "spec/scenarios/actions.v0.yaml",
    "spec/artifacts/p_a.v0.yaml",
    "spec/artifacts/i_a2.v0.yaml",
    "spec/kafka/topics.yaml",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _file_sha256(rel: str) -> str:
    import hashlib
    return hashlib.sha256((_repo_root() / rel).read_bytes()).hexdigest()


def _code_sha256() -> str:
    """Hash of every mtgen source file (sorted by path)."""
    import hashlib
    h = hashlib.sha256()
    pkg = Path(__file__).resolve().parent
    for p in sorted(pkg.rglob("*.py")):
        h.update(p.relative_to(pkg).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def _generator_version() -> str:
    """Return a stable version string for the generator code."""
    import mtgen
    return getattr(mtgen, "__version__", "mtgen.v0")


# ---------------------------------------------------------------------------
# Argument parsing and dispatch
# ---------------------------------------------------------------------------

def _parse_build_args(argv):
    """Minimal argument parser for the build command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen build",
        description="Generate one MicroTRACE dataset run.",
    )
    parser.add_argument("--world", default="Small",
                        choices=["Small", "Reference", "Large"],
                        help="World size (default: Small)")
    parser.add_argument("--shape", default="clean",
                        help="Observability profile name (default: clean)")
    parser.add_argument("--scenarios", default="all",
                        help="Comma-separated scenario IDs, or 'all' (default: all)")
    parser.add_argument("--split", default="PILOT",
                        choices=["PILOT", "RESEARCH", "HELD_OUT"],
                        help="Dataset split (default: PILOT)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Integer seed for determinism (default: 42)")
    parser.add_argument("--out", required=True,
                        help="Output directory for the run artifacts")
    parser.add_argument("--duration-s", type=int, default=3600,
                        dest="duration_s",
                        help="Run duration in seconds (default: 3600)")
    parser.add_argument("--variants", default="",
                        help="Comma-separated scenario_id=variant_id for scenarios "
                             "that run a variant other than v1 (default: all v1)")
    parser.add_argument("--catalogue-overlay", action="append", default=[],
                        dest="catalogue_overlay", metavar="PATH",
                        help="Repository-relative catalogue file whose scenarios are "
                             "added to catalogue.v0.yaml (repeatable)")
    parser.add_argument("--flags", default="",
                        help="Comma-separated generator flags (workload.GENERATOR_FLAGS)")
    return parser.parse_args(argv)


def _parse_from_manifest_args(argv):
    """Argument parser for the from-manifest command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen from-manifest",
        description="Rebuild a run from an existing manifest (byte-identical).",
    )
    parser.add_argument("manifest_dir",
                        help="Directory containing manifest.json to rebuild from")
    parser.add_argument("--out",
                        default=None,
                        help="Output directory (default: overwrite manifest_dir)")
    parser.add_argument("--allow-spec-change", action="store_true",
                        help="rebuild although the scenario catalogue or an overlay changed "
                             "since the build (re-truth); otherwise an error")
    return parser.parse_args(argv)


def _cmd_from_manifest(args):
    """Rebuild a run from an existing manifest (byte-identical rebuild)."""
    import argparse
    manifest_dir = Path(args.manifest_dir)
    manifest_path = manifest_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[from-manifest] ERROR: manifest not found: {manifest_path}",
              file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Reconstruct build args from manifest fields.
    rebuild_args = argparse.Namespace()
    rebuild_args.world = manifest.get("world_name", "Small")
    rebuild_args.shape = manifest.get("observability_profile", "clean")
    scenario_ids = manifest.get("scenario_ids")
    if scenario_ids:
        rebuild_args.scenarios = ",".join(scenario_ids)
    else:
        # Legacy manifest without scenario_ids: fall back to scenario_id
        single = manifest.get("scenario_id")
        rebuild_args.scenarios = single if single else "all"
    rebuild_args.split = manifest.get("split", "PILOT")
    # The build moves the seeds out of manifest.json into restricted/.
    seeds = manifest.get("seeds")
    seeds_path = manifest_dir / "restricted" / "seeds" / "manifest.json"
    if not seeds and seeds_path.exists():
        seeds = json.loads(seeds_path.read_text(encoding="utf-8")).get("seeds")
    rebuild_args.seed = (seeds or {}).get("generator_seed", 42)
    rebuild_args.duration_s = manifest.get("duration_s", 3600)
    rebuild_args.variants = ",".join(
        f"{sid}={vid}" for sid, vid in manifest.get("variant_per_scenario", {}).items()
        if vid != "v1")
    rebuild_args.catalogue_overlay = list(manifest.get("catalogue_overlays", {}))
    rebuild_args.flags = ",".join(manifest.get("generator_flags", []))
    rebuild_args.out = args.out if args.out else str(manifest_dir)

    # The run_id does not hash the catalogue, so a changed catalogue would be
    # rebuilt under the same run_id. Refuse that unless asked (re-truth does).
    recorded = dict(manifest.get("catalogue_overlays", {}))
    if manifest.get("scenario_catalogue_version"):
        recorded["spec/scenarios/catalogue.v0.yaml"] = manifest["scenario_catalogue_version"]
    changed = [rel for rel, h in sorted(recorded.items())
               if not (_repo_root() / rel).exists() or _file_sha256(rel) != h]
    if changed:
        if not getattr(args, "allow_spec_change", False):
            print(f"[from-manifest] ERROR: catalogue changed since the build: {', '.join(changed)} "
                  "(--allow-spec-change rebuilds with the current one)", file=sys.stderr)
            sys.exit(1)
        print(f"[from-manifest] NOTE: rebuilding with a changed catalogue: {', '.join(changed)}")

    print(f"[from-manifest] rebuilding run_id={manifest.get('run_id', '?')}  "
          f"out={rebuild_args.out}")
    _cmd_build(rebuild_args)


def _parse_external_args(argv):
    """Argument parser for the external command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen external",
        description="Write external benchmark partitions from converter output.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dataset", metavar="ID",
                       help="Converter output directory name (e.g. beth, cadets-e3)")
    group.add_argument("--all", action="store_true",
                       help="Process all datasets with a manifest.json")
    parser.add_argument("--out", required=True,
                        help="Output root directory for external partitions")
    return parser.parse_args(argv)


def _cmd_external(args):
    """Write external partitions for one or all datasets."""
    from .external import write_external_partition, list_convertable_datasets

    repo_root = _repo_root()
    converter_out = repo_root / "dataset-review" / "output"
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.all:
        dirs = list_convertable_datasets(converter_out)
    else:
        dirs = [converter_out / args.dataset]

    # Sort so CADETS (largest dataset) runs last.
    _CADETS_PREFIX = "cadets"
    dirs = sorted(
        dirs,
        key=lambda p: (1 if _CADETS_PREFIX in p.name.lower() else 0, p.name),
    )

    for dataset_dir in dirs:
        if not (dataset_dir / "manifest.json").exists():
            print(f"[external] SKIP {dataset_dir.name}: no manifest.json",
                  file=sys.stderr)
            continue
        t0 = time.time()
        print(f"[external] processing {dataset_dir.name} ...")
        part = write_external_partition(dataset_dir, out_dir)
        elapsed = time.time() - t0
        print(
            f"[external] {part['dataset_id']}: "
            f"records={part['record_count']}, labels={part['label_count']}, "
            f"local_only={part['local_only']}, elapsed={elapsed:.1f}s"
        )


def _parse_assemble_args(argv):
    """Argument parser for the assemble command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen assemble",
        description="Assemble a dataset package from one or more run directories.",
    )
    parser.add_argument(
        "--runs", action="append", dest="runs", required=True,
        metavar="RUN_DIR",
        help="Run directory with a parquet/ subdir; repeat for multiple runs",
    )
    parser.add_argument("--out", required=True,
                        help="Output directory for the assembled package")
    parser.add_argument("--external", default=None,
                        help="External partitions directory (e.g. datasets/generated/external/)")
    return parser.parse_args(argv)


def _cmd_assemble(args):
    """Assemble a dataset package."""
    from .layout import assemble_dataset
    run_dirs = [Path(r) for r in args.runs]
    out_dir = Path(args.out)
    external_dir = Path(args.external) if args.external else None
    print(f"[assemble] {len(run_dirs)} run(s) -> {out_dir}")
    manifest = assemble_dataset(run_dirs, out_dir, external_dir=external_dir)
    n_ext = len(manifest.get("external", {}))
    print(
        f"[assemble] done: {manifest['run_count']} run(s), "
        f"{len(manifest['tables'])} tables, {n_ext} external dataset(s)"
    )
    print(f"[assemble] manifest: {out_dir / 'manifests' / 'dataset_manifest.json'}")


def _parse_seal_args(argv):
    """Argument parser for the seal command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen seal",
        description="Seal an assembled dataset package (write SEALED marker).",
    )
    parser.add_argument("dataset_dir", help="Assembled dataset directory")
    return parser.parse_args(argv)


def _cmd_seal(args):
    """Seal an assembled dataset."""
    from .layout import seal_dataset
    dataset_dir = Path(args.dataset_dir)
    print(f"[seal] sealing {dataset_dir} ...")
    try:
        seal_record = seal_dataset(dataset_dir)
        print(f"[seal] sealed: manifest_sha256={seal_record['manifest_sha256'][:16]}...")
    except (RuntimeError, FileNotFoundError) as e:
        print(f"[seal] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def _parse_package_args(argv):
    """Argument parser for the package command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen package",
        description=(
            "Assemble a dataset package from one or more run directories "
            "(run=<id>/split=<SPLIT>/ layout)."
        ),
    )
    parser.add_argument(
        "runs", nargs="+", metavar="RUN_DIR",
        help="Run directories with parquet/ subdirs",
    )
    parser.add_argument("--root", required=True,
                        help="Output root directory for the assembled package")
    parser.add_argument("--external", default=None,
                        help="External partitions directory")
    return parser.parse_args(argv)


def _cmd_package(args):
    """Assemble a dataset package (package command; alias for assemble)."""
    from .layout import assemble_dataset
    run_dirs = [Path(r) for r in args.runs]
    out_dir = Path(args.root)
    external_dir = Path(args.external) if args.external else None
    print(f"[package] {len(run_dirs)} run(s) -> {out_dir}")
    manifest = assemble_dataset(run_dirs, out_dir, external_dir=external_dir)
    n_ext = len(manifest.get("external", {}))
    print(
        f"[package] done: {manifest['run_count']} run(s), "
        f"{len(manifest['tables'])} tables, {n_ext} external dataset(s)"
    )
    print(f"[package] manifest: {out_dir / 'manifests' / 'dataset_manifest.json'}")


def _parse_verify_seal_args(argv):
    """Argument parser for the verify-seal command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen verify-seal",
        description="Verify an assembled dataset against its seal record.",
    )
    parser.add_argument("dataset_dir", help="Sealed dataset directory")
    return parser.parse_args(argv)


def _cmd_verify_seal(args):
    """Verify a sealed dataset."""
    from .layout import verify_seal
    dataset_dir = Path(args.dataset_dir)
    try:
        result = verify_seal(dataset_dir)
    except FileNotFoundError as e:
        print(f"[verify-seal] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    if result["ok"]:
        print(f"[verify-seal] PASS  checked={result['checked']}  modified=0")
    else:
        n = len(result["modified"])
        print(
            f"[verify-seal] FAIL  checked={result['checked']}  modified={n}",
            file=sys.stderr,
        )
        sys.exit(1)


def _parse_public_package_args(argv):
    """Argument parser for the public-package command."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m mtgen public-package",
        description=(
            "Copy only publicly distributable parts of an assembled package, "
            "excluding local_only external partitions."
        ),
    )
    parser.add_argument("dataset_dir", help="Assembled dataset directory")
    parser.add_argument("--out", required=True,
                        help="Output directory for the public package")
    return parser.parse_args(argv)


def _cmd_public_package(args):
    """Write the public package."""
    from .layout import public_package
    dataset_dir = Path(args.dataset_dir)
    out_dir = Path(args.out)
    print(f"[public-package] {dataset_dir} -> {out_dir}")
    result = public_package(dataset_dir, out_dir)
    n_inc = len(result["included_external"])
    n_exc = len(result["excluded_external"])
    print(
        f"[public-package] done: "
        f"included_external={n_inc}, excluded_external={n_exc}"
    )
    if result["excluded_external"]:
        print(
            f"[public-package] excluded (local_only): "
            f"{', '.join(result['excluded_external'])}"
        )
    print(f"[public-package] datasheet: {out_dir / 'manifests' / 'datasheet.md'}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m mtgen <command> [args]")
        print("Commands: spec-check, build, from-manifest, verify, nuisance, audit,")
        print("          project, external, package, assemble, seal, verify-seal,")
        print("          public-package, reconcile")
        sys.exit(1)

    command = sys.argv[1]

    if command == "spec-check":
        _cmd_spec_check()

    elif command == "build":
        args = _parse_build_args(sys.argv[2:])
        _cmd_build(args)

    elif command == "from-manifest":
        args = _parse_from_manifest_args(sys.argv[2:])
        _cmd_from_manifest(args)

    elif command == "verify":
        from .verify import main as _verify_main
        sys.exit(_verify_main(sys.argv[2:]))

    elif command == "nuisance":
        from .nuisance import main as _nuisance_main
        sys.exit(_nuisance_main(sys.argv[2:]))

    elif command == "audit":
        from .audit_trace import main as _audit_main
        sys.exit(_audit_main(sys.argv[2:]))

    elif command == "project":
        from .project import project_run
        if len(sys.argv) < 3:
            print("Usage: python -m mtgen project <run_dir>")
            sys.exit(1)
        run_dir = Path(sys.argv[2])
        if not run_dir.exists():
            print(f"[project] ERROR: run_dir not found: {run_dir}", file=sys.stderr)
            sys.exit(1)
        parquet_dir = project_run(run_dir)
        print(f"[project] done: {parquet_dir}")

    elif command == "external":
        args = _parse_external_args(sys.argv[2:])
        _cmd_external(args)

    elif command == "package":
        args = _parse_package_args(sys.argv[2:])
        _cmd_package(args)

    elif command == "assemble":
        args = _parse_assemble_args(sys.argv[2:])
        _cmd_assemble(args)

    elif command == "seal":
        args = _parse_seal_args(sys.argv[2:])
        _cmd_seal(args)

    elif command == "verify-seal":
        args = _parse_verify_seal_args(sys.argv[2:])
        _cmd_verify_seal(args)

    elif command == "public-package":
        args = _parse_public_package_args(sys.argv[2:])
        _cmd_public_package(args)

    elif command == "reconcile":
        from .reconcile import main as _reconcile_main
        sys.exit(_reconcile_main(sys.argv[2:]))

    else:
        print(f"Unknown command: {command!r}")
        print("Commands: spec-check, build, from-manifest, verify, nuisance, audit,")
        print("          project, external, package, assemble, seal, verify-seal,")
        print("          public-package, reconcile")
        sys.exit(1)


if __name__ == "__main__":
    main()
