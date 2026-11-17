"""Audit trace: human-readable markdown for one benign and one attack action.

Usage::

    python -m mtgen audit <run_dir> --out <file.md>

Writes a markdown file tracing one benign action and one attack action
through all four layers:

1. Events — NormalizedEvent envelopes whose ``logical_id`` is in the action's
   ``rendered_event_ids``.
2. Truth rows — FindingOpportunity and ActionLink records that reference this
   action's ``action_seq``.
3. Manifest entries — the relevant fields from ``manifest.json``.
4. Template provenance — placeholder (phase 3, not yet implemented).

Refuses to run when ``manifest.split == "HELD_OUT"``.

Exit codes:
  0 — audit written
  1 — refused (HELD_OUT) or no actions found
  2 — fatal error (missing directory / load failure)
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

_REPO_DIR = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# Proto I/O helpers (duplicated from verify.py to keep modules independent)
# ---------------------------------------------------------------------------

def _read_ld_protos(path: Path, message_class) -> list:
    msgs = []
    with open(path, "rb") as fh:
        while True:
            hdr = fh.read(4)
            if not hdr:
                break
            (length,) = struct.unpack(">I", hdr)
            data = fh.read(length)
            m = message_class()
            m.ParseFromString(data)
            msgs.append(m)
    return msgs


def _load_base_stream(run_dir: Path) -> List:
    """Load Envelopes from base.pb; silently skip truncated/bad frames."""
    from microtrace.v0 import envelope_pb2
    base_pb = run_dir / "base.pb"
    envelopes = []
    if not base_pb.exists():
        return envelopes
    data = base_pb.read_bytes()
    offset = 0
    while offset + 4 <= len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        if offset + length > len(data):
            break
        env = envelope_pb2.Envelope()
        try:
            env.ParseFromString(data[offset:offset + length])
        except Exception:  # noqa: BLE001
            pass
        else:
            envelopes.append(env)
        offset += length
    return envelopes


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _ts_str(ts) -> str:
    """Format a protobuf Timestamp as a short RFC3339 string."""
    import datetime
    if ts.seconds == 0 and ts.nanos == 0:
        return "(unset)"
    dt = datetime.datetime.fromtimestamp(ts.seconds, tz=datetime.timezone.utc)
    frac = f".{ts.nanos:09d}".rstrip("0").rstrip(".")
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + frac + "Z"


_SOURCE_NAMES: Dict[int, str] = {}  # populated lazily


def _source_name(src: int) -> str:
    global _SOURCE_NAMES
    if not _SOURCE_NAMES:
        from microtrace.v0 import common_pb2
        _SOURCE_NAMES = {
            common_pb2.EBPF: "EBPF",
            common_pb2.GATEWAY: "GATEWAY",
            common_pb2.AUDIT: "AUDIT",
            common_pb2.KYVERNO: "KYVERNO",
            common_pb2.CLUSTER_CONTEXT: "CLUSTER_CONTEXT",
            common_pb2.DB_AUDIT: "DB_AUDIT",
            common_pb2.PATH_FLOW: "PATH_FLOW",
        }
    return _SOURCE_NAMES.get(src, f"src={src}")


def _env_one_line(env) -> str:
    """Single markdown list-item summary for one Envelope."""
    lid = env.logical_id or "(no logical_id)"
    pf = env.WhichOneof("payload")
    if pf == "normalized_event":
        ne = env.normalized_event
        t = _ts_str(ne.time.event_time)
        rec = ne.WhichOneof("record") or "(no record)"
        return (f"- `{lid[:32]}` "
                f"source={_source_name(ne.source)} "
                f"record={rec} "
                f"event_time={t}")
    return f"- `{lid[:32]}` kind={pf or '?'}"


def _state_name(state: int) -> str:
    from microtrace.v0 import dataset_pb2
    return {
        dataset_pb2.PRESENT: "PRESENT",
        dataset_pb2.ABSENT: "ABSENT",
        dataset_pb2.UNOBSERVABLE: "UNOBSERVABLE",
    }.get(state, f"state={state}")


def _opp_block(opp) -> str:
    lines = [
        f"- **opportunity_id**: `{opp.opportunity_id}`",
        f"- **finding_type**: {opp.finding_type}",
        f"- **expected_state**: {_state_name(opp.expected_state)}",
        f"- **window**: {_ts_str(opp.window_start)} – {_ts_str(opp.window_end)}",
    ]
    if opp.evidence_requirements:
        lines.append(
            "- **evidence_requirements**: "
            + ", ".join(f"`{r}`" for r in list(opp.evidence_requirements)[:6])
        )
    if opp.evidence_event_ids:
        ids = list(opp.evidence_event_ids)[:5]
        lines.append(
            "- **evidence_event_ids** (%d): " % len(opp.evidence_event_ids)
            + ", ".join(f"`{e[:20]}`" for e in ids)
            + ("…" if len(opp.evidence_event_ids) > 5 else "")
        )
    if opp.reason:
        lines.append(f"- **reason**: {opp.reason}")
    return "\n".join(lines)


def _link_block(lnk) -> str:
    from microtrace.v0 import witness_pb2
    wt_name = (witness_pb2.WitnessType.Name(lnk.witness_type)
               if lnk.witness_type else "UNSPECIFIED")
    parts = [
        f"- **link_id**: `{lnk.link_id}`",
        f"- **from_action_seq**: {lnk.from_action_seq}",
        f"- **to_action_seq**: {lnk.to_action_seq}",
        f"- **expected_state**: {_state_name(lnk.expected_state)}",
        f"- **witness_type**: {wt_name}",
    ]
    if lnk.shared_keys:
        parts.append(f"- **shared_keys**: {', '.join(lnk.shared_keys)}")
    if lnk.reason:
        parts.append(f"- **reason**: {lnk.reason}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Per-action section builder
# ---------------------------------------------------------------------------

def _action_section(
    gta,
    envelopes_by_id: Dict[str, object],
    truth_findings: list,
    truth_links: list,
    manifest: dict,
) -> str:
    label = "Attack" if gta.is_attack else "Benign"
    lines: List[str] = []
    lines += [
        f"### {label} action — action_seq={gta.action_seq}",
        "",
        "#### Action summary",
        "",
        f"- **action_seq**: {gta.action_seq}",
        f"- **scenario_id**: `{gta.scenario_id or '(none)'}`",
        f"- **is_attack**: {gta.is_attack}",
        f"- **step_label**: `{gta.step_label or '(none)'}`",
        f"- **harness_outcome**: `{gta.harness_outcome or '(none)'}`",
        f"- **started_at**: {_ts_str(gta.started_at)}",
        f"- **ended_at**: {_ts_str(gta.ended_at)}",
    ]
    if gta.expected_finding_types:
        lines.append(
            "- **expected_finding_types**: "
            + ", ".join(gta.expected_finding_types)
        )
    lines += ["", "#### Events", ""]

    rendered_ids = list(gta.rendered_event_ids)
    if rendered_ids:
        for eid in rendered_ids[:20]:
            env = envelopes_by_id.get(eid)
            if env is not None:
                lines.append(_env_one_line(env))
            else:
                lines.append(f"- `{eid[:32]}` *(not found in base stream)*")
        if len(rendered_ids) > 20:
            lines.append(f"- … ({len(rendered_ids) - 20} more)")
    else:
        lines.append("*(no rendered_event_ids)*")

    lines += ["", "#### Truth rows", ""]

    opps = [o for o in truth_findings if o.action_seq == gta.action_seq]
    if opps:
        lines.append("**FindingOpportunity records:**")
        lines.append("")
        for opp in opps:
            lines.append(_opp_block(opp))
            lines.append("")
    else:
        lines.append("*(no FindingOpportunity rows for this action)*")
        lines.append("")

    lnks = [
        lnk for lnk in truth_links
        if lnk.from_action_seq == gta.action_seq
        or lnk.to_action_seq == gta.action_seq
    ]
    if lnks:
        lines.append("**ActionLink records:**")
        lines.append("")
        for lnk in lnks:
            lines.append(_link_block(lnk))
            lines.append("")
    else:
        lines.append("*(no ActionLink rows involving this action)*")
        lines.append("")

    lines += ["#### Manifest entries", ""]
    for key in (
        "run_id", "split", "world_name", "duration_s",
        "observability_profile", "capture_profile",
        "generator_version", "generator_spec_version",
    ):
        val = manifest.get(key, "(not in manifest)")
        lines.append(f"- **{key}**: `{val}`")
    scenario_ids = manifest.get("scenario_ids")
    if scenario_ids:
        lines.append(
            f"- **scenario_ids** ({len(scenario_ids)}): "
            + ", ".join(f"`{s}`" for s in scenario_ids[:5])
            + ("…" if len(scenario_ids) > 5 else "")
        )
    lines.append("")

    lines += ["#### Template provenance", ""]
    lines.append(
        "*(Phase 3 (benign templates) not yet implemented; "
        "no template provenance rows are available for this run.)*"
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Top-level renderer
# ---------------------------------------------------------------------------

def render_audit(run_dir: Path, out_path: Path) -> None:
    """Write a markdown audit trace for *run_dir* to *out_path*.

    Raises:
        ValueError: if the run is HELD_OUT or manifest is missing.
    """
    from microtrace.v0 import dataset_pb2

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise ValueError(f"no manifest.json in {run_dir}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    split = manifest.get("split", "")
    if split == "HELD_OUT":
        raise ValueError(
            f"audit refused: run {manifest.get('run_id', run_dir.name)!r} "
            f"is HELD_OUT"
        )

    # Load truth tables
    restricted = run_dir / "restricted"
    truth_actions: list = []
    truth_findings: list = []
    truth_links: list = []
    if (restricted / "truth_actions.pb").exists():
        truth_actions = _read_ld_protos(
            restricted / "truth_actions.pb",
            dataset_pb2.GroundTruthAction,
        )
    if (restricted / "truth_findings.pb").exists():
        truth_findings = _read_ld_protos(
            restricted / "truth_findings.pb",
            dataset_pb2.FindingOpportunity,
        )
    if (restricted / "truth_links.pb").exists():
        truth_links = _read_ld_protos(
            restricted / "truth_links.pb",
            dataset_pb2.ActionLink,
        )

    # Index base stream by logical_id
    envelopes = _load_base_stream(run_dir)
    envelopes_by_id: Dict[str, object] = {
        env.logical_id: env for env in envelopes if env.logical_id
    }

    # Attack actions: has at least one PRESENT FindingOpportunity
    present_seqs = {
        opp.action_seq
        for opp in truth_findings
        if opp.expected_state == dataset_pb2.PRESENT
    }

    # Choose one benign and one attack action
    benign_gta = None
    attack_gta = None
    for gta in truth_actions:
        if not gta.is_attack and benign_gta is None:
            benign_gta = gta
        if gta.is_attack and gta.action_seq in present_seqs and attack_gta is None:
            attack_gta = gta
        if benign_gta and attack_gta:
            break

    # Fallbacks: any attack or any action
    if attack_gta is None:
        attack_gta = next((g for g in truth_actions if g.is_attack), None)
    if benign_gta is None and truth_actions:
        benign_gta = truth_actions[0]

    run_id = manifest.get("run_id", run_dir.name)
    world = manifest.get("world_name", "?")
    dur = manifest.get("duration_s", "?")

    md: List[str] = [
        f"# Audit trace: run `{run_id}`",
        "",
        f"Run directory: `{run_dir}`",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| split | {split} |",
        f"| world_name | {world} |",
        f"| duration_s | {dur} |",
        f"| total_actions | {len(truth_actions)} |",
        f"| total_findings | {len(truth_findings)} |",
        f"| total_links | {len(truth_links)} |",
        f"| stream_envelopes | {len(envelopes)} |",
        "",
        "---",
        "",
    ]

    if benign_gta is not None:
        md.append(_action_section(
            benign_gta, envelopes_by_id, truth_findings, truth_links, manifest,
        ))
    else:
        md.append("*No benign action found in this run.*")
        md.append("")

    md.append("---")
    md.append("")

    if attack_gta is not None:
        md.append(_action_section(
            attack_gta, envelopes_by_id, truth_findings, truth_links, manifest,
        ))
    else:
        md.append("*No attack action found in this run.*")
        md.append("")

    out_path.write_text("\n".join(md), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    """CLI entry point for ``python -m mtgen audit``."""
    parser = argparse.ArgumentParser(
        description=(
            "Write a human-readable audit trace for one MicroTRACE run. "
            "Refused for HELD_OUT runs."
        ),
    )
    parser.add_argument("run_dir", help="Path to the run output directory")
    parser.add_argument("--out", required=True,
                        help="Output markdown file path")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"error: run_dir does not exist: {run_dir}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    try:
        render_audit(run_dir, out_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2

    print(f"audit trace written to {out_path}")
    return 0
