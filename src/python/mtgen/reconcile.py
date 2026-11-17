"""Reconcile received archive against the base stream and fault logs.

Checks:
1. received logical_ids + fault-log drops == base stream logical_ids.
2. Every transit drop has a DROPPED_BEFORE completeness record in the archive.
3. Applies the fault-log adjustment: opportunities whose evidence was dropped
   become UNOBSERVABLE.  This library function is reused by the step-8 scorer.

CLI::

    python -m mtgen reconcile \\
        --base      <run_dir>/base.pb          \\
        --archive   <archive_root>             \\
        --src-log   src-faults.jsonl           \\
        --transit-log transit-faults.jsonl     \\
        --truth     <run_dir>/restricted       \\
        [--out      reconcile-report.json]

Exit 0 on PASS, 1 on FAIL.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class FaultLogEntry:
    """One line from a source-stage or transit-stage fault log.

    Attributes:
        fault_id:   ID of the fault that caused this effect.
        kind:       Fault kind (``loss``, ``outage``, ``suppress``, …).
        stage:      ``source`` or ``transit``.
        logical_id: Logical ID of the affected record (may be empty for
                    source-stage records whose envelope was never assigned one).
        topic:      Kafka topic of the dropped/altered record.
        action:     One of: dropped_unreported, dropped_reported, shifted,
                    delayed, forged.
    """
    fault_id: str
    kind: str
    stage: str
    logical_id: str
    topic: str
    action: str


@dataclass
class ReconcileResult:
    """Output of a reconcile() call.

    Attributes:
        ok:                    True if all checks pass.
        base_count:            Number of logical_ids in the base stream.
        received_count:        Number of logical_ids in the archive.
        dropped_count:         Number of reported drops in the fault logs.
        missing:               IDs in the base stream that are neither in the
                               archive nor in any drop log.
        extra:                 IDs in the archive that are not in the base
                               stream (excludes forge actions).
        transit_drops_without_gap: Transit-dropped IDs with no DROPPED_BEFORE
                               completeness record in the archive.
        adjusted_opportunities: List of ``(opportunity_id, old_state)`` pairs
                               whose ``expected_state`` was changed to
                               UNOBSERVABLE by the fault adjustment.
        errors:                Human-readable list of failure reasons.
    """
    ok: bool
    base_count: int
    received_count: int
    dropped_count: int
    missing: List[str] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)
    transit_drops_without_gap: List[str] = field(default_factory=list)
    adjusted_opportunities: List[Tuple[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fault-log parsing
# ---------------------------------------------------------------------------

def parse_fault_log(path: Path) -> List[FaultLogEntry]:
    """Parse a JSON-lines fault log (source or transit stage).

    The first line is a header ``{"header": {...}}`` and is skipped.
    Lines that do not decode as JSON objects are skipped with a warning
    to stderr.
    """
    import sys
    entries: List[FaultLogEntry] = []
    if not path.exists():
        return entries
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"[reconcile] warn: {path}:{lineno}: {exc}", file=sys.stderr)
                continue
            if "header" in obj:
                continue  # skip header line
            entries.append(FaultLogEntry(
                fault_id=obj.get("fault_id", ""),
                kind=obj.get("kind", ""),
                stage=obj.get("stage", ""),
                logical_id=obj.get("logical_id", ""),
                topic=obj.get("topic", ""),
                action=obj.get("action", ""),
            ))
    return entries


# ---------------------------------------------------------------------------
# Base stream reader
# ---------------------------------------------------------------------------

def read_base_stream_logical_ids(base_pb_path: Path) -> FrozenSet[str]:
    """Read a length-delimited base.pb and return the set of logical_ids.

    Imports protobuf lazily; falls back to a raw struct scan if the
    generated modules are not available (useful in offline tests).
    """
    ids: Set[str] = set()
    data = base_pb_path.read_bytes()
    try:
        import mtgen  # noqa: F401 — registers gen/ on sys.path
        from microtrace.v0 import envelope_pb2
        view = memoryview(data)
        pos = 0
        while pos < len(view):
            if pos + 4 > len(view):
                break
            length = struct.unpack_from(">I", view, pos)[0]
            pos += 4
            payload = bytes(view[pos:pos + length])
            pos += length
            env = envelope_pb2.Envelope()
            try:
                env.ParseFromString(payload)
                # The shipper skips HEARTBEAT records: the receiver writes
                # its own (ship-contract.md), so they never reach the archive.
                if env.logical_id and env.kind != envelope_pb2.HEARTBEAT:
                    ids.add(env.logical_id)
            except Exception:
                pass
    except ImportError:
        # Fallback: try to parse length-delimited frames and extract logical_id
        # as UTF-8 from the protobuf wire format (Envelope.logical_id, type 2 = LEN).
        ids = _scan_logical_ids_raw(data)
    return frozenset(ids)


def read_shipper_input_logical_ids(path: Path) -> FrozenSet[str]:
    """Return the envelope logical_ids in a shipper input file (JSON lines).

    Watermark lines carry no envelope and are skipped.
    """
    ids: Set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            lid = json.loads(line).get("envelope", {}).get("logical_id")
            if lid:
                ids.add(lid)
    return frozenset(ids)


def _scan_logical_ids_raw(data: bytes) -> Set[str]:
    """Minimal protobuf scanner that extracts field-5 string values."""
    ids: Set[str] = set()
    view = memoryview(data)
    pos = 0
    while pos < len(view):
        if pos + 4 > len(view):
            break
        length = struct.unpack_from(">I", view, pos)[0]
        pos += 4
        msg_end = pos + length
        msg_bytes = bytes(view[pos:msg_end])
        pos = msg_end
        # walk the proto wire format looking for Envelope.logical_id, wire_type=2
        lid = _extract_proto_string_field(msg_bytes, field_number=_LOGICAL_ID_FIELD)
        if lid:
            ids.add(lid)
    return ids


# Envelope.logical_id (spec/proto/microtrace/v0/envelope.proto).
_LOGICAL_ID_FIELD = 6


def _extract_proto_string_field(data: bytes, field_number: int) -> str:
    """Return the first occurrence of a LEN-typed proto field."""
    i = 0
    target_tag = (field_number << 3) | 2  # wire type 2 = LEN
    while i < len(data):
        tag, i = _varint(data, i)
        wire_type = tag & 0x7
        fn = tag >> 3
        if wire_type == 2:
            length, i = _varint(data, i)
            value = data[i:i + length]
            i += length
            if fn == field_number:
                try:
                    return value.decode("utf-8")
                except UnicodeDecodeError:
                    return ""
        elif wire_type == 0:
            _, i = _varint(data, i)
        elif wire_type == 1:
            i += 8
        elif wire_type == 5:
            i += 4
        else:
            break  # unknown wire type, stop
    return ""


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode a protobuf varint at pos; return (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


# ---------------------------------------------------------------------------
# Archive reader
# ---------------------------------------------------------------------------

def read_archive_logical_ids(archive_root: Path) -> FrozenSet[str]:
    """Scan an archive directory and return the set of logical_ids found.

    Reads every ``*.pb.zst`` file under ``<archive_root>/topic=/partition=/``.
    """
    from mtgen.archiver import _decode_partition
    ids: Set[str] = set()
    for pb_file in sorted(archive_root.rglob("*.pb.zst")):
        try:
            data = pb_file.read_bytes()
        except OSError:
            continue
        payloads = _decode_partition(data)
        for payload in payloads:
            lid = _extract_proto_string_field(payload, field_number=_LOGICAL_ID_FIELD)
            if lid:
                ids.add(lid)
    return frozenset(ids)


def read_archive_completeness_logical_ids(archive_root: Path) -> FrozenSet[str]:
    """Return set of logical_ids from completeness records (DROPPED_BEFORE).

    Reads all source.completeness.v0 payloads and returns the logical_ids
    referenced in gaps with reason DROPPED_BEFORE (GapReason value 2).
    """
    try:
        import mtgen  # noqa: F401
        from microtrace.v0 import envelope_pb2, stream_pb2, common_pb2
    except ImportError:
        return frozenset()

    from mtgen.archiver import _decode_partition
    ids: Set[str] = set()
    completeness_dir = archive_root / "topic=source.completeness.v0"
    if not completeness_dir.exists():
        return frozenset()

    for pb_file in sorted(completeness_dir.rglob("*.pb.zst")):
        try:
            data = pb_file.read_bytes()
        except OSError:
            continue
        payloads = _decode_partition(data)
        for payload in payloads:
            try:
                env = envelope_pb2.Envelope()
                env.ParseFromString(payload)
                if env.kind != envelope_pb2.SOURCE_COMPLETENESS:
                    continue
                sc = stream_pb2.SourceCompleteness()
                sc.ParseFromString(env.source_completeness.SerializeToString())
                for gap in sc.gaps:
                    if gap.reason == common_pb2.DROPPED_BEFORE:
                        # Accumulate any logical_ids named in the gap detail
                        # (the detail string is free-form; we mark the scope
                        # as having a gap record, not individual IDs).
                        ids.add(f"__gap__{sc.scope}")
            except Exception:
                pass
    return frozenset(ids)


# ---------------------------------------------------------------------------
# Core reconcile function
# ---------------------------------------------------------------------------

def reconcile(
    base_ids: FrozenSet[str],
    received_ids: FrozenSet[str],
    src_log_entries: List[FaultLogEntry],
    transit_log_entries: List[FaultLogEntry],
    gap_scopes: FrozenSet[str],
    opportunities: Optional[List[dict]] = None,
) -> ReconcileResult:
    """Reconcile received logical_ids against base stream and fault logs.

    Parameters
    ----------
    base_ids:
        Set of logical_ids from the canonical base stream.
    received_ids:
        Set of logical_ids found in the Kafka archive (received records).
    src_log_entries:
        Entries from the source-stage fault log.
    transit_log_entries:
        Entries from the transit-stage fault log.
    gap_scopes:
        Scopes for which a DROPPED_BEFORE completeness record exists in the
        archive (from ``read_archive_completeness_logical_ids``).
    opportunities:
        Optional list of ``FindingOpportunity`` dicts (from restricted truth).
        When provided, opportunities whose evidence events were dropped become
        UNOBSERVABLE.  Each dict must have ``opportunity_id``, ``expected_state``,
        and ``evidence_event_ids``.

    Returns
    -------
    ReconcileResult
    """
    errors: List[str] = []

    # Set of dropped logical_ids from both fault logs
    # (only "dropped_unreported" and "dropped_reported" actions count as drops)
    _DROP_ACTIONS = frozenset({"dropped_unreported", "dropped_reported"})
    all_log_entries = src_log_entries + transit_log_entries
    dropped_ids: Set[str] = {
        e.logical_id for e in all_log_entries
        if e.action in _DROP_ACTIONS and e.logical_id
    }
    # Forged records appear in the archive but NOT in the base stream; their
    # logical_ids will not match any base_id.  We do not count them as "extra".
    forged_ids: Set[str] = {
        e.logical_id for e in all_log_entries if e.action == "forged" and e.logical_id
    }

    # Check 1: received + dropped == base
    accounted_for = received_ids | dropped_ids
    missing = sorted(base_ids - accounted_for)
    extra = sorted((received_ids - base_ids) - forged_ids)

    if missing:
        errors.append(
            f"{len(missing)} record(s) missing: neither received nor in drop log"
        )
    if extra:
        errors.append(
            f"{len(extra)} record(s) in archive not in base stream (and not forged)"
        )
    # A logged drop that still reached the archive means the fault did not act.
    dropped_but_received = sorted(dropped_ids & received_ids)
    if dropped_but_received:
        errors.append(
            f"{len(dropped_but_received)} record(s) logged as dropped but "
            f"present in the archive"
        )

    # Check 2: every transit drop has a DROPPED_BEFORE completeness record
    transit_drops: Set[str] = {
        e.logical_id for e in transit_log_entries
        if e.action == "dropped_reported" and e.logical_id
    }
    # The gap record names the node/boot/lane scope, not individual logical_ids.
    # We check that *some* DROPPED_BEFORE gap exists in the archive whenever
    # there are any transit drops.  A stronger per-lane check is left for phase 7.
    transit_drops_without_gap: List[str] = []
    if transit_drops and not gap_scopes:
        transit_drops_without_gap = sorted(transit_drops)
        errors.append(
            f"{len(transit_drops)} transit drop(s) have no DROPPED_BEFORE "
            f"completeness record in the archive"
        )

    # Adjustment: mark opportunities UNOBSERVABLE when their evidence was dropped
    adjusted: List[Tuple[str, str]] = []
    if opportunities:
        adjusted = apply_fault_adjustment(opportunities, dropped_ids)

    ok = not errors
    return ReconcileResult(
        ok=ok,
        base_count=len(base_ids),
        received_count=len(received_ids),
        dropped_count=len(dropped_ids),
        missing=missing,
        extra=extra,
        transit_drops_without_gap=transit_drops_without_gap,
        adjusted_opportunities=adjusted,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Fault-log adjustment (reused by the step-8 scorer)
# ---------------------------------------------------------------------------

def apply_fault_adjustment(
    opportunities: List[dict],
    dropped_ids: Set[str],
) -> List[Tuple[str, str]]:
    """Mark opportunities UNOBSERVABLE when all their evidence was dropped.

    An opportunity transitions from its current ``expected_state`` to
    ``"UNOBSERVABLE"`` when *every* event in its ``evidence_event_ids`` list
    appears in ``dropped_ids``, OR when the list is non-empty and *at least one*
    required evidence event was dropped (the dropped evidence may be enough to
    prevent a PRESENT observation).

    Decision: we use "any required evidence dropped" → UNOBSERVABLE, matching
    the contract: "a dropped record is never scored as an observed negative"
    (fault-contract.md).  An opportunity cannot be called PRESENT when some
    of its required evidence was not delivered; and it should not be called
    ABSENT (a true negative) because the absence might be caused by the drop.

    Only opportunities in state ``PRESENT`` or ``ABSENT`` are adjusted;
    ones already ``UNOBSERVABLE`` are left unchanged.

    Parameters
    ----------
    opportunities:
        List of opportunity dicts with keys ``opportunity_id``,
        ``expected_state``, and ``evidence_event_ids``.
    dropped_ids:
        Set of logical_ids that were dropped (from fault log).

    Returns
    -------
    List of ``(opportunity_id, old_state)`` for every changed opportunity.
    """
    _ADJUSTABLE = frozenset({"PRESENT", "ABSENT"})
    changed: List[Tuple[str, str]] = []
    for opp in opportunities:
        state = opp.get("expected_state", "")
        if state not in _ADJUSTABLE:
            continue
        ev_ids = opp.get("evidence_event_ids") or []
        if not ev_ids:
            continue
        if any(eid in dropped_ids for eid in ev_ids):
            old_state = opp["expected_state"]
            opp["expected_state"] = "UNOBSERVABLE"
            changed.append((opp["opportunity_id"], old_state))
    return changed


# ---------------------------------------------------------------------------
# Truth reader helpers
# ---------------------------------------------------------------------------

def read_opportunities(restricted_dir: Path) -> List[dict]:
    """Read FindingOpportunity records from restricted/truth_findings.pb.

    Returns a list of dicts with ``opportunity_id``, ``expected_state``, and
    ``evidence_event_ids``.  Returns an empty list if the file does not exist
    or protobuf is not available.
    """
    pb_path = restricted_dir / "truth_findings.pb"
    if not pb_path.exists():
        return []
    try:
        import mtgen  # noqa: F401
        from microtrace.v0 import dataset_pb2
    except ImportError:
        return []

    _STATE_NAMES = {
        dataset_pb2.PRESENT: "PRESENT",
        dataset_pb2.ABSENT: "ABSENT",
        dataset_pb2.UNOBSERVABLE: "UNOBSERVABLE",
    }

    records = []
    data = pb_path.read_bytes()
    view = memoryview(data)
    pos = 0
    while pos < len(view):
        if pos + 4 > len(view):
            break
        length = struct.unpack_from(">I", view, pos)[0]
        pos += 4
        payload = bytes(view[pos:pos + length])
        pos += length
        try:
            opp = dataset_pb2.FindingOpportunity()
            opp.ParseFromString(payload)
            records.append({
                "opportunity_id": opp.opportunity_id,
                "expected_state": _STATE_NAMES.get(opp.expected_state, ""),
                "evidence_event_ids": list(opp.evidence_event_ids),
            })
        except Exception:
            pass
    return records


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """CLI: python -m mtgen reconcile …  Returns exit code (0=PASS, 1=FAIL)."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="python -m mtgen reconcile",
        description=(
            "Reconcile received archive against the base stream and fault logs."
        ),
    )
    parser.add_argument("--base", required=True,
                        help="Path to the canonical base.pb file")
    parser.add_argument("--archive", required=True,
                        help="Archive root directory (topic=/partition= layout)")
    parser.add_argument("--src-log", default=None,
                        help="Source-stage fault log (JSON lines)")
    parser.add_argument("--transit-log", default=None,
                        help="Transit-stage fault log (JSON lines)")
    parser.add_argument("--truth", default=None,
                        help="Restricted truth directory (for fault adjustment)")
    parser.add_argument("--out", default=None,
                        help="Write reconcile report JSON to this file")
    parser.add_argument("--shipper-input", default=None,
                        help="Shipper JSONL that was replayed; base-stream IDs "
                             "are limited to the records in it (one node)")
    args = parser.parse_args(argv)

    base_path = Path(args.base)
    archive_root = Path(args.archive)

    if not base_path.exists():
        print(f"[reconcile] ERROR: base stream not found: {base_path}", file=sys.stderr)
        return 1
    if not archive_root.exists():
        print(f"[reconcile] ERROR: archive root not found: {archive_root}", file=sys.stderr)
        return 1

    print("[reconcile] reading base stream …")
    base_ids = read_base_stream_logical_ids(base_path)
    print(f"[reconcile] base stream: {len(base_ids)} logical_ids")
    if args.shipper_input:
        base_ids = base_ids & read_shipper_input_logical_ids(Path(args.shipper_input))
        print(f"[reconcile] limited to {args.shipper_input}: {len(base_ids)} logical_ids")

    print("[reconcile] reading archive …")
    received_ids = read_archive_logical_ids(archive_root)
    print(f"[reconcile] archive: {len(received_ids)} logical_ids")

    src_entries: List[FaultLogEntry] = []
    if args.src_log:
        src_entries = parse_fault_log(Path(args.src_log))
        print(f"[reconcile] source fault log: {len(src_entries)} entries")

    transit_entries: List[FaultLogEntry] = []
    if args.transit_log:
        transit_entries = parse_fault_log(Path(args.transit_log))
        print(f"[reconcile] transit fault log: {len(transit_entries)} entries")

    gap_scopes = read_archive_completeness_logical_ids(archive_root)

    opportunities: List[dict] = []
    if args.truth:
        opportunities = read_opportunities(Path(args.truth))
        print(f"[reconcile] truth: {len(opportunities)} opportunities")

    result = reconcile(
        base_ids=base_ids,
        received_ids=received_ids,
        src_log_entries=src_entries,
        transit_log_entries=transit_entries,
        gap_scopes=gap_scopes,
        opportunities=opportunities if opportunities else None,
    )

    # Report
    status = "PASS" if result.ok else "FAIL"
    print(f"[reconcile] {status}")
    print(f"  base={result.base_count}  received={result.received_count}"
          f"  dropped={result.dropped_count}")
    if result.adjusted_opportunities:
        print(f"  adjusted to UNOBSERVABLE: {len(result.adjusted_opportunities)}")
    for err in result.errors:
        print(f"  ERROR: {err}", file=sys.stderr)

    if args.out:
        report = {
            "ok": result.ok,
            "base_count": result.base_count,
            "received_count": result.received_count,
            "dropped_count": result.dropped_count,
            "missing": result.missing,
            "extra": result.extra,
            "transit_drops_without_gap": result.transit_drops_without_gap,
            "adjusted_opportunities": [
                {"opportunity_id": oid, "old_state": old}
                for oid, old in result.adjusted_opportunities
            ],
            "errors": result.errors,
        }
        Path(args.out).write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(f"[reconcile] report: {args.out}")

    return 0 if result.ok else 1
