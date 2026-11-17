"""Witness audit for truth links (multistep-chain-plan.md, phase 0).

For a sample of runs of every linked scenario, decode the rendered events of
both actions of each ActionLink and check whether the declared witness holds
in the stream:

  PROCESS_ANCESTRY        later process descends from the earlier one (eBPF
                          parent field); one shared process is same_process
  NETWORK_FLOW            both actions carry the same FlowId (node, boot, cookie)
  REQUEST_IDENTITY        both gateway records carry the same request_id
  CREDENTIAL_READ_TO_USE  a token read in Pod P, then an API request bound to P

Results are mtgen.verify.link_witness_result's: holds, same_process, none,
no_events, unchecked. Read-only; prints a summary per (scenario, link,
witness, expected, result) and writes every row as JSON.

    python src/scripts/pilot/audit_link_witness.py datasets/generated/pilot-v2 \
        --per 5 --out link_witness_audit.json
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

# mtgen.verify puts the generated microtrace package on the path; import it first.
from mtgen.verify import (  # noqa: E402
    _link_endpoint_keys, _load_base_stream, _load_truth_files, _pk_tuple,
    link_witness_result, stream_connects,
)
from microtrace.v0 import dataset_pb2, witness_pb2  # noqa: E402

def _linked_scenarios(manifests) -> set:
    """Catalogue scenarios (base and the runs' overlays) that declare a link."""
    from mtgen.specs import catalogue_of_runs
    cat = catalogue_of_runs(manifests)
    return {s["id"] for s in cat["scenarios"] if s.get("links")}


def _pick_runs(split_dir: Path, per: int) -> list[Path]:
    """Up to `per` runs per linked scenario, clean runs first."""
    manifests = sorted(split_dir.glob("*/manifest.json"))
    linked = _linked_scenarios(json.loads(f.read_text(encoding="utf-8")) for f in manifests)
    pick: dict[str, list[Path]] = collections.defaultdict(list)
    for clean_only in (True, False):
        for f in manifests:
            m = json.loads(f.read_text(encoding="utf-8"))
            if clean_only and m["observability_profile"] != "clean":
                continue
            for s in linked & set(m["scenario_ids"]):
                if len(pick[s]) < per and f not in pick[s]:
                    pick[s].append(f)
    return sorted({f.parent for fs in pick.values() for f in fs})


def audit_run(run: Path) -> list[dict]:
    """One row per link of the run: the witness result on the stream.

    Uses verify's witness functions (mtgen.verify.link_witness_result), so
    the audit and verify's link_witness check read the stream the same way.
    """
    m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    actions, _, links = _load_truth_files(run)
    envs, _ = _load_base_stream(run)
    by_id = {e.logical_id: e for e in envs}
    by_seq = {a.action_seq: a for a in actions}
    parent: dict = {}
    for env in envs:
        ne = env.normalized_event
        if ne.WhichOneof("record") == "ebpf":
            child, par = _pk_tuple(ne.ebpf.process), _pk_tuple(ne.ebpf.parent)
            if child and par:
                parent.setdefault(child, par)
    connects = stream_connects(envs)

    rows = []
    for lnk in links:
        a_act, b_act = by_seq.get(lnk.from_action_seq), by_seq.get(lnk.to_action_seq)
        if a_act is None or b_act is None:
            continue
        a = _link_endpoint_keys(a_act, by_id)
        b = _link_endpoint_keys(b_act, by_id)
        result = link_witness_result(lnk.witness_type, a, b, parent, connects)
        gap = (min(b["times"]) - max(a["times"])) / 1e9 if a["times"] and b["times"] else None
        rows.append(dict(
            scenario=a_act.scenario_id, run=run.name,
            profile=m["observability_profile"],
            link=f"{a_act.step_label}->{b_act.step_label}",
            witness=witness_pb2.WitnessType.Name(lnk.witness_type),
            expected=dataset_pb2.TruthExpectation.Name(lnk.expected_state),
            result=result,
            shared=[k for k in ("pod_uid", "lineage_id", "principal", "remote_ip")
                    if a[k] & b[k]],
            gap_s=None if gap is None else round(gap, 1),
        ))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("split_dir", type=Path)
    ap.add_argument("--per", type=int, default=5, help="runs per linked scenario")
    ap.add_argument("--out", type=Path, default=Path("link_witness_audit.json"))
    args = ap.parse_args()

    runs = _pick_runs(args.split_dir, args.per)
    rows = []
    for i, run in enumerate(runs, 1):
        rows.extend(audit_run(run))
        print(f"{i}/{len(runs)} {run.name[:8]}", file=sys.stderr, flush=True)
    args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    summary = collections.Counter(
        (r["scenario"], r["link"], r["witness"], r["expected"], r["result"]) for r in rows)
    for key, n in sorted(summary.items()):
        print(n, *key, sep=" | ")


if __name__ == "__main__":
    main()
