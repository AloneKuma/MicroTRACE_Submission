"""Ablation switches the orchestrator honours (`orchestrator.ablations`).

Each switch removes one mechanism and keeps every other rule, so a run with
it isolates that mechanism's effect. An unknown name is an error, never a
silent no-op: a misspelt switch would otherwise report the full design's
numbers under an ablation's label.
"""
from collections import namedtuple

Ablation = namedtuple("Ablation", "name paper meaning")

ABLATIONS = {a.name: a for a in [
    Ablation("no_index", "No-Index (Exp. 4)",
             "test every processed pair instead of index candidates; must give the same link set"),
    Ablation("no_eps_cap", "none (proofs weakened variant)",
             "drop the per-witness uncertainty cap eps_bar from TimeValid; not a paper ablation"),
    Ablation("no_conflict", "No-Conflict",
             "a decisive contradiction no longer rejects a link"),
    Ablation("no_distinct", "No-Distinct",
             "skip DistinctAction: two findings of one action may link"),
    Ablation("no_contra_coverage", "No-ContraCoverage",
             "confirm links whose contradiction sources were not covered (loss or idle gaps)"),
    Ablation("no_coverage", "No-Coverage (Exp. 3)",
             "ignore loss and idle (coverage) records when admitting a link: missing observations are complete"),
    Ablation("no_uncertainty", "No-Uncertainty (Exp. 3)",
             "TimeValid on nominal timestamps: every clock uncertainty is 0 (the eps_bar cap then always holds)"),
    Ablation("no_epoch", "No-Epoch",
             "no node-trust epochs: evidence after a compromise onset is trusted"),
    Ablation("no_tactic", "No-Tactic",
             "q_ab = 1 for every link: no tactic-transition weight, no q_unmapped; admissibility unchanged"),
    Ablation("no_witness", "No-Witness",
             "link findings that share a Pod, principal, remote IP or lineage within W_nw, without a witness"),
    Ablation("no_origin", "No-Origin",
             "a workload-set key (trace or request ID a caller sets) supports a link as if sensor-set"),
    Ablation("no_ancestry_chain", "none (pre-A1 baseline)",
             "process types confirm on a shared lineage, without the parent chain (G-0); not a paper ablation"),
    Ablation("no_trigger_exemption", "none (D3_v5 Covered text)",
             "an epoch opened by the pair's own target event still leaves the interval uncovered"),
]}


def validate(names):
    """Raise ValueError naming every switch the orchestrator does not know."""
    unknown = sorted(set(names or ()) - set(ABLATIONS))
    if unknown:
        raise ValueError(f"unknown orchestrator ablation(s) {unknown}; known: {sorted(ABLATIONS)}")
    return frozenset(names or ())
