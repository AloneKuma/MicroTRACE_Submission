"""Link nuisance check (multistep-chain-plan.md, phase 4 gate).

Can a link's label (PRESENT vs ABSENT) be predicted without its witness? For
every scored link of a split, the features are what a correlator sees around
the pair besides the witness itself:

  gap_s          time between the two actions
  from_kind,     action kinds of the endpoints (the event families they
  to_kind        render), one-hot
  same_pod       both actions act in one Pod
  profile,world  the run's observability profile and world size

A cross-validated ROC-AUC (GroupKFold by run) at or above the threshold
means the labels may have a shortcut: decoys or controls differ from real
links in something other than the witness. As for the findings check, a
score at or above the threshold passes when a permutation test (labels
shuffled among the same rows, --permutations times) gives p >= 0.05: the
null reaches it often, a small-sample effect. Same-process continuity links
and same-socket continuity links (connect -> transfer on that socket, not a
witness of the paper's table) are reported apart, since their witness is
identity; so are witness types verify has no checker for
(CONTROL_PLANE_CAUSALITY_INSTANCE), whose labels no correlator can read, and
links with no PRESENT finding opportunity at one end (D-20, exp2-gaps-plan B0a):
the GO links findings, so it is never asked to decide them.

The purity table lists every (witness, from kind, to kind) pair with at
least 10 scored links and its label split; a pair with one label only lets
the endpoint kinds stand in for the witness (link-twin-decoys-plan.md).

    python src/scripts/pilot/link_nuisance.py datasets/generated/pilot-multistep \
        --json link_nuisance.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

import mtgen  # noqa: F401,E402 — puts the generated protos on the path
from mtgen.specs import catalogue_of_runs  # noqa: E402
from mtgen.verify import _load_truth_files  # noqa: E402
from microtrace.v0 import common_pb2, dataset_pb2, envelope_pb2, witness_pb2  # noqa: E402

# Links whose witness is identity rather than a causal hop, reported apart:
# one process acting twice, bytes counted on the connect's own socket, or
# two findings inside one benign incident (score.py BENIGN_CONTINUITY)
# (not a witness of the paper's table; multistep-chain-plan.md G-0).
CONTINUITY_PREFIXES = ("same-process continuity", "same-socket continuity", "benign continuity")

# Witness types verify's link_witness check reads; others are reported only.
CHECKED_WITNESSES = {"PROCESS_ANCESTRY", "NETWORK_FLOW", "REQUEST_IDENTITY",
                     "CREDENTIAL_READ_TO_USE"}


def _event_pods(run_dir: Path, wanted: set) -> dict:
    """Pod UIDs visible on the wanted events of base.pb, streamed frame by
    frame (a whole run is never held in memory): logical ID -> set of Pods.

    "Same Pod" is what a correlator sees on the events, not the truth's actor
    IDs: an actor named as a Pod and one named as a process key of that Pod
    are one Pod (comparing the IDs made the feature follow catalogue wording).
    """
    pods: dict = {}
    with open(run_dir / "base.pb", "rb") as fh:
        while True:
            head = fh.read(4)
            if len(head) < 4:
                break
            frame = fh.read(struct.unpack(">I", head)[0])
            env = envelope_pb2.Envelope()
            env.ParseFromString(frame)
            if env.logical_id in wanted:
                keys = _link_endpoint_keys_one(env)
                if keys:
                    pods.setdefault(env.logical_id, set()).update(keys)
    return pods


def _link_endpoint_keys_one(env) -> set:
    ne = env.normalized_event
    if not env.HasField("normalized_event"):
        return set()
    out = {ent.uid for ent in ne.entities if ent.type == common_pb2.POD and ent.uid}
    rec = ne.WhichOneof("record")
    if rec == "ebpf" and ne.ebpf_derived.HasField("pod_uid"):
        out.add(ne.ebpf_derived.pod_uid)
    elif rec == "audit" and ne.audit_derived.HasField("bound_pod_uid"):
        out.add(ne.audit_derived.bound_pod_uid)
    return out


def link_rows(split_dir: Path, catalogue: dict) -> list:
    action_kind = {(s["id"], str(st["step"])): st["action"]
                   for s in catalogue["scenarios"] for st in s["steps"]}
    # Continuity is read from the catalogue, so a split built before a
    # link's reason changed is classified as the catalogue now declares.
    continuity = {(s["id"], str(lk["from"]), str(lk["to"]))
                  for s in catalogue["scenarios"] for lk in s.get("links", [])
                  if lk.get("reason", "").startswith(CONTINUITY_PREFIXES)}
    rows = []
    for mf in sorted(split_dir.glob("*/manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8"))
        actions, opps, links = _load_truth_files(mf.parent)
        by_seq = {a.action_seq: a for a in actions}
        has_opp = {o.action_seq for o in opps if o.expected_state == dataset_pb2.PRESENT}
        scored = [lk for lk in links
                  if lk.expected_state in (dataset_pb2.PRESENT, dataset_pb2.ABSENT)]
        wanted = {ev for lk in scored for s in (lk.from_action_seq, lk.to_action_seq)
                  for ev in by_seq[s].rendered_event_ids}
        ev_pods = _event_pods(mf.parent, wanted) if wanted else {}

        def pods(gta):
            return set().union(*(ev_pods.get(ev, set()) for ev in gta.rendered_event_ids))

        for lk in scored:
            a, b = by_seq[lk.from_action_seq], by_seq[lk.to_action_seq]
            gap = (b.started_at.ToNanoseconds() - a.started_at.ToNanoseconds()) / 1e9
            rows.append(dict(
                run=m["run_id"], profile=m["observability_profile"], world=m["world_name"],
                witness=witness_pb2.WitnessType.Name(lk.witness_type),
                continuity=((a.scenario_id, a.step_label, b.step_label) in continuity
                            or lk.reason.startswith(CONTINUITY_PREFIXES)),
                label=int(lk.expected_state == dataset_pb2.PRESENT),
                gap_s=gap,
                from_kind=action_kind.get((a.scenario_id, a.step_label), "?"),
                to_kind=action_kind.get((b.scenario_id, b.step_label), "?"),
                same_pod=int(bool(pods(a) & pods(b))),
                decidable=int(lk.from_action_seq in has_opp and lk.to_action_seq in has_opp),
            ))
    return rows


def _cv_auc(X, labels, groups, n_splits: int, seed: int) -> float:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import GroupKFold

    pred = np.zeros(len(labels))
    for train, test in GroupKFold(n_splits=min(n_splits, len(set(groups)))).split(X, labels, groups):
        if len(set(labels[train])) < 2:
            pred[test] = labels[train].mean()
            continue
        clf = RandomForestClassifier(n_estimators=200, random_state=seed, min_samples_leaf=5)
        clf.fit(X[train], labels[train])
        pred[test] = clf.predict_proba(X[test])[:, 1]
    return float(roc_auc_score(labels, pred))


def score(rows: list, n_splits: int = 5, seed: int = 0, threshold: float = 0.65,
          permutations: int = 0) -> dict:
    """Cross-validated AUC; with permutations, also its p-value when the AUC
    reaches the threshold (labels shuffled among the same rows)."""
    labels = np.array([r["label"] for r in rows])
    if len(set(labels)) < 2 or min(Counter(labels).values()) < 2:
        return {"auc": None, "reason": "insufficient_labels",
                "counts": dict(Counter(labels.tolist()))}
    cats = ["from_kind", "to_kind", "profile", "world"]
    vocab = {c: sorted({r[c] for r in rows}) for c in cats}
    X = np.array([
        [r["gap_s"], r["same_pod"]]
        + [int(r[c] == v) for c in cats for v in vocab[c]]
        for r in rows
    ], dtype=float)
    groups = np.array([r["run"] for r in rows])
    if len(set(groups)) < 2:
        return {"auc": None, "reason": "insufficient_runs",
                "counts": dict(Counter(labels.tolist()))}
    auc = _cv_auc(X, labels, groups, n_splits, seed)
    out = {"auc": round(auc, 4),
           "counts": {"PRESENT": int(labels.sum()), "ABSENT": int((1 - labels).sum())}}
    if permutations and auc >= threshold:
        rng = np.random.default_rng(seed)
        null = np.array([_cv_auc(X, rng.permutation(labels), groups, n_splits, seed)
                         for _ in range(permutations)])
        out.update(p_value=round(float((np.sum(null >= auc) + 1) / (len(null) + 1)), 4),
                   null_mean=round(float(null.mean()), 4),
                   null_p95=round(float(np.percentile(null, 95)), 4),
                   permutations=permutations)
    return out


def purity(rows: list, min_links: int = 10) -> list:
    """Label split of every (witness, from kind, to kind) pair with enough links."""
    split = Counter((r["witness"], r["from_kind"], r["to_kind"], r["label"]) for r in rows)
    table = []
    for w, f, t in sorted({k[:3] for k in split}):
        p, a = split[(w, f, t, 1)], split[(w, f, t, 0)]
        if p + a >= min_links:
            table.append({"witness": w, "from_kind": f, "to_kind": t, "PRESENT": p, "ABSENT": a,
                          "minority_share": round(min(p, a) / (p + a), 3)})
    return table


def _fails(v: dict, threshold: float) -> bool:
    """Score at or above the threshold, unless the permutation test clears it."""
    if v.get("auc") is None or v["auc"] < threshold:
        return False
    return v.get("p_value", 0.0) < 0.05


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("split_dir", type=Path)
    ap.add_argument("--threshold", type=float, default=0.65)
    ap.add_argument("--permutations", type=int, default=100,
                    help="permutations for the p-value of a score at or above the "
                         "threshold (0: none, the threshold alone decides)")
    ap.add_argument("--min-links", type=int, default=10,
                    help="purity table: pairs with at least this many scored links")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    # The base catalogue and the overlays the runs were built with (D-31).
    catalogue = catalogue_of_runs(json.loads(mf.read_text(encoding="utf-8"))
                                  for mf in sorted(args.split_dir.glob("*/manifest.json")))
    rows = link_rows(args.split_dir, catalogue)
    result = {"threshold": args.threshold, "links": len(rows), "by_witness": {}}
    # Pool every non-continuity, decidable link of a checked witness type,
    # then each witness type with both labels.
    scored = [r for r in rows if not r["continuity"] and r["witness"] in CHECKED_WITNESSES
              and r["decidable"]]
    kw = dict(threshold=args.threshold, permutations=args.permutations)
    result["pooled"] = score(scored, **kw)
    for w in sorted({r["witness"] for r in scored}):
        result["by_witness"][w] = score([r for r in scored if r["witness"] == w], **kw)
    result["continuity_links"] = sum(r["continuity"] for r in rows)
    result["unchecked_witness_links"] = dict(Counter(
        r["witness"] for r in rows if not r["continuity"] and r["witness"] not in CHECKED_WITNESSES))
    result["undecidable_links"] = dict(Counter(
        f"{r['witness']} {'PRESENT' if r['label'] else 'ABSENT'}" for r in rows
        if not r["continuity"] and r["witness"] in CHECKED_WITNESSES and not r["decidable"]))
    result["purity"] = purity(scored, args.min_links)
    result["one_label_pairs"] = [f"{p['witness']} {p['from_kind']}->{p['to_kind']}"
                                 for p in result["purity"] if p["minority_share"] == 0]
    failed = [k for k, v in [("pooled", result["pooled"]), *result["by_witness"].items()]
              if _fails(v, args.threshold)]
    result["failed"] = failed
    result["passed"] = not failed
    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
