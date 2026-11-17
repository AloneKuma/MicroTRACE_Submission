"""Nuisance check: per-finding predictability from run metadata only.

Usage::

    python -m mtgen nuisance <split_dir>

For each run directory in *split_dir* that contains a ``manifest.json`` and
``restricted/truth_findings.pb``, extract nuisance features and per-finding
opportunity labels.  Train a LogisticRegression classifier with GroupKFold
cross-validation (group = run_id) and report AUC or balanced accuracy per
finding type.  Each finding gets one verdict, with the values from
``generator-spec.v0.yaml`` (``pilot_default`` until the pilot freeze):

- NOT_TESTABLE: fewer than ``min_windows_per_label`` PRESENT or ABSENT
  windows.  At that size even a perfect score is reached by chance, so the
  check can vouch neither way.
- FAIL: score at least the threshold and permutation p-value below alpha.
- PASS: otherwise.

Exit 1 when any finding FAILs.  NOT_TESTABLE findings do not fail the split;
they are counted on the summary line and listed.

Features used:
- capture profile (one-hot)
- log run duration
- source presence and log source event count per family
- log total envelopes
- workload identity: world_name (one-hot) + observability_profile (one-hot)
- time position: window_start absolute nanoseconds (proxy for ordering within run)
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

_REPO_DIR = Path(__file__).resolve().parents[3]
_SPEC_DIR = _REPO_DIR / "spec"

_SOURCE_FAMILIES = (
    "EBPF", "GATEWAY", "AUDIT", "KYVERNO",
    "CLUSTER_CONTEXT", "DB_AUDIT", "PATH_FLOW",
)
_WORLD_NAMES = ("Small", "Reference", "Large")
_OBS_PROFILES = (
    "clean", "degraded_gateway", "degraded_audit",
    "degraded_ebpf", "degraded_context",
)
_CAPTURE_PROFILES = ("evaluated-v0", "research-superset-v0")


# ---------------------------------------------------------------------------
# Spec helpers
# ---------------------------------------------------------------------------

def _load_gen_spec(spec_dir: Optional[Path] = None) -> dict:
    import yaml
    p = (spec_dir or _SPEC_DIR) / "generator" / "generator-spec.v0.yaml"
    with open(p, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _nuisance_threshold(gen_spec: dict) -> float:
    """Return the active nuisance threshold (frozen value or pilot_default)."""
    nc = gen_spec.get("nuisance_check", {})
    t = nc.get("threshold", {})
    if isinstance(t, dict):
        frozen = t.get("frozen")
        if frozen is not None:
            return float(frozen)
        return float(t.get("pilot_default", 0.65))
    return float(t) if t else 0.65


def _min_windows_per_label(gen_spec: dict) -> int:
    m = gen_spec.get("nuisance_check", {}).get("min_windows_per_label", {})
    if isinstance(m, dict):
        frozen = m.get("frozen")
        return int(frozen if frozen is not None else m.get("pilot_default", 20))
    return int(m) if m else 20


def _significance(gen_spec: dict) -> dict:
    s = gen_spec.get("nuisance_check", {}).get("significance", {}) or {}
    return {
        "alpha": float(s.get("alpha", 0.05)),
        "permutations": int(s.get("permutations", 1000)),
        "seed": int(s.get("seed", 0)),
    }


# ---------------------------------------------------------------------------
# Proto I/O
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


def _ts_to_ns(ts) -> int:
    return ts.seconds * 1_000_000_000 + ts.nanos


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _run_level_features(manifest: dict) -> Dict[str, float]:
    """Extract all run-level nuisance features from a manifest dict."""
    feats: Dict[str, float] = {}

    # Capture profile (one-hot)
    profile = manifest.get("capture_profile", "")
    for cp in _CAPTURE_PROFILES:
        feats[f"cap_{cp.replace('-', '_').replace('.', '_')}"] = float(profile == cp)

    # Run duration
    feats["log_duration_s"] = math.log1p(float(manifest.get("duration_s", 0)))

    # Source presence and event volume
    stats = manifest.get("stream_statistics", {})
    total = stats.get("total_envelopes", 0)
    feats["log_total_envelopes"] = math.log1p(float(total))
    per_src = stats.get("events_per_source_family", {})
    for src in _SOURCE_FAMILIES:
        feats[f"src_present_{src}"] = float(bool(per_src.get(src, 0)))
        feats[f"log_src_count_{src}"] = math.log1p(float(per_src.get(src, 0)))

    # Workload identity: world name + observability profile (one-hot each)
    world = manifest.get("world_name", "")
    for w in _WORLD_NAMES:
        feats[f"world_{w}"] = float(world == w)
    obs = manifest.get("observability_profile", "")
    for op in _OBS_PROFILES:
        feats[f"obs_{op.replace('-', '_')}"] = float(obs == op)

    # Time position proxy: log generator seed (varies between runs)
    seed = manifest.get("seeds", {}).get("generator_seed", 0)
    feats["log_generator_seed"] = math.log1p(float(abs(seed)))

    return feats


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

@dataclass
class OppRow:
    """One data point: a single FindingOpportunity with its nuisance features."""
    run_id: str
    finding_type: str
    label: int         # 1 = PRESENT, 0 = ABSENT
    features: Dict[str, float]


def _load_split(split_dir: Path) -> List[OppRow]:
    """Load all PRESENT/ABSENT opportunity rows from a split directory.

    Scans all subdirectories with a manifest.json.  UNOBSERVABLE opportunities
    are excluded (neither a clear positive nor a clear negative).
    """
    from microtrace.v0 import dataset_pb2

    rows: List[OppRow] = []
    for run_dir in sorted(split_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        mf_path = run_dir / "manifest.json"
        if not mf_path.exists():
            continue
        manifest = json.loads(mf_path.read_text(encoding="utf-8"))
        run_id = manifest.get("run_id", run_dir.name)
        duration_ns = float(manifest.get("duration_s", 3600)) * 1_000_000_000
        run_feats = _run_level_features(manifest)

        findings_path = run_dir / "restricted" / "truth_findings.pb"
        if not findings_path.exists():
            continue
        findings = _read_ld_protos(findings_path, dataset_pb2.FindingOpportunity)

        for opp in findings:
            if opp.expected_state not in (
                dataset_pb2.PRESENT, dataset_pb2.ABSENT,
            ):
                continue  # skip UNOBSERVABLE
            label = int(opp.expected_state == dataset_pb2.PRESENT)
            # Time position: window_start absolute nanoseconds
            ws_ns = float(_ts_to_ns(opp.window_start))
            feats = dict(run_feats)
            feats["time_position_ns"] = ws_ns
            rows.append(OppRow(
                run_id=run_id,
                finding_type=opp.finding_type,
                label=label,
                features=feats,
            ))

    return rows


# ---------------------------------------------------------------------------
# Per-finding check
# ---------------------------------------------------------------------------

@dataclass
class FindingResult:
    finding_type: str
    n_windows: int
    n_positive: int
    metric: str    # "roc_auc", "balanced_accuracy" or "insufficient_labels"
    score: float
    threshold: float
    passed: bool
    n_absent: int = 0
    verdict: str = ""                # "PASS", "FAIL" or "NOT_TESTABLE"
    p_value: Optional[float] = None  # permutation p; None when not computed


def _check_finding(
    rows: List[OppRow],
    finding_type: str,
    threshold: float,
    n_splits: int = 5,
) -> FindingResult:
    """Train and cross-validate a nuisance predictor for one finding type."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    from sklearn.metrics import roc_auc_score, balanced_accuracy_score
    from sklearn.preprocessing import StandardScaler

    relevant = [r for r in rows if r.finding_type == finding_type]
    n = len(relevant)
    if not relevant:
        return FindingResult(finding_type, 0, 0,
                             "balanced_accuracy", 0.5, threshold, True)

    feat_names = sorted(relevant[0].features)
    X = np.array([[r.features.get(k, 0.0) for k in feat_names]
                  for r in relevant], dtype=float)
    y = np.array([float(r.label) for r in relevant])
    groups = np.array([r.run_id for r in relevant])

    n_pos = int(y.sum())
    n_neg = int((y == 0).sum())
    min_class = min(n_pos, n_neg)
    n_unique_groups = len(np.unique(groups))

    if min_class < 2 or n_unique_groups < 2:
        # Too few labels of one class (or too few runs) to cross-validate:
        # the check cannot vouch for this finding.
        return FindingResult(finding_type, n, n_pos,
                             "insufficient_labels", 0.5, threshold, False)

    actual_splits = min(n_splits, min_class, n_unique_groups)
    if actual_splits < 2:
        return FindingResult(finding_type, n, n_pos,
                             "balanced_accuracy", 0.5, threshold, True)

    gkf = GroupKFold(n_splits=actual_splits)

    all_true: List[float] = []
    all_probs: List[float] = []
    all_preds: List[float] = []

    for train_idx, test_idx in gkf.split(X, y, groups):
        X_tr, X_te = X[train_idx], X[test_idx]
        y_tr, y_te = y[train_idx], y[test_idx]

        if len(np.unique(y_tr)) < 2:
            # Degenerate fold: predict majority class.
            majority = float(np.round(y_tr.mean()))
            all_true.extend(y_te.tolist())
            all_preds.extend([majority] * len(y_te))
            all_probs.extend([majority] * len(y_te))
            continue

        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr)
        X_te_s = scaler.transform(X_te)

        clf = LogisticRegression(
            max_iter=500, class_weight="balanced", random_state=0,
        )
        clf.fit(X_tr_s, y_tr)

        all_true.extend(y_te.tolist())
        all_preds.extend(clf.predict(X_te_s).tolist())
        proba = clf.predict_proba(X_te_s)
        # Column 1 is P(class=1); fall back to column 0 for degenerate fits.
        all_probs.extend(
            proba[:, 1].tolist() if proba.shape[1] > 1
            else proba[:, 0].tolist()
        )

    all_true_a = np.array(all_true)
    all_probs_a = np.array(all_probs)
    all_preds_a = np.array(all_preds)

    if len(np.unique(all_true_a)) > 1 and len(all_probs_a) > 0:
        metric = "roc_auc"
        score = float(roc_auc_score(all_true_a, all_probs_a))
    else:
        metric = "balanced_accuracy"
        score = float(balanced_accuracy_score(all_true_a, all_preds_a))

    passed = score <= threshold
    return FindingResult(
        finding_type=finding_type,
        n_windows=n,
        n_positive=n_pos,
        metric=metric,
        score=score,
        threshold=threshold,
        passed=passed,
    )


def _permutation_p(
    rows: List[OppRow],
    finding_type: str,
    observed: float,
    threshold: float,
    n_splits: int,
    permutations: int,
    seed: int,
) -> float:
    """p = (k + 1) / (permutations + 1), k = label shuffles among the
    finding's windows that score at least *observed*."""
    relevant = [r for r in rows if r.finding_type == finding_type]
    labels = np.array([r.label for r in relevant])
    rng = np.random.default_rng(seed)
    k = 0
    for _ in range(permutations):
        perm = rng.permutation(labels)
        shuffled = [OppRow(r.run_id, r.finding_type, int(perm[i]), r.features)
                    for i, r in enumerate(relevant)]
        if _check_finding(shuffled, finding_type, threshold,
                          n_splits=n_splits).score >= observed:
            k += 1
    return (k + 1) / (permutations + 1)


def _judge_finding(
    rows: List[OppRow],
    finding_type: str,
    threshold: float,
    min_per_label: int,
    alpha: float,
    permutations: int,
    seed: int,
    n_splits: int = 5,
) -> FindingResult:
    """Score one finding and give its verdict (see the module docstring).

    With ``permutations=0`` no p-value is computed and a score at or over
    the threshold fails on its own (the stricter, score-only rule).
    """
    fr = _check_finding(rows, finding_type, threshold, n_splits=n_splits)
    fr.n_absent = fr.n_windows - fr.n_positive
    if min(fr.n_positive, fr.n_absent) < min_per_label:
        fr.verdict = "NOT_TESTABLE"
    else:
        if permutations > 0:
            fr.p_value = _permutation_p(rows, finding_type, fr.score, threshold,
                                        n_splits, permutations, seed)
        over = fr.score >= threshold
        significant = fr.p_value is None or fr.p_value < alpha
        fr.verdict = "FAIL" if over and significant else "PASS"
    fr.passed = fr.verdict == "PASS"
    return fr


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class NuisanceResult:
    split_dir: str
    threshold: float
    findings: List[FindingResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    min_per_label: int = 20
    alpha: float = 0.05
    permutations: int = 1000

    def count(self, verdict: str) -> int:
        return sum(f.verdict == verdict for f in self.findings)

    @property
    def ok(self) -> bool:
        return self.count("FAIL") == 0 and not self.errors

    def to_dict(self) -> dict:
        return {
            "split_dir": self.split_dir,
            "threshold": self.threshold,
            "min_windows_per_label": self.min_per_label,
            "alpha": self.alpha,
            "permutations": self.permutations,
            "ok": self.ok,
            "n_pass": self.count("PASS"),
            "n_fail": self.count("FAIL"),
            "n_not_testable": self.count("NOT_TESTABLE"),
            "findings": [
                {
                    "finding_type": f.finding_type,
                    "verdict": f.verdict,
                    "n_windows": f.n_windows,
                    "n_positive": f.n_positive,
                    "n_absent": f.n_absent,
                    "metric": f.metric,
                    "score": f.score,
                    "p_value": f.p_value,
                    "threshold": f.threshold,
                    "passed": f.passed,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


def check_nuisance(
    split_dir: Path,
    spec_dir: Optional[Path] = None,
    n_splits: int = 5,
    permutations: Optional[int] = None,
) -> NuisanceResult:
    """Run the nuisance check on a split directory.

    Args:
        split_dir:    Directory whose immediate subdirectories are run dirs.
        spec_dir:     Root of the spec/ tree; auto-detected when None.
        n_splits:     Number of GroupKFold folds (default 5).
        permutations: Permutation count; None takes the spec's.  0 skips the
                      test, so a score at or over the threshold fails alone.

    Returns:
        NuisanceResult with one FindingResult per finding type present.
    """
    gen_spec = _load_gen_spec(spec_dir)
    threshold = _nuisance_threshold(gen_spec)
    sig = _significance(gen_spec)
    if permutations is not None:
        sig["permutations"] = permutations
    result = NuisanceResult(
        split_dir=str(split_dir), threshold=threshold,
        min_per_label=_min_windows_per_label(gen_spec),
        alpha=sig["alpha"], permutations=sig["permutations"],
    )

    rows = _load_split(split_dir)
    if not rows:
        result.errors.append(f"no PRESENT/ABSENT opportunity rows found in {split_dir}")
        return result

    all_finding_types = sorted({r.finding_type for r in rows})
    for ft in all_finding_types:
        fr = _judge_finding(
            rows, ft, threshold, result.min_per_label, sig["alpha"],
            sig["permutations"], sig["seed"], n_splits=n_splits,
        )
        result.findings.append(fr)

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_result(result: NuisanceResult) -> None:
    """Print a human-readable nuisance check summary."""
    status = "PASS" if result.ok else "FAIL"
    print(f"nuisance {status}  split_dir={result.split_dir}"
          f"  threshold={result.threshold:.3f}  alpha={result.alpha}"
          f"  min_per_label={result.min_per_label}"
          f"  permutations={result.permutations}")
    print(f"  tested={result.count('PASS') + result.count('FAIL')}"
          f"  failed={result.count('FAIL')}"
          f"  not_testable={result.count('NOT_TESTABLE')}")
    for fr in result.findings:
        p = "-" if fr.p_value is None else f"{fr.p_value:.3f}"
        print(f"  {fr.finding_type}: {fr.verdict}  {fr.metric}={fr.score:.3f}"
              f"  p={p}  present={fr.n_positive}  absent={fr.n_absent}")
    for err in result.errors:
        print(f"  ERROR: {err}")


def main(argv=None) -> int:
    """CLI entry point for ``python -m mtgen nuisance``."""
    parser = argparse.ArgumentParser(
        description=(
            "Nuisance check: per-finding AUC from run metadata only. "
            "Fails if any testable finding scores at least the threshold "
            "with a permutation p-value below alpha (generator-spec)."
        ),
    )
    parser.add_argument(
        "split_dir",
        help="Directory whose subdirectories are run directories",
    )
    parser.add_argument(
        "--json", metavar="OUT",
        help="Write JSON result to this path",
    )
    parser.add_argument(
        "--n-splits", type=int, default=5, dest="n_splits",
        help="GroupKFold splits (default: 5)",
    )
    parser.add_argument(
        "--permutations", type=int, default=None,
        help="permutation count (default: the spec's; 0 = score-only rule)",
    )
    args = parser.parse_args(argv)

    split_dir = Path(args.split_dir)
    if not split_dir.exists():
        print(f"error: split_dir does not exist: {split_dir}", file=sys.stderr)
        return 2

    result = check_nuisance(split_dir, n_splits=args.n_splits,
                            permutations=args.permutations)
    print_result(result)

    if args.json:
        Path(args.json).write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8",
        )

    return 0 if result.ok else 1
