"""Isolation Forest export and scoring without pickles.

A fitted sklearn IsolationForest is exported to plain JSON (each tree's
children, split feature, threshold and leaf sample counts, plus the feature
subset each tree saw). score() reproduces sklearn's score_samples on that
JSON with numpy only, so a frozen model artifact stays readable and
bit-for-bit scoreable after library upgrades. The anomaly score used by the
agents is the negation, 2^(-E[h(x)] / c(psi)), in (0, 1]; larger is more
anomalous (paper Eq. ml-anomaly-score).
"""
import math

import numpy as np

EULER_GAMMA = 0.5772156649015329


def average_path_length(n):
    """c(n) from Liu et al., as sklearn's _average_path_length (vectorised)."""
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    two = n == 2
    big = n > 2
    out[two] = 1.0
    nb = n[big]
    out[big] = 2.0 * (np.log(nb - 1.0) + EULER_GAMMA) - 2.0 * (nb - 1.0) / nb
    return out


def export(model, feature_names):
    """JSON-ready dict of a fitted sklearn IsolationForest."""
    trees = []
    for est, feats in zip(model.estimators_, model.estimators_features_):
        t = est.tree_
        trees.append({
            "features_used": [int(f) for f in feats],
            "children_left": t.children_left.tolist(),
            "children_right": t.children_right.tolist(),
            "feature": t.feature.tolist(),
            "threshold": [float(x) for x in t.threshold],
            "n_node_samples": t.n_node_samples.tolist(),
        })
    return {"features": list(feature_names), "max_samples": int(model.max_samples_), "trees": trees}


def _depths(tree, X):
    left = np.asarray(tree["children_left"])
    right = np.asarray(tree["children_right"])
    feat = np.asarray(tree["feature"])
    thr = np.asarray(tree["threshold"])
    nsamp = np.asarray(tree["n_node_samples"], dtype=np.float64)
    cols = np.asarray(tree["features_used"])
    # sklearn trees compare float32 inputs against float64 thresholds.
    Xs = X[:, cols].astype(np.float32)
    out = np.empty(X.shape[0])
    for i in range(X.shape[0]):
        node, depth = 0, 0
        while left[node] != -1:
            node = left[node] if Xs[i, feat[node]] <= thr[node] else right[node]
            depth += 1
        out[i] = depth + average_path_length([nsamp[node]])[0]
    return out


def score(forest, X):
    """Anomaly scores (larger = more anomalous) for rows of X."""
    X = np.asarray(X, dtype=np.float64)
    if X.ndim == 1:
        X = X[None, :]
    depths = np.zeros(X.shape[0])
    for tree in forest["trees"]:
        depths += _depths(tree, X)
    denom = len(forest["trees"]) * average_path_length([forest["max_samples"]])[0]
    return 2.0 ** (-depths / denom)


def vector(forest, features):
    """Feature dict -> row in the artifact's feature order; missing is an error."""
    return [float(features[name]) for name in forest["features"]]


def finite(x):
    return x is not None and not math.isnan(x)
