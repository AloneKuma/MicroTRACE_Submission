"""Anomaly detectors compared with the Isolation Forest (docs/plans/ml-model-compare-plan.md).

Each detector is fitted on benign feature rows and scores rows so that a larger
score is more anomalous, as iforest.score. Settings are fixed in
experiments/ml-compare/RULE-modelcompare.md and are not tuned.

ECOD and HBOS are written here in numpy (no new dependency); kNN, LOF and the
one-class SVM come from scikit-learn. The distance-based three see log1p then
median/IQR-scaled inputs (counts are heavy-tailed and on different scales); ECOD,
HBOS and the forest work per feature and see the raw values.
"""
import numpy as np

NAMES = ("ecod", "hbos", "knn", "lof", "ocsvm")


class RobustScale:
    """log1p, then (x - median) / IQR per feature (IQR 0 -> 1), fitted on training rows."""

    def fit(self, X):
        Z = np.log1p(np.maximum(np.asarray(X, dtype=np.float64), 0.0))
        self.med = np.median(Z, axis=0)
        q1, q3 = np.percentile(Z, [25, 75], axis=0)
        iqr = q3 - q1
        self.iqr = np.where(iqr > 0, iqr, 1.0)
        return self

    def __call__(self, X):
        Z = np.log1p(np.maximum(np.asarray(X, dtype=np.float64), 0.0))
        return (Z - self.med) / self.iqr


class ECOD:
    """Empirical-CDF outlier detection (Li et al., TKDE 2022, Alg. 1).

    Per feature, the left tail P(X <= x) and right tail P(X >= x) from the training
    rows with add-one smoothing, (count + 1) / (n + 1), so no probability is 0. The
    score is the largest of: sum of -log left, sum of -log right, and the sum that
    takes each feature's tail by the sign of its training skewness (left if < 0).
    """

    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        self.cols = [np.sort(X[:, j]) for j in range(X.shape[1])]
        self.n = X.shape[0]
        sd = X.std(axis=0)
        mu = X.mean(axis=0)
        with np.errstate(divide="ignore", invalid="ignore"):
            skew = np.where(sd > 0, ((X - mu) ** 3).mean(axis=0) / sd ** 3, 0.0)
        self.left_side = skew < 0
        return self

    def score(self, X):
        X = np.asarray(X, dtype=np.float64)
        n = self.n
        ul = np.empty_like(X)
        ur = np.empty_like(X)
        for j, col in enumerate(self.cols):
            le = np.searchsorted(col, X[:, j], side="right")          # count <= x
            ge = n - np.searchsorted(col, X[:, j], side="left")       # count >= x
            ul[:, j] = -np.log((le + 1) / (n + 1))
            ur[:, j] = -np.log((ge + 1) / (n + 1))
        us = np.where(self.left_side, ul, ur)
        return np.maximum(np.maximum(ul.sum(axis=1), ur.sum(axis=1)), us.sum(axis=1))


class HBOS:
    """Histogram-based outlier score (Goldstein and Dengel 2012), PyOD's defaults.

    Per feature, 10 equal-width bins over the training range, density-normalised;
    a value's term is -log(density + alpha). A value outside the range by at most
    tol bin widths takes the edge bin; further out it takes the lowest density.
    """

    def __init__(self, n_bins=10, alpha=0.1, tol=0.5):
        self.n_bins, self.alpha, self.tol = n_bins, alpha, tol

    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        self.hists, self.edges = [], []
        for j in range(X.shape[1]):
            h, e = np.histogram(X[:, j], bins=self.n_bins, density=True)
            self.hists.append(h + self.alpha)
            self.edges.append(e)
        return self

    def score(self, X):
        X = np.asarray(X, dtype=np.float64)
        out = np.zeros(X.shape[0])
        for j, (h, e) in enumerate(zip(self.hists, self.edges)):
            x = X[:, j]
            width = e[1] - e[0]
            idx = np.clip(np.searchsorted(e, x, side="right") - 1, 0, len(h) - 1)
            dens = h[idx]
            far = (x < e[0] - self.tol * width) | (x > e[-1] + self.tol * width)
            dens = np.where(far, h.min(), dens)
            out += -np.log(dens)
        return out


class KNN:
    """Distance to the k-th nearest training row (PyOD 'largest'), k = 5."""

    def __init__(self, k=5):
        self.k = k

    def fit(self, X):
        from sklearn.neighbors import NearestNeighbors
        self.scale = RobustScale().fit(X)
        self.nn = NearestNeighbors(n_neighbors=min(self.k, len(X))).fit(self.scale(X))
        return self

    def score(self, X):
        d, _ = self.nn.kneighbors(self.scale(X))
        return d[:, -1]


class LOF:
    """Local outlier factor, k = 20, novelty mode (sklearn)."""

    def __init__(self, k=20):
        self.k = k

    def fit(self, X):
        from sklearn.neighbors import LocalOutlierFactor
        self.scale = RobustScale().fit(X)
        self.m = LocalOutlierFactor(n_neighbors=min(self.k, len(X) - 1), novelty=True).fit(self.scale(X))
        return self

    def score(self, X):
        return -self.m.score_samples(self.scale(X))


class OCSVM:
    """One-class SVM, RBF kernel, gamma 'scale', nu 0.01 (sklearn)."""

    def __init__(self, nu=0.01):
        self.nu = nu

    def fit(self, X):
        from sklearn.svm import OneClassSVM
        self.scale = RobustScale().fit(X)
        self.m = OneClassSVM(kernel="rbf", gamma="scale", nu=self.nu).fit(self.scale(X))
        return self

    def score(self, X):
        return -self.m.score_samples(self.scale(X))


def make(name):
    return {"ecod": ECOD, "hbos": HBOS, "knn": KNN, "lof": LOF, "ocsvm": OCSVM}[name]()


# ---- frozen artifacts (no pickles): kNN and the one-class SVM as plain JSON -----------------
# A frozen detector is scored from its JSON with numpy only, as iforest.score, so the
# artifact stays readable and scoreable after library upgrades. Larger = more anomalous.

def export(model):
    """JSON-ready dict of a fitted KNN or OCSVM."""
    sc = {"median": model.scale.med.tolist(), "iqr": model.scale.iqr.tolist()}
    if isinstance(model, KNN):
        return {"kind": "knn", "k": int(model.nn.n_neighbors), "scale": sc,
                "train": model.nn._fit_X.tolist()}
    if isinstance(model, OCSVM):
        m = model.m
        return {"kind": "ocsvm", "scale": sc, "gamma": float(m._gamma),
                "support_vectors": m.support_vectors_.tolist(), "dual_coef": m.dual_coef_[0].tolist()}
    raise TypeError(f"no frozen form for {type(model).__name__}")


def _scaled(det, X):
    Z = np.log1p(np.maximum(np.asarray(X, dtype=np.float64), 0.0))
    return (Z - np.asarray(det["scale"]["median"])) / np.asarray(det["scale"]["iqr"])


def score_export(det, X):
    """Scores of rows X under an exported detector (same values as the fitted model)."""
    Z = _scaled(det, X)
    if det["kind"] == "knn":
        T = np.asarray(det["train"], dtype=np.float64)
        d2 = ((Z[:, None, :] - T[None, :, :]) ** 2).sum(axis=2)
        k = det["k"]
        return np.sqrt(np.partition(d2, k - 1, axis=1)[:, k - 1])
    if det["kind"] == "ocsvm":
        S = np.asarray(det["support_vectors"], dtype=np.float64)
        d2 = ((Z[:, None, :] - S[None, :, :]) ** 2).sum(axis=2)
        return -(np.exp(-det["gamma"] * d2) @ np.asarray(det["dual_coef"], dtype=np.float64))
    raise ValueError(f"unknown detector kind {det['kind']!r}")


class RankMix:
    """Mean over detectors of each score's empirical rank among that detector's
    scores of the reference (training) rows: rank = fraction of reference scores <= s."""

    def __init__(self, references):
        self.refs = {k: np.sort(np.asarray(v, dtype=np.float64)) for k, v in references.items()}

    def score(self, scores):
        """scores: {detector: array}, the same keys as the references."""
        ranks = [np.searchsorted(self.refs[k], np.asarray(scores[k], dtype=np.float64), side="right")
                 / len(self.refs[k]) for k in sorted(self.refs)]
        return np.mean(ranks, axis=0)
