"""OR-with-provenance combination of a predicate and the Isolation Forest path.

design-spec, "ML-assisted detection": a type fires when its predicate holds or
its anomaly score reaches gamma; the finding records which path fired. The
score is never a witness. With ML off (No-ML ablation), no model for the type,
or an entity in cold start, only the predicate decides.

Veto mode (ml.veto {type: cut}, usually with ml.or_path false): a predicate
finding whose window is scored below the cut is dropped. It fails open: with no
score (cold start, no model, ML off) the predicate stands.
"""


class Decision:
    __slots__ = ("fire", "path", "status", "score", "model_version")

    def __init__(self, fire, path, status, score=None, model_version=None):
        self.fire, self.path, self.status = fire, path, status
        self.score, self.model_version = score, model_version

    def apply(self, spec):
        spec.detection_path = self.path
        spec.ml_status = self.status
        spec.anomaly_score = self.score
        spec.model_version = self.model_version
        return spec

    def features(self, features):
        features = dict(features)
        features["ml_status"] = self.status
        if self.score is not None:
            features["anomaly_score"] = f"{self.score:.6f}"
            features["model_version"] = self.model_version
        return features


def decide(ctx, type_id, entity, features, predicate):
    """features: {name: number} in the rulebook `ml.features` order."""
    params = ctx.params
    if not params.ml_enabled or ctx.scorer is None:
        return Decision(predicate, "PREDICATE" if predicate else "DETECTION_PATH_UNSPECIFIED", "ML_DISABLED")
    status, score, version = ctx.scorer.score(type_id, entity, features)
    if status != "ML_SCORED":
        return Decision(predicate, "PREDICATE" if predicate else "DETECTION_PATH_UNSPECIFIED", status)
    if predicate and type_id in params.veto and score < params.veto[type_id]:
        predicate = False                         # vetoed: the window scores as normal
    ml = params.ml_or and score >= params.gamma[type_id]
    path ="BOTH" if predicate and ml else "PREDICATE" if predicate else "ML" if ml else "DETECTION_PATH_UNSPECIFIED"
    return Decision(predicate or ml, path, "ML_SCORED", score, version)
