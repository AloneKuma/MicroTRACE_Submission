"""Loads frozen model artifacts and scores feature vectors for mlpath.decide."""
import json

from mtcore.agents.ml import ARTIFACT_FORMAT, DETECTOR_FORMAT, model_version
from mtcore.agents.ml import iforest


class Scorer:
    def __init__(self, artifacts, n_cold):
        self.by_type = {}
        self.n_cold = n_cold
        forests, dets = {}, {}
        for art in artifacts:
            fmt = art.get("format")
            if fmt not in (ARTIFACT_FORMAT, DETECTOR_FORMAT):
                raise ValueError(f"unknown model artifact format {fmt!r}")
            if art.get("model_version") != model_version(art):
                raise ValueError(f"model artifact {art.get('agent')} fails its content hash")
            into = forests if fmt == ARTIFACT_FORMAT else dets
            for type_id, m in art["types"].items():
                if type_id in into:
                    raise ValueError(f"two {fmt} artifacts score {type_id}")
                into[type_id] = (m, art["model_version"])
        for type_id, (m, v) in dets.items():
            # a detector takes a type from the forest only when it says so
            if type_id in forests and m.get("replaces") != "iforest":
                raise ValueError(f"detector for {type_id} does not declare replaces: iforest")
        self.by_type = {**forests, **dets}

    @classmethod
    def load(cls, params):
        arts = []
        for _agent, path in sorted(params.models.items()):
            with open(path, encoding="utf-8") as fh:
                arts.append(json.load(fh))
        return cls(arts, params.n_cold)

    def score(self, type_id, entity, features):
        """(ml_status, score or None, model_version or None)."""
        if type_id not in self.by_type:
            return "ML_COLD_START", None, None
        m, version = self.by_type[type_id]
        # cold_start "none" (B2): every key is scored; an attacking source is
        # new by definition, so a per-source gate would never score one.
        if m.get("cold_start", "N_cold") != "none" and m["entities"].get(entity or "", 0) < self.n_cold:
            return "ML_COLD_START", None, version
        if "detector" in m:
            from mtcore.agents.ml import detectors
            x = [[float(features[n]) for n in m["features"]]]
            return "ML_SCORED", float(detectors.score_export(m["detector"], x)[0]), version
        return "ML_SCORED", float(iforest.score(m["forest"], iforest.vector(m["forest"], features))[0]), version


class Recorder:
    """Collects (type, entity, features) during a training pass; never scores,
    so only predicates decide while features are extracted."""

    def __init__(self):
        self.rows = []

    def score(self, type_id, entity, features):
        self.rows.append((type_id, entity or "", dict(features)))
        return "ML_COLD_START", None, None
