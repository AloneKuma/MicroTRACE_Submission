"""Isolation Forest path for agents B, G and H (design-spec, "ML-assisted
detection"). One artifact per agent (IF_B, IF_G, IF_H) holds one forest per
ML type, each on that type's key, window and rulebook `ml.features`."""
import hashlib
import json

ARTIFACT_FORMAT = "microtrace-iforest.v0"
# A non-forest detector (detectors.export) for one or more types; a type it lists with
# replaces: iforest is scored by it instead of the agent's forest (ml-model-compare-plan).
DETECTOR_FORMAT = "microtrace-detector.v0"
ML_TYPES = {"B": ["B1", "B2", "B3"], "G": ["G1a"], "H": ["H1"]}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def model_version(artifact):
    body = {k: v for k, v in artifact.items() if k != "model_version"}
    prefix = "DET" if artifact.get("format") == DETECTOR_FORMAT else "IF"
    return "%s_%s@sha256:%s" % (prefix, artifact["agent"],
                                hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()[:16])
