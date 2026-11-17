"""Parameter sets and declared artifacts for the agents.

A parameter set (src/params/*.yaml) holds windows, thresholds, gates, ML
settings, reporting values and the declared artifacts the rulebook names
(P_A, E_D1, Q_G1a, ...). Each artifact is versioned by the SHA-256 of its
canonical JSON, and that version is recorded on every finding that uses it.
"""
import hashlib
import json
import os

import yaml

from mtcore import REPO

DEV_PARAMS = os.path.join(REPO, "src", "params", "dev.v0.yaml")
NS = 1_000_000_000

# Artifacts that are baselines (Finding.baseline_version) rather than
# declared lists (Finding.artifact_versions).
BASELINES = {"Q_B1", "Q_B3", "Q_G1a", "Q_H1", "Q_H2"}


def artifact_version(name, value):
    canon = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{name}@sha256:{hashlib.sha256(canon.encode('utf-8')).hexdigest()[:16]}"


class Params:
    def __init__(self, data, source="<dict>"):
        self.data = data
        self.source = source
        self.version = data["parameter_set_version"]
        self.lateness_ns = int(data.get("lateness_s", 0) * NS)
        self.artifacts = data.get("artifacts") or {}
        self.versions = {k: artifact_version(k, v) for k, v in self.artifacts.items()}
        ml = data.get("ml") or {}
        self.ml_enabled = bool(ml.get("enabled", False))
        self.n_cold = int(ml.get("N_cold", 0))
        self.gamma = dict(ml.get("gamma") or {})
        self.forest = dict(ml.get("forest") or {})
        # a relative model path is read from the parameter file's folder, so a
        # frozen set and its models can travel together
        base = os.path.dirname(os.path.abspath(source)) if source != "<dict>" else None
        self.models = {a: (os.path.normpath(os.path.join(base, p)) if base and not os.path.isabs(p) else p)
                       for a, p in (ml.get("models") or {}).items()}
        # or_path false: the anomaly score never adds a finding on its own.
        # veto {type: cut}: a predicate finding of that type whose window is
        # scored below the cut is dropped (fail-open on cold start / no model).
        self.ml_or = bool(ml.get("or_path", True))
        self.veto = {k: float(v) for k, v in (ml.get("veto") or {}).items()}

    @classmethod
    def load(cls, path=DEV_PARAMS):
        with open(path, encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh), path)

    def window_ns(self, symbol):
        return int(self.data["windows_s"][symbol] * NS)

    def threshold(self, symbol):
        return self.data["thresholds"][symbol]

    def gate(self, symbol):
        return bool((self.data.get("gates") or {}).get(symbol, False))

    def shipped_sources(self):
        """node ID (or "default") -> set of Source values its shipper carries,
        or None when the parameter set declares none."""
        from microtrace.v0 import common_pb2
        decl = self.data.get("shipped_sources")
        if decl is None:
            return None
        return {node: {common_pb2.Source.Value(s) for s in srcs} for node, srcs in decl.items()}

    def artifact(self, name):
        return self.artifacts[name]

    def reporting(self, finding_type):
        rep = self.data.get("reporting") or {}
        base = dict(rep.get("default") or {"severity": "MEDIUM", "confidence": 0.5})
        base.update((rep.get("overrides") or {}).get(finding_type, {}))
        return base["severity"], float(base["confidence"])

    def with_overrides(self, **changes):
        """A copy with top-level sections updated (tests and ablations)."""
        data = json.loads(json.dumps(self.data))
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(data.get(key), dict):
                data[key].update(value)
            else:
                data[key] = value
        return Params(data, self.source)
