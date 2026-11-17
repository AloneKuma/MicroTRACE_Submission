"""Train the per-agent Isolation Forest artifacts from PILOT/RESEARCH data.

    python -m mtcore.agents.ml.train --params src/params/dev.v0.yaml \
        --input pilot.jsonl [--input more.jsonl] --out-dir models/ [--agents B,G,H]

Input lines use the shipper's format ({"topic", "envelope"}, envelope as
Protobuf JSON); normalized events are routed to agent topics as the
restreamer would. Features come from running the same rules over the data,
so training and scoring see identical feature definitions. Any record from a
HELD_OUT (or unlabelled) split stops training: models are fitted on
chronologically earlier development data only (paper, Phase 2).
"""
import argparse
import hashlib
import json
import os
import sys

import numpy as np

from mtcore.agents.engine import Engine
from mtcore.agents.events import Ev
from mtcore.agents.ml import ARTIFACT_FORMAT, ML_TYPES, canonical, iforest, model_version
from mtcore.agents.ml.scorer import Recorder
from mtcore.agents.params import Params
from mtcore.agents import routing
from mtcore.agents.rules import for_agents
from microtrace.v0 import dataset_pb2, envelope_pb2
from google.protobuf import json_format

ALLOWED_SPLITS = {dataset_pb2.DataSplit.Value("PILOT"), dataset_pb2.DataSplit.Value("RESEARCH")}


class SplitError(ValueError):
    pass


def read_records(paths):
    """[(topic, Envelope)] in file order, with a manifest of the inputs."""
    records, manifest = [], []
    for path in paths:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for raw in fh:
                h.update(raw)
                line = raw.strip()
                if not line:
                    continue
                obj = json.loads(line)
                env = json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())
                records.append((obj["topic"], env))
        manifest.append({"file": os.path.basename(path), "sha256": h.hexdigest()})
    return records, manifest


def check_splits(records):
    for topic, env in records:
        if env.WhichOneof("payload") == "heartbeat":
            continue
        if env.run.split not in ALLOWED_SPLITS:
            raise SplitError(f"record {env.logical_id or '?'} on {topic} has split "
                             f"{dataset_pb2.DataSplit.Name(env.run.split)}; training uses PILOT/RESEARCH only")


def routed(records):
    out = []
    for topic, env in records:
        if topic == "norm.events.v0" and env.HasField("normalized_event"):
            out += [(t, env) for t, k in routing.routes(Ev(env)) if k is not None]
        else:
            out.append((topic, env))
    return out


def extract(records, params, agents):
    """Feature rows {type: [(entity, {feature: value})]} from a predicate pass."""
    rec = Recorder()
    p = params.with_overrides(ml={"enabled": True})
    eng = Engine(for_agents(agents), p, scorer=rec)
    for topic, env in routed(records):
        eng.feed(env, topic)
    eng.finish()
    rows = {}
    for type_id, entity, feats in rec.rows:
        rows.setdefault(type_id, []).append((entity, feats))
    return rows


def train(records, params, agents=("B", "G", "H"), manifest=None):
    check_splits(records)
    rows = extract(records, params, agents)
    return fit_forests(rows, params, agents, _interval(records), manifest)


def fit_forests(rows, params, agents=("B", "G", "H"), interval=None, manifest=None):
    """Artifacts {agent: dict} from feature rows {type: [(entity, {feature: value})]}
    (src/scripts/pilot/crossfit_ml.py passes rows extracted with scenario events removed)."""
    from sklearn import __version__ as sk_version
    from sklearn.ensemble import IsolationForest

    rulebook_ml = _rulebook_ml()
    artifacts = {}
    for agent in agents:
        types = {}
        for type_id in ML_TYPES[agent]:
            data = rows.get(type_id, [])
            if not data:
                continue
            names = rulebook_ml[type_id]["features"]
            X = np.array([[float(f[n]) for n in names] for _e, f in data])
            cfg = dict(params.forest)
            model = IsolationForest(n_estimators=cfg.get("n_estimators", 100),
                                    max_samples=min(cfg.get("max_samples", 256), len(X)),
                                    max_features=cfg.get("max_features", 1.0),
                                    bootstrap=cfg.get("bootstrap", False),
                                    random_state=cfg.get("random_state", 0)).fit(X)
            entities = {}
            for e, _f in data:
                entities[e] = entities.get(e, 0) + 1
            types[type_id] = {"forest": iforest.export(model, names), "entities": dict(sorted(entities.items())),
                              "cold_start": rulebook_ml[type_id].get("cold_start", "N_cold"),
                              "training_windows": len(X), "scaling": "none (splits are invariant to "
                                                                     "per-feature monotone scaling)"}
        art = {"format": ARTIFACT_FORMAT, "agent": agent, "types": types,
               "training_interval": interval or [],
               "forest_settings": params.forest, "parameter_set_version": params.version,
               "libraries": {"scikit-learn": sk_version, "numpy": np.__version__},
               "training_inputs": manifest or []}
        art["model_version"] = model_version(art)
        artifacts[agent] = art
    return artifacts


def _interval(records):
    """Event-time range of the training data (RFC 3339), so evaluation data
    can be checked to lie after it."""
    times = [env.normalized_event.time.event_time for _t, env in records if env.HasField("normalized_event")]
    if not times:
        return []
    ns = sorted(t.seconds * 10**9 + t.nanos for t in times)
    from mtcore.agents.emit import rfc3339
    return [rfc3339(ns[0]), rfc3339(ns[-1])]


def _rulebook_ml():
    """Each ML type's rulebook `ml` block (features, cold_start, ...)."""
    import yaml
    from mtcore import REPO
    with open(os.path.join(REPO, "spec", "rules", "rulebook.v0.yaml"), encoding="utf-8") as fh:
        rb = yaml.safe_load(fh)
    return {f["id"]: f["ml"] for f in rb["findings"] if f.get("ml")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--params", required=True)
    ap.add_argument("--input", action="append", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--agents", default="B,G,H")
    a = ap.parse_args(argv)
    params = Params.load(a.params)
    records, manifest = read_records(a.input)
    try:
        arts = train(records, params, a.agents.split(","), manifest)
    except SplitError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    os.makedirs(a.out_dir, exist_ok=True)
    for agent, art in arts.items():
        path = os.path.join(a.out_dir, f"IF_{agent}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(canonical(art))
        print(f"{path}: {art['model_version']} ({', '.join(art['types']) or 'no ML type had data'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
