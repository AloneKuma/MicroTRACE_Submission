"""ML model comparison (src/scripts/pilot/model_compare.py): measures, labels,
the G1a window join, the filter, and the step 1 / step 2 rules."""
import gzip
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

_DIR = Path(__file__).resolve().parents[2] / "scripts" / "pilot"
sys.path.insert(0, str(_DIR))
_spec = importlib.util.spec_from_file_location("model_compare", _DIR / "model_compare.py")
mc = importlib.util.module_from_spec(_spec)
sys.modules["model_compare"] = mc                  # worker processes pickle its functions
_spec.loader.exec_module(mc)


def test_average_precision_and_roc_equal_sklearn():
    m = pytest.importorskip("sklearn.metrics")
    rng = np.random.default_rng(3)
    for _ in range(20):
        y = rng.integers(0, 2, size=60).astype(bool)
        s = rng.integers(0, 8, size=60).astype(float)            # many ties
        if y.all() or not y.any():
            continue
        assert mc.average_precision(y, s) == pytest.approx(m.average_precision_score(y, s))
        assert mc.roc_auc(y, s) == pytest.approx(m.roc_auc_score(y, s))
    assert mc.average_precision([True, True], [1, 2]) is None


def test_labels_are_three_way():
    from mtcore.harness import score as S          # sets the import path of the generated code
    from microtrace.v0 import dataset_pb2
    opp = dataset_pb2.FindingOpportunity
    truth = S.Truth([], [opp(opportunity_id="p", finding_type="B1", evidence_event_ids=["e1"], expected_state=S.PRESENT),
                         opp(opportunity_id="u", finding_type="B1", evidence_event_ids=["e2"],
                             expected_state=S.UNOBSERVABLE),
                         opp(opportunity_id="a", finding_type="B1", evidence_event_ids=["e3"], expected_state=S.ABSENT)],
                    [])
    lab = mc.make_label(truth)
    assert lab("B1", ["e1", "e2"]) == "true"          # PRESENT wins
    assert lab("B1", ["e2", "e3"]) == "unobs"
    assert lab("B1", ["e3"]) == "false"
    assert lab("B1", ["zz"]) == "false"               # background
    assert lab("B3", ["e1"]) == "false"               # other type's evidence does not count


def _line(topic, rec):
    return json.dumps({"topic": topic, "record": rec}) + "\n"


def _write_run(tmp_path, lines):
    d = tmp_path / "raw" / "runs" / "r1"
    d.mkdir(parents=True)
    with gzip.open(d / "output.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.writelines(lines)
    return tmp_path / "raw"


def test_table_joins_features_and_g1a_windows(tmp_path, monkeypatch):
    names, _ = mc.feature_names()
    b3 = {n: str(i + 1) for i, n in enumerate(names["B3"])}
    g = {n: "2" for n in names["G1a"]}
    lines = [
        _line("findings.v0", {"findingId": "fB", "findingType": "B3", "inputEventIds": ["e1"],
                              "mlStatus": "ML_SCORED", "anomalyScore": 0.71}),
        _line("rule.evaluations.v0", {"ruleId": "B3", "findingId": "fB", "stateKeyHex": "k",
                                      "windowStart": "2026-01-01T00:00:00Z", "windowEnd": "2026-01-01T00:01:00Z",
                                      "features": {**b3, "ml_status": "ML_SCORED", "anomaly_score": "0.710000"}}),
        _line("findings.v0", {"findingId": "fG", "findingType": "G1a", "inputEventIds": ["e9"],
                              "mlStatus": "ML_DISABLED"}),
        _line("rule.evaluations.v0", {"ruleId": "G1a", "findingId": "fG", "stateKeyHex": "pod",
                                      "windowStart": "2026-01-01T00:00:30Z", "windowEnd": "2026-01-01T00:00:30Z",
                                      "features": {"edge": "a->b:80"}}),
        _line("rule.evaluations.v0", {"ruleId": "G1a", "stateKeyHex": "pod",
                                      "windowStart": "2026-01-01T00:00:00Z", "windowEnd": "2026-01-01T00:01:00Z",
                                      "features": {**g, "ml_status": "ML_SCORED", "anomaly_score": "0.650000",
                                                   "covered_by_predicate": "true"}}),
        _line("findings.v0", {"findingId": "fC", "findingType": "C1b", "inputEventIds": ["e5"]}),
    ]
    raw = _write_run(tmp_path, lines)
    monkeypatch.setattr(mc, "labeller", lambda _d: (lambda t, ev: "true" if "e1" in ev else "false"))
    out = tmp_path / "r1.jsonl"
    run, msg = mc.table_run(("r1", "A", str(raw), str(tmp_path), str(out)))
    rows = {r["fid"]: r for r in map(json.loads, out.read_text().splitlines())}
    assert set(rows) == {"fB", "fG"}                  # C1b is not an ML type
    assert rows["fB"]["x"] == [float(i + 1) for i in range(len(names["B3"]))]
    assert rows["fB"]["label"] == "true" and rows["fB"]["if_score"] == pytest.approx(0.71)
    assert rows["fG"]["status"] == "ML_SCORED" and rows["fG"]["if_score"] == pytest.approx(0.65)
    assert rows["fG"]["finding_score"] is None and rows["fG"]["x"] == [2.0] * len(names["G1a"])


def test_filter_drops_only_named_findings(tmp_path):
    lines = [_line("findings.v0", {"findingId": f"f{i}", "findingType": "B3"}) for i in range(4)]
    lines.append(_line("rule.evaluations.v0", {"ruleId": "B3", "findingId": "f1"}))
    raw = _write_run(tmp_path, lines)
    dst = tmp_path / "r1.output.jsonl.gz"
    run, msg = mc.filter_run(("r1", str(raw / "runs" / "r1" / "output.jsonl.gz"), str(dst), {"f1", "f3"}))
    kept = [json.loads(x) for x in gzip.open(dst, "rt").read().splitlines()]
    assert [k["record"]["findingId"] for k in kept if k["topic"] == "findings.v0"] == ["f0", "f2"]
    assert any(k["topic"] == "rule.evaluations.v0" for k in kept)       # evaluations stay
    run, msg = mc.filter_run(("r1", str(raw / "runs" / "r1" / "output.jsonl.gz"), str(tmp_path / "x.gz"), {"nope"}))
    assert msg.startswith("FAILED")


def _arm(ap_a, ap_b, lost=0):
    return {F: {"pr_auc": v, "true_lost": lost, "false_removed": 0, "mcc": None} for F, v in (("A", ap_a), ("B", ap_b))}


def test_select1_rule(tmp_path):
    arms = {a: _arm(0.50, 0.50) for a in mc.ARMS}
    arms["ecod"] = _arm(0.60, 0.58)                   # passes
    arms["knn"] = _arm(0.70, 0.54)                    # fold B gain < 0.05
    arms["mix_all"] = _arm(0.60, 0.58)                # ties ecod; single wins
    arms["lof"] = _arm(0.70, 0.70, lost=5)            # loses more true findings
    boot = {a: {"lo": 0.01} for a in mc.ARMS if a != "iforest"}
    comp = {"rule_sha": "x", "types": {"B1": {"testable": True, "arms": arms, "bootstrap": boot},
                                       "B2": {"testable": False}}}
    (tmp_path / "compare.json").write_text(json.dumps(comp))
    (tmp_path / "drops.json").write_text(json.dumps({a: {"B1": {"A": ["x@r"], "B": []}} for a in mc.ARMS}))
    (tmp_path / "frozen.json").write_text(json.dumps({"B3": ["b@r"]}))
    ns = type("NS", (), {"compare": str(tmp_path / "compare.json"), "out": str(tmp_path / "step1.json"),
                         "frozen_drops": str(tmp_path / "frozen.json")})
    mc.st_select1(ns)
    s = json.loads((tmp_path / "step1.json").read_text())
    assert s["candidates"] == {"B1": "ecod"}
    assert s["types"]["B2"]["verdict"] == "NOT TESTABLE"
    assert set(s["configs"]) == {"none", "frozen", "cand_B1_ecod"}
    d = json.loads((tmp_path / "dropsets.json").read_text())
    assert d["none"] == [] and d["frozen"] == ["b@r"] and d["cand_B1_ecod"] == ["b@r", "x@r"]


def test_select2_rule(tmp_path):
    runs = [f"r{i}" for i in range(30)] + [mc.LARGE]

    def write(cfg, fp):
        for r in runs:
            d = tmp_path / "s2" / cfg / "runs" / r
            d.mkdir(parents=True)
            (d / "score.json").write_text(json.dumps({"findings": {"overall": {"tp": 5, "fp": fp, "fn": 1}},
                                                      "links": {"tp": 3, "fp": 2, "fn": 4}}))
    write("frozen", 10)
    write("cand_B1_ecod", 8)                          # 20% fewer false findings, tp and links equal
    write("cand_H1_knn", 10)
    (tmp_path / "split.json").write_text(json.dumps({"all": runs}))
    (tmp_path / "step1.json").write_text(json.dumps({"configs": {"none": {}, "frozen": {}, "cand_B1_ecod": {},
                                                                 "cand_H1_knn": {}}}))
    ns = type("NS", (), {"step1": str(tmp_path / "step1.json"), "step2_dir": str(tmp_path / "s2"),
                         "runs": str(tmp_path / "split.json") + ":all", "out": str(tmp_path / "step2.json")})
    mc.st_select2(ns)
    s = json.loads((tmp_path / "step2.json").read_text())
    assert s["configs"]["cand_B1_ecod"]["adopt_worthy"] is True
    assert s["configs"]["cand_H1_knn"]["adopt_worthy"] is False


def test_compare_end_to_end_synthetic(tmp_path):
    """Two folds of B3 rows: attacks are extreme in the first feature. Every arm is
    fitted, the Isolation Forest gate holds, and the measures and drops are written."""
    pytest.importorskip("sklearn")
    from sklearn.ensemble import IsolationForest
    from mtcore.agents.ml import iforest
    names, _ = mc.feature_names()
    feats = names["B3"]
    rng = np.random.default_rng(7)
    pilot, rows, models, table = (tmp_path / d for d in ("pilot", "rows", "models", "table"))
    folds = {"A": [f"a{i}" for i in range(10)], "B": [f"b{i}" for i in range(10)]}
    for r in folds["A"] + folds["B"]:
        (pilot / r).mkdir(parents=True)
        (pilot / r / "manifest.json").write_text(json.dumps({"world_name": "w", "observability_profile": "p"}))
    table.mkdir()
    other = {"A": "B", "B": "A"}

    def benign(n):
        return rng.poisson(5, size=(n, len(feats))).astype(float)

    for F in "AB":
        (rows / f"fold{F}-max").mkdir(parents=True)
        train = folds[other[F]]
        for r in train:
            X = benign(30)
            (rows / f"fold{F}-max" / f"{r}.json").write_text(json.dumps(
                {"rows": [["B3", "ent", dict(zip(feats, x.tolist()))] for x in X]}))
        Xall = np.vstack([[[float(v) for v in row[2].values()] for row in
                           json.load(open(rows / f"fold{F}-max" / f"{r}.json"))["rows"]] for r in train])
        m = IsolationForest(n_estimators=20, max_samples=64, random_state=0).fit(Xall)
        art = {"types": {"B3": {"forest": iforest.export(m, feats)}}}
        (models / f"fold{F}-max").mkdir(parents=True)
        (models / f"fold{F}-max" / "IF_B.json").write_text(json.dumps(art))
        (models / f"fold{F}-max" / "train.json").write_text(json.dumps({"gamma": {}}))
        for r in folds[F]:
            recs = []
            for j in range(6):
                atk = j < 3
                x = benign(1)[0]
                if atk:
                    x[0] += 40
                recs.append({"run": r, "fold": F, "type": "B3", "fid": f"{r}-{j}", "label": "true" if atk else "false",
                             "status": "ML_SCORED", "x": x.tolist(), "finding_score": None,
                             "if_score": float(iforest.score(art["types"]["B3"]["forest"], x[None, :])[0])})
            (table / f"{r}.jsonl").write_text("".join(json.dumps(x) + "\n" for x in recs))
    (tmp_path / "folds.json").write_text(json.dumps(folds))
    ns = type("NS", (), {"pilot": str(pilot), "table": str(table), "rows": str(rows), "models": str(models),
                         "folds": str(tmp_path / "folds.json"), "out_dir": str(tmp_path / "out"),
                         "rule_sha": "test", "workers": 2})
    old = mc.DRAWS
    mc.DRAWS = 50
    try:
        assert mc.st_compare(ns) == 0
    finally:
        mc.DRAWS = old
    c = json.loads((tmp_path / "out" / "compare.json").read_text())
    T = c["types"]["B3"]
    assert T["testable"] and T["folds"]["A"]["n_true"] == 30 and T["folds"]["A"]["alpha"] == 0.01
    for arm in mc.ARMS:
        # every arm ranks the extreme ones high; HBOS least (alpha 0.1 caps the far tail)
        assert min(T["arms"][arm][F]["pr_auc"] for F in "AB") > 0.75
    assert len(T["arms"]["mix_best3"]["A"]["members"]) == 3
    assert set(T["bootstrap"]) == set(mc.ARMS) - {"iforest"}
    assert c["types"]["B1"] == {"testable": False, "why": "no training rows"}
    drops = json.loads((tmp_path / "out" / "drops.json").read_text())
    assert set(drops) == set(mc.ARMS) and set(drops["ecod"]["B3"]) == {"A", "B"}
