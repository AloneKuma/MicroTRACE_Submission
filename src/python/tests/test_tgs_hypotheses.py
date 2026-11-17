"""TGS build step 6c: the template library, template selection, gap
reports, and hypotheses (tgs-contract.md section 5)."""
import os
import shutil

import agent_fixtures as F
import pytest
from microtrace.v0 import envelope_pb2

import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.tgs import apply as A
from mtcore.tgs import templates as TP
from mtcore.tgs.hashes import graph_hash
from mtcore.tgs.hypotheses import ANALYST, GO, generate

LIB = TP.load_templates()
RB = TP.load_rulebook()


def fnd(fid, ftype):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("FINDING"), logical_id=fid)
    f = env.finding
    f.finding_id, f.finding_type = fid, ftype
    f.event_start.CopyFrom(F.ts(1))
    return env


def incident_of(store, iid, members, speculative=()):
    env = TS.inc(iid, members=tuple(f for f, _t in members))
    env.incident.event_start.CopyFrom(F.ts(1))
    env.incident.event_end.CopyFrom(F.ts(60))
    for a, b, w in speculative:
        env.incident.speculative_paths.add(path_id=f"pt-{a}-{b}", finding_ids=[a, b], witness_ids=[w])
    A.apply_batch(store, [(T.FND, 0, k, fnd(f, t)) for k, (f, t) in enumerate(members)])
    A.apply_batch(store, [(T.INC, 0, 0, env)])
    return env


# --- library ---------------------------------------------------------------------------
def test_the_template_library_is_valid_and_its_hash_is_stable():
    assert TP.check_library() == []
    assert {t.id for t in LIB} == {"chain-1-token-pivot", "chain-2-escape-exfil", "chain-3-implant"}
    assert TP.library_hash(LIB) == TP.library_hash(list(reversed(LIB)))


@pytest.mark.parametrize("bad, problem", [
    ("{id: s, finding_types: [D1], tactic: DISCOVERY, required: true}", "rulebook maps D1 to CREDENTIAL_ACCESS"),
    ("{id: s, finding_types: [Z9], tactic: null, required: true}", "Z9 is not in the rulebook"),
    ("{id: s, finding_types: [D1], tactic: CREDENTIAL_ACCESS, required: true, pod_uid: x}", "instance fields"),
    ("{id: s, finding_types: [D1], tactic: CREDENTIAL_ACCESS, required: false}", "no required stage"),
])
def test_the_checker_rejects_bad_templates(tmp_path, bad, problem):
    shutil.copy(os.path.join(TP.TEMPLATE_DIR, "chain-1-token-pivot.yaml"), tmp_path)
    (tmp_path / "bad.yaml").write_text(f"template_version: tgs-template.v0\nid: bad\nstages:\n  - {bad}\n",
                                       encoding="utf-8")
    problems = TP.check_library(str(tmp_path), RB)
    assert any(problem in p for p in problems) and all(p.startswith("bad.yaml") for p in problems)


def test_the_checker_rejects_an_instance_value(tmp_path):
    (tmp_path / "t.yaml").write_text("template_version: tgs-template.v0\nid: t\nbasis: 2026-10-10T00:00:00Z\n"
                                     "stages:\n  - {id: s, finding_types: [D1], tactic: CREDENTIAL_ACCESS, "
                                     "required: true}\n", encoding="utf-8")
    assert any("instance value" in p for p in TP.check_library(str(tmp_path), RB))


# --- selection -------------------------------------------------------------------------
@pytest.mark.parametrize("types, want", [
    (["D1", "B1"], "chain-1-token-pivot"),          # every required stage
    (["D1"], "chain-1-token-pivot"),                # half of chain 1, nothing elsewhere
    (["A2", "E3"], "chain-3-implant"),              # 1/3 of chain 2 against 1/2 of chain 3
    (["D1", "E3"], None),                           # 1/2 against 1/2: a tie is not a fit
    (["A2"], None),                                 # 1/3 is below the threshold 0.5
    (["E1", "E2"], None),                           # unmapped evidence covers no required stage
])
def test_selection_uses_observed_finding_types_only(types, want):
    t, _scores, reason = TP.select(LIB, types, 0.5)
    assert (t.id if t else None) == want, reason


# --- gap reports and hypotheses --------------------------------------------------------
def test_a_gap_report_names_candidates_and_never_assumes_a_source_healthy(store):
    idle = F.loss(10, 20, source="AUDIT", reason="SOURCE_IDLE")[1]
    A.apply_batch(store, [("source.completeness.v0", 0, 0, idle)])
    env = incident_of(store, "in-1", [("f1", "D1")])
    rep = generate(store, "in-1", LIB, 0.5, RB)
    assert rep["template"] == "chain-1-token-pivot" and rep["record_sha256"] == A.sha256(env.incident)
    gaps = {g["stage"]: g for g in rep["gaps"]}
    assert set(gaps) == {"api-enumeration", "rbac-grant", "cross-workload-access"}
    assert gaps["api-enumeration"]["required"] and gaps["api-enumeration"]["finding_types"] == ["B1"]
    assert gaps["api-enumeration"]["sources"]["AUDIT"]["status"] == TP.IDLE
    assert gaps["cross-workload-access"]["sources"]["EBPF"]["status"] == TP.UNKNOWN   # no record: unknown


def test_hypotheses_are_written_once_and_never_change_the_graph(store):
    incident_of(store, "in-1", [("f1", "D1"), ("f3", "G1b")])
    before = graph_hash(store), store.rows("edges")
    rep = generate(store, "in-1", LIB, 0.5, RB)
    hyps = {h["stage_id"]: h for h in store.rows("hypotheses") if h["origin"] == ANALYST}
    assert set(hyps) == {"api-enumeration", "rbac-grant"}
    assert len(rep["hypotheses"]) == 2
    edges = [(e["src"], e["dst"]) for e in store.rows("hypothesis_edges") if e["hyp_id"] == hyps["api-enumeration"]["hyp_id"]]
    ph = "stage:chain-1-token-pivot/api-enumeration"
    assert edges and all(ph in pair for pair in edges)       # between f1's stage and the next covered one (f3)
    assert graph_hash(store) == before[0] and store.rows("edges") == before[1]   # P4: no graph change
    generate(store, "in-1", LIB, 0.5, RB)
    assert len([h for h in store.rows("hypotheses") if h["origin"] == ANALYST]) == 2


def test_no_template_fits_means_no_gap_report_and_no_hypotheses(store):
    incident_of(store, "in-1", [("f1", "D1"), ("f2", "E3")])
    rep = generate(store, "in-1", LIB, 0.5, RB)
    assert rep["template"] is None and "tie" in rep["reason"] and rep["gaps"] == []
    assert store.rows("hypotheses") == []
    assert generate(store, "in-unknown", LIB, 0.5, RB) is None


def test_go_speculative_paths_become_go_hypotheses_at_ingest(store):
    incident_of(store, "in-1", [("f1", "E1"), ("f2", "E2")], speculative=[("f1", "f2", "wt-en")])
    [h] = store.rows("hypotheses")
    assert h["origin"] == GO and h["detail"]["witness_ids"] == ["wt-en"]
    [e] = store.rows("hypothesis_edges")
    assert e["label"] == "wt-en" and e["origin"] == GO
    assert all(x["edge_type"] != "HYPOTHESIS" for x in store.rows("edges"))   # never in the graph's edges


def test_source_completeness_status_rules(store):
    recs = [F.loss(1, 5, source="GATEWAY")[1], F.loss(1, 5, source="AUDIT", reason="SOURCE_IDLE")[1]]
    clean = F.loss(1, 5, source="KYVERNO")[1]
    clean.source_completeness.ClearField("gaps")
    clean.source_completeness.status = 1      # NO_KNOWN_GAP
    A.apply_batch(store, [("source.completeness.v0", 0, k, e) for k, e in enumerate(recs + [clean])])
    lo, hi = F.ns(2), F.ns(3)
    assert TP.source_status(store, "GATEWAY", lo, hi)[0] == TP.LOSSY
    assert TP.source_status(store, "AUDIT", lo, hi)[0] == TP.IDLE
    assert TP.source_status(store, "KYVERNO", lo, hi)[0] == TP.AVAILABLE
    assert TP.source_status(store, "EBPF", lo, hi)[0] == TP.UNKNOWN
    assert TP.source_status(store, "GATEWAY", F.ns(6), F.ns(7))[0] == TP.UNKNOWN   # outside the record
