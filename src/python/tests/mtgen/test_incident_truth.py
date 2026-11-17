"""Incident truth (exp2-gaps-plan B1): each scenario execution's actions
grouped into incidents, written next to the other restricted truth, and
checked by verify's incidents check."""
import pytest

import mtgen  # noqa: F401 — registers gen/ on sys.path
from mtgen import specs
from mtgen.scenarios import is_attack_scenario
from mtgen.truth import TruthWriter
from mtgen.verify import check_incidents
from microtrace.v0 import dataset_pb2


@pytest.fixture(scope="module")
def catalogue():
    return specs.load_scenario_catalogue()


def _incidents(catalogue, scenario):
    writer = TruthWriter("r1", specs.load_evidence_rendering(), catalogue)
    step_map = {str(st["step"]): i + 1 for i, st in enumerate(scenario["steps"])}
    return writer._build_incidents([(scenario["id"], "v1", step_map)]), step_map


def test_every_catalogue_link_respects_its_scenarios_incidents(catalogue):
    # verify's rule applied to the catalogue as declared: a PRESENT link stays
    # inside one incident; an ABSENT link inside one incident needs a linked
    # path between its actions (otherwise the two are separate activities).
    for sc in catalogue["scenarios"]:
        incs, step_map = _incidents(catalogue, sc)
        actions = [dataset_pb2.GroundTruthAction(action_seq=seq) for seq in step_map.values()]
        links = [dataset_pb2.ActionLink(link_id=f"{sc['id']}:{lk['from']}->{lk['to']}",
                                        from_action_seq=step_map[str(lk["from"])],
                                        to_action_seq=step_map[str(lk["to"])],
                                        expected_state=getattr(dataset_pb2, lk.get("expected", "PRESENT")))
                 for lk in sc.get("links", [])]
        result = check_incidents(actions, links, incs)
        assert result.ok, (sc["id"], result.failures)


def test_decoys_form_their_own_incident_and_a_present_link_merges_groups(catalogue):
    sc = next(s for s in catalogue["scenarios"] if s["id"] == "chain_token_theft_exfil")
    incs, step_map = _incidents(catalogue, sc)
    label = {seq: lbl for lbl, seq in step_map.items()}
    groups = {frozenset(label[s] for s in i.action_seqs): i.is_attack for i in incs}
    attack = [g for g, a in groups.items() if a]
    assert len(attack) == 1 and {"1", "3", "9", "10"} <= attack[0]
    assert frozenset({"19", "20", "21"}) in groups                    # decoy2 float group
    # the health check's own flows (16 -> 18 same socket) and its connect 11
    # (11 -> 18 benign continuity, review fix A) join its decoy group
    assert frozenset({"4", "8", "11", "16", "18"}) in groups


def test_degraded_attacks_are_attacks_and_their_decoys_are_not(catalogue):
    # T-1 (2026-11-02): a degraded scenario is an attack with lost evidence.
    sc = next(s for s in catalogue["scenarios"] if s["id"] == "chain_exfil_first_unobserved")
    incs, step_map = _incidents(catalogue, sc)
    benign = {str(st["step"]) for st in sc["steps"] if st.get("benign")}
    label = {seq: lbl for lbl, seq in step_map.items()}
    for i in incs:
        assert i.is_attack == any(label[s] not in benign for s in i.action_seqs)
    assert any(i.is_attack for i in incs)


def test_attack_scenario_kinds(catalogue):
    by_id = {s["id"]: s for s in catalogue["scenarios"]}
    assert is_attack_scenario(by_id["a1_blocked_by_waf"])
    assert not is_attack_scenario(by_id["b2_auth_failure_below_threshold"])
    assert not is_attack_scenario(by_id["g2_exec_session_ambiguous"])
    for s in catalogue["scenarios"]:
        if s["kind"] in ("lookalike", "nonlink", "benign_workload", "admin"):
            assert not is_attack_scenario(s), s["id"]
        if s["kind"] == "attack":
            assert is_attack_scenario(s), s["id"]


def test_verify_flags_a_present_link_across_incidents_and_a_missing_file():
    acts = [dataset_pb2.GroundTruthAction(action_seq=s) for s in (1, 2)]
    lk = dataset_pb2.ActionLink(link_id="L", from_action_seq=1, to_action_seq=2,
                                expected_state=dataset_pb2.PRESENT)
    split = [dataset_pb2.GroundTruthIncident(incident_id="a", action_seqs=[1]),
             dataset_pb2.GroundTruthIncident(incident_id="b", action_seqs=[2])]
    assert not check_incidents(acts, [lk], split).ok
    assert not check_incidents(acts, [lk], None).ok
