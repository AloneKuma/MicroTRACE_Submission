"""twin_safety.py: findings on scenario steps without an opportunity
(link-twin-decoys-plan.md phase D, twin-safety-labels-plan.md)."""
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import yaml

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "src" / "scripts" / "pilot"))

import twin_safety as ts  # noqa: E402


def _action(seq, sid, step, events, attack=False):
    return NS(action_seq=seq, scenario_id=sid, step_label=str(step),
              rendered_event_ids=events, is_attack=attack)


def _finding(fid, ftype, events):
    return NS(finding_id=fid, finding_type=ftype, input_event_ids=events)


ACTIONS = [_action(1, "admin_scheduled_job", 1, ["e1"]),
           _action(2, "h3_external_bulk_enumeration", 5, ["e2"], attack=True)]
OPPS = [NS(finding_type="H3", evidence_event_ids=["e2"])]


def test_finding_without_an_opportunity_of_its_type_is_reported():
    findings = [_finding("f1", "B1", ["e1", "bg"]),   # benign step, no B1 opportunity
                _finding("f2", "H3", ["e2"]),         # covered
                _finding("f3", "B1", ["e2"]),         # H3 opportunity only: wrong type
                _finding("f4", "B1", ["bg"])]         # background only: not this check's
    bad = ts.unlabelled(ACTIONS, OPPS, findings, "run-1")
    assert [b["finding_id"] for b in bad] == ["f1", "f3"]
    assert bad[0]["steps"] == ["admin_scheduled_job/1 (benign)"]
    assert bad[1]["steps"] == ["h3_external_bulk_enumeration/5"]


def test_catalogue_declaration_counts_before_a_rebuild():
    # A label added to the catalogue clears the finding on outputs computed
    # before the runs were rebuilt with it.
    findings = [_finding("f1", "B1", ["e1"]), _finding("f3", "B1", ["e2"])]
    declared = {("admin_scheduled_job", "1"): {"B1"}}
    bad = ts.unlabelled(ACTIONS, OPPS, findings, "run-1", declared)
    assert [b["finding_id"] for b in bad] == ["f3"]


def test_declared_findings_reads_every_step_of_the_catalogue():
    cat = yaml.safe_load((REPO / "spec/scenarios/catalogue.v0.yaml").read_text(encoding="utf-8"))
    declared = ts.declared_findings(cat)
    assert declared[("b3_kube_ids0_rate_spike", "3")] == {"B3", "B1"}
    assert declared[("admin_scheduled_job", "1")] == {"B1"}
    assert ("h3_external_bulk_enumeration", "1") in declared
