"""Every rulebook rule, negative control and abstain entry has a tagged test;
the rule objects agree with the rulebook; the agents never read ground truth."""
import agent_fixtures  # noqa: F401
import test_agent_a, test_agent_b, test_agent_c, test_agent_d  # noqa: F401,E401
import test_agent_e, test_agent_f, test_agent_g, test_agent_h  # noqa: F401,E401
from agent_testlib import COVERED, RULEBOOK

from mtcore.agents import routing
from mtcore.agents.rules import ALL, input_topics


def test_every_rulebook_item_has_a_tagged_test():
    missing = []
    for f in RULEBOOK["findings"]:
        want = {"positive"} | {f"neg:{i}" for i in range(len(f["negative_controls"]))} | \
               {f"abstain:{i}" for i in range(len(f["abstain"]))}
        missing += [f"{f['id']} {w}" for w in sorted(want) if (f["id"], w) not in COVERED]
    assert not missing, "untested rulebook items: " + ", ".join(missing)


def test_rules_match_rulebook():
    by_id = {f["id"]: f for f in RULEBOOK["findings"]}
    assert {r.id for r in ALL} == set(by_id)
    for r in ALL:
        f = by_id[r.id]
        assert (r.agent, r.tactic, r.name) == (f["agent"], f["primary_tactic"], f["name"]), r.id
        assert (r.gate is not None) == (f["status"] == "conditional"), r.id
        assert r.gate == f.get("gate"), r.id
        assert r.topic in routing.FINDING_INPUTS[r.id], r.id
        if r.window:
            assert r.window in f["parameters"] or r.window == f["state"].get("window") or \
                r.window == (f.get("ml") or {}).get("window"), r.id


def test_agents_never_read_ground_truth():
    assert "ground.truth.v0" not in input_topics(ALL)
    assert all(not t.startswith("ground.") for t in routing.ROUTES)
