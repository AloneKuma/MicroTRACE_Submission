"""Shared helpers for the agent rule tests.

@covers("D1", "positive" | "neg:<i>" | "abstain:<i>") tags a test with the
rulebook item it exercises (the i-th negative_controls / abstain entry);
test_agent_rulebook_coverage.py fails when any item is untagged.
"""
import os

import yaml

from mtcore import REPO
from mtcore.agents import emit
from mtcore.agents.engine import run_offline
from mtcore.agents.params import Params
from mtcore.agents.rules import ALL

COVERED = set()
RULEBOOK = yaml.safe_load(open(os.path.join(REPO, "spec", "rules", "rulebook.v0.yaml"), encoding="utf-8"))
FIRED, NOT_FIRED, ABSTAINED = emit.FIRED, emit.NOT_FIRED, emit.ABSTAINED


def covers(rule_id, *items):
    def deco(fn):
        for it in items:
            COVERED.add((rule_id, it))
        return fn
    return deco


def params(**overrides):
    p = Params.load()
    return p.with_overrides(**overrides) if overrides else p


def run(records, rule_ids=None, p=None, scorer=None):
    rules = [r for r in ALL if rule_ids is None or r.id in rule_ids]
    return run_offline(rules, p or params(), records, scorer=scorer)


def outcomes(evals, rule_id):
    return [e.outcome for e in evals if e.rule_id == rule_id]


def of(findings, rule_id):
    return [f for f in findings if f.finding_type == rule_id]


def reasons(evals, rule_id):
    from microtrace.v0 import common_pb2
    return sorted({common_pb2.GapReason.Name(r) for e in evals if e.rule_id == rule_id for r in e.abstain_reasons})


def gates_on():
    return params(gates={"G_D2": True, "G_E3": True, "G_F2": True, "G_G1b": True})
