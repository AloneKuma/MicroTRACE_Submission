"""The 23 finding rules of spec/rules/rulebook.v0.yaml, by agent."""
from mtcore.agents.rules import a, b, c, d, e, f, g, h

BY_AGENT = {"A": a.RULES, "B": b.RULES, "C": c.RULES, "D": d.RULES,
            "E": e.RULES, "F": f.RULES, "G": g.RULES, "H": h.RULES}
ALL = [r for rules in BY_AGENT.values() for r in rules]


def for_agents(agents):
    return [r for ag in agents for r in BY_AGENT[ag]]


def input_topics(rules):
    return sorted({r.topic for r in rules})
