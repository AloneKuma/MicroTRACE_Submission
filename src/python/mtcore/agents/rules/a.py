"""Agent A: gateway request evidence (A1, A2)."""
from microtrace.v0 import gateway_pb2

from mtcore.agents.rules.common import (GATEWAY, FindingSpec, Rule, abstain, entity, fired,
                                        not_fired)

LOC = gateway_pb2.MatchLocation
BODY = LOC.Value("REQUEST_BODY")
SENSOR = 1  # KeyOrigin.SENSOR


def _request_entity(gw):
    strength = "STRENGTH_HIGH" if gw.request_id_origin == SENSOR else "STRENGTH_LOW"
    return entity("HTTP_REQUEST", uid=gw.request_id, strength=strength)


def _matches(ctx, gw):
    """(usable matches, body matches withheld because the body was not fully observed)."""
    p_a = ctx.params.artifact("P_A")
    usable, withheld = [], []
    for m in gw.matches:
        if m.pattern_id not in p_a:
            continue
        if m.location == BODY and (gw.body_truncated or gw.observer_loss):
            withheld.append(m)
        else:
            usable.append(m)
    return usable, withheld


class A1(Rule):
    id, name, agent, tactic = "A1", "injection-pattern", "A", None
    topic, sources, mode = "agent.A.v0", frozenset({GATEWAY}), "instant"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        gw = ev.gateway
        if not gw.request_id:
            return abstain("FIELD_ABSENT")
        usable, withheld = _matches(ctx, gw)
        feats = {"usable_matches": len(usable), "withheld_body_matches": len(withheld)}
        if not usable:
            # A body that was not fully observed cannot show the absence of a
            # body pattern.
            if withheld or gw.body_truncated or gw.observer_loss:
                return abstain("TRUNCATED", features=feats)
            return not_fired(feats)
        m = sorted(usable, key=lambda m: (m.location, m.pattern_id))[0]
        spec = FindingSpec(entities=[_request_entity(gw), *ev.ne.entities], artifacts=["P_A"],
                           action_id=ev.action_id,
                           attributes={"pattern_id": m.pattern_id,
                                       "match_location": LOC.Name(m.location),
                                       "pattern_set_version": m.pattern_set_version,
                                       "body_truncated": str(gw.body_truncated).lower()})
        return fired(spec, feats)


class A2(Rule):
    id, name, agent, tactic = "A2", "injection-success-indicator", "A", "INITIAL_ACCESS"
    topic, sources, mode = "agent.A.v0", frozenset({GATEWAY}), "instant"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        gw = ev.gateway
        if not gw.request_id:
            return abstain("FIELD_ABSENT")
        usable, _ = _matches(ctx, gw)
        if not usable:
            return not_fired({"a1_holds": "false"})
        if gw.observer_loss:
            # Response not observed: A2 abstains, A1 still reports the attempt.
            return abstain("FIELD_ABSENT", features={"a1_holds": "true", "response_observed": "false"})
        p_a, i_a2 = ctx.params.artifact("P_A"), ctx.params.artifact("I_A2")
        got = {r.indicator_id for r in gw.response_indicators}
        for m in sorted(usable, key=lambda m: m.pattern_id):
            hits = sorted(got & set(i_a2.get(p_a[m.pattern_id], [])))
            if hits:
                spec = FindingSpec(entities=[_request_entity(gw), *ev.ne.entities], artifacts=["P_A", "I_A2"],
                                   action_id=ev.action_id,
                                   attributes={"pattern_id": m.pattern_id, "indicator_id": hits[0],
                                               "response_status": gw.response_status})
                return fired(spec, {"a1_holds": "true"})
        return not_fired({"a1_holds": "true", "response_status": gw.response_status})


RULES = [A1(), A2()]
