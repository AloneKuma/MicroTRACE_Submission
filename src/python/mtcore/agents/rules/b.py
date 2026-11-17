"""Agent B: Kubernetes API behavior per principal and per observed source."""
from mtcore.agents import mlpath
from mtcore.agents.rules.common import (AUDIT, FindingSpec, Rule, abstain, entity, fired,
                                        not_fired, ok_2xx, unique_audits)

READ_VERBS = {"get", "list", "watch"}
MUTATING = {"create", "update", "patch", "delete", "deletecollection"}


def _principal_entity(evs):
    e = entity("USER")
    e.CopyFrom(evs[0].ad.principal)
    return e


def _baseline_key(ev):
    """Q_B1 and Q_B3 are keyed by principal name (system:serviceaccount:ns:sa):
    a UID is new in every cluster, so a UID-keyed baseline never carries over."""
    return ev.ad.principal.name or ev.principal[1]


def _unbaselined(features):
    features = dict(features)
    features["abstain"] = "principal not in the frozen baseline"
    return abstain(features=features)


class B1(Rule):
    id, name, agent, tactic = "B1", "resource-enumeration", "B", "DISCOVERY"
    topic, sources, mode, window = "agent.B.v0", frozenset({AUDIT}), "tumbling", "W_B1"

    def evaluate(self, ctx, key, lo, hi, evs):
        reqs = unique_audits(evs)
        reads = [e for e in reqs if e.audit.verb in READ_VERBS and ok_2xx(e.audit.response_code)
                 and e.audit.object_ref.resource]
        if not reads:
            return not_fired({"distinct_resource_count": 0}, inputs=reqs)
        kinds = {(e.audit.object_ref.api_group, e.audit.object_ref.resource, e.audit.object_ref.namespace)
                 for e in reads}
        principal = reads[0].principal[1]
        feats = {"distinct_resource_count": len(kinds), "read_request_count": len(reads),
                 "distinct_namespace_count": len({k[2] for k in kinds}),
                 "list_watch_fraction": round(sum(e.audit.verb != "get" for e in reads) / len(reads), 6)}
        q = ctx.params.artifact("Q_B1").get(_baseline_key(reads[0]))
        if q is None:
            return _unbaselined(feats)
        # ML entity = the baseline key (name): the cold-start count must carry over runs, as Q_B1 does
        d = mlpath.decide(ctx, "B1", _baseline_key(reads[0]), feats, len(kinds) > q)
        feats = d.features(feats)
        if not d.fire:
            return not_fired(feats, inputs=reads)
        spec = d.apply(FindingSpec(entities=[_principal_entity(reads)], artifacts=["Q_B1"], inputs=reads,
                                   attributes={"principal": principal, "distinct_resource_count": len(kinds),
                                               "window_param": "W_B1"}))
        return fired(spec, feats, inputs=reads)


class B2(Rule):
    id, name, agent, tactic = "B2", "auth-failure-burst", "B", "CREDENTIAL_ACCESS"
    topic, sources, mode, window = "agent.B.authn.v0", frozenset({AUDIT}), "tumbling", "W_B2"

    def evaluate(self, ctx, key, lo, hi, evs):
        reqs = unique_audits(evs)
        if not reqs:
            return abstain("FIELD_ABSENT")
        unauth = [e for e in reqs if e.audit.response_code == 401]
        forbidden = [e for e in reqs if e.audit.response_code == 403]
        source = reqs[0].ad.observed_source
        feats = {"unauthorized_401_count": len(unauth), "forbidden_403_count": len(forbidden),
                 "distinct_user_agent_count": len({e.audit.user_agent for e in reqs}),
                 "request_count": len(reqs)}
        d = mlpath.decide(ctx, "B2", source, feats, len(unauth) > ctx.params.threshold("N_B2"))
        feats = d.features(feats)
        if not d.fire:
            return not_fired(feats, inputs=reqs)
        spec = d.apply(FindingSpec(
            entities=[entity("UNAUTHENTICATED_SOURCE", name=source, strength="STRENGTH_CONTEXT")],
            inputs=unauth or reqs,
            attributes={"observed_source": source, "failure_count": len(unauth),
                        "forbidden_count_separate": len(forbidden)}))
        return fired(spec, feats, inputs=reqs)


class B3(Rule):
    id, name, agent, tactic = "B3", "request-rate-spike", "B", None
    topic, sources, mode, window = "agent.B.v0", frozenset({AUDIT}), "tumbling", "W_B3"

    def evaluate(self, ctx, key, lo, hi, evs):
        reqs = unique_audits(evs)
        if not reqs:
            return abstain("FIELD_ABSENT")
        principal = reqs[0].principal[1]
        feats = {"request_count": len(reqs), "distinct_verb_count": len({e.audit.verb for e in reqs}),
                 "mutating_request_fraction": round(sum(e.audit.verb in MUTATING for e in reqs) / len(reqs), 6)}
        q = ctx.params.artifact("Q_B3").get(_baseline_key(reqs[0]))
        if q is None:
            return _unbaselined(feats)
        d = mlpath.decide(ctx, "B3", _baseline_key(reqs[0]), feats, len(reqs) > q)
        feats = d.features(feats)
        if not d.fire:
            return not_fired(feats, inputs=reqs)
        spec = d.apply(FindingSpec(entities=[_principal_entity(reqs)], artifacts=["Q_B3"], inputs=reqs,
                                   attributes={"principal": principal, "request_count": len(reqs)}))
        return fired(spec, feats, inputs=reqs)


RULES = [B1(), B2(), B3()]
