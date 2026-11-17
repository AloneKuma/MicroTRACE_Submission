"""Agent F: privilege gain at runtime (F1) and through RBAC (F2)."""
from mtcore.agents import rbac
from mtcore.agents.rules.common import (AUDIT, CONTEXT, EBPF, FindingSpec, Rule, abstain,
                                        entity, fired, not_fired, ok_2xx, pod_entity, lineage_entity)

RBAC_GROUP = "rbac.authorization.k8s.io"
RBAC_RESOURCES = {"rolebindings", "clusterrolebindings", "roles", "clusterroles"}
MUTATIONS = {"create", "update", "patch", "delete"}


class F1(Rule):
    id, name, agent, tactic = "F1", "capability-gain", "F", "PRIVILEGE_ESCALATION"
    topic, sources, mode = "agent.F.runtime.v0", frozenset({EBPF}), "instant"
    families = frozenset({"priv.creds"})

    def accepts(self, ev):
        return ev.family == "priv.creds"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        d = ev.detail
        if d is None or ev.ed is None:
            return abstain("FIELD_ABSENT")
        if not d.HasField("before"):
            return abstain("FIELD_ABSENT", features={"before_known": "false"})
        if not ev.pod_uid:
            return not_fired({"pod_attributed": "false"})
        b, a = d.before, d.after
        to_root = b.euid != 0 and a.euid == 0
        new_caps = a.cap_effective & ~b.cap_effective
        feats = {"euid_to_root": str(to_root).lower(), "new_cap_mask": hex(new_caps)}
        if not to_root and not new_caps:
            return not_fired(feats)
        via = d.via_executable.resolved_path if d.HasField("via_executable") else ""
        workload = ctx.context.workload(ev.pod_uid, ev.t) or ""
        if via and via in ctx.params.artifact("E_F1").get(workload, []):
            return not_fired(dict(feats, declared_in_E_F1="true"))
        spec = FindingSpec(entities=[pod_entity(ev.pod_uid), lineage_entity(ev.ed.lineage_id)],
                           artifacts=["E_F1"],
                           attributes={"before_creds": f"euid={b.euid} caps={hex(b.cap_effective)}",
                                       "after_creds": f"euid={a.euid} caps={hex(a.cap_effective)}",
                                       "via_executable": via})
        return fired(spec, feats)


class F2(Rule):
    """Effective-rights comparison across one successful RBAC mutation, from the
    versioned context history. The after-state is the object's observation
    with the mutation's resourceVersion; without it the transition cannot be
    attributed to this audit action and F2 abstains."""
    id, name, agent, tactic = "F2", "RBAC-grant-mutation", "F", "PRIVILEGE_ESCALATION"
    topic, sources, mode = "agent.F.rbac.v0", frozenset({AUDIT, CONTEXT}), "instant"
    gate = "G_F2"

    def accepts(self, ev):
        a = ev.audit
        return a is not None and a.stage == "ResponseComplete" and a.object_ref.resource in RBAC_RESOURCES

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        a = ev.audit
        if a.verb not in MUTATIONS or not ok_2xx(a.response_code):
            return not_fired({"successful_mutation": "false"})
        if not ctx.params.artifact("authorizer_chain_known"):
            return abstain("FIELD_ABSENT", features={"authorizer_chain_known": "false"})
        uid, rv = a.object_ref.uid, a.object_ref.resource_version
        hist = ctx.context.history(uid)
        idx = next((i for i, o in enumerate(hist) if o.resource_version == rv and rv), None)
        if idx is None:
            return abstain("JOIN_UNCERTAIN", features={"transition_attributed": "false"})
        obs = hist[idx]
        t_after = obs.observed_time.seconds * 10**9 + obs.observed_time.nanos
        prev_t = None
        if idx > 0:
            p = hist[idx - 1].observed_time
            prev_t = p.seconds * 10**9 + p.nanos
        if ctx.context.watch_gap_overlaps(RBAC_GROUP, prev_t if prev_t is not None else -(1 << 62), t_after):
            return abstain("WATCH_RELIST_GAP")
        before = rbac.RbacState(ctx.context.rbac_objects(t_after - 1))
        after = rbac.RbacState(ctx.context.rbac_objects(t_after))
        external = set(ctx.params.artifact("external_groups"))
        if rbac.unresolvable_groups([before, after], external):
            return abstain("FIELD_ABSENT", features={"external_group_membership": "unknown"})
        members = ctx.params.artifact("group_members")
        subjects = sorted(after.subjects() | before.subjects(), key=str)
        gains = {s: rbac.added_rights(before, after, s, members) for s in subjects}
        gains = {s: g for s, g in gains.items() if g}
        feats = {"subjects_evaluated": len(subjects), "subjects_gaining": len(gains)}
        if not gains:
            return not_fired(feats)
        subj = sorted(gains, key=str)[0]
        ents = [entity("RBAC_OBJECT", uid=uid, name=a.object_ref.name, namespace=a.object_ref.namespace),
                entity("AUDIT_ACTION", uid=a.audit_id)]
        ents += [entity("SERVICE_ACCOUNT" if s.kind == "ServiceAccount" else "GROUP" if s.kind == "Group" else "USER",
                        name=s.name, namespace=s.namespace, strength="STRENGTH_CONTEXT") for s in sorted(gains, key=str)]
        spec = FindingSpec(entities=ents, action_id=a.audit_id or None,
                           artifacts=["group_members", "external_groups"],
                           attributes={"subject": str(subj), "added_rights": ";".join(gains[subj][:20]),
                                       "mutation_audit_id": a.audit_id, "binding_uid": uid,
                                       "reconstruction_source": "context-history"})
        return fired(spec, feats)


RULES = [F1(), F2()]
