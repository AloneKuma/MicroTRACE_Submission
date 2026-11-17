"""Agent H: data access and egress (H1-H5)."""
from microtrace.v0 import offnode_pb2

from mtcore.agents import mlpath
from mtcore.agents.rules.common import (AUDIT, CONTEXT, DB_AUDIT, EBPF, EXTERNAL, PATH_FLOW,
                                        SUCCESS, FindingSpec, Rule, abstain, endpoint, entity,
                                        fired, lineage_entity, not_fired, ok_2xx, opt,
                                        pod_entity, unique_audits)

SAC = offnode_pb2.SourceAddressClass
POD_ADDRESS, NODE_HOST, AMBIGUOUS = (SAC.Value(n) for n in ("POD_ADDRESS", "NODE_HOST_CONTEXT", "AMBIGUOUS"))
READ_STATEMENTS = {"select", "read", "query"}


def _external(ev):
    return ev.ed is not None and ev.ed.remote_class == EXTERNAL


class H1(Rule):
    id, name, agent, tactic = "H1", "egress-volume-anomaly", "H", None
    topic, sources, mode, window = "agent.H.egress.v0", frozenset({EBPF, CONTEXT}), "tumbling", "W_H1"
    families = frozenset({"net.flow_bytes"})

    def accepts(self, ev):
        return ev.family == "net.flow_bytes" and _external(ev)

    def evaluate(self, ctx, key, lo, hi, evs):
        pod = evs[0].pod_uid
        workload = ctx.context.workload(pod, evs[0].t) if pod else None
        total = sum(e.detail.bytes_out for e in evs)
        feats = {"external_bytes_out": total, "external_flow_count": len({e.detail.flow.socket_cookie for e in evs}),
                 "distinct_external_destination_count": len({endpoint(e.detail.remote) for e in evs})}
        q = ctx.params.artifact("Q_H1").get(workload) if workload else None
        if q is None:
            return abstain(features=dict(feats, abstain="workload not in the frozen baseline"))
        d = mlpath.decide(ctx, "H1", workload, feats, total > q)
        feats = d.features(feats)
        if not d.fire:
            return not_fired(feats)
        spec = d.apply(FindingSpec(entities=[pod_entity(pod)], artifacts=["Q_H1"],
                                   attributes={"bytes_out": total, "window_param": "W_H1",
                                               "baseline_quantile": q}))
        return fired(spec, feats)


class H2(Rule):
    id, name, agent, tactic = "H2", "unseen-destination", "H", None
    topic, sources, mode = "agent.H.egress.v0", frozenset({EBPF, CONTEXT}), "instant"
    families = frozenset({"net.connect"})

    def accepts(self, ev):
        return ev.family == "net.connect" and _external(ev)

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        workload = ctx.context.workload(ev.pod_uid, ev.t) if ev.pod_uid else None
        known = ctx.params.artifact("Q_H2").get(workload) if workload else None
        if known is None:
            return abstain(features={"abstain": "workload not in the frozen destination set"})
        dest = endpoint(ev.detail.remote)
        if dest in known:
            return not_fired({"destination": dest})
        spec = FindingSpec(entities=[pod_entity(ev.pod_uid), entity("NETWORK_ENDPOINT", name=dest,
                                                                    strength="STRENGTH_MEDIUM")],
                           artifacts=["Q_H2"],
                           attributes={"destination": ev.detail.remote.ip, "port": ev.detail.remote.port})
        return fired(spec, {"destination": dest})


class H3(Rule):
    id, name, agent, tactic = "H3", "bulk-secret-enumeration", "H", "CREDENTIAL_ACCESS"
    topic, sources, mode, window = "agent.H.audit.v0", frozenset({AUDIT}), "tumbling", "W_H3"

    def evaluate(self, ctx, key, lo, hi, evs):
        reqs = [e for e in unique_audits(evs) if ok_2xx(e.audit.response_code)]
        lists = [e for e in reqs if e.audit.verb in ("list", "watch")]
        gets = {(e.audit.object_ref.namespace, e.audit.object_ref.name) for e in reqs
                if e.audit.verb == "get" and e.audit.object_ref.name}
        n = len(lists) + len(gets)
        feats = {"list_requests": len(lists), "distinct_secret_gets": len(gets)}
        if n <= ctx.params.threshold("N_H3"):
            return not_fired(feats, inputs=reqs or evs)
        principal = reqs[0].principal[1]
        spec = FindingSpec(entities=[reqs[0].ad.principal], inputs=reqs,
                           attributes={"principal": principal, "list_requests": len(lists),
                                       "distinct_secret_gets": len(gets),
                                       "namespaces": ",".join(sorted({e.audit.object_ref.namespace for e in reqs}))})
        return fired(spec, feats, inputs=reqs)


class H4(Rule):
    """A read of a C_H4 file, then (node_seq order, within W_H) an external
    connect whose flow, owned by the same lineage, carries bytes out."""
    id, name, agent, tactic = "H4", "suspected-exfiltration", "H", "EXFILTRATION"
    topic, sources, mode, window = "agent.H.lineage.v0", frozenset({EBPF}), "anchored", "W_H"
    families = frozenset({"file.open", "file.read", "net.connect", "net.flow_bytes"})

    def anchor(self, ev, ctx):
        return (ev.family == "file.read" and ev.ed is not None and ev.ebpf.result == SUCCESS
                and ev.detail.bytes > 0 and ev.ed.data_class in ctx.params.artifact("C_H4"))

    def evaluate(self, ctx, key, lo, hi, evs):
        read = ctx.anchor
        evs = [e for e in evs if e.ebpf is not None]
        if len({(e.ebpf.node_id, e.ebpf.boot_id) for e in evs}) != 1:
            return abstain("DROPPED_BEFORE", features={"single_boot": "false"})
        evs.sort(key=lambda e: e.node_order)
        connects = {}
        for e in evs:
            if e.node_order <= read.node_order:
                continue
            d = e.detail
            if e.family == "net.connect" and _external(e):
                connects[(d.flow.node_id, d.flow.boot_id, d.flow.socket_cookie)] = e
            elif e.family == "net.flow_bytes" and d.bytes_out > 0:
                c = connects.get((d.flow.node_id, d.flow.boot_id, d.flow.socket_cookie))
                if c is not None:
                    spec = FindingSpec(entities=[pod_entity(read.pod_uid), lineage_entity(read.ed.lineage_id),
                                                 entity("NETWORK_ENDPOINT", name=endpoint(c.detail.remote),
                                                        strength="STRENGTH_MEDIUM")],
                                       artifacts=["C_H4"], inputs=[read, c, e],
                                       attributes={"read_event": read.id, "transfer_flow": c.id,
                                                   "destination": endpoint(c.detail.remote),
                                                   "bytes_out": d.bytes_out})
                    return fired(spec, {"data_class": read.ed.data_class}, inputs=[read, c, e])
        return not_fired({"data_class": read.ed.data_class})


class H5(Rule):
    """A successful database read by source address S, then path-flow records
    from S to external destinations ending after the read (plus both clock
    uncertainties) within W_H5, whose octets reach rho_H5 x bytes read.
    A path-flow record's event time is its flow start, so the window also
    reaches W_H5 back: a flow opened before the read and still sending after
    it counts (the rulebook asks only that the flow end after the read)."""
    id, name, agent, tactic = "H5", "offnode-suspected-exfiltration", "H", "EXFILTRATION"
    topic, sources, mode, window = "agent.H.offnode.v0", frozenset({DB_AUDIT, PATH_FLOW}), "anchored", "W_H5"
    lookback = "W_H5"

    def anchor(self, ev, ctx):
        return ev.db is not None

    def evaluate(self, ctx, key, lo, hi, evs):
        read = ctx.anchor
        db, od = read.db, read.od
        if not db.succeeded or db.statement_class.lower() not in READ_STATEMENTS:
            return not_fired({"successful_read": "false"})
        if od is None or od.source_address_class == AMBIGUOUS or od.source_address_class not in (POD_ADDRESS, NODE_HOST):
            return abstain("JOIN_UNCERTAIN", features={"source_address_class": "ambiguous"})
        bytes_read = opt(db, "bytes_returned")
        if bytes_read is None:
            return abstain("FIELD_ABSENT", features={"bytes_returned_logged": "false"})
        flows, octets, sampled, host = [], 0, False, False
        signatures = set(ctx.params.artifact("host_signatures"))
        for e in sorted((e for e in evs if e.flow is not None), key=lambda e: (e.t, e.id)):
            f, fod = e.flow, e.od
            if fod is None or fod.remote_class != EXTERNAL:
                continue
            if fod.host_component_match or endpoint(f.dst) in signatures:
                host = True                # a declared host component's flow, not the reader's
                continue
            end = f.flow_end.seconds * 10**9 + f.flow_end.nanos
            if end <= read.t + read.unc + e.unc:
                continue
            if f.sampled:
                sampled = True
                continue
            flows.append(e)
            octets += f.octets
        feats = {"bytes_read": bytes_read, "octets_out": octets, "flows": len(flows)}
        if sampled:
            return abstain("POLICY_EXCLUDED", features=dict(feats, sampled="true"))
        if not flows or octets < ctx.params.threshold("rho_H5") * bytes_read:
            if host:
                return abstain("POLICY_EXCLUDED", features=dict(feats, host_component_flow="true"))
            return not_fired(feats)
        dests = sorted({endpoint(e.flow.dst) for e in flows})
        ents = [entity("NETWORK_ENDPOINT", name=od.source_address, strength="STRENGTH_MEDIUM")]
        if od.HasField("pod_uid"):
            ents.append(pod_entity(od.pod_uid))
        if od.HasField("node_uid"):
            ents.append(entity("NODE", uid=od.node_uid))
        spec = FindingSpec(entities=ents, artifacts=["host_signatures"], inputs=[read, *flows],
                           attributes={"source_address": od.source_address,
                                       "source_address_class": SAC.Name(od.source_address_class),
                                       "pod_uid": opt(od, "pod_uid") or "", "node_uid": opt(od, "node_uid") or "",
                                       "boot_id": opt(od, "boot_id") or "", "db_read_event": read.id,
                                       "path_flows": ",".join(e.id for e in flows), "destination": ",".join(dests),
                                       "bytes_read": bytes_read, "octets_out": octets})
        return fired(spec, feats, inputs=[read, *flows])


RULES = [H1(), H2(), H3(), H4(), H5()]
