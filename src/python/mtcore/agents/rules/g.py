"""Agent G: service-to-service movement (G1a, G1c, G1b, G2)."""
import urllib.parse

from mtcore.agents import mlpath, routing  # noqa: F401  (routing sets the mtcodec import path)
from mtcore.agents.rules.common import (AUDIT, CONTEXT, EBPF, FAILURE, SUCCESS,
                                        FindingSpec, Rule, abstain, argv_hash, entity, fired,
                                        has_gap, not_fired, ok_2xx, opt, pod_entity)

import mtcodec  # noqa: E402

IN_CLUSTER = {"cluster_pod", "cluster_service"}    # EbpfDerived.remote_class values


def _edge(ctx, ev):
    """(source workload, destination workload, port) or None if unresolved."""
    src = ctx.context.workload(ev.pod_uid, ev.t) if ev.pod_uid else None
    remote = opt(ev.ed, "remote_pod_uid")
    dst = ctx.context.workload(remote, ev.t) if remote else None
    if not src or not dst:
        return None
    return src, dst, ev.detail.remote.port


def _inbound_edge(ctx, ev):
    """G1c: (source workload, destination workload, port) of an accepted
    connection, the source from the peer, the port the local one; or None."""
    src_pod = opt(ev.ed, "remote_pod_uid")
    src = ctx.context.workload(src_pod, ev.t) if src_pod else None
    dst = ctx.context.workload(ev.pod_uid, ev.t) if ev.pod_uid else None
    if not src or not dst:
        return None
    return src, dst, ev.detail.local.port


def _baselined(ctx, edge):
    return [edge[0], edge[1], edge[2]] in [list(e) for e in ctx.params.artifact("Q_G1a")]


class G1a(Rule):
    """Per connection: a successful in-cluster connect on an edge absent from
    the frozen service-edge baseline (PREDICATE)."""
    id, name, agent, tactic = "G1a", "unbaselined-connection", "G", None
    topic, sources, mode = "agent.G.v0", frozenset({EBPF, CONTEXT}), "instant"
    families = frozenset({"net.connect"})

    def accepts(self, ev):
        return ev.family == "net.connect" and ev.ed is not None and ev.ed.remote_class in IN_CLUSTER

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        if has_gap(ev, "JOIN_UNCERTAIN"):
            return abstain("JOIN_UNCERTAIN")
        if ev.ebpf.result != SUCCESS:
            return not_fired({"connect_success": "false"})
        edge = _edge(ctx, ev)
        if edge is None:
            return abstain("JOIN_UNCERTAIN", features={"edge_resolved": "false"})
        feats = {"edge": "%s->%s:%d" % edge}
        if _baselined(ctx, edge):
            return not_fired(feats)
        spec = FindingSpec(entities=[pod_entity(ev.pod_uid), pod_entity(ev.ed.remote_pod_uid)],
                           artifacts=["Q_G1a"],
                           attributes={"source_workload": edge[0], "destination_workload": edge[1],
                                       "port": edge[2]})
        return fired(spec, feats)


class G1c(Rule):
    """Per accepted connection: G1a's edge test seen from the receiving
    workload (PREDICATE; rule path only, D-27)."""
    id, name, agent, tactic = "G1c", "unbaselined-inbound-connection", "G", None
    topic, sources, mode = "agent.G.v0", frozenset({EBPF, CONTEXT}), "instant"
    families = frozenset({"net.accept"})

    def accepts(self, ev):
        return ev.family == "net.accept" and ev.ed is not None and ev.ed.remote_class in IN_CLUSTER

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        if has_gap(ev, "JOIN_UNCERTAIN"):
            return abstain("JOIN_UNCERTAIN")
        if ev.ebpf.result != SUCCESS:
            return not_fired({"accept_success": "false"})
        edge = _inbound_edge(ctx, ev)
        if edge is None:
            return abstain("JOIN_UNCERTAIN", features={"edge_resolved": "false"})
        feats = {"edge": "%s->%s:%d" % edge}
        if _baselined(ctx, edge):
            return not_fired(feats)
        spec = FindingSpec(entities=[pod_entity(ev.pod_uid), pod_entity(ev.ed.remote_pod_uid)],
                           artifacts=["Q_G1a"],
                           attributes={"source_workload": edge[0], "destination_workload": edge[1],
                                       "port": edge[2]})
        return fired(spec, feats)


class G1aModel(Rule):
    """G1a's Isolation Forest path over a Pod's connections in W_G1a_ml. It
    fires (path ML) only when no per-connection G1a finding fired for that
    Pod in the window, so one behavior is not reported twice."""
    id, name, agent, tactic = "G1a", "unbaselined-connection", "G", None
    topic, sources, mode, window = "agent.G.v0", frozenset({EBPF, CONTEXT}), "tumbling", "W_G1a_ml"
    families = frozenset({"net.connect"})

    def accepts(self, ev):
        return ev.family == "net.connect" and ev.ed is not None and ev.ed.remote_class in IN_CLUSTER

    def evaluate(self, ctx, key, lo, hi, evs):
        if not ctx.params.ml_enabled or ctx.scorer is None:
            return None     # no model path: the per-connection G1a evaluations stand alone
        edges, unbaselined, ports = set(), 0, set()
        for ev in evs:
            e = _edge(ctx, ev)
            if e is not None:
                edges.add(e)
                unbaselined += not _baselined(ctx, e)
            ports.add(ev.detail.remote.port)
        feats = {"connect_count": len(evs), "distinct_edge_count": len(edges),
                 "unbaselined_edge_count": unbaselined, "distinct_port_count": len(ports),
                 "failed_connect_fraction": round(sum(e.ebpf.result == FAILURE for e in evs) / len(evs), 6)}
        workload = ctx.context.workload(evs[0].pod_uid, evs[0].t) if evs[0].pod_uid else None
        d = mlpath.decide(ctx, "G1a", workload or "", feats, False)
        feats = d.features(feats)
        covered = [f for t, f in ctx.fired_keys.get(("G1a", key.hex()), []) if lo <= t <= hi]
        if not d.fire or covered:
            return not_fired(dict(feats, covered_by_predicate=str(bool(covered)).lower()))
        spec = d.apply(FindingSpec(entities=[pod_entity(evs[0].pod_uid)], artifacts=["Q_G1a"],
                                   attributes={"source_workload": workload or "", "destination_workload": "",
                                               "port": ""}))
        return fired(spec, feats)


class G1b(Rule):
    """credential-read-to-use (JTI of the read token version equals the used
    credential ID) followed by a distinct, successful action across a declared
    boundary. Input: credential.instance.v0, keyed by JTI."""
    id, name, agent, tactic = "G1b", "token-pivot", "G", "LATERAL_MOVEMENT"
    topic, sources, mode, window = "credential.instance.v0", frozenset({EBPF, AUDIT}), "anchored", "W_w"
    families = frozenset({"file.read", "token.jti_index"})
    gate = "G_G1b"

    def anchor(self, ev, ctx):
        return ev.family == "file.read"

    def evaluate(self, ctx, key, lo, hi, evs):
        jti = _jti(key)
        read = ctx.anchor
        reader_ns = _namespace(ctx, read)
        boundaries = {tuple(b) for b in ctx.params.artifact("Bnd_G1b")}
        for use in sorted((e for e in evs if e.audit is not None and e.t > read.t), key=lambda e: (e.t, e.id)):
            a = use.audit
            if opt(use.ad, "used_credential_id") != jti or not ok_2xx(a.response_code):
                continue
            if a.object_ref.subresource == "exec":
                continue                   # an exec is represented by G2
            target_ns = a.object_ref.namespace
            if (reader_ns, target_ns) not in boundaries:
                continue
            spec = FindingSpec(entities=[entity("TOKEN_INSTANCE", uid=jti), pod_entity(read.pod_uid or ""),
                                         entity("AUDIT_ACTION", uid=a.audit_id)],
                               action_id=a.audit_id or None, artifacts=["Bnd_G1b"], inputs=[read, use],
                               attributes={"jti": jti, "read_event": read.id, "use_audit_id": a.audit_id,
                                           "boundary": f"{reader_ns}->{target_ns}",
                                           "effect": f"{a.verb} {a.object_ref.resource} {a.response_code}"})
            return fired(spec, {"jti": jti}, inputs=[read, use])
        return not_fired({"jti": jti})


def _jti(key):
    comps = mtcodec.decode_key(key)[2]
    return comps[0][1] if comps else ""


def _namespace(ctx, ev):
    pod = ctx.context.pod(ev.pod_uid, ev.t) if ev.pod_uid else None
    return pod.namespace if pod is not None else ""


def _exec_request(uri):
    """(container, argv) from a pods/exec request URI."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)
    return (q.get("container") or [""])[0], q.get("command") or []


class G2(Rule):
    """The request is timed by the API server and the exec by the node, so an
    exec counts from the request time minus both clock uncertainties; the
    window reaches back (buffering only) so such an exec is still held."""
    id, name, agent, tactic = "G2", "exec-into-container", "G", "EXECUTION"
    topic, sources, mode, window = "agent.G.v0", frozenset({AUDIT, EBPF}), "anchored", "W_G2"
    families = frozenset({"proc.exec"})
    lookback = "W_G2"

    def accepts(self, ev):
        a = ev.audit
        if a is not None:
            return a.object_ref.subresource == "exec" and a.stage == "ResponseStarted"
        return ev.family == "proc.exec"

    def anchor(self, ev, ctx):
        return ev.audit is not None

    def evaluate(self, ctx, key, lo, hi, evs):
        req = ctx.anchor
        a = req.audit
        if a.verb not in ("get", "create") or a.response_code != 101:
            return not_fired({"exec_accepted": "false", "response_code": a.response_code})
        target = opt(req.ad, "resolved_target_pod_uid")
        if not target:
            return abstain("JOIN_UNCERTAIN", features={"target_resolved": "false"})
        container, argv = _exec_request(a.request_uri)
        want = argv_hash(argv)
        execs = (e for e in evs if e.ebpf is not None and e.t >= req.t - req.unc - e.unc)
        for ev in sorted(execs, key=lambda e: (e.t, e.id)):
            d = ev.detail
            if (ev.pod_uid == target and ev.ed.container_name == container and d.starts_new_lineage
                    and d.argv_sha256 == want):
                spec = FindingSpec(entities=[pod_entity(target), entity("CONTAINER", name=container),
                                             entity("AUDIT_ACTION", uid=a.audit_id),
                                             entity("PROCESS_LINEAGE", uid=ev.ed.lineage_id)],
                                   action_id=a.audit_id, inputs=[req, ev],
                                   attributes={"audit_id": a.audit_id, "target_pod_uid": target,
                                               "target_container": container,
                                               "target_process": ev.ed.lineage_id,
                                               "boundary_crossed": ""})
                return fired(spec, {"joined": "true"}, inputs=[req, ev])
        return abstain("JOIN_UNCERTAIN", features={"matching_exec_observed": "false"})


RULES = [G1a(), G1c(), G1aModel(), G1b(), G2()]
