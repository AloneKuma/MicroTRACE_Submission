"""Agent C: container-escape and process-injection indicators."""
from microtrace.v0 import ebpf_pb2

from mtcore.agents.rules.common import (EBPF, FindingSpec, Rule, abstain, fired, has_gap,
                                        lineage_entity, not_fired, pod_entity)

NSOP = ebpf_pb2.NamespaceOp
NS_OPS = {NSOP.Value("SETNS"): "setns", NSOP.Value("UNSHARE"): "unshare", NSOP.Value("MOUNT"): "mount"}
CAPSET = ebpf_pb2.PrivilegeOp.Value("CAPSET")
PTRACE_ATTACH, PTRACE_SEIZE = 16, 0x4206
RESULT = ebpf_pb2.OpResult


def _pod_attribution(ev):
    """'pod' when the lineage is Pod-attributed, 'uncertain' on JOIN_UNCERTAIN, else None."""
    if has_gap(ev, "JOIN_UNCERTAIN"):
        return "uncertain"
    return "pod" if ev.pod_uid else None


def _base_entities(ev):
    return [pod_entity(ev.pod_uid), lineage_entity(ev.ed.lineage_id)]


def _indicator(ctx, ev):
    d = ev.detail
    if ev.family == "ns.change" and d is not None and d.op in NS_OPS:
        return NS_OPS[d.op]
    if ev.family == "priv.creds" and d is not None and d.op == CAPSET and d.HasField("before"):
        if d.after.cap_effective & ~d.before.cap_effective:
            return "capset"
    if ev.family == "ipc.runtime_socket" and d is not None:
        if d.remote.unix_path in ctx.params.artifact("Z_C")["runtime_sockets"]:
            return "runtime_socket"
    if ev.family == "bpf.call" and d is not None and not d.caller_is_sensor:
        return "bpf"
    return None


class C1a(Rule):
    id, name, agent, tactic = "C1a", "escape-indicators", "C", None
    topic, sources, mode = "agent.C.v0", frozenset({EBPF}), "instant"
    families = frozenset({"bpf.call", "ipc.runtime_socket", "ns.change", "priv.creds"})

    def accepts(self, ev):
        return ev.family in ("ns.change", "priv.creds", "ipc.runtime_socket", "bpf.call")

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        if ev.ed is None:
            return abstain("FIELD_ABSENT")
        kind = _indicator(ctx, ev)
        if kind is None:
            return not_fired({"indicator_kind": ""})
        attribution = _pod_attribution(ev)
        if attribution == "uncertain":
            return abstain("JOIN_UNCERTAIN", features={"indicator_kind": kind})
        if attribution is None:   # not Pod-attributed (e.g. the runtime's own setns)
            return not_fired({"indicator_kind": kind, "pod_attributed": "false"})
        spec = FindingSpec(entities=_base_entities(ev), artifacts=["Z_C"] if kind == "runtime_socket" else [],
                           attributes={"indicator_kind": kind, "result": RESULT.Name(ev.ebpf.result),
                                       "lineage_id": ev.ed.lineage_id})
        return fired(spec, {"indicator_kind": kind})


def _host_equal(ns, host):
    return ns.mnt != 0 and ns.mnt == host.mnt and ns.pid == host.pid


class C1b(Rule):
    """Fires on a transition into host namespaces by a lineage observed
    outside them first. A lineage that starts in host namespaces (a declared
    privileged DaemonSet) never shows a transition."""
    id, name, agent, tactic = "C1b", "observed-escape", "C", "PRIVILEGE_ESCALATION"
    topic, sources, mode = "agent.C.v0", frozenset({EBPF}), "instant"
    families = frozenset({"ns.change", "ns.sample", "proc.exec", "proc.fork"})

    def accepts(self, ev):
        return ev.family in ("ns.change", "ns.sample", "proc.exec", "proc.fork")

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        if ev.ed is None:
            return abstain("FIELD_ABSENT")
        if has_gap(ev, "JOIN_UNCERTAIN"):
            return abstain("JOIN_UNCERTAIN")
        if not ev.pod_uid:
            return not_fired({"pod_attributed": "false"})
        memo = ctx.memo.setdefault(("C1b", key), {})
        d = ev.detail
        if ev.family in ("ns.change", "ns.sample") and d is not None:
            before_host = d.HasField("before") and _host_equal(d.before, d.host_reference)
            after_host = _host_equal(d.after, d.host_reference) or ev.ed.host_namespace_after
            if d.HasField("before") and not before_host:
                memo.setdefault("non_host_since", ev.t)
            if not after_host:
                memo.setdefault("non_host_since", ev.t)
                return not_fired({"namespaces_equal_host": "false"})
            if (d.HasField("before") and not before_host) or "non_host_since" in memo:
                via = NS_OPS.get(d.op, "exec-or-sample")
                return self._fire(ev, via, memo)
            return not_fired({"namespaces_equal_host": "true", "transition_observed": "false"})
        # exec/fork: host_namespace_after from the normalizer
        if not ev.ed.host_namespace_after:
            memo.setdefault("non_host_since", ev.t)
            return not_fired({"namespaces_equal_host": "false"})
        if "non_host_since" in memo:
            return self._fire(ev, "exec", memo)
        return not_fired({"namespaces_equal_host": "true", "transition_observed": "false"})

    def _fire(self, ev, via, memo=None):
        # One finding per lineage: later host-namespace events of the same
        # escaped lineage add no new transition.
        if memo is not None:
            if memo.get("fired"):
                return not_fired({"namespaces_equal_host": "true", "already_reported": "true"})
            memo["fired"] = True
        spec = FindingSpec(entities=_base_entities(ev),
                           attributes={"lineage_id": ev.ed.lineage_id, "namespaces_equal_host": "true",
                                       "via_operation": via})
        return fired(spec, {"namespaces_equal_host": "true"})


class C2(Rule):
    id, name, agent, tactic = "C2", "ptrace-observed", "C", None
    topic, sources, mode = "agent.C.v0", frozenset({EBPF}), "instant"
    families = frozenset({"proc.ptrace"})

    def accepts(self, ev):
        return ev.family == "proc.ptrace"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        d = ev.detail
        if ev.ed is None or d is None:
            return abstain("FIELD_ABSENT")
        if d.request not in (PTRACE_ATTACH, PTRACE_SEIZE):
            return not_fired({"ptrace_request": d.request})
        if _pod_attribution(ev) != "pod":
            return not_fired({"ptrace_request": d.request, "pod_attributed": "false"})
        t = d.target
        spec = FindingSpec(entities=_base_entities(ev),
                           attributes={"ptrace_request": d.request,
                                       "target_process": f"{t.node_id}/{t.boot_id}/{t.tgid}/{t.start_time_ns}"})
        return fired(spec, {"ptrace_request": d.request})


RULES = [C1a(), C1b(), C2()]
