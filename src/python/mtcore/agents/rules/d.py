"""Agent D: workload credential evidence (D1, D2)."""
from microtrace.v0 import ebpf_pb2

from mtcore.agents.rules.common import (AUDIT, EBPF, HOST_READER, SUCCESS, UNATTRIBUTED,
                                        FindingSpec, Rule, abstain, entity, fired, has_gap,
                                        not_fired, opt, pod_entity, process_name)

READER = ebpf_pb2.ReaderClass


class D1(Rule):
    id, name, agent, tactic = "D1", "token-read-anomaly", "D", "CREDENTIAL_ACCESS"
    topic, sources, mode = "agent.D.read.v0", frozenset({EBPF}), "instant"
    families = frozenset({"file.open", "file.read", "token.file_index"})

    def accepts(self, ev):
        # An open that is never read is not a D1 input (rulebook: "Open
        # without a successful read" abstains; it produces no evaluation).
        return ev.family == "file.read"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        e, d, ed = ev.ebpf, ev.detail, ev.ed
        if d is None or ed is None:
            return abstain("FIELD_ABSENT")
        if e.result != SUCCESS or d.bytes == 0:
            return not_fired({"read_success": "false"})
        tf = opt(ed, "token_file")
        if tf is None:                      # (dev, ino) not in the token index
            return abstain("JOIN_UNCERTAIN", features={"token_resolved": "false"})
        if e.reader_class == UNATTRIBUTED or has_gap(ev, "JOIN_UNCERTAIN"):
            return abstain("JOIN_UNCERTAIN", features={"reader_resolved": "false"})
        workload = ctx.context.workload(tf.owner_pod_uid, ev.t)
        expected = ctx.params.artifact("E_D1")
        if workload is None or workload not in expected:
            return abstain("FIELD_ABSENT", features={"owner_workload_in_E_D1": "false"})
        reader = process_name(ev)
        if reader is None:
            return abstain("FIELD_ABSENT", features={"reader_process": ""})
        host = e.reader_class == HOST_READER
        feats = {"reader_class": READER.Name(e.reader_class), "reader_process": reader,
                 "owner_workload": workload}
        if not host and reader in expected[workload]:
            return not_fired(feats)
        reader_pod = "" if host else (ev.pod_uid or "")
        ents = [pod_entity(tf.owner_pod_uid),
                entity("FILE_OBJECT", uid=f"{d.file.dev}:{d.file.ino}", name=tf.version_dir),
                entity("HOST_PROCESS" if host else "PROCESS", name=reader, strength="STRENGTH_MEDIUM")]
        if reader_pod:
            ents.append(pod_entity(reader_pod))
        spec = FindingSpec(entities=ents, artifacts=["E_D1"],
                           attributes={"token_owner_pod_uid": tf.owner_pod_uid,
                                       "token_version_dir": tf.version_dir,
                                       "reader_class": READER.Name(e.reader_class),
                                       "reader_process": reader, "reader_pod_uid": reader_pod})
        return fired(spec, feats)


class D2(Rule):
    id, name, agent, tactic = "D2", "token-binding-mismatch", "D", None
    topic, sources, mode = "agent.D.use.v0", frozenset({AUDIT}), "instant"
    families = frozenset({"net.connect"})      # rulebook input; read from audit here
    gate = "G_D2"

    def accepts(self, ev):
        # RequestReceived carries no outcome; later stages share action_id
        # (the audit ID), so the orchestrator deduplicates them.
        return ev.audit is not None and ev.audit.stage != "RequestReceived"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        ad, a = ev.ad, ev.audit
        bound = opt(ad, "bound_pod_uid")
        if not bound:                       # legacy or unbound token
            return abstain("FIELD_ABSENT", features={"pod_bound": "false"})
        routes = (opt(ad, "attributed_caller_pod_uid"), opt(ad, "peer_caller_pod_uid"))
        if not routes[0] or not routes[1]:  # a caller route absent or ambiguous
            return abstain("JOIN_UNCERTAIN", features={"caller_routes": sum(bool(r) for r in routes)})
        if routes[0] != routes[1]:
            return abstain("JOIN_UNCERTAIN", features={"caller_routes_agree": "false"})
        caller = routes[0]
        feats = {"bound_pod_uid": bound, "caller_pod_uid": caller}
        if caller == bound:
            return not_fired(feats)
        spec = FindingSpec(entities=[pod_entity(bound), pod_entity(caller),
                                     entity("AUDIT_ACTION", uid=a.audit_id)],
                           action_id=a.audit_id or None,
                           attributes={"bound_pod_uid": bound, "caller_pod_uid": caller,
                                       "audit_id": a.audit_id})
        return fired(spec, feats)


RULES = [D1(), D2()]
