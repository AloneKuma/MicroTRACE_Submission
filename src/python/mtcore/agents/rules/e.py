"""Agent E: admission and artifact evidence (E1, E2, E3)."""
from microtrace.v0 import ebpf_pb2, kyverno_pb2

from mtcore.agents.rules.common import (CONTEXT, EBPF, KYVERNO, FindingSpec, Rule, abstain,
                                        entity, fired, has_gap, not_fired, opt, pod_entity,
                                        process_name)
from mtcore.agents.events import ts_ns

FAIL = kyverno_pb2.AdmissionVerdict.Value("FAIL")
MUT = ebpf_pb2.FileMutationOp
MMAP = MUT.Value("MMAP_SHARED_WRITE")
WRITE_OPS = {MUT.Value(n) for n in ("WRITE", "CREATE", "RENAME", "CHMOD")}
UNLINK = MUT.Value("UNLINK")
BREAK_OPS = {UNLINK, MUT.Value("RENAME")}


class E1(Rule):
    id, name, agent, tactic = "E1", "unsigned-image-admitted", "E", None
    topic, sources, mode = "agent.E.v0", frozenset({KYVERNO, CONTEXT}), "instant"

    def accepts(self, ev):
        return ev.kyverno is not None

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        k = ev.kyverno
        if k.dry_run:
            return abstain("POLICY_EXCLUDED", features={"dry_run": "true"})
        feats = {"verdict": kyverno_pb2.AdmissionVerdict.Name(k.verdict), "audit_mode": str(k.enforcement_audit_mode).lower()}
        if k.verdict != FAIL or not k.enforcement_audit_mode:
            return not_fired(feats)
        uid = opt(k, "resource_uid")
        if not uid or not ctx.context.ever_seen(uid):
            # generateName retry or no created Pod: an evidence gap. E1 has no
            # image-only weaker output (rulebook, decided 2026-10-08).
            return abstain("JOIN_UNCERTAIN", features=dict(feats, pod_uid_join_status="unobserved"))
        digest = k.image_digests[0] if k.image_digests else ""
        spec = FindingSpec(entities=[pod_entity(uid), *[entity("IMAGE", uid=d, strength="STRENGTH_MEDIUM")
                                                        for d in k.image_digests]],
                           attributes={"policy": k.policy, "rule": k.rule, "image_digest": digest,
                                       "pod_uid_join_status": "observed"})
        return fired(spec, feats)


def _qualifying_write(ctx, ev, workload):
    """(qualifies, reason) for an E2 write by ev."""
    d = ev.detail
    path = d.file.resolved_path or d.file.path_as_opened
    pkg = any(path.startswith(p) for p in ctx.params.artifact("E_E2_package_paths"))
    if d.op == UNLINK or not (d.executable_after or (pkg and d.op in WRITE_OPS)):
        return False, "not executable or package"
    writer = process_name(ev)
    for decl in ctx.params.artifact("E_E2").get(workload, []):
        if writer == decl["writer"] and path.startswith(decl["path_prefix"]):
            return False, "declared in E_E2"
    return True, ""


def _identity(f):
    return (f.mnt_id, f.dev, f.ino)


class E2(Rule):
    id, name, agent, tactic = "E2", "post-start-binary-write", "E", None
    topic, sources, mode = "agent.E.v0", frozenset({EBPF, CONTEXT}), "instant"
    families = frozenset({"file.mutation"})

    def accepts(self, ev):
        return ev.family == "file.mutation"

    def evaluate(self, ctx, key, lo, hi, evs):
        ev = evs[0]
        d = ev.detail
        if d is None or ev.ed is None or not ev.pod_uid:
            return abstain("FIELD_ABSENT")
        if d.op == MMAP or has_gap(ev, "JOIN_UNCERTAIN"):
            return abstain("JOIN_UNCERTAIN", features={"mutation_op": MUT.Name(d.op)})
        c = ctx.context.container(ev.pod_uid, ev.ed.container_name, ev.t)
        started = ts_ns(c.started_at) if c is not None else None
        if started is None:
            return abstain("FIELD_ABSENT", features={"container_start_known": "false"})
        if ev.t < started:
            return not_fired({"after_start": "false"})
        workload = ctx.context.workload(ev.pod_uid, ev.t) or ""
        ok, why = _qualifying_write(ctx, ev, workload)
        feats = {"mutation_op": MUT.Name(d.op), "executable_after": str(d.executable_after).lower()}
        if not ok:
            return not_fired(dict(feats, reason=why))
        writer = process_name(ev) or ""
        spec = FindingSpec(entities=[pod_entity(ev.pod_uid), entity("CONTAINER", name=ev.ed.container_name),
                                     entity("FILE_OBJECT", uid="%d:%d:%d" % _identity(d.file),
                                            name=d.file.resolved_path, strength="STRENGTH_MEDIUM")],
                           artifacts=["E_E2", "E_E2_package_paths"],
                           attributes={"file_identity": "%d:%d:%d" % _identity(d.file),
                                       "mutation_op": MUT.Name(d.op), "writer_process": writer})
        return fired(spec, feats)


class E3(Rule):
    """Write, then a same-Pod container restart, then execution of the same
    file object (mount, dev, ino), all in node_seq order within W_E. Artifact
    identity is option (c): continuity of the file object, not content."""
    id, name, agent, tactic = "E3", "persisted-implant", "E", "PERSISTENCE"
    topic, sources, mode, window = "agent.E.v0", frozenset({EBPF, CONTEXT}), "anchored", "W_E"
    families = frozenset({"file.mutation", "proc.exec"})
    gate = "G_E3"

    def accepts(self, ev):
        return ev.family in ("file.mutation", "proc.exec")

    def anchor(self, ev, ctx):
        d = ev.detail
        return (ev.family == "file.mutation" and d is not None and d.op != UNLINK
                and (d.executable_after or d.op in WRITE_OPS))

    def evaluate(self, ctx, key, lo, hi, evs):
        evs = [e for e in evs if e.ebpf is not None]
        boots = {(e.ebpf.node_id, e.ebpf.boot_id) for e in evs}
        if len(boots) != 1:
            return abstain("DROPPED_BEFORE", features={"single_boot": "false"})
        evs.sort(key=lambda e: e.node_order)
        write = ctx.anchor
        if write is None or not write.pod_uid:
            return abstain("FIELD_ABSENT")
        workload = ctx.context.workload(write.pod_uid, write.t) or ""
        ok, _ = _qualifying_write(ctx, write, workload)
        if not ok:
            return not_fired({"e2_qualifying": "false"})
        ident = _identity(write.detail.file)
        cid = write.ebpf.container.container_id
        restart = None
        for e in evs:
            if e.node_order <= write.node_order:
                continue
            d = e.detail
            if e.family == "file.mutation" and d.op in BREAK_OPS and _identity(d.file) == ident:
                return not_fired({"continuity": "broken"})
            if e.family != "proc.exec":
                continue
            if restart is None and e.ebpf.container.container_id and e.ebpf.container.container_id != cid:
                restart = e
            if restart is not None and _identity(d.executable) == ident:
                spec = FindingSpec(entities=[pod_entity(write.pod_uid),
                                             entity("CONTAINER", name=write.ed.container_name),
                                             entity("FILE_OBJECT", uid="%d:%d:%d" % ident, strength="STRENGTH_MEDIUM")],
                                   inputs=[write, restart, e],
                                   attributes={"artifact_identity": "mount-dev-ino:%d:%d:%d" % ident,
                                               "write_event": write.id, "reexec_event": e.id,
                                               "restart_evidence": f"container_id {cid} -> {restart.ebpf.container.container_id}"})
                return fired(spec, {"restart_observed": "true"}, inputs=[write, restart, e])
        return not_fired({"restart_observed": str(restart is not None).lower(), "reexec_observed": "false"})


RULES = [E1(), E2(), E3()]
