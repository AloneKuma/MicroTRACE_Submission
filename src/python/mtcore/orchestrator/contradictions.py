"""Witness-specific contradictions (D3_v4.tex table "witnesses"; design-spec.md
gate 3). Only sensor-originated evidence is used, and evidence that is
degraded by a node-trust epoch is recorded but never decisive. Missing
telemetry is never a contradiction (that is Covered's job).

Built types:
- PROCESS_ANCESTRY: the two events share a lineage but run in different
  container instances, and the target is not a verified host transition
  ("container-instance change without a verified host transition").
- NETWORK_FLOW: another CONNECT on the same connection tuple from a different
  socket, after the source connect and up to the accept: the client port was
  reused, so the accept may belong to that other connection ("different
  connection instance").
- HOST_TRANSITION: no contradiction beyond Supported.

Link-level contradictions (Conflict_L) need cluster context and are not built.
"""
from dataclasses import dataclass, field

from mtcore.orchestrator.keys import NETWORK_FLOW, PROCESS_ANCESTRY, flow_key


@dataclass
class Found:
    cid: str
    detail: str
    evidence_ids: list = field(default_factory=list)
    degraded: bool = False

    @property
    def decisive(self):
        return not self.degraded


def _container(ev):
    return ev.ebpf.container.container_id if ev.ebpf is not None else ""


def find(d, evidence, degraded):
    """Contradictions for PairDecision d. evidence: EvidenceIndex; degraded(ev)."""
    src, tgt = d.source_ev, d.target_ev
    out = []
    if d.wtype == PROCESS_ANCESTRY:
        a, b = _container(src), _container(tgt)
        if a and b and a != b and not (tgt.ed is not None and tgt.ed.host_namespace_after):
            out.append(Found(f"container-change:{src.id}:{tgt.id}",
                             f"lineage {d.join_key} runs in container {a} then {b} with no host transition",
                             [src.id, tgt.id], degraded(src) or degraded(tgt)))
    elif d.wtype == NETWORK_FLOW:
        fk, _ = flow_key(src)
        own = (src.ebpf.socket.flow.node_id, src.ebpf.socket.flow.boot_id, src.ebpf.socket.flow.socket_cookie)
        hi = tgt.t + tgt.unc if tgt.t is not None else None
        for e in sorted(evidence.connects.get(fk, []), key=lambda e: (e.t or 0, e.id)):
            f = e.ebpf.socket.flow
            if (f.node_id, f.boot_id, f.socket_cookie) == own or e.id == src.id:
                continue
            if e.t is None or src.t is None or hi is None or not (src.t < e.t <= hi):
                continue
            out.append(Found(f"port-reuse:{e.id}", f"another connection on {d.join_key} at its accept",
                             [src.id, e.id, tgt.id], degraded(e)))
    return out
