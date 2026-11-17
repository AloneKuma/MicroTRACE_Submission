"""Node-trust epochs (design-spec.md, "Node-trust epoch"; D3_v4.tex eq. epoch).

A processed C1b finding (host-namespace transition) on node N opens a
confirmed epoch on N's current boot. Onset tau_N is the trigger's earliest
corrected event time minus its uncertainty. Evidence from N whose off-node
receipt (ingest_time) is at or after tau_N is *degraded*, whatever event time
it carries, because a host attacker can backdate records. An unknown receipt
time counts as degraded. The trigger's own events are received after tau_N;
they stay trusted when received within beta_onset of their event time (the
declared ship-latency assumption; onset sealing is not built).

Degraded evidence cannot support a confirming witness or a decisive
contradiction, and an epoch opening before the end of a contradiction
interval plus beta leaves that interval uncovered (admit.covered), unless
the epoch opens at the pair's own target event and degrades none of the
pair's contradictions: then it can have hidden nothing the pair depends on.

An epoch ends when N is re-provisioned: a new boot ID is a different key.
Off-node sources are unaffected (they do not run on N).

Not built: F1 at host scope (F1 cannot fire without a Pod UID today) and
suspected epochs (an unexplained sequence gap or silence: the spec does not
define how to tell one from an idle period; open item in src/README.md).
"""
from mtcore.orchestrator.evidence import ingest_ns

TRIGGERS = {"C1b"}


class EpochIndex:
    def __init__(self, beta_onset_ns, enabled=True):
        self.beta_onset_ns = beta_onset_ns
        self.enabled = enabled
        self.onsets = {}           # (node, boot) -> tau_N
        self.trigger = {}          # (node, boot) -> finding ID that set tau_N (ties: smallest ID)
        self.trigger_events = set()

    def observe(self, finding, events):
        """Open or move earlier an epoch if finding is a trigger; events are its
        input Evs. Returns the (node, boot) keys it touched."""
        if not self.enabled or finding.finding_type not in TRIGGERS:
            return []
        touched = []
        for ev in events:
            e = ev.ebpf
            if e is None or not e.node_id or ev.t is None:
                continue
            nb = (e.node_id, e.boot_id)
            tau = ev.t - ev.unc
            if nb not in self.onsets or tau < self.onsets[nb]:
                self.onsets[nb] = tau
                self.trigger[nb] = finding.finding_id
            elif tau == self.onsets[nb]:
                self.trigger[nb] = min(self.trigger[nb], finding.finding_id)
            self.trigger_events.add(ev.id)
            touched.append(nb)
        return sorted(set(touched))

    def onset(self, node, boot):
        return self.onsets.get((node, boot)) if self.enabled else None

    def degraded(self, ev):
        e = ev.ebpf
        if not self.enabled or e is None:
            return False
        tau = self.onsets.get((e.node_id, e.boot_id))
        if tau is None:
            return False
        ing = ingest_ns(ev)
        if ing is None:
            return True
        if ev.id in self.trigger_events and ev.t is not None and ing <= ev.t + self.beta_onset_ns:
            return False
        return ing >= tau
