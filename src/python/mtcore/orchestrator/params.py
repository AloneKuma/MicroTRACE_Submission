"""The orchestrator's view of a parameter set (the `orchestrator:` section).

Every value is in nanoseconds or a plain number. Witness types are keyed by
their WitnessType name. Values in src/params/dev.v0.yaml are UNFROZEN.
"""
from microtrace.v0 import witness_pb2

from mtcore.agents.params import NS, Params
from mtcore.orchestrator import ablations

WT = witness_pb2.WitnessType
ENABLING_TYPES = {WT.Value("IMAGE_CLASS"), WT.Value("CONTROL_PLANE_CAUSALITY_CLASS")}
# Built types that stay off unless a parameter set gates them on (D-32):
# a params file without a gates block must not change witness output.
OFF_UNLESS_GATED = {WT.Value("REQUEST_IDENTITY")}


class OrchParams:
    def __init__(self, params):
        self.params = params
        o = params.data.get("orchestrator") or {}
        self.status = o.get("status", "")
        self.version = params.version
        self._w = {WT.Value(k): int(v * NS) for k, v in (o.get("W_w_s") or {}).items()}
        self.eps_bar_ns = int(o.get("eps_bar_s", 0) * NS)
        self.A_ns = int(o.get("A_s", 0) * NS)
        self.T_ns = int(o.get("T_s", 0) * NS)
        self.beta_ns = int(o.get("beta_s", 0) * NS)
        self.beta_onset_ns = int(o.get("beta_onset_s", 0) * NS)
        self.lateness_ns = int(o.get("lateness_s", 0) * NS)
        self.max_idle_ns = int(o.get("max_idle_s", 0) * NS)
        self.heartbeat_ms = int(o.get("heartbeat_ms", 1000))
        self.K = int(o.get("K", 1))
        self.L = int(o.get("L", 2))
        self.lam = float(o.get("lambda", 1.0))
        self.q_unmapped = float(o.get("q_unmapped", 0.0))
        # Tactic-transition table (A2): a weight per direction along the
        # ATT&CK tactic order (finding_pb2.Tactic values ascend with it); a
        # plain number is one weight for every mapped pair.
        qt = o.get("q_transition", 1.0)
        self._q_tr = ({k: float(qt[k]) for k in ("forward", "same", "backward")} if isinstance(qt, dict)
                      else dict.fromkeys(("forward", "same", "backward"), float(qt)))
        self._q_w = {WT.Value(k): float(v) for k, v in (o.get("q_w") or {}).items()}
        self._gates = {WT.Value(k): bool(v) for k, v in (o.get("gates") or {}).items()}
        self.ablations = ablations.validate(o.get("ablations") or [])
        # 2026-11-17 (post-hoc, after the held-out Exp. 3 loss rows): a loss record that names the
        # witness keys of the records it lost (scope "keys=") blocks Covered and the DistinctAction
        # fallback only for pairs and findings that use one of those keys. Off by default, so every
        # frozen parameter set keeps its node-wide behaviour.
        self.scoped_loss = bool(o.get("scoped_loss", False))
        if "no_witness" in self.ablations:
            # D-15: W_nw, the largest gap of a PRESENT link in PILOT, so the
            # window loses no real link; q_nw scores such a link.
            unspec = WT.Value("WITNESS_TYPE_UNSPECIFIED")
            self._w[unspec] = int(float(o.get("W_nw_s", 60)) * NS)
            self._q_w[unspec] = float(o.get("q_nw", 0.8))

    @classmethod
    def load(cls, path=None):
        return cls(Params.load(path) if path else Params.load())

    def window_ns(self, wtype):
        """W_w for one witness type."""
        return self._w[wtype]

    def horizon_ns(self, wtype):
        """Lemma 1 posting horizon H_w = W_w + eps_bar_w + 2A. Enabling types
        have no window, so they are kept for the path span T."""
        if wtype in ENABLING_TYPES:
            return self.T_ns + 2 * self.A_ns
        return self._w[wtype] + self.eps_bar_ns + 2 * self.A_ns

    def max_horizon_ns(self):
        return max(self.horizon_ns(w) for w in self._w) if self._w else 0

    def max_window_ns(self):
        """Largest witness window over the direct types."""
        return max((v for w, v in self._w.items() if w not in ENABLING_TYPES), default=0)

    def q_w(self, wtype):
        return self._q_w.get(wtype, 0.0)

    def q_ab(self, ta, tb):
        """Tactic-transition weight from tactic ta to tb (Tactic values; 0 =
        no primary tactic). No-Tactic removes the weight, q_unmapped included."""
        if self.ablated("no_tactic"):
            return 1.0
        if not ta or not tb:
            return self.q_unmapped
        return self._q_tr["forward" if tb > ta else "same" if tb == ta else "backward"]

    def gate(self, wtype):
        """Conditional witness types are off unless gated on; others are always on."""
        return self._gates.get(wtype, wtype not in OFF_UNLESS_GATED)

    def ablated(self, name):
        return name in self.ablations

    def with_overrides(self, **changes):
        """A copy with orchestrator settings changed (tests and ablations)."""
        o = dict(self.params.data.get("orchestrator") or {})
        o.update(changes)
        return OrchParams(self.params.with_overrides(orchestrator=o))
