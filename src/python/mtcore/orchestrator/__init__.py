"""Global Orchestrator (build step 5): witness index, link admission,
contradiction checks, watermark, sealing and amendments.

Inputs: findings.v0, norm.events.v0 (evidence detail findings do not carry),
source.completeness.v0, and credential.instance.v0 when G_G1b is on. It never
reads ground.truth.v0. Outputs: witness.decisions.v0 and incidents.v0; the
graph store (step 6) starts there. The engine is pure Python, so Kafka runs
and offline replay make the same decisions (design-spec.md, "Correlation").
"""
from mtcore.agents import routing  # noqa: F401  (puts spec/tools on the path for mtcodec)

DECISION_VERSION = "orch-0.1"
PRODUCER_ID = "orchestrator"
