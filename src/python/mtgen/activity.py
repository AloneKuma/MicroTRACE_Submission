"""Activity record: abstract unit the workload engine and scenario engine produce.

Renderers in phase 2.4 convert Activities into typed NormalizedEvent source
records.  The private action_seq field is reserved for the scenario engine and
is never written to any rendered record.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Activity:
    """One unit of work in the generated world.

    Attributes:
        time_ns:     event time in nanoseconds since epoch
        kind:        action id from spec/scenarios/actions.v0.yaml
        actor_uid:   UID of the acting entity (Pod UID, process key, SA UID, ...)
        actor_type:  kind of actor, e.g. "Pod", "Process", "ServiceAccount",
                     "InfraService", or "External" (for off-world callers)
        target_uid:  UID or name of the target (service name, Pod UID, file path, ...)
        target_type: kind of target, e.g. "Service", "Pod", "File",
                     "APIResource", "InfraService", or "Endpoint"
        parameters:  action-specific free-form dict; fields mirror the action's
                     parameter list in spec/scenarios/actions.v0.yaml
        outcome:     "success" or "attempt_failed"
        action_seq:  private integer set by the scenario engine only; None for
                     workload activities. Never passed to renderers.
        unobserved:  private; sources (catalogue names) whose records of this
                     step are lost in a declared gap window.
    """
    time_ns: int
    kind: str
    actor_uid: str
    actor_type: str
    target_uid: str
    target_type: str
    parameters: dict = field(default_factory=dict)
    outcome: str = "success"
    action_seq: Optional[int] = field(default=None, repr=False)
    # Scenario step sources whose records are lost (catalogue `unobserved`);
    # private like action_seq: the build drops them in a declared gap.
    unobserved: tuple = field(default=(), repr=False)
