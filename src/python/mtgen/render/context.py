"""Context renderer: ObjectObservation -> NormalizedEvent (context record alternative).

The world builder (phase 2.1) already constructs ObjectObservation proto messages
in world.context_observations. This renderer wraps each one in a NormalizedEvent
with source=CLUSTER_CONTEXT and routes it to norm.events.v0 (as a CONTEXT_OBSERVATION
record in the generator's output stream; the context.cluster.v0 raw feed is what the
real context-collector emits, but the generator produces NormalizedEvents directly).

Raw context observations route to context.cluster.v0 (kinds: CONTEXT_OBSERVATION,
CONTEXT_WATCH_GAP); NormalizedEvents route to norm.events.v0 (kind: NORMALIZED_EVENT).
The generator emits the NormalizedEvent form; the raw form is archived separately.

Time basis: WATCH_OBSERVATION (knowledge time, as per context.proto).
"""
from typing import List

from microtrace.v0 import common_pb2, context_pb2, normalized_pb2
from .common import (
    CAPTURE_MANIFEST_VERSION, CONTEXT_VERSION, NORMALIZER_VERSION,
    empty_completeness, event_id, make_time_info,
)

_SOURCE_STAGE: str = "watch"


class ContextRenderer:
    """Wraps world ObjectObservation protos into NormalizedEvent records.

    Args:
        world: World-like object with .context_observations (list of
               ObjectObservation protos, already constructed by world.py).
    """

    def __init__(self, world):
        self._observations: list = list(world.context_observations)

    def render_all(self) -> List["normalized_pb2.NormalizedEvent"]:
        """Render every ObjectObservation in the world into a NormalizedEvent.

        Returns a list sorted by the observation time of each record.
        """
        result = []
        for obs in self._observations:
            result.append(self._wrap(obs))
        result.sort(key=lambda ne: (
            ne.time.event_time.seconds,
            ne.time.event_time.nanos,
        ))
        return result

    def render_one(
        self,
        obs: "context_pb2.ObjectObservation",
    ) -> "normalized_pb2.NormalizedEvent":
        """Wrap a single ObjectObservation into a NormalizedEvent."""
        return self._wrap(obs)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wrap(
        self,
        obs: "context_pb2.ObjectObservation",
    ) -> "normalized_pb2.NormalizedEvent":
        # Observation time is knowledge time (watch event time)
        obs_ts = obs.observed_time
        time_ns = obs_ts.seconds * 1_000_000_000 + obs_ts.nanos

        # native_id per kafka-contract.md: uid/resource_version/change_type
        native_id = context_native_id(obs)
        ev_id = event_id("context", native_id, _SOURCE_STAGE)

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.CLUSTER_CONTEXT,
            source_native_id=native_id,
            source_stage=_SOURCE_STAGE,
            time=make_time_info(time_ns, common_pb2.WATCH_OBSERVATION),
            context=obs,
            completeness=empty_completeness(),
            normalizer_version=NORMALIZER_VERSION,
            context_version=CONTEXT_VERSION,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
        )


def context_native_id(obs: "context_pb2.ObjectObservation") -> str:
    """Contract native ID of a context record: uid/resource_version/change_type."""
    change = context_pb2.ChangeType.Name(obs.change_type)
    return f"{obs.uid}/{obs.resource_version}/{change}"
