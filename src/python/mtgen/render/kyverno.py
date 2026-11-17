"""Kyverno renderer: Activity -> List[NormalizedEvent] wrapping AdmissionDecision.

Handles admit_pod activities and produces one NormalizedEvent per container of
the admitted Pod. Each NormalizedEvent carries an AdmissionDecision (kyverno
record) and an AdmissionDerived with the container name and Pod UID.

Policy model: audit-mode (enforcement_audit_mode=True), never dry-run. Verdict
is sensor-computed from the container's image_signed flag:
  unsigned image -> FAIL  (E1 finding evidence)
  signed image   -> PASS

This matches E1's requirement: the policy records a violation but admits the
Pod (audit mode), and dry_run is always False so the record is not a test probe.
"""

from mtgen.minting import UuidMinter
from typing import List, Optional

from microtrace.v0 import common_pb2, kyverno_pb2, normalized_pb2
from .common import (
    CAPTURE_MANIFEST_VERSION, CONTEXT_VERSION, NORMALIZER_VERSION,
    empty_completeness, event_id, make_time_info,
)
from mtgen.activity import Activity
from mtgen.simtime import ns_to_timestamp

# Kyverno version string written on every record
_KYVERNO_VERSION: str = "1.11.0"

# Policy and rule names for the image-signature policy
_POLICY_NAME: str = "image-signature-policy"
_RULE_NAME: str = "image-signed"

_SOURCE_STAGE: str = "admission"
_ADDRESS_MAP_VERSION: str = "addrmap.v0"


class KyvernoRenderer:
    """Renders admit_pod Activities into NormalizedEvent/AdmissionDecision records.

    One NormalizedEvent per container of the admitted Pod. Verdict is
    sensor-computed from the container's image_signed flag.

    Args:
        world: World-like object with .containers iterable (ContainerState objects).
    """

    def __init__(self, world):
        # Build pod_uid -> [ContainerState] lookup
        self._pod_containers: dict = {}
        self._ids = UuidMinter("kyverno")
        for ctr in world.containers:
            self._pod_containers.setdefault(ctr.pod_uid, []).append(ctr)

    def render(self, activity: Activity) -> List["normalized_pb2.NormalizedEvent"]:
        """Render one admit_pod Activity into zero or more NormalizedEvent records.

        Returns one NormalizedEvent per container of the admitted Pod. If the
        Pod UID is not found in the world the result is empty (race condition or
        scenario-only Pod whose lifecycle is not tracked).

        Activity.parameters expected keys:
          pod_name     str  Pod name (default: target_uid)
          namespace    str  namespace (default "default")
          image_digest str  image digest override; uses container.image_digest
                            when absent
        """
        if activity.kind != "admit_pod":
            return []

        pod_uid = activity.target_uid
        p = activity.parameters
        pod_name = p.get("pod_name", pod_uid)
        namespace = p.get("namespace", "default")

        containers = self._pod_containers.get(pod_uid, [])
        if not containers:
            # Scenario-driven admission for a pod not in the world model; emit
            # one synthetic record using the activity parameters directly.
            return [self._render_one(
                pod_uid=pod_uid,
                pod_name=pod_name,
                namespace=namespace,
                container_name=p.get("container_name", "app"),
                image_digest=p.get("image_digest", ""),
                image_signed=_verdict_from_params(p),
                time_ns=activity.time_ns,
            )]

        results = []
        for ctr in containers:
            # Only render for containers that belong to this pod lifetime.
            # When the pod was recreated the renderer may receive the same
            # pod_uid multiple times; containers filter by valid_from <= time.
            if ctr.valid_from > activity.time_ns:
                continue
            image_digest = p.get("image_digest", ctr.image_digest)
            results.append(self._render_one(
                pod_uid=pod_uid,
                pod_name=pod_name,
                namespace=namespace,
                container_name=ctr.name,
                image_digest=image_digest,
                image_signed=ctr.image_signed,
                time_ns=activity.time_ns,
            ))
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _render_one(
        self,
        pod_uid: str,
        pod_name: str,
        namespace: str,
        container_name: str,
        image_digest: str,
        image_signed: bool,
        time_ns: int,
    ) -> "normalized_pb2.NormalizedEvent":
        admission_uid = self._ids.mint("admission", pod_uid, time_ns)
        report_uid = self._ids.mint("report", pod_uid, time_ns)
        verdict = kyverno_pb2.PASS if image_signed else kyverno_pb2.FAIL

        ts = ns_to_timestamp(time_ns)

        decision = kyverno_pb2.AdmissionDecision(
            admission_request_uid=admission_uid,
            resource_uid=pod_uid,
            resource_kind="Pod",
            namespace=namespace,
            resource_name=pod_name,
            policy=_POLICY_NAME,
            rule=_RULE_NAME,
            verdict=verdict,
            enforcement_audit_mode=True,
            dry_run=False,
            admission_time=ts,
            report_uid=report_uid,
            report_observed_time=ts,
            kyverno_version=_KYVERNO_VERSION,
        )
        if image_digest:
            decision.image_digests.append(image_digest)

        derived = normalized_pb2.AdmissionDerived(
            pod_uid=pod_uid,
            container_name=container_name,
        )

        native_id = f"{admission_uid}/{_POLICY_NAME}/{_RULE_NAME}"
        ev_id = event_id("kyverno", native_id, _SOURCE_STAGE)

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.KYVERNO,
            source_native_id=native_id,
            source_stage=_SOURCE_STAGE,
            time=make_time_info(time_ns, common_pb2.KYVERNO_ADMISSION),
            kyverno=decision,
            admission_derived=derived,
            completeness=empty_completeness(),
            normalizer_version=NORMALIZER_VERSION,
            context_version=CONTEXT_VERSION,
            capture_manifest_version=CAPTURE_MANIFEST_VERSION,
        )


def _verdict_from_params(params: dict) -> bool:
    """Determine image_signed from activity parameters when no world container.

    Treats policy_verdict="FAIL" as unsigned; anything else (including "PASS")
    as signed.
    """
    return params.get("policy_verdict", "PASS").upper() != "FAIL"
