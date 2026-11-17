"""Audit renderer: Activity -> NormalizedEvent wrapping AuditEvent + AuditDerived.

Derives the following AuditDerived fields from the AuditEvent and the world
history:

  authentication_failed  True when response_code==401 or user.username is empty.
  principal              EntityRef(USER) from user.uid or user.username;
                         absent when authentication_failed.
  observed_source        Last source_ips entry (TCP peer address).
  bound_pod_uid          From user.extra["...pod-uid"] token binding only.
  bound_pod_name         From user.extra["...pod-name"] token binding only.
  used_credential_id     JTI stripped from user.extra["...credential-id"].
  resolved_target_pod_uid  Unambiguous namespace/name -> Pod history lookup
                           for pods/* requests; absent if ambiguous.
  peer_caller_pod_uid    Last source_ip -> PodIP history lookup; absent when
                         ambiguous, with a JOIN_UNCERTAIN completeness gap.
"""

from mtgen.minting import UuidMinter
from typing import Optional

from microtrace.v0 import (
    audit_pb2,
    common_pb2,
    normalized_pb2,
)
from .common import (
    NORMALIZER_VERSION, CONTEXT_VERSION, CAPTURE_MANIFEST_VERSION,
    completeness_gap, empty_completeness, event_id, make_entity_ref,
    make_time_info,
)
from mtgen.activity import Activity
from mtgen.history import Ambiguous, WorldHistory
from mtgen.simtime import ns_to_timestamp

_POLICY_VERSION: str = "audit-policy.v0"

# Kubernetes extra key names used in AuditUser.extra
_CRED_ID_KEY = "authentication.kubernetes.io/credential-id"
_POD_UID_KEY = "authentication.kubernetes.io/pod-uid"
_POD_NAME_KEY = "authentication.kubernetes.io/pod-name"
_NODE_NAME_KEY = "authentication.kubernetes.io/node-name"
_NODE_UID_KEY = "authentication.kubernetes.io/node-uid"


class AuditRenderer:
    """Renders api_request Activities into NormalizedEvent/AuditEvent + AuditDerived.

    Args:
        world_history:  WorldHistory for time-indexed Pod and IP lookups
        policy_version: audit policy hash/version recorded in each event
        world:          optional World; resolves ServiceAccount identities for
                        requests whose parameters name none
    """

    def __init__(
        self,
        world_history: WorldHistory,
        policy_version: str = _POLICY_VERSION,
        world=None,
    ):
        self._history = world_history
        self._policy_version = policy_version
        # Identity lookups: ServiceAccount by UID and by (namespace, name),
        # Pod by UID. Without a world, requests carry only the identity their
        # parameters give.
        self._sa_by_uid: dict = {}
        self._sa_by_ns_name: dict = {}
        self._pod_by_uid: dict = {}
        if world is not None:
            for sa in world.service_accounts:
                self._sa_by_uid[sa.uid] = sa
                self._sa_by_ns_name[(sa.namespace, sa.name)] = sa
            for pod in world.pods:
                self._pod_by_uid[pod.uid] = pod
        self._ids = UuidMinter("audit")

    def _with_defaults(self, activity: Activity) -> dict:
        """Return the activity parameters with request and identity defaults.

        Action kinds that name a fixed request (secret_list, secret_get,
        rbac_change) get their verb, group and resource. A request whose
        parameters carry no username or uid authenticates as its actor: a
        ServiceAccount actor as itself, a Pod actor as the Pod's
        ServiceAccount through a Pod-bound projected token. Explicit
        parameters always win; api_auth_failure stays unauthenticated.
        """
        p = dict(activity.parameters)
        kind = activity.kind
        if kind in ("secret_list", "secret_get"):
            p.setdefault("verb", "list" if kind == "secret_list" else "get")
            p.setdefault("resource", "secrets")
        elif kind == "rbac_change":
            p.setdefault("verb", p.get("mutation_type", "update"))
            p.setdefault("api_group", "rbac.authorization.k8s.io")
            object_type = str(p.get("object_type", "Role"))
            p.setdefault("resource", object_type.lower() + "s")

        if kind == "api_auth_failure":
            # A failed authentication is a 401 from the scenario's source
            # address (the TCP peer, observed_source).
            p.setdefault("response_code", 401)
            if not p.get("source_ips") and p.get("source_ip"):
                p["source_ips"] = [p["source_ip"]]
            return p
        if p.get("username") or p.get("uid"):
            return p
        sa = self._sa_by_uid.get(activity.actor_uid)
        pod = self._pod_by_uid.get(activity.actor_uid)
        if sa is None and pod is not None:
            sa = self._sa_by_ns_name.get((pod.namespace, pod.service_account))
        if sa is None:
            return p
        p["username"] = f"system:serviceaccount:{sa.namespace}:{sa.name}"
        p["uid"] = sa.uid
        p.setdefault("groups", [
            "system:serviceaccounts",
            f"system:serviceaccounts:{sa.namespace}",
            "system:authenticated",
        ])
        if pod is not None and "extra" not in p:
            p["extra"] = {_POD_UID_KEY: pod.uid, _POD_NAME_KEY: pod.name}
        return p

    def render(
        self,
        activity: Activity,
        audit_id: Optional[str] = None,
        normalizer_version: str = NORMALIZER_VERSION,
        context_version: str = CONTEXT_VERSION,
        capture_manifest_version: str = CAPTURE_MANIFEST_VERSION,
    ) -> "normalized_pb2.NormalizedEvent":
        """Render one api_request or api_auth_failure Activity.

        Expected activity.parameters keys:
          username        str        authenticated username (empty on failed auth)
          uid             str        authenticated user UID (may be empty)
          groups          list[str]  group memberships
          extra           dict       AuditUser.extra mapping key -> str|list[str]
          source_ips      list[str]  list of IPs; last entry is the TCP peer
          user_agent      str
          verb            str        Kubernetes verb (get/list/create/...)
          resource        str        resource kind (pods/secrets/...)
          api_group       str        API group ("" for core)
          api_version     str        API version (default "v1")
          namespace       str        object namespace
          name            str        object name
          resource_uid    str        object UID (optional)
          resource_version str       object resourceVersion (optional)
          subresource     str        subresource (optional)
          request_uri     str        full request URI (optional)
          response_code   int        HTTP response code
          response_reason str        response reason phrase (optional)
          annotations     dict       map<string,string> audit annotations
          stage           str        audit stage (default "ResponseComplete")
          level           str        audit level (default "Metadata")

        Args:
            activity: Activity with kind in {"api_request", "api_auth_failure",
                      "secret_list", "secret_get", ...}
            audit_id: explicit audit ID; auto-generated if None

        Returns:
            NormalizedEvent with record=audit and derived=audit_derived
        """
        if audit_id is None:
            audit_id = self._ids.mint(
                activity.time_ns, activity.kind,
                sorted((str(k), str(v)) for k, v in activity.parameters.items()))

        p = self._with_defaults(activity)
        stage = p.get("stage", "ResponseComplete")
        level = p.get("level", "Metadata")

        username = p.get("username", "")
        uid = p.get("uid", "")
        groups = list(p.get("groups", []))

        # Build AuditUser.extra: each value is ExtraValues(values=[...])
        extra_map: dict = {}
        for k, vals in p.get("extra", {}).items():
            if isinstance(vals, str):
                vals = [vals]
            extra_map[k] = audit_pb2.ExtraValues(values=list(vals))

        user = audit_pb2.AuditUser(
            username=username,
            uid=uid,
            groups=groups,
            extra=extra_map,
        )

        object_ref = audit_pb2.ObjectRef(
            api_group=p.get("api_group", ""),
            api_version=p.get("api_version", "v1"),
            resource=p.get("resource", ""),
            subresource=p.get("subresource", ""),
            namespace=p.get("namespace", ""),
            name=p.get("name", ""),
            uid=p.get("resource_uid", ""),
            resource_version=p.get("resource_version", ""),
        )

        response_code = int(p.get("response_code", 200))
        source_ips = list(p.get("source_ips", []))
        user_agent = p.get("user_agent", "")
        verb = p.get("verb", "get")
        request_uri = p.get("request_uri", "")
        annotations = dict(p.get("annotations", {}))

        ts = ns_to_timestamp(activity.time_ns)

        audit_event = audit_pb2.AuditEvent(
            audit_id=audit_id,
            stage=stage,
            level=level,
            request_uri=request_uri,
            verb=verb,
            user=user,
            source_ips=source_ips,
            user_agent=user_agent,
            object_ref=object_ref,
            response_code=response_code,
            response_reason=p.get("response_reason", ""),
            annotations=annotations,
            request_received_timestamp=ts,
            stage_timestamp=ts,
            policy_version=self._policy_version,
            position=audit_pb2.CollectorPosition(
                route=audit_pb2.LOG_FILE_TAIL,
            ),
        )

        gaps: list = []
        derived = _derive_audit(
            audit_event=audit_event,
            history=self._history,
            activity_time_ns=activity.time_ns,
            gaps=gaps,
        )

        completeness = (
            common_pb2.Completeness(gaps=gaps) if gaps else empty_completeness()
        )

        # Use AUDIT_REQUEST_RECEIVED for the RequestReceived stage; AUDIT_STAGE
        # for all other stages (ResponseStarted, ResponseComplete, Panic).
        if stage == "RequestReceived":
            basis = common_pb2.AUDIT_REQUEST_RECEIVED
        else:
            basis = common_pb2.AUDIT_STAGE

        ev_id = event_id("audit", audit_id, stage)

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.AUDIT,
            source_native_id=audit_id,
            source_stage=stage,
            action_id=audit_id,
            time=make_time_info(activity.time_ns, basis),
            audit=audit_event,
            audit_derived=derived,
            completeness=completeness,
            normalizer_version=normalizer_version,
            context_version=context_version,
            capture_manifest_version=capture_manifest_version,
        )


# ---------------------------------------------------------------------------
# Derivation logic
# ---------------------------------------------------------------------------

def _derive_audit(
    audit_event: "audit_pb2.AuditEvent",
    history: WorldHistory,
    activity_time_ns: int,
    gaps: list,
) -> "normalized_pb2.AuditDerived":
    """Compute all AuditDerived fields. Appends JOIN_UNCERTAIN gap when needed."""
    user = audit_event.user

    # Authentication failure: 401 response or no username/uid present
    auth_failed = (
        audit_event.response_code == 401
        or (not user.username and not user.uid)
    )

    # Principal: user.uid (STRENGTH_HIGH when uid present) else username;
    # absent on failed authentication.
    principal = None
    if not auth_failed and (user.uid or user.username):
        principal = make_entity_ref(
            entity_type=common_pb2.USER,
            uid=user.uid,
            namespace="",
            name=user.username,
            strength=(
                common_pb2.STRENGTH_HIGH if user.uid else common_pb2.STRENGTH_MEDIUM
            ),
        )

    # observed_source: last source_ips entry (TCP peer)
    observed_source = user.extra  # avoid shadowing; set properly below
    observed_source = (
        audit_event.source_ips[-1] if audit_event.source_ips else ""
    )

    # Extract token-binding and credential fields from user.extra
    extra = user.extra
    bound_pod_uid = _extra_first(extra, _POD_UID_KEY)
    bound_pod_name = _extra_first(extra, _POD_NAME_KEY)
    unverified_node_name = _extra_first(extra, _NODE_NAME_KEY)
    unverified_node_uid = _extra_first(extra, _NODE_UID_KEY)

    raw_cred = _extra_first(extra, _CRED_ID_KEY)
    used_credential_id = None
    if raw_cred is not None:
        # Strip "JTI=" prefix if present
        used_credential_id = (
            raw_cred[4:] if raw_cred.startswith("JTI=") else raw_cred
        )

    # resolved_target_pod_uid: for pods/* requests only, via unambiguous name lookup
    resolved_target_pod_uid = None
    obj = audit_event.object_ref
    if obj.resource == "pods" and obj.namespace and obj.name:
        pod_state = history.at("Pod:name", obj.name, activity_time_ns)
        if (
            pod_state is not None
            and pod_state is not Ambiguous
            and getattr(pod_state, "namespace", "") == obj.namespace
        ):
            resolved_target_pod_uid = pod_state.uid

    # peer_caller_pod_uid: last source_ip -> PodIP history
    # Absent when ambiguous; JOIN_UNCERTAIN gap recorded.
    peer_caller_pod_uid = None
    if observed_source:
        ip_state = history.at("PodIP", observed_source, activity_time_ns)
        if ip_state is Ambiguous:
            gaps.append(completeness_gap(
                reason=common_pb2.JOIN_UNCERTAIN,
                scope="field=peer_caller_pod_uid",
                detail=(
                    f"Pod IP {observed_source} ambiguous at request time"
                ),
            ))
        elif ip_state is not None:
            peer_caller_pod_uid = ip_state.uid

    # Assemble keyword arguments; only set optional fields that are present.
    kw: dict = {
        "authentication_failed": auth_failed,
        "observed_source": observed_source,
    }
    if principal is not None:
        kw["principal"] = principal
    if used_credential_id is not None:
        kw["used_credential_id"] = used_credential_id
    if bound_pod_uid is not None:
        kw["bound_pod_uid"] = bound_pod_uid
    if bound_pod_name is not None:
        kw["bound_pod_name"] = bound_pod_name
    if unverified_node_name is not None:
        kw["unverified_node_name"] = unverified_node_name
    if unverified_node_uid is not None:
        kw["unverified_node_uid"] = unverified_node_uid
    if resolved_target_pod_uid is not None:
        kw["resolved_target_pod_uid"] = resolved_target_pod_uid
    if peer_caller_pod_uid is not None:
        kw["peer_caller_pod_uid"] = peer_caller_pod_uid

    return normalized_pb2.AuditDerived(**kw)


def _extra_first(extra: dict, key: str) -> Optional[str]:
    """Return the first value of an AuditUser.extra key, or None if absent."""
    ev = extra.get(key)
    if ev is None:
        return None
    vals = ev.values
    return vals[0] if vals else None
