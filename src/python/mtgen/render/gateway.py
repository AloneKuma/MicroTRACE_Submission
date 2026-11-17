"""Gateway renderer: Activity -> NormalizedEvent wrapping GatewayObservation.

Runs the frozen P_A pattern set over path, query, and body. Runs the I_A2
indicator set over the rendered response. Body is capped at BODY_CAP_BYTES
(64 KiB); body-class patterns abstain when the body is truncated, when
observer_loss is set, or when body_context == "json_string_field" (A1
negative control).

A scripted payload that P_A does not match stays unmatched; the renderer
never injects PatternMatch entries that were not produced by running the
frozen artifact regexes.

Listeners (exp2-conflict-origin-cases-plan G3). The edge listener (default)
replaces any client-supplied x-request-id with one it mints: request_id_origin
SENSOR, and the request ID is also the event's native and action ID. The
internal listener keeps a client-supplied ID (Envoy on a non-edge listener)
and generates one only when none is sent; either way the origin is WORKLOAD
(gateway.proto field 16). Its native and action IDs come from the gateway's
own stream ID, so two requests that carry one ID stay two actions. A
request on the internal listener may propagate the ID of the latest edge
request to the calling service (`propagate_from`), as a service does when it
calls downstream while serving that request.
"""
import base64
import hashlib
import hmac
import re
import uuid
from typing import Optional

from microtrace.v0 import (
    common_pb2,
    gateway_pb2,
    normalized_pb2,
)
from .common import (
    NORMALIZER_VERSION, CONTEXT_VERSION, CAPTURE_MANIFEST_VERSION,
    completeness_gap, empty_completeness, event_id, make_time_info,
)
from mtgen.activity import Activity
from mtgen.evidence import EvidenceArchive

# 64 KiB body cap; matches parameter-register.md setting 2026-10-08.
BODY_CAP_BYTES: int = 65536

# Body context value that suppresses body-pattern matching (A1 negative control).
# When an activity sets body_context to this value, the body contains injection
# tokens only inside JSON string field values; those must not produce PatternMatch.
BODY_CONTEXT_JSON_STRING: str = "json_string_field"

EDGE, INTERNAL = "edge", "internal"
# An edge request a service is still serving: its ID may be propagated on the
# service's downstream calls up to this long after it arrived.
PROPAGATE_WINDOW_NS: int = 5_000_000_000

# MatchLocation mapping from YAML location string to proto enum value.
_LOC_MAP: dict = {
    "PATH": gateway_pb2.PATH,
    "QUERY": gateway_pb2.QUERY,
    "REQUEST_BODY": gateway_pb2.REQUEST_BODY,
}


class GatewayRenderer:
    """Renders http_request Activities into NormalizedEvent/GatewayObservation.

    Args:
        pa_artifact:    parsed p_a.v0.yaml dict (patterns list)
        ia2_artifact:   parsed i_a2.v0.yaml dict (indicators list)
        archive:        EvidenceArchive for this run (body chunks stored here)
        redaction_key:  bytes key for HMAC keyed-hash redaction of sensitive
                        query parameters; defaults to a built-in constant
    """

    def __init__(
        self,
        pa_artifact: dict,
        ia2_artifact: dict,
        archive: EvidenceArchive,
        redaction_key: bytes = b"",
    ):
        self._archive = archive
        self._request_counter = 0
        self._pa_version = pa_artifact.get("version", "p_a.v0")
        self._ia2_version = ia2_artifact.get("version", "i_a2.v0")
        self._redaction_key = redaction_key or b"microtrace-redact-v0"
        self._pa_compiled = _compile_pa(pa_artifact)
        self._ia2_compiled = _compile_ia2(ia2_artifact)
        # target service or Pod -> (time, request ID) of its latest edge request
        self._last_edge: dict = {}

    def render(
        self,
        activity: Activity,
        request_id: Optional[str] = None,
        normalizer_version: str = NORMALIZER_VERSION,
        context_version: str = CONTEXT_VERSION,
        capture_manifest_version: str = CAPTURE_MANIFEST_VERSION,
    ) -> "normalized_pb2.NormalizedEvent":
        """Render one http_request Activity into a NormalizedEvent.

        Expected activity.parameters keys:
          path            str   URL path component (required)
          query           str   query string without leading '?' (default "")
          method          str   HTTP method (default "GET")
          authority       str   Host header (default "")
          route           str   gateway route label (default "")
          peer_ip         str   client IP (default "")
          body            str|bytes  request body (default b"")
          body_context    str   "raw" (default) or "json_string_field"
          response_status int   HTTP status code (default 200)
          response_body   str|bytes  response body (default b"")
          observer_loss   bool  flag observer disconnection (default False)
          sensitive_params list[str] query params to redact (default [])
          listener        str   "edge" (default) or "internal"
          client_request_id str x-request-id the client sends; kept on the
                                internal listener only
          propagate_from  str   internal listener without client_request_id:
                                send the ID of this service's latest edge
                                request within PROPAGATE_WINDOW_NS, if any

        Args:
            activity:   Activity with kind "http_request"
            request_id: gateway-minted request ID; auto-generated if None

        Returns:
            NormalizedEvent with record=gateway
        """
        p = activity.parameters
        listener = p.get("listener", EDGE)
        if listener not in (EDGE, INTERNAL):
            raise ValueError(f"unknown gateway listener {listener!r}")
        stream_id = request_id
        if request_id is None:
            # Deterministic: same inputs must give the same request ID
            # (byte-identical builds); the counter separates identical requests.
            self._request_counter += 1
            stream_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"gateway-request:{activity.time_ns}:{self._request_counter}"
                f":{p.get('method', 'GET')}:{p.get('authority', '')}"
                f":{p.get('path', '/')}:{p.get('query', '')}"
                f":{p.get('peer_ip', '')}",
            ))
        if listener == EDGE:
            request_id = stream_id
            origin = common_pb2.SENSOR
            self._last_edge[activity.target_uid] = (activity.time_ns, request_id)
        else:
            request_id = p.get("client_request_id") or self._propagated(activity) or str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"client-request:{stream_id}"))
            origin = common_pb2.WORKLOAD

        path = p.get("path", "/")
        # Accept query_params as an alias for query (catalogue uses query_params)
        query = p.get("query", p.get("query_params", ""))
        method = p.get("method", "GET")
        authority = p.get("authority", "")
        route = p.get("route", "")
        peer_ip = p.get("peer_ip", "")
        body_context = p.get("body_context", "raw")
        response_status = int(p.get("response_status", 200))
        observer_loss = bool(p.get("observer_loss", False))

        body_raw = p.get("body", b"")
        if isinstance(body_raw, str):
            body_raw = body_raw.encode("utf-8")
        # Accept body_prefix_b64 (base64-encoded body prefix) when body is absent
        if not body_raw and "body_prefix_b64" in p:
            try:
                body_raw = base64.b64decode(p["body_prefix_b64"])
            except Exception:
                body_raw = b""

        response_body_raw = p.get("response_body", b"")
        if isinstance(response_body_raw, str):
            response_body_raw = response_body_raw.encode("utf-8")

        # Keyed-hash redaction for sensitive query parameters
        sensitive_params = p.get("sensitive_params", [])
        if sensitive_params and query:
            query = _redact_query_params(query, sensitive_params, self._redaction_key)

        # Cap body at 64 KiB
        body_truncated = len(body_raw) > BODY_CAP_BYTES
        body_bytes = body_raw[:BODY_CAP_BYTES]

        # Body patterns abstain when truncated, observer loss, or JSON string context
        skip_body = body_truncated or observer_loss or (
            body_context == BODY_CONTEXT_JSON_STRING
        )
        matches = _run_pa(
            self._pa_compiled,
            path=path,
            query=query,
            body=body_bytes,
            skip_body=skip_body,
            pa_version=self._pa_version,
        )

        # Response indicators (only when observer has not lost the response)
        response_indicators: list = []
        if not observer_loss:
            response_indicators = _run_ia2(
                self._ia2_compiled,
                response_status=response_status,
                response_body=response_body_raw,
                has_request_match=bool(matches),
                ia2_version=self._ia2_version,
            )

        # Archive body chunk as PROTECTED_HTTP_BODY evidence
        body_chunk_refs: list = []
        if body_bytes:
            ref = self._archive.put(body_bytes, common_pb2.PROTECTED_HTTP_BODY)
            body_chunk_refs.append(ref)

        obs = gateway_pb2.GatewayObservation(
            request_id=request_id,
            route=route,
            method=method,
            authority=authority,
            path=path,
            peer_ip=peer_ip,
            response_status=response_status,
            response_body_bytes=len(response_body_raw),
            matches=matches,
            response_indicators=response_indicators,
            body_truncated=body_truncated,
            observer_loss=observer_loss,
            chunk_lookback_bytes=BODY_CAP_BYTES,
            body_chunks=body_chunk_refs,
            gateway_build="mtgen.v0",
            request_id_origin=origin,
        )

        gaps: list = []
        if observer_loss:
            gaps.append(completeness_gap(
                common_pb2.SOURCE_IDLE,
                "family=gateway",
                "observer_loss set on activity",
            ))
        completeness = (
            common_pb2.Completeness(gaps=gaps) if gaps else empty_completeness()
        )

        ev_id = event_id("gateway", stream_id, "ResponseComplete")

        return normalized_pb2.NormalizedEvent(
            event_id=ev_id,
            source=common_pb2.GATEWAY,
            source_native_id=stream_id,
            source_stage="ResponseComplete",
            action_id=stream_id,
            time=make_time_info(activity.time_ns, common_pb2.GATEWAY_OBSERVATION),
            gateway=obs,
            completeness=completeness,
            normalizer_version=normalizer_version,
            context_version=context_version,
            capture_manifest_version=capture_manifest_version,
        )


    def _propagated(self, activity: Activity) -> Optional[str]:
        """ID of the calling service's latest edge request, while it is served."""
        src = activity.parameters.get("propagate_from")
        last = self._last_edge.get(src) if src else None
        if last is None or not 0 <= activity.time_ns - last[0] <= PROPAGATE_WINDOW_NS:
            return None
        return last[1]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_pa(artifact: dict) -> list:
    """Compile P_A pattern regexes into a list of pattern dicts."""
    result = []
    for p in artifact.get("patterns", []):
        try:
            compiled = re.compile(p["regex"])
        except re.error:
            continue
        locs = [_LOC_MAP[loc] for loc in p.get("locations", []) if loc in _LOC_MAP]
        if locs:
            result.append({
                "pattern_id": p["pattern_id"],
                "locations": locs,
                "regex": compiled,
            })
    return result


def _compile_ia2(artifact: dict) -> list:
    """Compile I_A2 indicators into a list of indicator dicts."""
    result = []
    for ind in artifact.get("indicators", []):
        compiled_regexes = []
        for r in ind.get("body_regexes", []):
            try:
                compiled_regexes.append(re.compile(r))
            except re.error:
                pass
        result.append({
            "indicator_id": ind["indicator_id"],
            "pattern_type": ind.get("pattern_type", ""),
            "status_codes": ind.get("status_codes", []),
            "body_regexes": compiled_regexes,
        })
    return result


def _run_pa(
    patterns: list,
    path: str,
    query: str,
    body: bytes,
    skip_body: bool,
    pa_version: str,
) -> list:
    """Apply compiled P_A patterns and return list of PatternMatch messages."""
    body_str = body.decode("utf-8", errors="replace") if body else ""
    targets = {
        gateway_pb2.PATH: path,
        gateway_pb2.QUERY: query,
    }
    if not skip_body:
        targets[gateway_pb2.REQUEST_BODY] = body_str

    matches = []
    for p in patterns:
        for loc in p["locations"]:
            if loc not in targets:
                continue
            if p["regex"].search(targets[loc]):
                matches.append(gateway_pb2.PatternMatch(
                    pattern_id=p["pattern_id"],
                    pattern_set_version=pa_version,
                    location=loc,
                    chunk_index=0,
                    spans_chunk_boundary=False,
                ))
    return matches


def _run_ia2(
    indicators: list,
    response_status: int,
    response_body: bytes,
    has_request_match: bool,
    ia2_version: str,
) -> list:
    """Apply I_A2 indicators and return list of ResponseIndicator messages."""
    body_str = response_body.decode("utf-8", errors="replace") if response_body else ""
    results = []

    for ind in indicators:
        ptype = ind["pattern_type"]
        matched = False

        if ptype == "status":
            # Status indicators only fire when a P_A request match was present
            if has_request_match and response_status in ind["status_codes"]:
                matched = True
        elif ptype == "body_marker":
            for rx in ind["body_regexes"]:
                if rx.search(body_str):
                    matched = True
                    break
        # "reflection" and "header" types are not implemented yet; they stay unmatched.

        if matched:
            results.append(gateway_pb2.ResponseIndicator(
                indicator_id=ind["indicator_id"],
                indicator_set_version=ia2_version,
            ))
    return results


def _redact_query_params(query: str, sensitive_params: list, key: bytes) -> str:
    """Replace sensitive query parameter values with keyed HMAC-SHA256 hashes."""
    parts = []
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k in sensitive_params:
                tag = hmac.new(key, v.encode("utf-8"), "sha256").hexdigest()[:16]
                pair = f"{k}=redacted_{tag}"
        parts.append(pair)
    return "&".join(parts)
