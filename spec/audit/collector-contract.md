# Audit collector contract (v0, design draft)

Status: **specified, not cluster-validated.** The policy is
[audit-policy.v0.yaml](audit-policy.v0.yaml); records use `AuditEvent` in
[audit.proto](../proto/microtrace/v0/audit.proto). Every claim below cites a
source listed in [SOURCES.md](../SOURCES.md). Anything that depends on a pinned
cluster is marked with its Gap 2 test ID from
[gap2-tests.yaml](../rules/gap2-tests.yaml).

## 1. Two separate paths

| Path | What decides its behavior | What is recorded per run |
|---|---|---|
| API server → backend | `--audit-log-mode` (default `blocking`; batching "not recommended" for `log`) or `--audit-webhook-mode` (default `batch`; events dropped when the buffer overflows) | Backend (`log`, `webhook`, provider export), mode, buffer/batch settings, truncation settings |
| Backend → collector | File tailing, webhook receiver, or provider export API | Collector route, file identity and offsets or provider cursor, collector lag, decode errors |

The collector reads backend output independently of request handling. A tailing
collector does not add request latency. The blocking file write, including disk
pressure, is still on the API request path. A webhook that sends directly to
the collector must use `batch` mode to keep collector processing off the
request path, and that mode can drop events. API latency and collector lag are
measured separately (AUD-API-LATENCY, AUD-LOSS-ROUTE).

## 2. Record identity and time

- `(audit_id, stage)` is the dedup identity. `audit_id` groups stages of one
  request and is the `action_id` for findings derived from that request.
- `request_received_timestamp` is used when a rule claims request initiation.
  `stage_timestamp` is used when it claims the recorded outcome of that stage
  (`TimeInfo.event_time_basis` records which).
- The policy omits `RequestReceived`. Every later stage still carries
  `requestReceivedTimestamp`, so no initiation time is lost for requests that
  reach a later stage.
- Unauthenticated requests are audited at `ResponseStarted` with an empty user.
  B2 therefore keys them by `observed_source` (last `sourceIPs` entry). That
  entry is the TCP peer and may be a NAT address (AUD-FAILED-AUTHN).

## 3. Fields and their meaning

| Field | Meaning | Required by | Optional? |
|---|---|---|---|
| `user.extra["authentication.kubernetes.io/credential-id"]` | JTI of the token **used** for this request (`JTI=<uuid>`) | D1→use join (conditional), G1b, `credential-read-to-use` | Absent for non-JTI credentials and legacy Secret tokens |
| `annotations["authentication.kubernetes.io/issued-credential-id"]` | JTI of a token **issued** by this TokenRequest | Issuance side of the JTI join | Only on `serviceaccounts/token` create |
| `user.extra["authentication.kubernetes.io/pod-uid"]`, `.../pod-name` | Pod binding, which the API server checks when a Pod-bound token is used | D2 | Absent for tokens that are not Pod-bound |
| `user.extra["authentication.kubernetes.io/node-name"]`, `.../node-uid` | Node metadata that is **not** verified at use | Context only; never caller location | Optional |
| `user.username`, `user.groups` | Authenticated principal and request-time groups | B1, B3, H3, F2 | Empty on failed authentication |
| `impersonated_user` | Effective identity when impersonation is used | F2, B*, H3 | Optional |
| `object_ref` | Resource, subresource, namespace, name, sometimes UID | All audit rules | Name or UID may be absent |
| `response_code`, `response_reason` | Outcome of the stage | B1, B2, F2, G2, H3 | Present at outcome stages |
| `request_object`, `response_object` | `EvidenceRef` to protected RBAC bodies | F2 | Absent if stripped, truncated, or level below RequestResponse |
| `policy_version`, `position` | Policy hash or provider record; collector read position | Completeness | Required |

An absent field stays absent. The collector never infers an audit event for a
request it expected but did not observe.

## 4. Loss, truncation, and completeness signals

- **Truncation.** `--audit-log-truncate-enabled` / `--audit-webhook-truncate-enabled`
  are off by default. When enabled and an event exceeds the configured maximum,
  the request and response objects are removed first, and the event is discarded
  if it is still too large. The truncation settings are recorded per run.
  `BODY_STRIPPED` is set when an RBAC mutation event lacks its expected objects
  (AUD-TRUNCATION-OVERSIZE).
- **Provider limits.** A provider export can strip bodies independently of
  kube-apiserver truncation. EKS documents a 1 MB CloudWatch entry limit: larger
  entries are truncated or keep only request metadata. The limit and observed
  effect are recorded in the provider coverage record (`PROVIDER_LIMIT` gap).
- **File rotation.** For `log`, record `--audit-log-maxsize`, `--audit-log-maxbackup`
  and `--audit-log-maxage`. Track `(dev, ino, offset)` across rotation. A rotated
  file the collector did not finish reading is a `DROPPED_BEFORE` gap for its interval.
- **Webhook buffer.** For a batched webhook, record the buffer and batch settings.
  Overflow is loss.
- **Counters.** `apiserver_audit_event_total` counts exported events and
  `apiserver_audit_error_total` counts events dropped on export errors. Both are
  recorded when exposed, but neither proves that the collector received every
  record.
- **No sequence-gap inference.** Audit IDs are UUIDs, not sequence numbers.
- **End-to-end status.** Each interval gets a `SourceCompleteness` record. When
  delivery cannot be established, its status is `DELIVERY_UNKNOWN`.

## 5. RBAC bodies and F2

RBAC request/response objects are stored only as `PROTECTED_RBAC_BODY` evidence.
F2 reconstructs rights before and after the mutation from those bodies or from
the complete versioned watch history in `context.cluster.v0`. It can use the
history instead of a stripped body when the mutation is still attributable to
the audited action (matching object UID, and the resourceVersion transition
observed in one watch stream). A `WatchGap` covering the interval leaves the
comparison incomplete unless the audit body fills it (F2-HISTORICAL-RIGHTS).

## 6. Managed control planes

Use [provider-coverage.template.yaml](provider-coverage.template.yaml). An
inaccessible audit feed is an unsupported capability, not an empty one. B1 and
H3 are marked incomplete when the selected feed lacks read events
(`get`/`list`/`watch`).
