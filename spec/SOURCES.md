# Primary sources for the Gap 1 artifacts

Checked on 2026-09-27. Each row names the claim the artifact relies on. A claim
that depends on a pinned cluster or export is also a named Gap 2 test in
[rules/gap2-tests.yaml](rules/gap2-tests.yaml). Documentation defaults describe
upstream behavior; they are not observations of any MicroTRACE cluster.

## Kubernetes

| Source | Claim used |
|---|---|
| [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) ([page source](https://github.com/kubernetes/website/blob/main/content/en/docs/tasks/debug/debug-cluster/audit.md)) | The first matching rule sets the level. `Metadata` has no bodies; `RequestResponse` has request and response bodies (not for non-resource requests). The stages are RequestReceived, ResponseStarted, ResponseComplete, and Panic, and `omitStages` suppresses a stage. The backends are `log` and `webhook`. `batch`, `blocking` and `blocking-strict` modes exist; `blocking` is the log default, and batching is "not recommended" for `log`. Batch buffer overflow drops events. Truncation is off by default; when enabled, objects are removed first and the event is then discarded if still too large. `apiserver_audit_event_total` and `apiserver_audit_error_total` exist. |
| [kube-apiserver flags](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/) | `--audit-log-mode` defaults to `blocking`; `--audit-webhook-mode` defaults to `batch`. Truncation flags exist per backend. |
| [apiserver `authn_audit.go`, release-1.32](https://github.com/kubernetes/kubernetes/blob/release-1.32/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authn_audit.go) | A request that fails authentication is audited with stage `ResponseStarted`, and the rule's `omitStages` apply. No authenticated user is set. |
| [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) | `user.extra` carries `authentication.kubernetes.io/credential-id` (`JTI=<uuid>`), `pod-name`, `pod-uid`, `node-name`, and `node-uid`. The node information "is **not** verified by the kube-apiserver when the token is used". |
| [KEP-4193](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/4193-bound-service-account-token-improvements/README.md) | `authentication.kubernetes.io/issued-credential-id` is the TokenRequest audit annotation; `credential-id` appears on later requests made with the token. |
| [Projected volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/) | `expirationSeconds` defaults to 1 hour, with a 10-minute minimum. A `subPath` mount of a projected volume receives no updates. |
| [kubelet `token_manager.go`, release-1.32](https://github.com/kubernetes/kubernetes/blob/release-1.32/pkg/kubelet/token/token_manager.go) | A token is refreshed when it is older than 80% of its TTL or older than 24 hours. |
| [kubelet `atomic_writer.go`, release-1.32](https://github.com/kubernetes/kubernetes/blob/release-1.32/pkg/volume/util/atomic_writer.go) | Projected files live in a timestamped `..YYYY_MM_DD_hh_mm_ss.*` directory. The `..data` symlink is swapped atomically, and user-visible names link through `..data`. |
| [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Permissions are purely additive. The control plane fills the rules of aggregated ClusterRoles. `system:masters` has unrestricted access. `escalate` and `bind` exist. |
| [Authorization overview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) | Authorizers are checked in sequence. The first allow **or deny** wins, and "no opinion" passes the request to the next authorizer. |
| [kubernetes/kubernetes#78741](https://github.com/kubernetes/kubernetes/issues/78741) | Exec over the WebSocket endpoint was authorized with `get` on `pods/exec`, while SPDY used `create`. The verb recorded on the pinned version is therefore checked (AUD-EXEC-VERB), not assumed. |

## Managed providers

| Source | Claim used |
|---|---|
| [EKS best practices: auditing and logging](https://docs.aws.amazon.com/eks/latest/best-practices/auditing-and-logging.html) | EKS publishes its audit policy and sends audit logs to CloudWatch Logs. "Log entries greater than 1MB will either be truncated or only include the request metadata." |
| [GKE audit policy](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/audit-policy) | Writes go to the Admin Activity log and reads (`get`, `list`) to the Data Access log, whose content depends on the audit log configuration. Secrets are logged at Metadata. The default Data Access state is **not** asserted. |
| [Monitor AKS](https://learn.microsoft.com/en-us/azure/aks/monitor-aks) | `kube-audit-admin` "excludes the `get` and `list` audit events". |

## Kafka

| Source | Claim used |
|---|---|
| [Kafka introduction](https://kafka.apache.org/intro/) | Consumers read a topic-partition's events in the order they were written. No cross-partition order is claimed. |
| [`TopicConfig.java`](https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/common/config/TopicConfig.java) | `retention.bytes` is enforced per partition, and `retention.ms` is the time limit for deletion. |
| [`BuiltInPartitioner.java`](https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/clients/producer/internals/BuiltInPartitioner.java) | A keyed record's partition is `toPositive(murmur2(key)) % numPartitions`. |
| [librdkafka CONFIGURATION.md](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md) | The default `partitioner` is `consistent_random` (CRC32). `murmur2_random` is "functionally equivalent to the default partitioner in the Java Producer". |

## Archive and broker settings

| Source | Claim used |
|---|---|
| [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) | Works only with versioning. Compliance mode cannot be deleted by any user before retention ends; governance mode can be bypassed with `s3:BypassGovernanceRetention`; legal holds have no expiry. |
| [Kafka 4.0 upgrade notes](https://kafka.apache.org/40/getting-started/upgrade/) | Kafka 4.0 supports only KRaft; ZooKeeper mode is removed. |
| [`ProducerConfig.java`](https://github.com/apache/kafka/blob/trunk/clients/src/main/java/org/apache/kafka/clients/producer/ProducerConfig.java) | Java producer defaults: `acks=all`, `enable.idempotence=true`. |

## Gateway (Envoy)

Checked on 2026-10-06.

| Source | Claim used |
|---|---|
| [HTTP header manipulation: x-request-id](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers) | Envoy generates `x-request-id` for all external-origin requests (the header is sanitized) and for internal requests that lack one; an internal request's existing ID is kept. A request is edge only when `use_remote_address` is true and the downstream address is external; `use_remote_address` defaults to false. |
| [HttpConnectionManager API](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto) | `generate_request_id` defaults to true; `preserve_external_request_id` (keep the ID on edge requests) defaults to false; `internal_address_config` defaults to RFC1918 addresses being internal. |

## Protocol Buffers

| Source | Claim used |
|---|---|
| [Proto serialization is not canonical](https://protobuf.dev/programming-guides/serialization-not-canonical/) | Hashes of serialized protos "are fragile and not stable across time or space", so IDs hash logical fields instead. |
| [Proto3 language guide](https://protobuf.dev/programming-guides/proto3/) | Field numbers are never reused, deleted fields and names are `reserved`, and adding fields or enum values is safe. |
