# Kafka keys, logical IDs, ordering, retention, and replay (v0)

Status: **specified, not cluster-validated.** Topics, producers, consumers, and key
types are listed in [topics.yaml](topics.yaml). Values are Protobuf `Envelope`
records ([envelope.proto](../proto/microtrace/v0/envelope.proto)). Key-type and
component codes come from [keys.proto](../proto/microtrace/v0/keys.proto). The
reference implementation of the encodings is
[../tools/mtcodec.py](../tools/mtcodec.py), and the offline check recomputes
every example key and ID with it.

## 1. Record keys

Kafka keys are opaque bytes. MicroTRACE keys are **not** Protobuf-encoded. They
use this length-delimited layout:

```
key = "MT"                      2 bytes, ASCII magic
      key_version               u8   (0 for this contract)
      key_type                  u16 big-endian (KeyType code)
      component_count           u8
      repeated component_count times:
        component_code          u8   (KeyComponent code)
        length                  u32 big-endian
        value                   UTF-8 bytes, no terminator
```

- Components appear in the order `topics.yaml` lists for that key type. Every
  topic using a key type must list the same components; the check verifies this.
- An absent value is never encoded as an empty string. A record missing a key
  component is not routed to that keyed topic. Its gap is recorded instead
  (for example, an unresolved Pod UID produces `JOIN_UNCERTAIN`).
- **Partitioner.** Every producer uses the Java-client default for keyed
  records, murmur2 of the key bytes modulo the partition count. librdkafka
  defaults to `consistent_random` (CRC32), so librdkafka producers must set
  `partitioner=murmur2_random`, which is documented as equivalent to the Java
  default. A mismatch splits one key across partitions (KAFKA-KEY-PARTITION).
- Partition counts and key serializers are frozen per topic generation (`.v0`).
  Changing either creates a new generation through a versioned restream.

## 2. Logical IDs

IDs hash a canonical encoding of named **logical** fields. They never hash
Protobuf wire bytes, because deterministic Protobuf serialization is not
canonical across versions, builds, or libraries.

```
canonical = "MTID" | u8 id_version (0) | u8 len(kind) | kind (ASCII)
            | u8 field_count
            | per field, in the declared order:
                u8 field_index (1-based) | u32be len(value) | value
value of a string field = UTF-8 bytes
value of a list field   = u32be item_count | per item: u32be len | UTF-8 item
                          (items sorted by byte order when declared "sorted")
id = prefix + "_" + lowercase hex of the first 16 bytes of SHA-256(canonical)
```

| Kind (prefix) | Fields, in order | Notes |
|---|---|---|
| `event` (`ev`) | `source`, `source_native_id`, `source_stage`, `payload_version` | The same ID for raw and normalized forms of one source record at one payload version. |
| `lineage` (`ln`) | `node_id`, `boot_id`, `tgid`, `start_time_ns` (decimal) | Lineage-root process key; used in `KEY_LINEAGE` and `KEY_POD_LINEAGE`. |
| `finding` (`fd`) | `finding_type`, `input_event_ids` (sorted), `detector_version` | Matches contracts.md. |
| `witness` (`wt`) | `relationship_type`, `source_finding_id`, `target_finding_id`, `evidence_event_ids` (sorted) | Matches contracts.md. |
| `incident` (`in`) | `anchor_finding_id` | Recomputed on merge; the previous ID becomes an alias. |
| `path` (`pt`) | `finding_ids` (ordered) | Order is the path order. |
| `ground_truth` (`gt`) | `run_id`, `action_seq` (decimal) | Harness action; see [../data/ml-data-design.md](../data/ml-data-design.md). |
| `evaluation` (`rv`) | `rule_id`, `state_key_hex`, `window_end` (RFC 3339), `detector_version` | One rule evaluation per key and window. |
| `graph_node` (`gn`) | `node_type`, `uid` (empty when absent), `namespace`, `name` | TGS node; never on Kafka ([tgs-contract.md](../graph/tgs-contract.md)). |
| `graph_edge` (`ge`) | `edge_type`, `source_node`, `target_node`, `label`, `identity_status`, `trust` | TGS edge; the merge key, so repeated observations share one ID. A witness edge's `label` is its witness ID. |

`source_native_id` per source:
- eBPF: `node_id/boot_id/node_seq`.
- Audit: `audit_id` (the stage is a separate field).
- Gateway: `request_id`.
- Kyverno: `admission_request_uid/policy/rule`.
- Context: `uid/resource_version/change_type`.
- Database audit (off-node): `record_id`.
- Path flow (off-node): `observer_id/exporter_flow_id`.

A source record without a native ID receives a collector-assigned durable ID at
first capture, and raw replay keeps it.

The truncation to 128 bits is a stated design choice. The collision probability
for evaluation-scale record counts is negligible, but it is not zero. Consumers
that detect two different payloads under one ID raise an error rather than
merging them.

## 3. Ordering: what is and is not claimed

- Kafka guarantees the write order of records within one partition only. No
  MicroTRACE rule uses an order across partitions or topics.
- Correlation orders findings by corrected event time after the watermark, with
  ties broken by stable finding ID.
- **Keyed state (H4, E3, H5).** Keying gives *co-location*: every record of a key is
  on one partition of the agent topic. Offsets are not the ordering authority,
  because a normalizer rebalance can interleave writes from two producer
  instances. Order comes from the source:
  - **H4** (`agent.H.lineage.v0`, key `(POD_UID, LINEAGE_ID)`). A Pod runs on one
    node. The data read and the outbound transfer are both eBPF records of that
    node, so `(node_id, boot_id, node_seq)` orders them totally. The agent
    buffers each key until the watermark passes and sorts by that tuple. A
    `node_seq` gap in the key's interval makes the result `DROPPED_BEFORE` and
    H4 abstains. A reboot changes `boot_id` and ends every lineage
    (KAFKA-RESTREAM-ORDER).
  - **E3** (`agent.E.v0`, key `(POD_UID, CONTAINER_NAME)`). The container name is
    stable across a same-Pod restart while the container ID changes. The write
    and the re-execution are both eBPF records of the same node and are ordered
    by `node_seq`. The restart indicator (changed container ID in eBPF, and
    `restartCount` in context) is corroboration ordered by event time. E3
    remains conditional on artifact identity.
  - **H5** (`agent.H.offnode.v0`, key `(SOURCE_ADDRESS)`). The database read and
    the path flows come from two off-node sources with no shared sequence, so
    the agent orders them by corrected event time and abstains when the read
    and the flow interval are not separated by both clock uncertainties. A
    flow record arrives at its active or idle timeout, so the lateness
    allowance must cover the active timeout (OFFNODE-FLOW-EXPORT).
- `raw.ebpf.v0` is keyed by node only. The earlier node-plus-sequence key
  (contracts.md, before v0) gave every record a different key and scattered one
  node's events across partitions.

## 4. Watermarks and heartbeats

- Each producer instance writes a `Heartbeat` to **every** partition it may
  write, by explicit partition number, at the frozen heartbeat interval.
  `low_watermark` promises that the instance writes no later record to that
  partition with an earlier `event_time`.
- The partition watermark is the minimum over active instances. The consumer
  watermark is the minimum over its input partitions, minus the lateness
  allowance, applied once.
- An instance silent for longer than the max-idle timeout is excluded, and every
  incident open over that interval records the exclusion. Heartbeats show
  silence, not honest telemetry from a compromised producer (KAFKA-HEARTBEAT).

## 5. Delivery and replay

- Producers enable idempotence, which removes retry duplicates within a producer
  session. Replays and cross-session duplicates are removed by consumers using
  `logical_id` (KAFKA-REPLAY-DEDUP). Kafka-to-Kafka stages may instead use transactions with
  `read_committed`. No end-to-end exactly-once claim is made.
- **Retention.** Set both `retention.ms` and `retention.bytes`.
  `retention.bytes` applies **per partition**, and byte eviction can remove
  records younger than `retention.ms`. The time floor for `R_raw`, `R_norm`,
  `R_agent`, `R_decision` must be at least the replay lookback of every
  consumer, plus the lateness allowance and margin. Agent topics need at least
  `max(W_H, W_E)` plus lateness plus margin. The earliest retained timestamp is
  monitored and compared with the time floor (KAFKA-RETENTION).
- **Replay levels.** Finding-stream replay reproduces correlation under frozen
  correlation code and parameters. Raw replay also needs frozen normalization,
  detectors, baseline and declared artifacts, the capture manifest, and the same
  event-time and lateness rules. It starts at `t - max(W_H, W_E)` for agent state.

## 6. Schema compatibility

- `schema_major` changes only for a breaking change, and consumers reject a major
  they do not implement (KAFKA-SCHEMA-REJECT). `schema_minor` adds fields only.
- Field numbers and names are never reused. A removed field is `reserved` by
  number and name.
- Enum values are only added. A consumer that sees an unknown enum value treats
  it as unspecified, and the dependent rule abstains.
- Credential bytes, raw HTTP bodies, and RBAC objects never appear in any value.
  They are referenced by `EvidenceRef`.
- Protobuf JSON is used only for examples and tests; the Kafka value is binary
  Protobuf.
