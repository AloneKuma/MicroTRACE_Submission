# Shipping contract (node to ingest receiver), version ship.v0

This is the wire spec for the log-shipping design in
[design-spec.md](../../docs/design/design-spec.md) ("Log shipping"). Messages:
[ship.proto](../proto/microtrace/v0/ship.proto). Records it delivers follow
[kafka-contract.md](kafka-contract.md).

## Roles

- **Shipper**, one per sending node. Takes records from the node agent (or,
  in replay, from the generator), assigns sequence numbers, keeps them in an
  on-disk spool until acknowledged, and sends them to the receiver.
- **Ingest receiver**, on the analysis host. The only writer to Kafka for
  shipped records. Kafka's `LogAppendTime` on the topics it writes is the
  receipt time.

## Transport and identity

- gRPC bidirectional stream (`Ingest.Ship`) over TLS 1.3 with a client
  certificate per node. The certificate's common name is the node ID.
- The first message is `Hello`. Its `node_id` must equal the certificate's
  node ID, and every `BatchHeader.node_id` and `boot_id` must equal the
  `Hello`. Otherwise the receiver sends `Reject` and closes the stream.
- A new stream for the same `(node_id, boot_id)` replaces the old one.

## Sequences, spool and acknowledgement

- Each `(node_id, boot_id, lane)` has its own sequence starting at 1, assigned
  by the shipper when a record enters the spool, before anything can drop it.
- The spool is written and fsynced before a record may be sent. It is bounded
  in bytes; acknowledged records are removed.
- The receiver answers `Hello` with `Welcome`: its durable next-expected
  sequence per lane. The shipper resends from there.
- The receiver accepts each lane **in order only**. Items below the expected
  sequence are duplicates: skipped and acknowledged. A batch starting above the
  expected sequence gets `Nack` from the expected sequence.
- `Ack(lane, n)` is sent only after Kafka has acknowledged every item up to
  `n` (`acks=all`, idempotent producer) and the receiver has durably stored
  `n + 1` as the next expected sequence.
- If Kafka rejects or times out, the receiver sends `Nack` and the shipper
  resends after a backoff. A receiver crash between the Kafka write and its
  state write can duplicate items in Kafka; consumers remove them by
  `logical_id` (kafka-contract.md, "Delivery and replay").

## Lanes

- `PRIORITY`: escape-class records, sent one per batch, never batched or
  enriched.
- `NORMAL`: batched by count or linger time.

## Integrity and checks

- `payload_sha256` is the lowercase hex SHA-256 over the deterministic
  serialization of each item, concatenated in order. A mismatch is a `Reject`.
- Items must have contiguous sequences matching `first_seq` and `count`.
- Each item's topic must be on the receiver's allowlist, its `key_type` must
  equal the topic's key type in [topics.yaml](topics.yaml), and it must carry
  one non-empty value per declared key component. The receiver encodes the
  Kafka key from those values. Envelopes are never altered.

## Loss is reported, never silent

- When the spool overflows, the shipper drops the oldest unacknowledged
  records and sends `GapNotice` for the dropped range, with the sources of the
  dropped records.
- When `Welcome` asks for a sequence the spool no longer holds (for example,
  dropped before a restart), the shipper sends `GapNotice` for the missing
  range.
- A `GapNotice` must start at the lane's expected sequence. The receiver
  writes one `SourceCompleteness` record per named source (or one with
  `SOURCE_UNSPECIFIED` when none is named) to `source.completeness.v0`:
  status `INCOMPLETE`, scope `node=<id>/boot=<boot_id>/lane=<lane>`, and a
  `Gap` with reason `DROPPED_BEFORE` whose detail names the exact sequence
  range. The expected sequence then moves past the range.
- **Gap times** *(added 2026-10-08)*. Agents abstain when a rule window
  overlaps a gap, so a gap carries an event-time range. When the shipper
  still holds the dropped records (spool overflow, transit faults), it sets
  `GapNotice.from` and `to` to the earliest and latest event time among them.
  When it does not (records lost before a restart), it leaves them unset. The
  receiver then takes `from` from the lane's last accepted event time, which
  it keeps in its durable lane state. It holds the gap, also durably, until
  the next accepted item on that lane, whose event time becomes `to` (unset
  when that batch's items carry no event time, as raw eBPF records do). If the
  stream closes or the node goes idle first, the record is written with `to`
  unset, and consumers treat it as open-ended.

## Watermarks and heartbeats

- Each lane carries the sender's low watermark (in `BatchHeader` or a
  `Watermark` message): no later item on that lane has an earlier event time.
  The shipper only forwards watermarks its input declares.
- The receiver is the Kafka producer instance for shipped records. At the
  heartbeat interval it writes a `Heartbeat` to every partition, by explicit
  partition, of every allowlisted topic whose kinds include `HEARTBEAT`, with
  `low_watermark` = the minimum over active node lanes (the Unix epoch while
  any active lane has declared none).
- A node with no stream activity for longer than the max-idle timeout gets one
  `SourceCompleteness` record with a `SOURCE_IDLE` gap and is left out of the
  minimum until it is active again.
- **Idle nodes in event time** *(2026-10-08)*. The idle gap is expressed in
  event time, not wall-clock time, so it holds for replay faster than real
  time. It starts at the node's latest accepted event time (unset if none) and
  has no end. The first item with an event time that the node sends afterwards
  ends it: the receiver writes a second `SOURCE_IDLE` record with the same
  start and `to` = that item's event time, and consumers use it to close the
  open gap. Both the open state and its start are kept in the durable lane
  state.
