# Fault-plan contract, version faultplan.v0

Experiment 3 runs every fault variant on the same frozen base stream
([evaluation-plan.md](../../docs/plans/evaluation-plan.md), section 4;
[dataset-generator-design.md](../../docs/plans/dataset-generator-design.md),
sections 4–6). A fault plan says which records to drop, delay, alter or
fabricate; the injector applies it deterministically and logs every effect.
Example: [example-plan.yaml](example-plan.yaml).

## Two stages

The shipping link ([ship-contract.md](../kafka/ship-contract.md)) delivers
each lane in order and retransmits, so a fault on the wire alone would be
undone. Each fault therefore names its stage:

| Stage | Applied by | Meaning | What the pipeline sees |
|---|---|---|---|
| `source` | `faultinject`, a filter in front of the shipper | The sensor or node itself dropped, delayed, mis-timed or fabricated the record, before it was sequenced | Nothing for a dropped record; late, shifted or fabricated records otherwise. No transport gap |
| `transit` | the shipper (`-faults`), after sequencing | The record was sequenced, then lost before delivery | A `GapNotice` naming the exact sequences, so the receiver writes a `DROPPED_BEFORE` completeness record |

Loss-type faults may use either stage, so a variant can test detected or
undetected loss.

## Plan format

```yaml
version: faultplan.v0
seed: 42
faults:
  - id: loss-10          # unique within the plan
    kind: loss
    stage: transit
    rate: 0.10
    select: {sources: [EBPF]}
```

Selector fields (all optional; every field given must match): `sources`
(Source enum names, from `NormalizedEvent.source` or else `Envelope.source`),
`topics`, `event_families` (eBPF), `logical_ids` (`Envelope.logical_id`), and
an event-time window `from` / `to` (RFC 3339, `from` inclusive, `to`
exclusive). Event time is `NormalizedEvent.time.event_time`; a record without
it never matches a time window, `after`, or a time-based fault.

| Kind | Stages | Parameters | Effect |
|---|---|---|---|
| `loss` | source, transit | `rate` (0–1; Exp. 3 predeclares 0–0.4) | Drops each selected record with probability `rate` |
| `outage` | source, transit | `select.from`, `select.to` (required) | Drops every matching record in the window |
| `suppress` | source, transit | `select.logical_ids` (required) | Drops the named records (contradiction suppression) |
| `skew` | source | `offset` (duration, may be negative), `declare_uncertainty` | Shifts `source_time` and `event_time` by `offset`; if declared, raises `clock_uncertainty_ns` to at least `abs(offset)` |
| `delay` | source | `delay` (duration > 0), optional `rate` (default 1) | Emits the record `delay` later in event time, so it arrives out of order |
| `stop` | source | `after` | From the first record with event time ≥ `after`, the node sends nothing more |
| `blind` | source | `after`, at least one selector | Drops matching records with event time ≥ `after` |
| `forge` | source | `after`, `count`, selector for the template | After the first matching record with event time ≥ `after`, inserts `count` fabricated copies |

Faults apply in plan order; once a fault drops a record, later faults do not
see it.

## Determinism

A record is selected by a rate when the top 53 bits of the first 8 bytes of
`SHA-256(seed as 8 bytes big-endian || 0x00 || fault_id || 0x00 || logical_id)`,
read as a big-endian unsigned integer and divided by 2^53, is below the rate. Records without a
`logical_id` use the hex SHA-256 of their canonical envelope bytes instead.
Reruns and retransmissions therefore make identical choices.

## Source-stage output order

Each record gets an emit time: its event time (or, without one, the previous
record's emit time) plus any delay. Output is a stable sort by emit time, so
undelayed records keep their order. Watermark lines are never delayed, so a
delayed record can arrive after a watermark that promised otherwise; that is
the out-of-order case. With `-pace s` (s > 0) records are written at event-time
speed times `s`; with 0 they are written at once.

## Fault log

JSON lines, restricted to the truth side (never given to detectors). The first
line is a header:
`{"header": {"version", "plan_sha256", "seed", "stage", "node"}}`. Every other
line is one effect on one record:
`{"fault_id", "kind", "stage", "logical_id", "topic", "lane", "seq", "action", "detail"}`,
where `seq` is set for the transit stage and `action` is `dropped_unreported`,
`dropped_reported`, `shifted`, `delayed` or `forged`. A transit record is
logged once even when retransmitted. The scorer uses the log to adjust truth
and coverage: a dropped record is never scored as an observed negative.

## Limits

- **Forge** fabricates copies of a template record with new logical IDs; they
  are marked only in the fault log. The schema has no seal-tag field yet (seal
  tags are opaque and verified only by the GO), so invalid-seal forgery is
  added when the GO defines the seal. Sender compromise remains a simulation.
- Time-based faults act on normalized events (the replay stream); raw records
  without an event time are passed through unchanged by them.
- The source stage reads the whole base stream into memory before emitting.
