# mtgen file overview

`mtgen` is the MicroTRACE synthetic dataset generator. Run it with `python -m mtgen`.

## Core / infrastructure

| File | Purpose |
|---|---|
| `__main__.py` | CLI entry point (`mtgen build`) |
| `specs.py` | Loads the specification YAML files |
| `rng.py` | Deterministic named random streams |
| `simtime.py` | Nanosecond time, protobuf Timestamp and RFC 3339 helpers |
| `ids.py` | Deterministic UIDs and logical IDs per stream |
| `minting.py` | Deterministic ID minting for renderers |

## World and simulation

| File | Purpose |
|---|---|
| `world.py` | Kubernetes world model and lifetime timeline |
| `history.py` | World history interval store |
| `activity.py` | The abstract Activity record produced by the workload and scenario engines |
| `workload.py` | Benign workload engine |
| `scenarios.py` | Runs catalogue (attack) scenarios in the world |
| `netmodel.py` | Accept and fixed-port reconnect delays, shared by background traffic and scenarios |

## Output pipeline

| File | Purpose |
|---|---|
| `emit.py` | Builds envelopes, assigns producer nodes, writes shipper files and the base stream |
| `envelopes.py` | Builds Envelope records with RunContext and serializes them length-delimited |
| `completeness.py` | Source completeness and heartbeat production |
| `truth.py` | Writes the restricted truth tables for a run |
| `evidence.py` | Content-addressed evidence archive per run |

## `render/`

Converts Activity records into NormalizedEvent protos, one renderer per source.

| File | Purpose |
|---|---|
| `audit.py` | Kubernetes audit events (AuditEvent + AuditDerived) |
| `ebpf.py` | eBPF records (RawEbpfRecord + EbpfDerived) |
| `kyverno.py` | Admission decisions |
| `gateway.py` | Gateway observations |
| `offnode.py` | DB audit and path-flow records |
| `context.py` | Object-observation context records |
| `common.py` | Shared helpers: time info, entity refs, completeness gaps, event IDs |

## Tests

Tests live in `src/python/tests/mtgen/`, named by plan phase (`test_p2_05` to `test_p2_10`) plus per-module tests.
