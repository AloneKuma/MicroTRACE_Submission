# Time-Aware Graph Store contract, version tgs.v0

The TGS is Phase 4's investigation graph (D3_v4.tex, Phase 4 Steps 1–2;
[design-spec.md](../../docs/design/design-spec.md) section 9). It is build step 6 in
[evaluation-plan.md](../../docs/plans/evaluation-plan.md) and the evidence store
read by both Experiment 5 interfaces
([exp5-automated-investigation.md](../../docs/plans/exp5-automated-investigation.md)).
Decided 2026-10-10.

*Update 2026-10-10:* Experiment 5 is now failure recovery and response
integrity (evaluation-plan.md section 4). The investigation comparison is
dropped, so the templates and read interfaces (sections 5 and 6) are kept but
no experiment measures them. Exp. 5 uses the TGS through sections 4 and 8
(snapshots, `check_approval`, consistency cases), the rebuild hashes and the
crash-between-batches test (section 9).

## 1. Authority

The TGS is derived. It reads Kafka and writes only its own Postgres tables. It
never writes to Kafka, never feeds the GO, and cannot confirm a link, change a
score or change incident membership. If it lags or fails, correlation is
unaffected and every graph-backed answer says how far the graph has read. Four
requirements from the paper are checked by tests (section 9):

| | Requirement |
|---|---|
| P1 | Graph updates and hypotheses never change GO-committed links or membership |
| P2 | A snapshot states whether it is complete; only synchronized snapshots are current |
| P3 | The GRE rejects an approval bound to a stale snapshot or an old `v_C` |
| P4 | Hypotheses and gap reports stay separate from confirmed links |

## 2. Inputs and consumption

| Topic | Use |
|---|---|
| `norm.events.v0` | Evidence rows and observed edges |
| `findings.v0` | FINDING nodes and finding-to-entity edges |
| `witness.decisions.v0` | Confirmed-witness edges (status `CONFIRMED` only) |
| `incidents.v0` | Incident versions, speculative paths, node epochs, input frontiers |
| `source.completeness.v0` | Coverage shown with incidents and gap reports |

- Consumer group `graph-view` (already named in `topics.yaml`).
- Each polled batch is applied in **one Postgres transaction that also writes
  the applied offset of every partition it touched** (`applied_offsets`).
  On restart the TGS seeks to the stored offsets; Kafka offset commits are not
  relied on. A crash can never leave data and offsets disagreeing.
- Every write is an idempotent upsert by stable ID (`edge_id`, event ID,
  finding ID, witness ID, `(incident_id, version)`), so a replayed record is
  recognised, not duplicated.
- Each transaction gets an increasing **apply sequence number** `seq`; it is
  the TGS's knowledge time (section 4).
- Rows are written with Postgres `COPY` in bulk inside the transaction.

## 3. Graph model

### Nodes

A node is a typed entity. Types are the existing `EntityType` values plus
`FINDING`, `K8S_OBJECT` (an API object with no type of its own, such as a
Secret or a gateway route; the resource is an edge attribute) and `DB_OBJECT`
(a table or other database object named by the DB audit):

| Paper's term | Node types |
|---|---|
| Findings | `FINDING` |
| Kubernetes entities | `POD`, `CONTAINER`, `NODE`, `NAMESPACE`, `SERVICE_ACCOUNT`, `USER`, `GROUP`, `RBAC_OBJECT`, `TOKEN_INSTANCE`, `K8S_OBJECT` |
| Requests | `HTTP_REQUEST`, `AUDIT_ACTION` |
| Artifacts | `IMAGE`, `FILE_OBJECT`, `PROCESS`, `PROCESS_LINEAGE`, `HOST_PROCESS`, `DB_OBJECT` |
| External destinations | `NETWORK_ENDPOINT`, `FLOW`, `UNAUTHENTICATED_SOURCE` |

Node ID: `(type, uid)` when a UID is present; otherwise `(type, namespace,
name)` marked as a class key. A UID is never invented. On a UID node,
namespace and name are labels, not identity: sources that name one instance
differently reach one node, which keeps the smallest non-empty namespace and
name and the weakest identity status seen, so the stored node does not
depend on arrival order. Normalized events are
not nodes: they are evidence rows that edges reference.

### Identity status

Every node and edge end carries one of:

| Status | From |
|---|---|
| `resolved` | UID present, `STRENGTH_HIGH` |
| `weak` | `STRENGTH_MEDIUM` |
| `class_only` | no UID; namespace and name only |
| `unresolved` | the event's completeness reports `JOIN_UNCERTAIN` for the join |

### Edge types

The paper's partition `E_obs ∪ E_wit ∪ E_hyp` maps to `GraphEdge.edge_type`:

| Edge type | Created from | Merged? |
|---|---|---|
| `OBSERVED` | One normalized event's own actor and object fields (below); finding-to-entity edges ("involves") | Yes, under section 3 "Merging" |
| `CONFIRMED_WITNESS` | A `CONFIRMED` witness (finding to finding), with its witness ID and `decision_version` | Never |
| `HYPOTHESIS` | A GO speculative path (`hypothesis_origin = GO`) or an analyst-template hypothesis (`ANALYST`, section 5) | Never |

### Observed edges: one extractor per record type

Source records already name who acted on what. One extractor per
`NormalizedEvent.record` type reads the actor and object fields and copies
the record's own label. No edge is built from co-occurrence, and every edge
keeps the event ID it came from.

| Record | Actor | Object | Label |
|---|---|---|---|
| eBPF (`RawEbpfRecord`) | `process` (for exec: `parent`) | by `detail`: exec → new process; file access or mutation → file; socket or flow counter → remote endpoint; ptrace → target process; namespace change → node (host namespaces); bpf → node | `event_family` |
| Audit (`AuditEvent`) | `user` (unauthenticated: observed source) | `object_ref` | `verb` |
| Gateway | `peer_ip` endpoint | HTTP request, then request → route (`K8S_OBJECT`, label `routed_to`) | `method` |
| DB audit | `client` endpoint | `object_name` in `database` (`DB_OBJECT`) | `statement_class` |
| Path flow | `src` | `dst` | `flow` (octets as attribute) |
| Admission (`AdmissionDecision`) | admitted resource | each `image_digests` entry | `admission:<verdict>` (policy, rule as attributes) |
| Context (`ObjectObservation`) | Pod | node (`runs_on`), ServiceAccount (`runs_as`), image (`uses_image`), owner (`owned_by`); RBAC subject → role (`bound_to`) | state, valid over its observation interval |

eBPF details that are coverage or control records (loss, clock sample,
projected-token index, raw syscall), and privilege changes (no object), create
no edge. A record missing its actor or object field creates no edge. Node
keys: a process is `node/boot/tgid/start_time` (resolved); a file with an
inode is `node:dev:ino` (weak, no version index), else its path (class only);
an endpoint is `ip:port/protocol` (class only: an address, not an instance).
The extractor version is recorded on every edge (`extractor_version`).

### Time

Two clocks on every edge:

- **Event time** (`event_start`, `event_end`): when it happened, from the
  events' corrected time.
- **Knowledge time** (`knowledge_time` and the apply `seq`): when the TGS
  learned it.

"As of incident version v" selects by knowledge time; investigation windows
("what happened 10:00–10:05") select by event time.

### Scope and storage

- Every normalized event that reaches `norm.events.v0` is stored **in full**,
  as the exact envelope bytes read from Kafka; every finding, witness,
  incident and completeness record likewise.
  The stream is already reduced at the source (capture manifest; the
  generator emits only the manifest's families), and a second filter in the
  TGS would give both Exp. 5 interfaces less evidence than the system
  collected.
- Graph edges are Postgres rows only; no graph topic is published. A lost
  graph is rebuilt from the inputs.
- Basic indexes only: by ID, and by `(entity, event time)`. Time
  partitioning is added only if pilot runs show a need.
- Nothing is deleted during the evaluation; retention follows the raw archive
  ("kept until the evaluation is complete").

### Merging repeated observations

Repeated observed edges merge into one edge with a count and first/last event
time. Merging changes how evidence is displayed, never what is stored:

1. **Every event stays.** `edge_events` holds one row per event: event ID,
   its own event time, its Kafka position and the apply `seq`.
2. **True repeats only.** Edges merge only when actor, object, label and
   identity status are identical.
3. **Trusted and degraded never merge.** Events from a node received at or
   after its node-trust epoch onset, or with no receipt time (as in the GO),
   form a separate edge. An epoch learned after the events moves them to the
   degraded edge in the same transaction, so arrival order never changes the
   result.
4. **Observed edges only.** Witness and hypothesis edges never merge.
5. **History stays exact.** An "as of" view counts only `edge_events` with
   `seq` at or before that point. Edges carry `created_seq` and `closed_seq`
   (closed when their last event moved away, or when a witness stops being
   `CONFIRMED`; reopened if it is confirmed again). Witness history itself is
   one `witnesses` row per distinct published record.
6. **Stable ID.** A merged edge's `edge_id` hashes the merge key (actor,
   object, label, identity status, trusted or degraded), never the first
   event, so a rebuild in another arrival order gives the same IDs.
7. The first/last times are shown as a **span**, not a duration; per-event
   times are one call away.

## 4. Versions and snapshots

- **Correlation version** `v_C = (incident_id, Incident.version, record_sha256)`
  (design-spec.md section 9). `record_sha256` is the key of the record's
  `incident_records` row, so an open incident that changes under one version
  still gets a new `v_C`.
- **History.** Evidence rows (events, findings, witness and incident records,
  `edge_events`) are append-only, each with the `seq` that wrote it. An
  edge's count and span are a summary kept current; its state at any point is
  rebuilt from its `edge_events` and its `created_seq`/`closed_seq`. "As of
  version v" reads what was applied at or before the `seq` at which that
  incident version was applied.
- **Snapshot.** When the TGS applies an incident version it records
  `Snapshot = <v_C, o_t, status_t>`: `o_t` is the applied offset of every
  input partition in that transaction. `sid = SHA-256(v_C, o_t)`. A snapshot
  can also be taken on request.
- **Status**, re-evaluated on every read:

| Status | Rule |
|---|---|
| `current` | Every partition in the version's `input_frontier` has an applied offset at or beyond it, every witness ID the version lists is applied, and no newer version of the incident is applied |
| `lagging` | Not yet caught up; shown, marked lagging |
| `stale` | A different record of the incident (a later open revision, an amendment, or a merge into another incident) has been applied |

  Coverage freshness is reported beside this status: source-completeness
  records are not part of `input_frontier`.
- **GRE check (P3).** An approval is accepted only if (1) its `v_C` matches
  the incident's latest applied record (same version and same
  `record_sha256`), (2) the incident has not been absorbed into another (its
  ID is not an alias), and (3) its `sid` was `current` when issued. A
  rejection names the reason (for example, a finding joined after review).
- **Merges.** An incident absorbed into another keeps its own version
  history under its old ID; an `incident_aliases` table maps old ID to new,
  matching `Incident.aliases`.
- **Rebuild.** Drop the database and replay from the earliest retained
  offsets or the archive. A canonical hash of each incident version's graph
  is taken before and after; they must be equal (section 9).

## 5. Templates, hypotheses and gap reports

- **Templates** are shared task knowledge given to both Exp. 5 investigators;
  the graph interface only automates the check. One template per multi-step
  chain family the generator uses for Exp. 5 incidents, in
  `spec/graph/templates/` (one YAML file each, `tgs-template.v0`): template
  ID, ordered stages (finding types and tactic each, from the rulebook
  mapping), each required or not. The sources that can supply a stage are
  derived from the rulebook's inputs when the library is loaded, so the two
  cannot drift apart. Templates hold no instance fields (UIDs, names, times,
  which stage is missing). The current three (one per design-spec chain) are
  **provisional** until the dataset build fixes the Exp. 5 chain families.
- **Check** (`python -m mtcore.tgs.templates --check`, also run by the
  tests): every finding type exists in the rulebook; every tactic matches its
  mapping; no unexpected keys or instance-like values; at least one required
  stage. "Every Exp. 5 chain family has a template" is added once the
  families exist. The library's hash is frozen before the test
  set is unsealed; tuning uses the development set only.
- **Selection rule**, from observed findings only: a template's score is the
  share of its required stages a member finding covers. The best score wins.
  If the best two tie, or the best is below `tgs.template_min_overlap` (set on
  the development set; UNFROZEN 0.5 in `dev.v0.yaml`), the answer is "no
  template fits" and no gap report is made.
- **Gap report.** For each expected stage with no supporting member finding:
  the finding types and sources that could supply it, and each source's
  status over the incident span from `source.completeness`: available, idle,
  lossy or unknown. A source with no record is `unknown`, never healthy.
- **Hypotheses** live in their own tables (`hypotheses`, `hypothesis_edges`)
  with their origin. GO speculative paths are copied there at ingest (origin
  `GO`). The generator (role `tgs_hyp`: insert hypotheses, read the rest)
  writes one `ANALYST` hypothesis per uncovered stage of the selected
  template, bound to the incident's `v_C` and the template's hash, with its
  gap entry; the stage is a placeholder node `stage:<template>/<stage>`
  between the findings of the nearest covered stages. Generating twice writes
  nothing new. Nothing in them enters links, scores, membership or metrics.

## 6. Read interfaces (Exp. 5)

| List interface (baseline) | Graph interface |
|---|---|
| `list_findings(time_from, time_to, namespace, pod_uid, identity, agent, finding_type, page)` | `get_incident(incident_id, as_of_version)` |
| `get_finding(finding_id)` with evidence references | `neighbours(node, edge_types, time_from, time_to, page)` |
| `get_event(event_id)` | `confirmed_path(finding_a, finding_b, incident_id, as_of_version)` |
| `list_coverage(time_from, time_to, page)` | `gaps_and_contradictions(incident_id, template_id)` |
| `list_witnesses(ids, time_from, time_to, page)` | `graph_as_of(incident_id, version)` |

- Times are RFC 3339 UTC strings; a range is `time_from` and `time_to`,
  either open. `as_of_version` in `confirmed_path` needs `incident_id`.
- One call is one retrieval operation; each page is one call; the page size
  is fixed (50). Records returned are counted per call.
- Python functions in `mtcore`, with a JSON tool wrapper (name, JSON-schema
  parameters, JSON result) for the LLM investigator. Every call goes through
  one logging layer (function, arguments, records returned, time); that log
  is the Exp. 5 measurement. An HTTP server, if ever needed, wraps the same
  functions.
- Signatures are frozen before the test set is unsealed.

### Security

| Risk | Control |
|---|---|
| Investigator writes | Investigators and the GRE use read-only Postgres roles (SELECT only); ingest and hypothesis generation have separate writer roles |
| SQL injection through tool arguments | No raw-SQL tool; fixed functions only; every query parameterized; every argument validated against its JSON schema (type, allowed values, length) |
| Ground truth leakage | Ground truth is not stored in the TGS database; results never include `Envelope.run` (run ID, split) or labels |
| Prompt injection in telemetry | Attacker-controlled text (paths, process names, user agents) is returned only as labelled structured fields; the investigator prompt states tool output is data. Read-only access bounds the effect to a wrong answer, which scoring catches |
| Sensitive content | Raw bodies and token bytes never enter the TGS; references and keyed hashes only |
| Runaway calls | Fixed page size, the per-task call budget, a per-query time limit |
| Credentials and network | Postgres listens on localhost or the private network; passwords from an environment file kept out of git |

## 7. Postgres

A separate Postgres 16 or 17 instance on the analysis host, never the
monitored application database. Plain tables (design-spec.md, "Graph store:
Postgres"); paths use recursive SQL, no graph extension.

## 8. Table 5 consistency tests

| Table 5 case | Harness | Expected |
|---|---|---|
| Observed/hypothetical edge | Insert observed and hypothesis edges that conflict with confirmed links | Integrity hash unchanged; no GO update (P1, P4) |
| Stale graph snapshot | Issue an approval, then apply a newer incident version | GRE rejects (P3) |
| Delayed graph updates | Pause the consumer on chosen partitions | Affected snapshots `lagging`, never `current` (P2) |

The GRE cases (expired, altered, replayed, UID or version conflict,
unauthorized, interrupted, valid) belong to build step 7.

## 9. Required tests

- Integrity: SHA-256 over every incident version's `(incident_id, version,
  finding_ids, link_witness_ids)` and the confirmed edges, before and after
  all investigation and hypothesis runs, is unchanged.
- Rebuild: per-version graph hashes equal before and after a full replay,
  including a replay in a different arrival order (merged edge IDs stable).
- Merging: no event lost (`edge_events` count equals events applied);
  trusted and degraded never share an edge; "as of" counts exclude later
  events.
- Snapshot status: `current` only at or beyond `input_frontier`; `stale`
  after a newer version.
- Crash between batches: restart resumes at stored offsets with no duplicate
  or missing rows.
- Read-only: every write attempted through an investigator role fails.

## Open items

- Node-trust epochs reach the TGS only through incidents; events from an
  epoch node that no incident names stay trusted until one does.
- Cluster context is read from `norm.events.v0` (`CLUSTER_CONTEXT` events);
  the raw `context.cluster.v0` topic is not an input.

- The overlap threshold for template selection (development set).
- The list of Exp. 5 chain families, and so the templates, follows the
  dataset build's Exp. 5 phase.
- Suspected node-trust epochs are not built in the GO; until they are, rule
  3 of "Merging" uses confirmed epochs only.
