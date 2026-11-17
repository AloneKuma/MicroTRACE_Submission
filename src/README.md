# MicroTRACE implementation

Code for the evaluation in [docs/plans/evaluation-plan.md](../docs/plans/evaluation-plan.md).
Go for node-side services, Python for the analysis side. Message formats come
from [spec/proto](../spec/proto); Kafka topics from [spec/kafka/topics.yaml](../spec/kafka/topics.yaml).

| Folder | Contents |
|---|---|
| `scripts/` | Toolchain setup, code generation, Kafka and Postgres start and stop |
| `kafka/` | Development topic settings (partitions, retention) |
| `go/` | Go module: `cmd/receiver` and `cmd/shipper` (the shipping link), `cmd/faultinject`, `cmd/devcerts`, `cmd/trace-check` |
| `python/mtcore/` | Analysis-side package: `agents/` (agents A-H, step 4), `restream.py`, `orchestrator/` (Global Orchestrator, step 5), `tgs/` (graph store, step 6), `gre/` (response executor, step 7) |
| `params/` | Agent and orchestrator parameter sets (`dev.v0.yaml` is a placeholder set, never used for results) |
| `python/tests/` | Tests |

Generated code (`go/gen/`, `python/gen/`) is not committed.

## Development host setup

Everything installs under one folder (default `~/microtrace-dev`), with no
system-wide changes: Python 3.12 (via uv) and a venv, Go, JDK 21, Kafka 4.3,
and Postgres 17 (built from source; needs gcc and make). Every download is
checked against its published checksum.

```sh
bash src/scripts/setup-dev-host.sh
source ~/microtrace-dev/env.sh
bash src/scripts/gen-proto.sh
(cd src/go && go build -o "$MT_DEV/bin/trace-check" ./cmd/trace-check)
bash src/scripts/kafka-up.sh                 # single node, 127.0.0.1 only
bash src/scripts/pg-up.sh                    # TGS Postgres, 127.0.0.1:55432
source ~/microtrace-dev/pg.env               # its generated credentials
(cd src/python && python -m mtcore.kafka_topics)
(cd src/go && go test -race ./...)
(cd src/python && python -m pytest -q --basetemp="$MT_DEV/pytest-tmp" tests)
bash src/scripts/pg-down.sh                  # --wipe also deletes data and credentials
bash src/scripts/kafka-down.sh               # --wipe also deletes its data
```

## Shipping link (step 2)

The shipper sends records to the ingest receiver over gRPC with TLS 1.3 and a
client certificate per node; the receiver is the only writer to Kafka. Wire
format and rules: [spec/kafka/ship-contract.md](../spec/kafka/ship-contract.md).

```sh
(cd src/go && for c in receiver shipper devcerts; do go build -o "$MT_DEV/bin/$c" ./cmd/$c; done)
devcerts -out "$MT_DEV/certs" -nodes node-1          # development only
C="$MT_DEV/certs"
receiver -cert $C/receiver.crt -key $C/receiver.key -ca $C/ca.crt \
  -topics spec/kafka/topics.yaml -state "$MT_DEV/rx-state"
shipper -node-id node-1 -cert $C/node-cert-node-1.crt -key $C/node-cert-node-1.key \
  -ca $C/ca.crt -spool "$MT_DEV/spool" -input records.jsonl -drain
shipper -status -spool "$MT_DEV/spool" -boot-id <boot>   # where a restarted producer resumes
```

Input lines: `{"lane","topic","key_type","key_components","envelope"}` or
`{"lane","watermark"}` (see `cmd/shipper`). The shipper's `-boot-id` defaults
to the host's boot ID; a new value starts new sequences.

## Fault injection (step 3)

Experiment 3 faults follow [spec/faults/fault-contract.md](../spec/faults/fault-contract.md).
Source-stage faults (skew, delay, stop, blind, forge, unreported loss) run in
`faultinject` before the shipper; transit-stage faults (reported loss, outage,
suppression) run inside the shipper after sequencing. Both write a fault log
for the scorer only.

```sh
faultinject -plan plan.yaml -node node-1 -log src-faults.jsonl -input base.jsonl -output faulted.jsonl
shipper ... -input faulted.jsonl -faults plan.yaml -fault-log transit-faults.jsonl -drain
```

`kafka-down.sh` stops only the Kafka that `kafka-up.sh` started (by its pid
file); it never stops other Kafka instances on a shared host.

## Agents A-H (step 4)

The 23 finding rules of [spec/rules/rulebook.v0.yaml](../spec/rules/rulebook.v0.yaml)
run in `mtcore/agents` (one module per agent under `rules/`). The engine is
pure Python, so Kafka runs and offline replay give the same findings and IDs.
The restreamer copies `norm.events.v0` into the keyed agent topics and writes
their heartbeats. Each agent writes `findings.v0`, `rule.evaluations.v0` and
heartbeats on both.

```sh
(cd src/python && python -m mtcore.restream)                       # norm.events.v0 -> agent.*.v0
(cd src/python && python -m mtcore.agents.run --agent A,B,C,D,E,F,G,H [--no-ml])
(cd src/python && python -m mtcore.agents.run --offline records.jsonl > out.jsonl)
(cd src/python && python -m mtcore.agents.ml.train --params ../params/dev.v0.yaml     --input pilot.jsonl --out-dir models/)                         # PILOT/RESEARCH only
```

- **Windows and abstention.** Count rules use epoch-aligned tumbling windows;
  join rules (G2, H4, E3, H5, G1b) use windows anchored at the first half.
  Each window is evaluated once, after the watermark passes its end and the
  completeness and context topics have been read to their end offsets as of
  that watermark. A gap on a required source overlapping the window means the
  rule abstains. H5 and G2 windows also reach back (`lookback`): H5 because a
  path flow's event time is its start, G2 by the two clocks' uncertainty.
- **Idle nodes.** A node's `SOURCE_IDLE` gap stops only what that node ships,
  per `shipped_sources` in the parameter set (dev: eBPF only). Without that
  section an idle node stops every source, as before.
- **G1b input.** A token read waiting for its `TokenFileVersion` holds the
  `credential.instance.v0` heartbeat at its time; after `W_w` it is given up
  and reported as a `JOIN_UNCERTAIN` completeness record.
- **Conditional types** D2, E3, F2 and G1b are complete rules behind the gates
  `G_D2`, `G_E3`, `G_F2` and `G_G1b`. They are off by default, which gives
  `CONDITIONAL_JOIN_UNVALIDATED`.
- **Isolation Forest** (B1, B2, B3, G1a, H1): one artifact per agent, made by
  `ml.train`. Trees are exported to JSON and scored with numpy; the scores
  match sklearn's `score_samples`. Predicate OR score >= `gamma`; findings
  record `detection_path`, `anomaly_score`, `model_version` and `ml_status`.
  Set the artifact paths under `ml.models` in the parameter set. `--no-ml` is
  the No-ML ablation.
- **Restarts.** Agents assign every partition by hand (no group session
  timeout on restart) and commit offsets only up to the oldest record an open
  window still needs, including the heartbeats above the watermark that set
  later windows' knowledge time; they re-read completeness and context from
  the start. A side record counts for a window only if its LogAppendTime is
  not after the knowledge time of the update that passed the window's end
  (the newest first heartbeat reaching it per input partition), so a restart
  that reads side topics further first decides as the uninterrupted run
  did. Re-emitted findings keep their IDs. Read and committed offsets are
  logged per commit (`--positions-log` or `MT_POSITIONS_LOG`).
- `argv_sha256` (G2) is the SHA-256 of the arguments joined by NUL; the
  dataset generator must use the same convention.

## Global Orchestrator (step 5)

`mtcore/orchestrator` links findings into incidents. It reads `findings.v0`,
`norm.events.v0` (the event detail that witness checks need and findings do not
carry) and `source.completeness.v0`, and writes `witness.decisions.v0` and
`incidents.v0`. It never reads `ground.truth.v0`. Parameters are in the
`orchestrator:` section of the parameter set; the dev values are UNFROZEN,
taken from the proofs reference model.

```sh
(cd src/python && python -m mtcore.orchestrator.run --offline records.jsonl > decisions.jsonl)
```

Built so far (5a):

- **Watermark.** Per partition, the minimum over active producer instances;
  over partitions, the minimum, minus the lateness allowance once. An instance
  whose heartbeats stop for longer than `max_idle_s` (measured on the
  heartbeats' `emitted_at`, so a replay matches) is excluded and recorded.
- **Processing order.** Findings in `(event_start, finding ID)` order, once
  the watermark passes them. A re-emitted finding (only `publish_time`
  differs) is dropped as a duplicate; a different payload under the same ID
  stops the engine.
- **Evidence index.** Normalized events by event ID, kept until the
  processing frontier is past them by the largest posting horizon
  (`W_w + eps_bar + 2A`) plus `A`.
- **IDs and keys** for witnesses, incidents and paths, checked against the
  example trace.

Witness search (5b):

- **Keys** from sensor fields only: `PROCESS_ANCESTRY` and `HOST_TRANSITION`
  on (node, boot, lineage), `NETWORK_FLOW` on the client/server tuple
  (CONNECT on one side, ACCEPT on the other). A Service address rewritten by
  DNAT does not match (gap2 NODE-SOCKET-FLOW). Conditional types stay off
  (`orchestrator.gates`); enabling types come with paths in 5d.
- **Index** postings are never truncated and are dropped only when the
  processing frontier passes `t + W_w + eps_bar + 2A`. The `no_index` ablation
  (Exp. 4) tests every pair and finds the same pairs.
- **Supported and TimeValid** for each candidate pair, in both directions.
  Direction comes from `node_seq` or connect -> accept, never from timestamps.
  Every ordered event pair is tried, so a finding with several events still
  links when any pair fits the window.
- A pair is tested when its later finding is processed.

Link admission (5c) publishes one witness per supported pair to
`witness.decisions.v0`:

- **Contradictions** (sensor evidence only; degraded evidence is recorded,
  never decisive): a lineage that changes container instance without a host
  transition, and a second CONNECT on the same tuple from another socket
  before the accept (port reuse).
- **Contradiction coverage.** The pair's eBPF nodes must report no loss or
  idle gap over `I = [t_src - eps, t_tgt + eps]`, and no node-trust epoch
  may open before `max(I) + beta`. The status waits until the watermark has
  passed `max(I) + beta + eps_bar`, so the loss records and epoch triggers
  for `I` are in.
- **DistinctAction.** Equal action IDs are one action. Without both IDs,
  disjoint input events decide, but only when the findings' sources report no
  loss within `A` (+ `beta`) of them.
- **Node-trust epochs.** A C1b finding opens an epoch on its node and boot,
  onset = earliest event time minus uncertainty. Evidence from that node
  received at or after the onset is degraded; its pairs are `POST_COMPROMISE`.
  When an epoch opens or moves earlier, witnesses already published on that
  node are re-checked and republished if their status changes.
- **Status:** `CONFIRMED`, `REJECTED` (decisive contradiction, same action,
  outside the window), `UNPROVEN` (uncovered, distinctness unresolved) or
  `POST_COMPROMISE`. Ablations: `no_conflict`, `no_distinct`,
  `no_contra_coverage`, `no_epoch`.
- **Not built yet:** suspected epochs (the trigger rule is undefined: design
  spec 8.11), F1 at host scope as a trigger (F1 needs a Pod UID), link-level
  contradictions (need cluster context).

Groups and paths (5d):

- **Inputs.** The orchestrator also reads `context.cluster.v0` (decided
  2026-10-09) for a Pod image history used by enabling witnesses.
- **Enabling witnesses.** `IMAGE_CLASS`: an admission decision names an image
  digest, and a later finding's event names the same image (an IMAGE entity)
  in a container that, per the Pod context known then, runs it. Published
  `ENABLING_ONLY` with evidence [admission event, context observation]; never
  a link. An event that only runs in the container (a token read) does not
  qualify. `CONTROL_PLANE_CAUSALITY_CLASS` is not built (needs RBAC history).
- **Groups.** Findings with the same action ID count once (the smallest
  finding ID stands for them). Groups are the connected components of
  CONFIRMED links; the anchor is the earliest finding by event time, then
  finding ID (the paper's eq. group-anchor and the proofs model now say the
  same).
- **Scores.** Link score = the strongest witness:
  `q_w * q_ab * q_c * exp(-lambda * delta / W_w)`, with `q_ab = q_unmapped`
  when either finding has no tactic, else the neutral band (no transition
  table yet), and `q_c = 0.8` per nondecisive contradiction. Path score is the
  geometric mean.
- **Paths.** Top-K per group by prefix-suffix joins over links in the order
  they were first CONFIRMED, at most `L` findings and span `T`; identical to
  the proofs model's `topk_paths` on random graphs. Speculative paths come
  from enabling witnesses touching the group.
- **Re-evaluation.** A completeness record re-checks every published witness
  whose interval it overlaps; a link that loses CONFIRMED leaves its group,
  which may split.
- `Engine.groups()` returns `GroupView`s, the input to sealing (5e).
- Enabling types have no window, so they are indexed for `T`; with the dev
  `T` (10 000 s) evidence and keys are kept that long.

Sealing and the Kafka runner (5e):

- **Incidents** (`seal.py`, `IncidentBook`, fed by `Engine.incidents_hook`
  after each advance). A new group is published `INCIDENT_OPEN`, version 1,
  and republished at version 1 while it changes; the latest record per
  incident ID is current. Holding the version makes the sealed record the
  same in a live run and a replay.
- **Seal** when the watermark reaches the group's last extension time: the
  last member's time plus the largest *enabled* direct window plus
  `eps_bar`, capped at anchor + `T`. Lateness is already in the watermark and
  is not added again. `watermark_time` is that time;
  `sealed_prediction_version` is `snapshot-<version>`. Published metrics read
  only the sealed record.
- **Exclusions.** A `SOURCE_IDLE` interval (a node's source-less idle gap
  counts as its eBPF) applies to every incident open over it: from its
  `event_start` to its seal time. Known at seal, it is frozen in
  `at_seal_excluded_sources`; learned later, it is an amendment and joins
  `current_excluded_sources`, which only grows.
- **Amendments.** Any change after seal (members, links, paths, a merge, a
  newly excluded source) is version + 1, `INCIDENT_AMENDED`, with an
  `Amendment` (late finding IDs, reason, time). The sealed snapshot never
  changes. Checked against the example trace's I1 (exactly, except that our
  seal time comes from the parameters, not the trace's illustrative 11:00)
  and I2 (with an idle interval that overlaps I1's open period).
- **Merge.** The incident ID follows the anchor. A group absorbs every
  incident whose anchor it contains; their IDs become `aliases`. A merge
  involving a sealed incident is an amendment and keeps a frozen snapshot.
- **Retirement.** A sealed incident leaves the book once the watermark is a
  posting horizon past its seal and its findings are pruned.
- **Kafka runner** (`python -m mtcore.orchestrator.run`). It reads
  `findings.v0` and `norm.events.v0` (plus `credential.instance.v0` with
  `G_G1b` on), and `source.completeness.v0` and `context.cluster.v0` from the
  start (or from its checkpoint; Restarts below). It advances only once the side topics are read up to
  their end offsets as of the watermark's heartbeats. Heartbeats on every
  partition of `witness.decisions.v0` and `incidents.v0` carry
  `output_low_watermark()`: the watermark, held back by witnesses awaiting
  coverage, open incidents and pending findings. Revisions of published
  records keep their original times and are updates by ID.
- **Ablations** (`ablations.py`): `no_index`, `no_eps_cap` (proofs variant),
  `no_conflict`, `no_distinct`, `no_contra_coverage`, `no_epoch`. An unknown
  name stops the run.
- **Restarts (step 7g).** Every partition is assigned by hand. A coverage or
  context record is known at a decision only if its LogAppendTime is not
  after the knowledge time of the watermark update making it (the newest
  emitted_at among each instance's first heartbeat reaching the threshold;
  `watermark.py`), so a gap arriving after a seal stays an amendment however
  far the side topics were read. `--commit-mode oldest-needed` (default)
  commits the smallest input offset still held (pending and posted findings,
  awaiting pairs, retained evidence) together with a checkpoint file
  (`--checkpoint`, written tmp + fsync + rename): read positions, held
  finding IDs, the side records that can still affect a decision with their
  receipt times, side positions, and the watermark history, epochs and
  incident book. Side state is pruned at each commit below
  B = T_old - (max H_w + A + lateness + eps_bar), T_old being the oldest
  event time held state or a live incident can still look at: closed gaps,
  superseded Pod observations and (once their closing record is known to
  every pending decision) idle intervals ending before B; open-ended gaps
  stay until closed. `--checkpoint-s` sets the commit interval (default:
  every heartbeat; longer means smaller write load but more reprocessing
  after a crash). A restart
  replays from those offsets and does not advance until it reaches the saved
  read position; heartbeats wait until the output low watermark passes the
  last one published. `full-replay` and `read-position` (the old behaviour)
  remain for Exp. 5 runs B and D.
- **Not built yet:** sharding.

Out of scope for step 5: a single shard only (no leader election); onset
sealing; `GraphEdge` (step 6 starts at `witness.decisions.v0` and
`incidents.v0`); the transition table (every tactic pair uses the neutral
band). Open spec items found while building it: the suspected-epoch trigger
(design-spec 8.11), and the paper's witness categories versus the
`WitnessType` enum.

## Time-Aware Graph Store (step 6)

`mtcore/tgs` is the investigation graph of
[spec/graph/tgs-contract.md](../spec/graph/tgs-contract.md). It reads
`norm.events.v0`, `findings.v0`, `witness.decisions.v0`, `incidents.v0` and
`source.completeness.v0` (consumer group `graph-view`) and writes only its
Postgres tables; it never writes to Kafka.

```sh
(cd src/python && python -m mtcore.tgs.run)                          # Kafka, DSN from $MT_TGS_DSN
(cd src/python && python -m mtcore.tgs.run --offline records.jsonl)  # same JSONL as the orchestrator
(cd src/python && python -m mtcore.tgs.run --reset)                  # rebuild: delete rows, replay from the start
(cd src/python && python -m mtcore.tgs.run --print-hash)             # canonical graph hash, before and after
```

Built so far (6a, ingest):

- **Evidence.** Every record is stored as the exact envelope bytes read, with
  indexed columns; findings, witnesses, incidents and completeness records
  once per distinct record (an open incident changes without a version bump,
  so each version can have several records).
- **Observed edges** from one extractor per record type (`extract.py`): the
  record's own actor and object fields and label, never co-occurrence. Node
  identity status: resolved, weak, class only, unresolved (`JOIN_UNCERTAIN`).
- **Merging** (`apply.py`): repeats share one edge whose ID hashes the merge
  key; every event keeps an `edge_events` row. Trusted and degraded evidence
  never share an edge; an epoch learned later moves the affected events.
- **Confirmed-witness edges**, never merged, closed when the witness stops
  being `CONFIRMED`; finding-to-entity `involves` edges.
- **Exactly once.** Each batch and its applied offsets commit in one
  transaction; Kafka offsets are never committed; a restart resumes after the
  last applied offset.
- **Stores.** `PgStore` (COPY for events, edge events and nodes) and
  `MemoryStore` (same semantics; the store tests run on both, the Postgres
  ones only when it is reachable).

Snapshots and rebuild (6b):

- **Correlation version** `v_C = (incident_id, version, record_sha256)`: an
  open incident changes under one version, so the record hash tells its
  states apart.
- **Snapshots** (`snapshot.py`). Each applied incident record gets
  `<v_C, offsets, status>` at the batch's applied offsets,
  `sid = SHA-256(v_C, offsets)`; `take_snapshot` makes one on request.
- **Status**, computed on every read: `stale` if a different record of the
  incident was applied since or it was merged into another (aliases);
  `lagging` until its `input_frontier` and listed witnesses are applied;
  else `current`.
- **`check_approval(v_C, sid)`**, the GRE's graph check: the snapshot exists
  for exactly `v_C`, was `current` when issued, and `v_C` is still the latest
  record. A rejection names the reason.
- **Rebuild** (`hashes.py`). Graph and per-incident hashes cover content only
  (no `seq`, no Kafka positions); a replay in any batch size or arrival order
  gives the same hashes.

Templates, gap reports and hypotheses (6c):

- **Templates** in `spec/graph/templates/`, one per design-spec chain,
  provisional until the dataset build fixes the Exp. 5 chain families.
  `python -m mtcore.tgs.templates --check` validates them against the
  rulebook; stage sources come from the rulebook's inputs.
- **Selection** from observed finding types only: share of required stages
  covered; a tie or a score below `tgs.template_min_overlap` means no
  template fits and no gap report.
- **Gap report** per uncovered stage: candidate finding types and each
  source's status over the incident span (available, idle, lossy, unknown;
  never assumed healthy).
- **Hypotheses** (`hypotheses.py`): GO speculative paths copied at ingest;
  `generate()` writes ANALYST hypotheses with placeholder stage nodes, bound
  to `v_C` and the template hash. They never touch links, scores or
  membership. `pg-up.sh` adds the `tgs_hyp` role.

Exp. 5 read interfaces (6d):

- **Two interfaces** (`interfaces.py`) over the same tables. List
  (baseline): `list_findings`, `get_finding`, `get_event`, `list_coverage`,
  `list_witnesses`. Graph: `get_incident`, `neighbours`, `confirmed_path`,
  `gaps_and_contradictions`, `graph_as_of`. Times are RFC 3339
  (`time_from`, `time_to`); pages hold 50 records.
- **`Session`** runs every call: arguments checked against the call's JSON
  schema, a read-only store (`ReadOnlyStore`), an optional call budget and
  one interface only (`calls=LIST_CALLS` or `GRAPH_CALLS`). Each call, failed
  ones included, writes one log entry `{function, arguments, records,
  duration_ms, error}`: the Exp. 5 effort measurement.
- **`open_session()`** connects as `tgs_reader` (`$MT_TGS_READER_DSN`): 5 s
  statement timeout, and each call is one read-only REPEATABLE READ
  transaction. A timed-out query is a failed call and the next call still
  works.
- **Tools** (`tools.py`): the same calls as Anthropic-format tools for the
  LLM investigator; every description says tool output is data. Results
  never carry `Envelope.run`.
- **Schema 4** adds the columns these filters use (`findings.agent_id`,
  witness finding IDs and source time) and grants `tgs_reader` SELECT in the
  TGS schema. A store holding rows written under an older schema version is
  refused until rebuilt with `--reset`.
- **Schema 5: node IDs follow the contract.** A node with a UID is
  `(type, uid)`; namespace and name are labels. Sources that name one
  instance differently (a gateway request named `GET /path`, the same
  request in a finding with no name) now reach one node. The node keeps the
  smallest non-empty label and the weakest identity status seen, so it does
  not depend on arrival order. Nodes without a UID keep their class key.

Table 5 consistency tests (6e, `tests/test_tgs_table5.py`):

- **Observed and hypothetical edges** that contradict a confirmed link
  leave `integrity_hash` (incident records and confirmed edges) unchanged,
  and nothing in `mtcore/tgs` can write to Kafka (P1, P4).
- **Delayed graph updates:** with the consumer paused on one partition,
  every snapshot of an incident whose frontier needs it is `lagging`, never
  `current`, and a lagging snapshot is never approvable (P2).
- **Stale graph snapshot:** an approval reviewed on an incident version
  is rejected by the GRE once a newer version is applied, and nothing is
  executed (P3).

## Guarded Response Executor (step 7)

`mtcore/gre` executes containment only on a signed analyst approval
(design-spec section 4; evaluation-plan.md section 5, step 7). Exp. 5 drives
it with a scripted approver.

Built so far (7.1, validation; no Kubernetes yet):

- **Request `R_resp`** (`request.py`): rid, gid, sid, v_C, cluster, ns, uid,
  rv, act, params, exp (Unix seconds), nonce (128 bits), evid, approval.
  Four actions with exact parameters: `isolate_pod {pod}`,
  `cordon_node {node}` (no namespace), `scale_to_zero {kind, name}`,
  `revoke_rolebinding {rolebinding}`. The Ed25519 signature covers the
  canonical JSON of every field and the approval's key ID and algorithm.
- **Scripted approver** (`approver.py`): signs a request for an incident's
  latest record, bound to its latest TGS snapshot.
- **Validation** (`validate.py`), fail-closed, first failure rejects: shape,
  signature, expiry (`now < exp`, at most `max_ttl + max_skew` ahead),
  scope (cluster, permitted action, application namespace, never a
  protected one), `gid` is the incident of v_C, TGS `check_approval` (an
  unreachable TGS rejects), then the nonce. Any error inside a check
  rejects.
- **Durable state** (`store.py`, schema `gre`, role `gre_exec`, added by
  `pg-up.sh`): nonces consumed atomically by a primary key, so concurrent
  GRE instances execute a request at most once; a nonce is kept until
  `exp + max_skew`. Every rejection is an `A_resp` row (`gre_attempts`).
  `open_gre()` connects as `gre_exec`, and reads the TGS as `tgs_reader`.

Kubernetes execution (7.2):

```sh
bash src/scripts/gre-kind-up.sh     # kind cluster microtrace-gre: Calico, audit policy, src/k8s/gre/*
. "$MT_DEV/gre-kind/gre.env"        # then tests/test_gre_kube.py runs against it
bash src/scripts/gre-kind-down.sh   # deletes only microtrace-gre (experiments/cluster/TEST-PLAN.md)
```

- **Cluster** (`src/k8s/gre/`): kind v1.35.8 with Calico v3.30.3 (checksum
  pinned; kindnet does not enforce NetworkPolicy), an audit policy that
  logs every GRE write with its request and response (token bodies never),
  the application namespace `shop` and its isolation NetworkPolicy.
- **Identities** (`response-rbac.yaml`): `gre-executor` may only create
  tokens for `gre-isolate`, `gre-cordon`, `gre-scale`, `gre-revoke`; each
  of those reads its target kind and makes its one write.
  `response-policies.yaml` (ValidatingAdmissionPolicy, fail-closed) limits
  each to its mutation class: only the isolation label, only
  `unschedulable: true`, only replicas 0 through `scale`, only deleting a
  RoleBinding outside system namespaces.
- **Executor** (`execute.py`, client `kube.py`, standard library only):
  after validation, one 600 s token for the action's account; target
  revalidation (UID, and if the resourceVersion moved, the fields the action
  depends on compared with an exact read of the reviewed version); a write
  with the current resourceVersion as precondition. A 409 is a certain
  non-execution, so revalidation and write repeat up to 3 times. Outcomes:
  `Rejected` before any write, then `Submitted`, `Failed` or `Unresolved`
  (no answer or a server error), each an `A_resp` row with the write's
  Audit-Id.

Interrupted submissions (7.3):

- **Intent journal.** Before the first write, the executor stores an intent
  (`gre_intents`); each write carries the User-Agent
  `microtrace-gre/<rid>/<nonce>`, which the audit log records. The outcome
  row closes the intent and the nonce in one transaction, so a crash leaves
  either an open intent or an unclosed nonce, never a half-recorded outcome.
- **Interruption points** (`mtcore/failpoint.py`, shared with the Exp. 5
  crash harness): `gre.before_intent`, `gre.after_intent_before_submit`,
  `gre.after_submit_before_record`, `gre.before_verify`.
- **Reconciliation** (`reconcile.py`, `python -m mtcore.gre.cli reconcile`)
  never writes and never resubmits. From the audit log and the target's
  state: an accepted write is `Submitted`; a refused one, or no write with
  the target unchanged after the grace period, is `Failed`; no write but
  the effect present, or an unreadable target, stays `Unresolved` (recorded
  once). An accepted request with no intent is `Failed`: a write is only
  sent after its intent is durable. Nonces are purged only once closed.
- **Tests on kind** (`test_gre_kube_crash.py`): the GRE process is killed
  (`os._exit(137)`) at each point and reconciled from the real audit log;
  a pause between check and write lets a label change land, which the
  write precondition and the next revalidation catch.

Postcondition verification (7.4):

- **Checks by behaviour** (`verify.py`), with a token for a fifth account,
  `gre-verify`: isolate, a probe Pod's new connections to the target time
  out (CONNECTED or REFUSED means reachable); cordon, a probe Pod pinned to
  the node by node affinity is reported Unschedulable; scale to zero, no
  Pod matches the workload's selector; revoke, a SubjectAccessReview for
  each subject of the deleted binding, on a permission its role grants,
  says no. Each ends `Verified`, `Failed` (the opposite observed) or
  `Unresolved` (nothing conclusive before the deadline, 60 s by default),
  as a second `A_resp` row with `ref_verify` and the write's `ref_audit`.
- **Planned before the write.** What a check needs that the write may
  remove (the binding's subjects and role, the selector, the target port)
  is stored with the intent (`postcondition`); the intent points at its
  latest verification (`verified_attempt_id`). Schema `gre-schema-3`.
- **Reconciliation verifies** a Submitted write that has no Verified or
  Failed row (a crash at `gre.before_verify`, a write reconciled as
  Submitted, an inconclusive check); a repeated inconclusive check adds no
  row. `--no-verify` stops at `Submitted`.
- **Bounds on `gre-verify`**: probe Pods only, in `microtrace-probe`
  (restricted Pod Security level), from the pinned images
  (`agnhost:2.53` by digest, `pause:3.10`), one container, no token (the
  `gre-verify` admission policy); reads Pods in `shop` and roles; asks
  SubjectAccessReviews. Its requests carry the User-Agent
  `microtrace-gre-verify/<rid>`, so reconciliation never counts them as
  the action's write. Probe Pods are deleted after each check.
- **Tests on kind** (`test_gre_kube_verify.py`): each action Verified;
  the isolation NetworkPolicy removed (an accepted but ineffective action)
  ends `Failed`, never `Verified`; a connection opened before isolation is
  probed and reported to `$MT_DEV/gre-kind/verify-report.jsonl`; the
  `gre-verify` token used directly is denied other images, a token mount,
  a privileged Pod, and any write in `shop`.

Guard ablation (7.5):

- **Switches** (`GreConfig.ablate`, `python -m mtcore.gre.cli --ablate
  GUARD`, repeatable; never set in a deployment): `nonce` (no nonce store),
  `snapshot` (no TGS `check_approval`), `revalidation` (no comparison with
  the reviewed object and writes without a resourceVersion or uid
  precondition), `postcondition` (`AcceptanceVerifier`: API acceptance is
  reported as `Verified`), `permissions` (every action as `gre-broad`,
  `src/k8s/gre/ablation-broad.yaml`: wide RBAC, no admission policy,
  applied only for ablation runs and deleted after).
- **One case per guard** (`test_gre_ablation.py`): a replay after the
  effect was undone (a replay right after the write is also stopped by
  revalidation, since the write changed the labels), a snapshot that went
  stale after approval, a target recreated under the same name, an
  isolation that does not take effect, the identity a write is made with.
  Each case runs with all guards on and with each single guard off, and is
  breached exactly when its own guard is off.
- **On kind** (`test_gre_kube_ablation.py`): each pair graded from the
  audit log and the objects (executions, the wrong object written, the
  reported status, what a misused token is allowed), appended to
  `$MT_DEV/gre-kind/ablation-report.jsonl` for Table V.

## Exp. 5 crash harness and scoring (step 8)

Failpoints and the run comparison for Exp. 5 part A, the randomised GRE
sequences for part B, and the Exp. 1-3 scorer (evaluation-plan.md
sections 4-5).

- **Failpoints** (`mtcore/failpoint.py`): `failpoint.hit(name, state=..., require=...)`
  in every build, a no-op unless `MT_FAILPOINT=<name>`. `MT_FAILPOINT_NTH=n`
  fires on the n-th hit whose `require` holds; the firing is logged as one
  fsynced JSON line to `MT_FAILPOINT_LOG` (name, hit, pid, time, open-state
  summary), then `os._exit(137)`. `MT_FAILPOINT_MODE=pause` blocks until the
  file `MT_FAILPOINT_RELEASE` exists instead; with `MT_FAILPOINT_AFTER=<file>`
  hits count only once that file exists. The Go receiver uses the same
  variables and log line (`internal/failpoint`, `os.Exit(137)`).
- **Failpoint sites** (8a, 8f): GO `go.*` (`orchestrator/run.py`, 7g); receiver
  `receiver.after_kafka_ack_before_seq_store` (Kafka write done, sequence not
  stored), `receiver.after_store_before_ack` (state stored, ack not sent),
  `receiver.mid_batch` (the batch's Kafka write split in two only while
  armed); agents `agent.window_open` (a poll with input while windows hold
  state), `agent.after_finding_before_commit` (findings flushed, offsets not
  committed); TGS `tgs.mid_transaction` (a batch's rows written, offsets,
  snapshots and commit not). Each logs the open state it interrupts and
  fires only when there is some (`require`). A Postgres server crash is left
  to the crash runner.
- **Component crash tests** (`test_crash_points.py`, dev Kafka and
  Postgres): each receiver, agent and TGS point kills the real process,
  which is restarted without it. The receiver loses no record, and
  duplicates appear only above the stored next sequence and are
  byte-identical; the agents' findings and evaluations equal the offline
  engine's; the TGS keeps no trace of the killed transaction, re-applies to
  a clean graph, and its Kafka runner killed in a later batch resumes to the
  offline graph. Runners seed their read positions with the offsets they
  start at, so a runner started at the end commits every input partition
  and a restart never falls back to the earliest record.
- **Projection** (`mtcore/harness/project.py`, `dump.py`): a run's
  witness.decisions.v0 and incidents.v0 records (offline output, or
  `python -m mtcore.harness.dump --out run.jsonl`) reduced to sets of finding
  IDs, confirmed witnesses, groups, links, aliases and exclusions, at seal
  and latest; paths, times and open-record counts are reported only.
- **Comparison** (`compare.py`): `python -m mtcore.harness.compare diff
  --reference A.jsonl --run X.jsonl --noise A2.jsonl --band 1`; differences
  also present between A and A′ are noise. `compare tally` gives k of N with
  the 95 % Clopper–Pearson upper bound on the failure rate.
- **Recovery** (`recovery.py`): recovery time to within A's p99 lag for 30 s,
  added sealing delay per incident, peak CPU and memory, outage to the first
  heartbeat; `python -m mtcore.harness.recovery sample` records a consumer
  group's committed lag.
- **Randomised GRE sequences** (8e, `gre_sequences.py`, `python -m
  mtcore.harness.gre_sequences --seeds 200 --steps 40 [--ablate GUARD]`):
  seeded random walks over a simulated API server (`mtcore/gre/sim.py`,
  also the GRE tests' fake) with the real validator, executor, stores and
  reconciler: issue (sometimes tampered), execute or replay, kill at an
  interruption point, change the target before the write, let time pass,
  move the incident on, recreate, relabel, lift an isolation, stop
  NetworkPolicy enforcement, reconcile. Graded from the simulated audit
  log, the world's history and the probe log: every accepted write had a
  valid, unexpired approval for the incident's latest version and the
  unchanged approved object; at most one accepted write per nonce;
  `Verified` only after a passing probe; every request settled after the
  final reconciliation. With every guard on nothing is violated (coverage
  counts show every interruption point and rejection reached); with one
  guard off, only its property is. `permissions` is graded on kind.
- **Scoring** (8g, `score.py`, Exp. 1-4): `python -m mtcore.harness.score --truth
  RUN/restricted --output out.jsonl [--fault-log faults.jsonl]` scores
  findings against `FindingOpportunity` (a match is an equal type and
  intersecting evidence event IDs; findings matching only `ABSENT` rows or
  nothing are false positives; `UNOBSERVABLE` counts neither way) and
  confirmed witnesses against `ActionLink` as directed action pairs (findings
  map to actions through `rendered_event_ids`). A fault-log drop turns the
  opportunities it touches, and links left without an observable end, into
  `UNOBSERVABLE`; the truth files are never rewritten. Output records come
  from offline runs or `python -m mtcore.harness.dump --topics
  findings.v0,witness.decisions.v0,incidents.v0,norm.events.v0 --events`.
- **Paths and latency** (8g, definitions chosen 2026-10-12). Top-K path
  recall: the reference paths are the source-to-sink chains of `PRESENT`
  links (an `UNOBSERVABLE` link breaks a chain); one is recovered when a
  single retained ranked path (latest incident record) holds a distinct
  finding for each of its actions, in order. False-chain rate: retained
  paths of two or more findings with a false step (no `PRESENT` or
  `UNOBSERVABLE` action pair) over all such paths. Exp. 4:
  `--reference-output` scores the run's paths against an exhaustive run's K
  best per incident. Latency, live runs only: a finding's first Kafka
  timestamp minus the latest LogAppendTime of its input events in
  `norm.events.v0` (dump `--events`); correlation latency from the later
  finding to the witness's first `CONFIRMED` record; count, mean, p50, p95,
  p99, max in ms.
- **Shared dev Kafka.** Test receivers (`shipping_rig.Receiver`) run with a
  10 min max-idle unless a test sets its own: an idle node's open-ended
  `SOURCE_IDLE` gap stays on the shared topics and makes later runs on that
  node abstain. Pipeline tests from two sessions at once also cross-talk
  (both restreamers and agent groups read each other's events), so run them
  one session at a time.
- **Crash runner** (8g, `harness/stack.py`, `crashrun.py`): `python -m
  mtcore.harness.crashrun --input node-1=stream.jsonl --out runs/
  [--parallel 3] [--reps 5] [--points ...]`. Each run gets a fresh stack
  under its run directory: its own single-node Kafka (512 MB heap) and
  Postgres server (TCP only) on ports derived from the slot (29092 + 10 s),
  plus receiver, restreamer, agents, GO and TGS. The shared dev Kafka and
  Postgres are never touched. The matrix is A and A' (no crash), B/C/D for each
  GO point (full-replay, oldest-needed, read-position), and X for the
  receiver, agent and TGS points and `pg.server_crash` (immediate
  shutdown). Repetition r arms a seeded random n-th hit. The killed process
  is restarted after `--outage-s` with the failpoint off; a run whose point
  never fired is discarded. A run ends when the shippers have drained and no
  data record has appeared for `--settle-s`; the producers then stop in
  pipeline order and the TGS applies the topic ends. Per run: output.jsonl
  (dump with heartbeats), tgs.json (`edge_hash`: observed and confirmed
  edges; `graph_hash` also covers timing-dependent intermediate records and
  is only reported), lag.jsonl, usage.jsonl, failpoint.jsonl, meta.json, and
  compare.json (band from the measured outage). summary.json gives k of N
  per (run, point). `test_crashrun.py` (MT_CRASHRUN=1) runs A, A' and one
  crash per component kind.
- **Recovery in each crash run** (8g): `compare.json` holds `recovery`:
  recovery time of the agents and the GO on *read* lag (the runners'
  positions log joined with end offsets sampled each second, `ends.jsonl`;
  committed lag would show run C as lagging while caught up) against A's
  p99, held for `--hold-s` (a run lasts that long after the restart); added
  sealing delay per incident against A; peak CPU and memory per process from
  restart to the end of catch-up; for a GO kill, the records C must re-read
  and the longest span of an incident open at the kill. `summary.json`
  lists these per cell.
- **Sweeps** (8g, `sweep.py`): `python -m mtcore.harness.sweep --input
  node-1=stream.jsonl [--prefill node-1=history.jsonl] --out sweeps/
  [--points ...] [--reps 5] [--factorial] [--dry-run]`. Pace x1, x2, x4
  (`crashrun --pace`: the input is fed through `faultinject -pace` with
  `spec/faults/none.yaml`); outage 3 s, 60 s, 600 s (below max_idle, above
  it within the posting horizon, beyond it); history 10 min, 1 h, 4 h
  (`crashrun --prefill --history-s`: the last H s of the prefill's event
  time are shipped and settled first, and failpoints count only from then
  on, `MT_FAILPOINT_AFTER`). One factor varies at a time around pace 1,
  outage 3 s and the shortest history; `--factorial` runs every
  combination. Each setting is a full matrix in its own directory;
  `sweep.json` collects the summaries.
