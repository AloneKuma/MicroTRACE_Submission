# Gap 1 artifacts: executable evidence and detection specification (v0)

Status: **design-complete by the offline checks below; selected audit/context
inputs validated only on a self-managed kind file route.** No complete
MicroTRACE system or pilot has been run. Three states are kept apart throughout:

- **specified**: fixed here;
- **cluster-validated**: a named Gap 2 test in [rules/gap2-tests.yaml](rules/gap2-tests.yaml)
  has passed. Eleven audit/context tests passed on a self-managed kind
  cluster only (run `20260927T133846Z`); every other test is `not_run`;
- **frozen**: a numeric parameter or declared artifact chosen from pilot data
  (none has; all are symbols in [../docs/design/parameter-register.md](../docs/design/parameter-register.md)).

Why each artifact is needed is explained in
[../docs/design/gap-1-specification-rationale.md](../docs/design/gap-1-specification-rationale.md). Sources
for every external fact are in [SOURCES.md](SOURCES.md).

## The four artifacts

| # | Artifact | Files |
|---|---|---|
| 1 | Audit policy and collector contract | [audit/audit-policy.v0.yaml](audit/audit-policy.v0.yaml) (self-managed candidate), [audit/collector-contract.md](audit/collector-contract.md), [audit/provider-coverage.template.yaml](audit/provider-coverage.template.yaml) (EKS/GKE/AKS record) |
| 2 | Versioned schemas and Kafka keys | [proto/microtrace/v0/](proto/microtrace/v0/envelope.proto) (15 files), [kafka/topics.yaml](kafka/topics.yaml), [kafka/kafka-contract.md](kafka/kafka-contract.md), [tools/mtcodec.py](tools/mtcodec.py) |
| 3 | Node capture manifest | [node/capture-manifest.v0.yaml](node/capture-manifest.v0.yaml) |
| 4 | Rulebook and traceability | [rules/rulebook.v0.yaml](rules/rulebook.v0.yaml) (23 findings plus 10 witness types), [traceability.md](traceability.md) (generated), [rules/gap2-tests.yaml](rules/gap2-tests.yaml) |
| — | Data design for evaluation and ML | [data/ml-data-design.md](data/ml-data-design.md), [proto/microtrace/v0/dataset.proto](proto/microtrace/v0/dataset.proto) |
| — | Investigation graph (TGS) | [graph/tgs-contract.md](graph/tgs-contract.md) |
| — | Example trace | [examples/trace-v0.json](examples/trace-v0.json), built by [tools/build_example_trace.py](tools/build_example_trace.py) |
| — | Checks | [tools/check_gap1.py](tools/check_gap1.py) |

## Manual trace through the example

All values are synthetic identifiers. No parameter has a value: applied limits
name their symbol under parameter set `UNFROZEN-EXAMPLE`.

1. **Raw evidence.**
   - **R1 (token census).** The node sensor records that the Pod's projected
     token file `(dev 2049, ino 1573005)` lives in version directory
     `..2026_09_26_09_40_00.3141592653` of volume `kube-api-access-x7k2p`.
   - **R2 (`file.read`).** A process `(tgid 4217)` in lineage root `(tgid 4100)`
     reads that `(dev, ino)`, `SUCCESS` with 1043 bytes. The path text is the
     in-container symlink, but identity comes from `(dev, ino)`, not the path.
   - **R3 (`file.mutation`).** The same lineage makes `/work/cache/helper`
     executable (`CHMOD`, `executable_after`). `node_seq` 71 < 72 fixes the order.
   - **R4 (Kyverno).** The admission decision is an audit-mode `FAIL` for the
     Pod's UID and image digest.
   - **R5 (audit).** A TokenRequest carrying the annotation
     `authentication.kubernetes.io/issued-credential-id`.
   - **R6 (gateway).** A request with a body pattern match.
   - **C1 (context).** The Pod watch observation that ties container ID
     `containerd://7f3b0c` and image digest to the Pod UID.
2. **Normalization.**
   - N2 adds the Pod UID (container → Pod through C1) and `token_file` (R1's
     index, matched on `(dev, ino)`). `lineage_id` is the logical ID of R2's
     `lineage_root` ProcessKey.
   - N3 and N4 route to `agent.E.v0` on key `(Pod UID, container name)`.
   - N2 routes to `agent.D.read.v0` on key `(token-owner Pod UID, volume)`.
   - N5 routes to `agent.D.use.v0` keyed by the issued JTI, for the issuance
     side of the conditional JTI join.
   - The eBPF clock model is unmeasured, so `event_time_uncertain` is true.
     W1's direction therefore rests on `node_seq` (`EVIDENCE_ORDER`), not on time.
3. **Findings.**
   - **F1 = D1, mapped (Credential Access).** The rule's predicate reads only
     N2's fields: a successful read with bytes > 0, `(dev, ino)` found in the
     index, and a reader absent from `E_D1`.
   - **F3 = E2, unmapped.** Built from N3 and `E_E2`.
   - **F2 = E1, unmapped.** Built from N4. It carries a
     `CONDITIONAL_JOIN_UNVALIDATED` gap because the Kyverno Pod-UID join is untested.
4. **Witnesses.**
   - **W1 `PROCESS_ANCESTRY`: direct, confirmed.** It links F1 → F3 on the
     shared `lineage_id`. Only `W_w[process-ancestry]` and `T` apply, because
     E2 is unmapped.
   - **W2 `IMAGE_CLASS`: enabling only.** It links F2 → F3 on the image digest
     through N4 and C1. It cannot confirm the link and appears only as a
     speculative path.
5. **Incident.**
   - I1 is version 1 and `INCIDENT_SEALED`. Its anchor is F1, the earliest
     event time, with the finding ID as tie-break. Its `link_witness_ids` are
     `[W1]` and its snapshot is `snapshot-1`.
   - I2 is version 2 and `INCIDENT_AMENDED` after the audit source was excluded
     by max-idle (SC record). It has the same incident ID and the same
     `sealed_prediction_version`.
6. **Stream control.** HB is a heartbeat sent to explicit partition 0 with a
   producer-instance key. SC records the idle audit interval as `INCOMPLETE`.

A reader can recompute every key and ID with [tools/mtcodec.py](tools/mtcodec.py),
using only the fields in the records.

## Offline checks (run 2026-10-06)

Command, from the repository root, with PyYAML available on `PYTHONPATH`:
`python spec/tools/check_gap1.py`. Result: **15 passed, 0 failed**.

| Check | Result |
|---|---|
| All 15 `.proto` files compile with protoc (libprotoc 33.5, via grpcio-tools 1.81) | pass |
| No `bytes` field exists in any schema, so no credential or body bytes can be carried | pass |
| 23 rules match Table I in `paper/D3_v4.tex` (IDs, agents, tactics, daggers; prose names are not compared); the unmapped set equals design-spec's 10 | pass |
| Every rule has inputs, joins, state, predicate, threshold, abstention, emits, a negative control, and Gap 2 tests; no numeric threshold | pass |
| All 287 field paths in the manifest and rulebook resolve in the compiled schema | pass |
| Every witness labels each join-key component `sensor`, `workload` or `gateway-minted`; every direct witness has a sensor-originated component; a gateway-minted key carries `request_id_origin` and stays conditional | pass |
| Every field, contradiction item and status in the `contracts.md` Witness v0 table exists in `witness.proto` | pass |
| Every eBPF rule input is exported by a manifest family that lists that rule; no orphan or unused capture; the research profile is a superset no rule reads | pass |
| All 54 Gap 2 tests are referenced and map to Stage 3 rows; every observed status cites an evidence record and scope | pass |
| All 27 rule symbols appear in `parameter-register.md` | pass |
| Topic keys use defined codes, stay consistent per key type, and cover each keyed rule's state key (H4, E3, H5) | pass |
| Audit policy: first-match simulation across 59 probes gives every audit rule its level and stages; credential objects stay at or below Metadata | pass |
| 24 example records parse into `Envelope` (unknown fields rejected); keys and IDs recompute; each carries a run context; mapped and unmapped findings, direct and enabling witnesses, sealed → amended incident, a ground-truth action, and fired/not-fired rule evaluations | pass |
| Relative Markdown links resolve | pass |
| `traceability.md` matches regeneration (156 rows) | pass |

Mutation test: six deliberately injected errors were each detected by the
matching check, and the files were then restored:
- a secret rule raised to RequestResponse;
- `ResponseStarted` omitted on the catch-all;
- H3's tactic changed;
- H4's topic key narrowed;
- a finding's detector version altered;
- a manifest consumer removed.

`main.tex` was edited in three places and rebuilt with `latexmk`: 8 pages, no
errors, no undefined references or citations, and no overfull boxes. 26
underfull-box warnings remain, all cosmetic, and BibTeX reported 0 warnings.

### Not checked offline

- kube-apiserver's own validation of the policy file (no API server or Go
  toolchain). The simulator is MicroTRACE's own first-match model.
- `buf breaking` or any schema-registry compatibility run (no buf; this is v0,
  so there is no prior version to compare).
- The offline checker does not validate runtime behavior. The separate Gap 2
  audit/context run below tested one self-managed cluster and file route;
  kernel sensing, Kafka broker behavior, and managed providers remain untested.
- External URLs were checked by fetching them on 2026-09-27, not by the script.

## What remains conditional for Gap 2

Each item is a named test in [rules/gap2-tests.yaml](rules/gap2-tests.yaml).
The audit/context experiment
([../evidence/cluster/audit-context-20260927T133846Z.md](../evidence/cluster/audit-context-20260927T133846Z.md))
installed this candidate policy on a disposable **self-managed kind** cluster
(Kubernetes v1.35.8, JSON log backend, blocking mode). These passed on that
cluster only:
- AUD-POLICY-EFFECTIVE, AUD-FIELDS-USEDTOKEN, AUD-ISSUED-ANNOTATION and
  AUD-POD-BINDING-EXTRA;
- AUD-FAILED-AUTHN, AUD-RBAC-BODY, AUD-EXEC-VERB and AUD-API-LATENCY;
- CTX-WATCH-410, CTX-POD-IP-REUSE and CTX-RBAC-RECREATE.

The observed exec shape (WebSocket `get`, SPDY `create`, 101 at
`ResponseStarted`) matches the G2 audit requirement, so no rulebook change
follows.

`objectRef.uid` is absent on create, patch and delete events. Instance joins
for those operations use the RequestResponse body UID or the watch history.

These passes do not transfer to managed control planes, and they do not make
F2, G1b, D2 or G2 demonstrated findings. What remains:

- **Audit.**
  - The same checks on each managed provider's effective policy and export.
  - GKE Data Access and AKS category read coverage (AUD-PROVIDER-READS: local
    file baseline only).
  - The EKS 1 MB CloudWatch limit (AUD-TRUNCATION-OVERSIZE: file route passed,
    with bodies stripped and the event kept).
  - Webhook overflow, export errors and provider delivery gaps (AUD-LOSS-ROUTE:
    rotation and stopped-reader passed on the file route).
- **Context.** The restart indicator (CTX-RESTART-INDICATOR, part of the E3
  experiment). The overlapping-interval `JOIN_UNCERTAIN` case of
  CTX-POD-IP-REUSE was exercised only by an offline fixture.
- **Node.**
  - Every probe attachment point in the manifest, since each is only a proposal.
  - Process lineage, successful-read detection, and token file identity across
    mount namespaces, rotation, and host readers.
  - Privilege and namespace transitions, ptrace, and bpf self-exclusion.
  - Write variants, flow ownership, loss under load, and the clock model.
- **Kafka.** Partitioner agreement across clients, restream co-location and
  ordering, replay dedup, schema rejection, retention under byte pressure, and heartbeats.
- **Gateway and Kyverno.** Split-chunk matching, oversize and slow-observer
  handling, and response indicators. Also whether Kyverno exports the Pod UID,
  dry-run status, and admission time.
- **Off-node (H5 and `host-context`).** All four tests are not run and need
  the placement in assumption 7.
  - OFFNODE-DBAUDIT-SOURCE: the database audit log records the client's own
    address (not a proxy's or a masqueraded node address), statement class,
    outcome and result bytes, for a read from a Pod and from a node's host
    network.
  - OFFNODE-PATH-COVERAGE: every node's egress, including hostNetwork and
    host-process traffic, passes the path observer with Pod addresses intact,
    and no route bypasses it.
  - OFFNODE-FLOW-EXPORT: flow records carry unsampled octets and start/end
    times; measure active/idle timeouts and export lag.
  - OFFNODE-HOST-SIGNATURES: freeze host-component flow signatures from
    pilot-only benign traffic, then run an undeclared benign host daemon as the
    `host-context` collision control.
- **Conditional findings.**
  - **E3** needs an artifact-identity method and observed re-execution.
  - **F2** needs the historical-rights controls.
  - **G1b** needs the JTI version index and the target effect
    (CRED-JTI-VERSION-INDEX, G1B-TARGET-EFFECT).
  - **D2** needs caller attribution (CRED-CALLER-ATTRIBUTION). It is now
    `conditional` in the rulebook, matching the dagger in `paper/D3_v4.tex`
    Table I; this is a provisional decision.
  - **`host-context`** (direct witness) is conditional on the OFFNODE tests;
    without them it is enabling context only, and C1b → H5 stays a
    speculative hypothesis. H5 itself is specified but untested.
  - **G2** needs the target-process join (G2-TARGET-PROCESS-JOIN).

## Assumptions for the cluster collaborator

1. **Self-managed first.** The candidate policy assumes a self-managed control
   plane. On a managed plane, fill [audit/provider-coverage.template.yaml](audit/provider-coverage.template.yaml)
   instead, and record observed values only.
2. **Version.** Kubernetes ≥ 1.32 is the floor. Record the exact patch version,
   because field names and the exec verb are checked on that version.
3. **No token bytes.** The sensor must never export token bytes. The
   `token.jti_index` family parses JWT claims inside the privileged agent and is
   off until CRED-JTI-VERSION-INDEX is approved. It raises the agent's trust requirement.
4. **Partitioner.** librdkafka-based producers must set `partitioner=murmur2_random`.
5. **Evidence records.** Record each test's result as passed, narrowed, or
   unsupported. A failed test narrows its rule according to that test's
   `failure_rule` and never reverses a Gap 1 decision silently.
6. **Symbols stay open.** The symbols in `parameter-register.md` (for example
   `E_D1`, `Q_B1`, `W_G2`, `C_H4`, `W_H5`, `rho_H5`) are chosen from pilot-only
   data in Gap 3, not from Gap 2 feasibility runs.
7. **Off-node placement for H5.** The escape-target node hosts none of the
   database, its audit collector, the path observer, Kafka, or the
   orchestrator. Route the Pod CIDR without masquerade through the observer,
   and record the database engine, audit plugin and policy, and the observer's
   export configuration per run. Use native Linux workers, not kind: kind
   nodes share one host network, so traffic between them does not cross an
   off-node path. Without this placement, record H5 and `host-context` as
   unsupported on that cluster.
8. **Paper of record.** Table I is checked against `paper/D3_v4.tex`.
   `main.tex`, `D3_v1`, `D3_v2` and `D3_Ajrev` are frozen earlier versions.
