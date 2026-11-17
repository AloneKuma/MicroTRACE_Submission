# MicroTRACE cluster test plan

Status: 2026-09-27. The immediate smoke run passed and its cluster was deleted.
The self-managed audit/context experiment ran as `20260927T133846Z`
(`evidence/audit-context-20260927T133846Z.md`); its clusters were deleted;
the remaining Stage 3 experiments are pending. Owner: Codex. Test host:
`user@test-host`. Results: `evidence/smoke-2026-09-27.md` and
`evidence/audit-context-20260927T133846Z.md`.

## Immediate run: disposable kind audit smoke test

**Goal:** establish that this host can run a pinned two-node Kubernetes cluster
and that a controlled API request produces an audit event through the configured
file backend. This is a platform smoke test, not validation of MicroTRACE's
finding rules or its final audit policy.

| Step | Action | Pass evidence | Cleanup |
|---|---|---|---|
| Baseline | Record UTC time, OS/kernel, Docker version, free memory/disk, existing kind clusters and Docker container count. | Pre/post counts show no unrelated container was changed. | None. |
| Pin | Download kind v0.33.0 and kubectl v1.35.8 into a dedicated user directory; verify published checksums/version and pin the kind node image digest. | Binary versions, checksum result, image reference. | Leave small binaries for repeatability; no system install. |
| Create | Create only `microtrace-smoke` from `kind-smoke.yaml` with `smoke-audit-policy.yaml`; keep kubeconfig under that user directory. | Both nodes `Ready`; API version v1.35.8; audit policy mount and flags present. | `kind delete cluster --name microtrace-smoke`. |
| Probe | Create, read, and delete a uniquely named test namespace. Inspect the control-plane audit log for those requests. | At least one `ResponseComplete` record with audit ID, verb, objectRef, user and success status for the probe. | Namespace deletion; cluster deletion. |
| Report | Save versions, configuration hashes, counts, redacted field presence, failures, and limitations locally. | A concise evidence file; no kubeconfig or credential bytes in the repository. | Delete cluster and confirm its Docker nodes/network are gone. |

Abort if the host is under resource pressure, the name is already in use, a
binary checksum fails, or cluster creation interferes with existing workloads.
Do not prune Docker images, volumes, containers, networks, or build cache.
Keep raw audit data and kubeconfig on the server; only record aggregate or
redacted evidence in this repository.

The smoke audit policy is Metadata-only. It cannot prove TokenRequest response
annotations, RBAC mutation bodies, credential IDs, audit loss, or any finding.

## Later Stage 3 experiments

These require the frozen Gap 1 schema/rulebook and purpose-built probes. Run
each as a separate, versioned experiment with a positive case, a negative
control, field-presence checks, measured loss/latency, and an explicit verdict.
The first audit/context run has an execution handoff in
[`../../docs/handoffs/CLAUDE-GAP2-AUDIT-HANDOFF.md`](../../docs/handoffs/CLAUDE-GAP2-AUDIT-HANDOFF.md).

| Experiment | Required deployment and control | Decision |
|---|---|---|
| Audit and context | Final audit policy/exporter; TokenRequest, RBAC mutation, large payload, object recreate, Pod-IP reuse and watch-gap controls. | Verify fields and historical context through the actual export route; mark missing fields/gaps. |
| Kafka envelope | Pinned broker and Protobuf messages; retry, replay, wrong schema, retention, key/partition controls. | Verify ordering scope, loss, duplicate and incompatible-decoder behavior. |
| Gateway | Pinned Envoy and separate `ext_proc` observer; split/oversized body, slow/disconnected observer controls; forged `x-request-id` from a Pod and from outside, with Envoy defaults as the negative control (`GW-REQUEST-ID-ORIGIN`). | Measure request latency/failure and body loss before claiming A1/A2 coverage. Record `request_id_origin` as `SENSOR` only if every forged ID is replaced. |
| Kyverno | Pinned compatible release and report/export route; admission verdict, dry-run and recreated-Pod controls. | Establish admission time and created Pod UID or retain image-class context only. |
| Token read and rotation | Privileged node probe on a **native Linux worker**; resolved mount/device/inode, cgroup/Pod identity, old/new projected-token versions and host reader. | Promote credential read-to-use only if token-instance joins survive both controls. |
| Node load | Native worker running the pinned Tetragon sensor; increasing benign/process/file/socket event rates; a Pod trying to alter exported 5-tuple, lineage and Pod identity (`NODE-ORIGIN-FORGERY`). | Record attempts, emitted, drops, queue, CPU, bytes and lag by event family; relabel any field a Pod can set as `workload`. |
| G2/G1b | Accepted exec plus target process observation; same-boundary and crossed-boundary actions. | Require the observed effect and independent access at the claimed boundary. |
| E3 | Existing workload with mounted artifact; same-Pod restart, real re-execution, altered/renamed/mmap/benign/concurrent-replica controls. | Prove identity and write continuity; measure restart backoff; otherwise keep E3 conditional. |
| Sole grant / F2 | Historical RBAC reconstruction and authorizer coverage with alternate grants, aggregation, groups and watch gaps. | Direct sole-grant witness only if all historical alternatives are excluded. |

The kind workers are Docker containers. Results from them can inform prototype
debugging, but native host kernel, mount and eBPF claims need a native worker.
Provider-specific GKE/EKS/AKS export checks require separate managed-cluster
runs; this self-managed test cannot stand in for them.

## Evidence and teardown rule

Each experiment must record exact component versions and configuration hashes,
UTC timestamps, input/control IDs, fields observed, attempted/emitted/dropped
counts where relevant, latency, limits and outcome (`pass`, `narrowed`,
`unsupported`, or `not run`). Retain redacted summaries in `evidence/cluster/`.
After the immediate smoke test, delete only `microtrace-smoke` and verify no
container carrying `io.x-k8s.kind.cluster=microtrace-smoke` remains. Future
Stage 3 experiments can recreate it or use an approved native-worker cluster.

Sources: [kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/),
[kind auditing](https://kind.sigs.k8s.io/docs/user/auditing/),
[kind v0.33.0 node images](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0),
[Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).
