# Gap 2 cluster work

Status (2026-09-27): the temporary kind smoke test passed. The first
audit/context experiment ran on a disposable kind cluster
([`audit-context/`](audit-context/README.md),
[evidence](../../evidence/cluster/audit-context-20260927T133846Z.md)): 11 of 14
audit/context test IDs passed overall on the self-managed file route, with two
additional file-route-only passes recorded under overall `not_run` IDs.
Provider checks remain unrun; `CTX-RESTART-INDICATOR` is a separate E3 test.
All test clusters were deleted.

Update (2026-10-02): the forgery probe ([`run-forgery-probe.sh`](run-forgery-probe.sh),
[evidence](../../evidence/cluster/forgery-probe-20261002T081235Z.md)) passed as
`AUD-ORIGIN-FORGERY` on a disposable kind cluster. A Pod could not change the audit
user, token-bound Pod UID or credential ID; `sourceIPs[0]`, `userAgent`,
`traceparent` and `X-Request-Id` arrived as sent. The kernel half
(`NODE-ORIGIN-FORGERY`) needs a native worker and has not run.

This Windows task has no visible `kubectl`, Docker/Podman, kind, minikube, or kubeconfig. A
read-only elevated check found a stopped Kali Linux WSL2 distribution (kernel
6.18.33.2) with about 7.6 GiB of available VM memory, but no `docker`,
`podman`, or `kubectl` inside it. The Windows C: drive has about 11.4 GB free;
the D: drive has much more room. A local cluster would require a deliberate
runtime/tool installation and disk-placement decision. No cloud resources or
paid services have been created.

The candidate is `user@test-host`. A read-only SSH check succeeded. It is
Ubuntu 22.04.5 (kernel `5.15.0-164-generic`, x86_64), with 12 CPUs, 15 GiB
RAM (about 11 GiB available at inspection), and about 420 GB free on `/`.
Docker 28.2.2 and containerd are present; this user can access Docker. No
`kubectl`, kind, kubeadm, k3s, Helm, or kubeconfig was found. There were 21
existing active Docker containers (55 total). Read-only `docker system df`
reported 28.9 GB of images and 13.13 GB of build cache; none was removed.
The user authorized a temporary test. It passed and was torn down; the active
container count remained 21. `sudo -n` requires a password, but the smoke test
did not require sudo. See `TEST-PLAN.md` and `evidence/smoke-2026-09-27.md`.

## Purpose

Use a pinned Kubernetes testbed to replace MicroTRACE's conditional sensor
claims with measured evidence. Gap 2 includes building small vertical
prototypes; it does not wait for the entire eight-agent system. The complete
test list and failure rules are in `../section-iii-completion-plan.md`, Stage 3.
Claude owns the offline Gap 1 artifacts. Cluster work stays in this directory
until both collaborators reconcile their field and test contracts.

## Target choice

Preferred for the first feasibility pass: an accessible **self-managed Linux
control plane and at least one Linux worker**, with permission to set the audit
policy/backend and inspect the worker's kernel, projected volumes, and process
events. This provides direct tests of audit configuration and host eBPF
semantics. The exact Kubernetes patch version, runtime, kernel, and machine
sizes must be pinned before tests; the manuscript's minimum is Kubernetes
1.32. Kubernetes' kubeadm guide lists 2 GB RAM per machine and 2 CPUs for a
control plane as installation minima, not as MicroTRACE load-test sizing.

An existing lab cluster is equally usable if it meets those access needs. A
managed cluster can test provider-exported audit behavior, but the provider's
effective policy and limits become part of the test configuration. A kind
cluster on a remote Linux host is useful for control-plane and pipeline smoke
tests; its containerized nodes do not substitute for a native worker when
claiming host eBPF, mount, or kernel behavior. The selected route depends on
the user's available infrastructure and budget.

Sources: [kubeadm installation requirements](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/),
[Kubernetes audit setup](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/),
[kind audit setup](https://kind.sigs.k8s.io/docs/user/auditing/).

## Minimum access and evidence

1. Cluster administration sufficient to deploy namespaces, DaemonSets,
   Kyverno, the Envoy test gateway, and RBAC test objects. Use an isolated test
   cluster or isolated test namespaces with explicit permission for security
   experiments.
2. Control-plane audit access: effective policy, backend, mode, truncation,
   rotation/buffer settings, and a way to read exported audit records. Managed
   clusters require the provider's category and delivery settings instead.
3. Worker access: Linux OS/kernel and container runtime details; permission to
   deploy and inspect the privileged node-sensor prototype; host mount and
   cgroup identity needed for token-file and E3 tests.
4. Evidence recording: exact versions and configuration hashes, source event
   samples with sensitive token bytes removed, timestamps, attempted/emitted/
   dropped counts, API latency, collector lag, and outcome of each negative
   control. Record failed and unavailable checks as such.

## First cluster milestones

1. **Select access route.** Record who provides the cluster, whether it is
   existing/self-managed/managed, and whether it has any cost. Never place
   credentials or kubeconfig contents in this repository.
2. **Read-only preflight.** Record exact Kubernetes and node versions, OS,
   kernel, runtime, capacity, authorization scope, and audit-feed access.
   Verify the effective audit policy or provider category separately; the API
   version alone does not prove JTI or body coverage.
3. **Minimal audit path.** Issue controlled API requests and TokenRequests;
   confirm audit ID, stages, outcome, used-token `user.extra`, issuance
   annotation, RBAC mutation body/history, and backend-specific loss. Test a
   large mutation through the actual export route.
4. **Node and token path.** Observe successful file reads with process, cgroup,
   Pod, device/inode, and mount context; test old and new projected-token
   versions and a host reader. Measure event loss under increasing load.
5. **Remaining vertical slices.** Test the pinned Kyverno exporter, Envoy
   `ext_proc` observation/latency/loss, E3 artifact identity and real
   re-execution after restart, and F2 historical RBAC/authorizer controls.
6. **Capability decision.** For each test, record passed, narrowed, or
   unsupported. Feed observations to the Gap 1 owner and paper; do not turn a
   conditional finding into a demonstrated one without its evidence record.

## Remote smoke test

`kind-smoke.yaml` is a two-node kind configuration based on the official kind
auditing guide. It mounts `smoke-audit-policy.yaml` into the control plane and
enables the API server's file audit backend. The smoke policy logs only metadata;
it is intentionally insufficient for MicroTRACE's TokenRequest and RBAC body
requirements. Replace it with the reviewed Gap 1 policy before those tests.

For reproducibility, the planned versions are kind v0.33.0 and its published
`kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0`.
The cluster name was `microtrace-smoke`, with kubeconfig held in a dedicated
user directory on the server. Binary checksums and versions were verified at
execution. The cluster, its network and kubeconfig were removed after the test.
Do not copy kubeconfig or audit records containing identities or tokens into
this repository.

This cluster can establish the control-plane audit path and pipeline smoke
tests. Its Docker-container workers cannot establish native host mount, eBPF,
or kernel observations required for the token read and E3 claims. Those need a
later native Linux worker or a separately justified kind result.

Sources: [kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/),
[kind auditing guide](https://kind.sigs.k8s.io/docs/user/auditing/),
[kind v0.33.0 release and node digest](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0).

## Current dependency

The server completed the pinned smoke and audit/context runs. The cluster is
down. The remaining Stage 3 checks require their dedicated prototypes;
native-worker feasibility still requires suitable access.
