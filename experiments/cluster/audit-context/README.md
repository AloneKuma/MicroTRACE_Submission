# Gap 2 audit and context harness

Executes [`../../../docs/handoffs/CLAUDE-GAP2-AUDIT-HANDOFF.md`](../../../docs/handoffs/CLAUDE-GAP2-AUDIT-HANDOFF.md)
on a disposable kind cluster. It tests kube-apiserver policy, the file audit
backend, collector behaviour and API-backed watches on a self-managed control
plane. It does **not** test managed-provider exports (GKE/AKS/EKS),
native-worker eBPF or token-file behaviour, or production performance.

| File | Role |
|---|---|
| `kind-config.yaml` | Generation `main`: the exact `spec/audit/audit-policy.v0.yaml`, blocking JSON file backend, every audit flag pinned |
| `kind-config-fault.yaml` | Generation `fault`: same policy; truncation at 16 KiB per event, 1 MiB rotation with one backup |
| `kind-config-noaudit.yaml` | Generation `baseline`: no auditing; latency comparison only |
| `run.sh` | Preflight, pins and checksums, the three sequential generations, teardown of only `microtrace-gap2-audit`, summary |
| `probe.py` | Request driver; writes a private request manifest (probe ID, test IDs, role, credential mode, expected result, UTC times, HTTP status, `Audit-Id`, object UID) |
| `collector.py` | Tails the audit log by `(dev, ino, offset)` with a content fingerprint, follows rotation, dedups by `(auditID, stage)`, records parse errors, read lag and gaps, emits redacted records |
| `context-watch.py` | RBAC and Pod watches with UID, resourceVersion, stream sequence, relist boundaries and explicit `watch_gap` on HTTP 410 |
| `summarize.py` | Joins manifest, collector records and context; outputs a verdict per test ID and refuses to write output that contains tokens, UUIDs or identities |
| `mtk8s.py` | Shared stdlib HTTPS client, kubeconfig loader and keyed pseudonyms |
| `tests/test_harness.py` | Offline fixtures: parsing, dedup, redaction, rotation, stopped-reader gap, simulated 410, Pod IP intervals, and policy review against the probe matrix |

## Data handling

- Raw audit lines exist only inside the kind control-plane container's `/var`
  volume. The collector container mounts that volume read-only, and it is
  deleted with each cluster.
- The kubeconfig and client certificate/key are kept in
  `~/microtrace-cluster/gap2-audit/<run>/private/<gen>/` (mode 0700) and
  removed at each teardown.
- TokenRequest tokens are held in memory only. Credential IDs, Pod UIDs and
  usernames are replaced by HMAC pseudonyms whose key is local to the run.
- Only `public/` outputs (counts, classes, shapes and booleans) are copied into
  `evidence/cluster/`.
- After review, delete the private directory with `run.sh --purge <run>`.

## Running

On the test host, from a checkout that contains `experiments/cluster/audit-context` and
the two `gap1` files:

```sh
bash experiments/cluster/audit-context/run.sh --preflight-only   # no cluster
bash experiments/cluster/audit-context/run.sh                    # main, fault, baseline
GENS=main bash experiments/cluster/audit-context/run.sh          # a subset
```

Offline checks alone: `python3 -m unittest -v tests.test_harness` (from this directory; needs PyYAML).
