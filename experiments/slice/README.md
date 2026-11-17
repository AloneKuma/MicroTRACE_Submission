# Audit-to-incident vertical slice

One end-to-end path through the Gap 1 contracts, run on a disposable kind
cluster with one pinned KRaft broker:

```
audit_collector  -> raw.audit.v0 (key AUDIT_ID) + source.completeness.v0 + heartbeats
context_collector -> context.cluster.v0 (key OBJECT_UID) + source.completeness.v0 + heartbeats
normalizer       -> norm.events.v0 (key primary entity): principal + token-bound Pod from watched history
restreamer       -> agent.H.audit.v0 (key PRINCIPAL_KIND, PRINCIPAL_ID)
agent_h3         -> rule.evaluations.v0 + findings.v0   (H3, UNFROZEN-SLICE parameters)
orchestrator     -> incidents.v0                         (single-finding incidents only)
```

This is **pipeline integration evidence**. It is not a Gap 2 sensor test and
not multi-finding correlation. Results:
[evidence/slice/slice-20260927T150701Z.md](../../evidence/slice/slice-20260927T150701Z.md).

## Design rules the code enforces

- **Contract encodings.** Envelopes, keys and logical IDs follow
  `spec/kafka/kafka-contract.md`: keys and IDs use `spec/tools/mtcodec.py`,
  and key specs come from `spec/kafka/topics.yaml`. Producers are idempotent
  and use `partitioner=murmur2_random`.
- **H3 waits for completeness.** H3 evaluates a window only once the input
  watermark has passed `window_end + lateness` and AUDIT completeness coverage
  has reached `window_end`. Any AUDIT gap overlapping the window gives
  `ABSTAINED`.
- **Token-bound Pod.** The Pod is resolved by UID and time interval in the
  watched history. A `WatchGap`, an idle context source or an unknown UID
  yields a completeness gap, never a guessed UID. The Pod is labelled the
  token's bound Pod, not the caller.
- **Replay-identical decisions.** The orchestrator seals at
  `event_end + T_seal`. A source is excluded at seal from records known by
  the seal watermark (knowledge time = `interval_end`), and amended on
  records known later.
- **Replay by design.** Every downstream decision is a function of recorded
  records and heartbeats, so `--replay` re-runs reproduce IDs, outcomes and
  incident versions.

## Files

| File | Role |
|---|---|
| `mtslice.py` | Envelopes, keys, IDs, the Kafka producer and consumer loop, watermarks |
| `audit_collector.py` | Subclass of the Gap 2 collector (`experiments/cluster/audit-context/collector.py`); rotation, fingerprint and gap logic unchanged |
| `context_collector.py`, `normalizer.py`, `restreamer.py`, `agent_h3.py`, `orchestrator.py` | Pipeline stages |
| `params.unfrozen-slice.yaml` | Slice-only parameter values and the H3 score interpretation |
| `driver.py` | Live scenario (P positive, Q below threshold, R controller-like, G known gap), with a controlled context outage and Pod churn for the post-seal 410 |
| `dump.py`, `summarize_slice.py` | Topic dumps; the redacted result, with key, partition and ID recomputation, replay comparison and a leak scan |
| `tests/fixture_pipeline.py` | Offline gate: real components and broker, synthetic inputs, no cluster |
| `kafka.sh`, `run.sh`, `Dockerfile`, `kind-config.yaml` | Broker, runner, runtime image, cluster config |

## Running

On the test host, from a checkout containing `experiments/slice/`,
`experiments/cluster/audit-context/{collector,mtk8s}.py`, `spec/tools/mtcodec.py`,
`spec/kafka/topics.yaml`, `spec/proto/` and the two `gap1` policy and rulebook
files:

```sh
bash experiments/slice/run.sh --offline-only   # fixture pipeline against a throwaway broker
bash experiments/slice/run.sh                  # offline gate, then the live slice
bash experiments/slice/run.sh --purge RUN_ID   # remove a run's private directory
```

`run.sh` deletes only `microtrace-slice`, containers labelled with its run
ID, and a run-created empty kind network.
