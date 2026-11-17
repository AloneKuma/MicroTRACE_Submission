# Section IV proposition tests

`correlator_ref.py` is an executable transcription of the paper's Phase 3
correlator (witness predicates, `Covered`, node-trust epochs, `DistinctAction`,
the typed index, re-evaluation before sealing, canonical deduplication and
bounded top-K paths). It is a **reference model**, not the production pipeline:
`experiments/slice/` still has no multi-finding correlation.

`test_props.py` generates random scenarios and checks each Section IV claim.
The paper's design must show **zero violations**. A matching weaker design must
show **at least one** violation, which shows the test can fail:

| Claim | Check | Must-fail variant |
|---|---|---|
| Prop. 1 forgery invariance | forging workload fields of `C` leaves links and groups unchanged | `no_origin` |
| Prop. 2 suppression monotonicity | deleting records (with loss records) creates no link; clock/epoch slack stays within the stated bounds | `covered_witness_only`, `no_eps_cap`, `distinct_no_coverage` |
| Lemma 1 retrieval completeness | indexed stream links = exhaustive links | `short_horizon`, `truncate_1` (`evict_by_watermark` reported) |
| Prop. 3 order invariance | links and groups equal across arrival orders and equal to exhaustive | `single_eval`, `first_arrival_dedup` |
| Paths | K=2 example reproduced; divergence rate measured; K=1 search reported | — |
| Tactic gate | old pair window drops D1→B1 only | `tactic_pair_window` |

`targeted.py` contains a hand-built case that random generation missed: a
suspected epoch that opens between a contradiction's event-time interval and
its receipt time. It fails under the D3_v1 `Covered` wording and passes once the
epoch check extends to `max(I) + beta`.

```sh
python proofs/test_props.py --cases 2000 --seed 11     # ~2 min locally
```

Reports go to `evidence/proofs/props-<UTC>-seed<S>-n<N>.json`. Stdlib only; Python ≥ 3.10.

## Fixes these tests forced (reflected in `paper/D3_v2.tex` and `design-spec.md`)

1. `DistinctAction` uses its fallback only when the action-ID source reports no
   loss. Otherwise, deleting an equal action ID created links.
2. `Covered` checks node-trust epochs up to `max(I) + beta`. Otherwise, a
   suspected epoch opened by an unrelated deletion made a contradiction
   nondecisive (`targeted.py`).
3. Index eviction follows the processing frontier, not the raw watermark.
4. (2026-10-23) `Covered` ignores the epoch opened by the target finding's own
   trigger unless the epoch degrades a sensor-originated contradiction for the
   pair; the trigger's own evidence stays trusted within `beta_onset`, as in
   production. Under the D3_v5 text (`no_trigger_exemption`) a link into a
   host escape can never confirm. `targeted.self_trigger_case` checks it; Props.
   1-3 still hold (seeds 3, 7, 11, 2000 cases). Guarding on *any* degraded
   contradiction broke Prop. 1: forged workload contradictions toggled the link.
   Otherwise, valid pairs were missed.
5. (2026-11-14) Reference-model fix, no paper change: two clock records of one
   source at the same time made `eps_of` depend on their arrival order, so one
   arrival order confirmed a link that exhaustive search rejected (seed 105,
   scenario 5,983 of 6,000; a Prop. 3 / Lemma 1 violation). Ties now resolve to
   the larger uncertainty, which is conservative and order-free. The paper and
   the production pipeline carry one uncertainty bound per event, so they had
   no such lookup. `targeted.clock_tie_case` checks it. The 8 x 6,000 run was
   repeated on the fixed code: `evidence/proofs/SUMMARY-2026-11-14.md`.
