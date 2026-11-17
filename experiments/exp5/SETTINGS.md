# Exp. 5 settings (fixed 2026-11-16, before any Exp. 5 run)

Decided by the user in chat on 2026-11-16, after Exp. 1-2 were scored (scoring order Option 2,
heldout-aws-plan.md section 8). Nothing here depends on an Exp. 1-2 result: inputs are chosen by
input volume alone, and Exp. 5 compares each crash run with its own uncrashed run A (no truth).
The design is evaluation-plan.md section 4, Exp. 5; the values below fill what it leaves open.

## Part A, crash recovery (`run_exp5_aws.sh`, analysis host m7i.8xlarge, on-demand)

| Setting | Value | Why |
|---|---|---|
| Parameters | `src/params/frozen/pilot-multistep-fit.K10.mlv2.yaml` for the agents and the GO | the configuration Exp. 1-2 scored (the stack gave the agents the dev set before; fixed in this commit) |
| Candidates | the 32 HELD_OUT runs with world Reference, profile clean | larger worlds hold more open state at a kill; clean keeps crash effects apart from telemetry loss (Exp. 3) |
| Inputs | the 3 candidates whose event count (lines over `shipper/*.jsonl`) is closest to the candidates' median, ties by run_id (`select_inputs.py`) | typical workload, chosen on input data only (user: option 2, not random, not by any score) |
| Main matrix | A, A′; each GO failpoint × restart modes B, C, D; each receiver, agent and TGS failpoint and `pg.server_crash` as X; 5 reps per cell, nth drawn from 1..5 (seed 1): 112 runs per input, 336 in all | the design's matrix and repetition count; 3 inputs give 15 runs per cell (0 failures: 95 % bound 20 %) and 75 for mode C pooled (4 %) |
| Main input rate | at once (`--pace 0`) | user 2026-11-16. The main matrix therefore reports correctness ("k of N identical") only; its recovery-time and lag numbers are not used |
| Outage (main) | 2 s (`crashrun` default) | below `max_idle_s` = 10 s: band 1, identical to A |
| Sweeps | on one input (the first of the 3 whose earlier history covers 4 h; else the one with the longest), one factor at a time around pace x1 / outage 3 s / history 10 min: pace x2, x4; outage 60 s, 600 s; history 1 h, 4 h | values fixed 2026-10-12 (sweep.py); 3 s, 60 s, 600 s fall below `max_idle_s`, inside the ~300 s posting horizon, and beyond it |
| Sweep cells | the 5 GO failpoints, restart mode C only, 3 reps, + A, A′: 17 runs per setting | user 2026-11-16 ("focused"); recovery time, added sealing delay, catch-up CPU and memory come from these paced runs |
| Corner cell | pace x4, outage 600 s, history 4 h, same cells | the one interaction a one-factor sweep misses (user accepted 2026-11-16) |
| History source | the other candidates (not the 3 inputs) whose last event precedes the sweep input's first event, per node in event-time order; `--history-s` keeps the last H s | user 2026-11-16; history is loaded, never scored. If it covers less than 4 h, the actual span is reported |
| Parallel stacks | main 8, sweeps 6 | main is correctness only; sweeps time recovery, so fewer stacks share the CPU. A′ measures the noise under the same load |
| Shakedown | one PILOT FIT run before any held-out cell: `MT_CRASHRUN` tests; 3 points at once; one pace-1 mode-C cell. Every C and X cell must equal A, else the session stops | catches harness faults on development data, so no held-out result shapes a fix |

## Part B, graph consistency and GRE (`run_exp5_kind.sh`, kind node m7i.2xlarge, on-demand)

| Setting | Value |
|---|---|
| Cluster | kind v0.33.0, node `kindest/node:v1.35.8@sha256:07b2536e…`, Calico v3.30.3, audit policy (`gre-kind-up.sh`) |
| Suite | every `tests/test_gre_*.py` and `tests/test_tgs*.py` (mutations, compromised executor, interrupted submissions by failpoint, postconditions incl. accepted-but-ineffective, guard ablation; TGS contract section 8) |
| Randomised sequences | 1,000 from seed 1, 40 steps; then each guard ablated alone (nonce, snapshot, revalidation, postcondition, permissions), 200 sequences from seed 1 (the runner's default count) |
| Not run | the toxiproxy API-fault cases: never built; the paper says so (user 2026-11-16) |

## Fixes after the development shakedown (2026-11-16, before any held-out cell)

- **Run end rule** (`crashrun._Drain`): the shakedown's paced test had runs B, C and D all differ
  from A by one record while A and A' agreed. A run ended once the shippers drained and the outputs
  were quiet for `settle_s` (10 s in the test, equal to the receiver's `max_idle`), so a short run
  (A, A') could stop before the idle coverage and the seals it releases, which a longer crash run
  still caught. Every run (and every prefill) now also waits `max_idle + settle_s` after the last
  shipper drained. Same rule for A, A' and every crash run; no scoring rule or parameter changed.
- **Nonce test** (`test_gre_validate`, part B): the second GRE shared the first GRE's graph
  connection across threads; a graph read's closing rollback could undo the other GRE's uncommitted
  nonce insert, so both executed. A deployed GRE has its own connections (`gre/cli.py`); the test
  now gives the second GRE its own graph and nonce connections. The nonce store itself (primary
  key, `INSERT ... ON CONFLICT DO NOTHING`) is unchanged.

## Part B runs (2026-11-16)

- `results/partB-run1/` (code 3c6b103): suite 424 passed, 4 failed; sequences as below.
- `results/partB/` (code eaaa1a8 + ece3b2f fixes, fresh kind node): suite 427 passed, 1 failed. Of run 1's
  failures: the nonce test was a test artefact (shared connection across threads; fixed, 20/20 on the
  test host); the GRE-role test and part of the e2e test failed for missing Kafka topics and TGS tables
  on a fresh machine (now created by `run_exp5_kind.sh`); the TGS ingest test was fixture drift
  (c6682f6). The one remaining failure, `test_tgs_e2e`, asserted `all(offset >= 0)`, which held only
  on a long-lived dev Kafka (empty fresh partitions are correctly -1); the test now checks that every
  partition holding records has its last record applied. Verified 2/2 on the test host's dev Kafka;
  the fresh-Kafka case is covered by the reasoning above, not by a rerun (the kind node had ended).
- Randomised sequences (both runs): full GRE 0 violations in 1,000; no-nonce, no-snapshot,
  no-revalidation, no-postcondition each violate their property; no-permissions violates none (the
  simulator does not model RBAC; the kube ablation tests cover permissions).

## Session

One Terraform workspace `exp5` (`session=exp5 kind_node=true spot=false scoring=false`), max_hours 14.
Price (us-east-1 on-demand): m7i.8xlarge $1.61/h + m7i.2xlarge $0.40/h. The kind node ends itself
when part B is done (expected 1-2 h). Expected ~$17-22; at most ~$28 at the cap.

## Added baseline (2026-11-17, after the part B results)

`results/partB/sequences-no-guards.json`: the same randomised sequences (200 from seed 1, 40 steps)
with all five guards removed at once, a plain executor that acts on any approval, as a no-guard
reference beside the single-guard ablations. Run on the laptop with the in-memory simulator
(`python -m mtcore.harness.gre_sequences --seeds 200 --first-seed 1 --steps 40 --ablate nonce
--ablate snapshot --ablate revalidation --ablate postcondition --ablate permissions`, code
19a749c). The simulator is deterministic: the laptop rerun of `--ablate nonce` gives the kind node's
32/200 exactly. Result: fresh_approval 197, one_execution 187, verified_probe 200 of 200 sequences.
