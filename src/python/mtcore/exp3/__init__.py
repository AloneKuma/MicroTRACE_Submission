"""Experiment 3 runner (robustness under telemetry faults).

docs/plans/evaluation-plan.md section 4 ("3 Robustness", "Exp. 3 by fault"),
docs/plans/heldout-aws-plan.md section 8, spec/faults/fault-contract.md.
Work log: docs/plans/exp3-runner-worklog.md.

Modules: base (base stream for the senders, without ground truth), plans
(fault-plan templates to per-run, per-node plans), slot (one receiver and
Kafka per replayed run, dump of what arrived), sender (faultinject and shipper
per node stream), run (the stages: base, transport, detect, score).
"""
