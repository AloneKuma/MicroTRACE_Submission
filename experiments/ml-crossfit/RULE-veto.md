# ML veto test rule (fixed 2026-11-10, confirmed by the user before any veto score)

Data and folds as the ML cross-fit (RULE.md): PILOT FIT half, 170 runs, ~/microtrace-ml/folds.json, 2 folds.
Each fold is scored with params and forests fitted on the other fold only. Forests: the existing
max-threshold models models/fold{A,B}-max (reused; re-training must reproduce them byte for byte).

Arms (code 8479daf): benign-max thresholds (qmax), ml.or_path false (the score never adds a finding),
ml.veto on B3 and H1 only: a rule finding is kept only if its anomaly score >= cut; fails open on cold start.
cut = conformal level alpha_v over the other fold's benign calibration windows (same windows and function
as gamma; no labels read). Grid alpha_v in {0.5, 0.25, 0.1}, one value shared by B3 and H1: arms
qmax_veto0.5, qmax_veto0.25, qmax_veto0.1. Fourth candidate: qmax_gnone (existing result, no veto).

Choose: (1) highest out-of-fold finding-level F1 over all 170 runs; (2) among candidates within 0.005 of
the best, highest link F1; (3) no veto before any veto, then the larger alpha_v (the milder veto).
Reported alongside: true and false findings removed per type vs qmax_gnone, and the numbers without the
Large run 226278d9 (diagnostic only, not used for the choice).
Disclosure: chosen after the FIT cross-fit results and an ML separability diagnostic
(~/microtrace-ml/diag), whose in-sample veto estimate was seen before this rule was written. A FIT-stage
development choice; held-out data is not touched.
