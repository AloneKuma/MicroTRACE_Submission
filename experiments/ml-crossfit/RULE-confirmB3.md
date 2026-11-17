# B3 confirmation arm rule (fixed 2026-11-10 after the label-free veto, confirmed by the user before this arm is scored)

Data and folds as RULE.md / RULE-veto.md: PILOT FIT half, 170 runs, ~/microtrace-ml/folds.json, 2 folds;
each fold scored with params and forests fitted on the other fold only (models/fold{A,B}-max).

Arm qmax_confirmB3 (code 8479daf): benign-max thresholds, ml.or_path false, ml.veto {B3: gamma_B3 at
alpha 0.001} read from models/foldF-max/train.json (the ML alarm threshold already calibrated on benign
calibration windows). A B3 rule finding is kept only if its anomaly score >= that value; fails open on cold
start. Every other type unchanged.

Choose among qmax_gnone, qmax_veto0.5, qmax_veto0.25, qmax_veto0.1, qmax_confirmB3: (1) highest out-of-fold
finding-level F1 over all 170 runs; (2) within 0.005 of the best, highest link F1; (3) no ML before any ML
arm, then the milder arm first (veto0.5, veto0.25, veto0.1, confirmB3).

Disclosure: B3 and this cut were picked after seeing labelled score distributions of rule-true windows on
the FIT half (benign B3 .626-.742, attack .761-.764; H1 left out because its attacks overlap its false
findings). A FIT-stage development choice; held-out data is not touched.

Priority report (no effect on detection or on the choice): for B1, B3 and H1 findings of this arm, precision
of findings with anomaly score >= gamma(0.001) vs below it. Findings records are kept per run
(runs/<run>/findings.json); full outputs are deleted for disk.
