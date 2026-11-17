# Choice rule: ML model comparison (fixed 2026-11-11, before any number)

Plan: docs/plans/ml-model-compare-plan.md. Data: the 170 PILOT FIT runs, folds A/B
of ~/microtrace-ml/folds.json. Held-out data is not read.

## Arms

0 Isolation Forest (fold models models/fold{A,B}-max, not refitted)
1 ECOD; 2 HBOS (10 bins, alpha 0.1, tol 0.5); 3 kNN (k 5, largest distance);
4 LOF (k 20, novelty); 5 One-class SVM (RBF, gamma "scale", nu 0.01);
6 rank mean of arms 0-5; 7 rank mean of the 3 best arms by PR AUC on the other fold.
Arms 3-5 use log1p then median/IQR scaling fitted on the training rows.
Cold start as today: an entity seen fewer than N_cold = 3 times in training keeps its finding.

## Unit and labels

One rule-finding record of type B1, B2, B3, G1a or H1. True: matches a PRESENT
opportunity. False: fp_absent or fp_background. Unobservable: left out.

## Step 1 (per type, fold, arm)

Models fit on the other fold's benign proper half. Cut: conformal_gamma on its
calibration half at alpha 0.001, or 0.01 where 0.001 is infeasible for that type and
fold (the same alpha for every arm). Measures: PR AUC (main), ROC AUC, MCC at the cut,
false records removed and true records lost at the cut. Bootstrap: 2,000 draws over
runs. Every number is also given without run 226278d9.

1. A type is testable only with >= 20 true and >= 20 false records out of fold in each
   fold; else NOT TESTABLE and it stays as frozen.
2. An arm passes for a type only if: PR AUC exceeds arm 0's by >= 0.05 in both folds;
   the bootstrap 95% lower bound of the pooled gain is > 0; at the cut it loses no more
   true records than arm 0.
3. Per type, the passing arm with the highest mean PR AUC is the candidate. Ties: a
   single model before a mix, then the lower arm number.

## Step 2 (system check by GO replay, fold configs of qmax_confirmB3)

Configurations: the frozen setup plus one candidate type at a time, then all candidates
together. A configuration is adopt-worthy only if, against qmax_confirmB3:
false finding records fall by >= 10% with bootstrap 95% lower bound of the fall > 0;
true findings (opportunities) do not fall; link F1 does not fall; and all of this also
holds without run 226278d9. System F1 and link F1 are reported, not decisive.

If no configuration is adopt-worthy, Isolation Forest stays. Adopting one is a separate
decision by the user (unfreeze, refit, new paper version).
