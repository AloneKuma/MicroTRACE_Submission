# Frozen GO parameter sets (K = 10)

Copies of the development fit parameter files with one change: the GO's `K`
(ranked paths kept per incident) is 10 instead of 2. Every other line equals
the original in the dataset's `_gates/` folder on the test host (checked with
`diff --strip-trailing-cr` on 2026-11-08). Stored with LF line endings (the repo
rule for .yaml); four originals use CRLF, which YAML reads the same way.

| File | Original (test host) | Use |
|---|---|---|
| `pilot-multistep-fit.K10.yaml` | `microtrace-pilot-multistep/pilot-multistep/_gates/pilot-multistep-fit.yaml` | PILOT, and the held-out PILOT-type set |
| `pidsmaker.v0.yaml` | (record, not a parameter set) | KAIROS and ORTHRUS frozen settings, 2026-11-11 |
| `pilot-multistep-fit.K10.mlB3.yaml` | the line above, plus the ML block (see below) | Same sets, B3 filter only (held-out side row `go_mlB3`) |
| `pilot-multistep-fit.K10.mlv2.yaml` | `mlB3` plus B1 and H1 filters (see below) | Same sets, **main ML setting** from 2026-11-12 (`go_main`) |
| `fit-ri-on.K10.yaml` | `microtrace-pilot-cases/pilot-cases/_gates/fit-ri-on.yaml` | Targeted, Full |
| `fit-ri-on-no_<x>.K10.yaml` | `..._gates/fit-ri-on-no_<x>.yaml` | Targeted ablations |

Why K = 10: `docs/design/parameter-register.md` (row `K`) and
`docs/plans/ROADMAP.md` section 2b. SAGE and ORTHRUS use the same value
(`src/params/sage.v0.yaml` `k`, `seeded records --k 10`).

## ML setting (`pilot-multistep-fit.K10.mlB3.yaml`)

Chosen 2026-11-10 (`experiments/ml-crossfit/RULE-confirmB3.md`, arm `qmax_confirmB3`). Equals
`pilot-multistep-fit.K10.yaml` except the `ml` block, `parameter_set_version` and `fit.ml`.
ML never adds a finding (`or_path: false`); a B3 rule finding is kept only if its window's
anomaly score is at least `ml.veto.B3` (0.6969, the B3 gamma at alpha 0.001); cold start fails open.
Forests for B, G and H in `models/pilot-multistep-fit/` were trained on the whole PILOT FIT half
(89 proper, 81 calibration runs) by `experiments/ml-crossfit/freeze.sh` (code 8479daf); `train.json`
holds the gammas and model versions. Model paths are relative to the parameter file.
The B3 cut was chosen in-sample on FIT; the held-out run is its real test.
Targeted-type sets (HELD_OUT-cases and the ablations) stay rules-only (`fit-ri-on*.K10.yaml`;
user decision 2026-11-11): the filter was chosen and checked on PILOT data only.
When moving or copying the mlB3 file (e.g. to the test host), copy `models/` with it: model
paths are read from the file's own folder.

## ML setting v2 (`pilot-multistep-fit.K10.mlv2.yaml`), main row from 2026-11-12

User choice 2026-11-12 after the ML model comparison (`experiments/ml-compare/`, plan
`docs/plans/ml-model-compare-plan.md`). Equals the mlB3 file plus two filters, made by
`src/scripts/pilot/freeze_detectors.py` (code c06192b) from the same rows and halves as the forests
(`~/microtrace-ml/freeze/rows`, 89 proper and 81 calibration runs):

| Type | Detector | Cut (`ml.veto`, alpha 0.001) | Calibration windows | Model |
|---|---|---|---|---|
| B1 | one-class SVM (RBF, gamma "scale", nu 0.01; log1p + median/IQR) | -1.73124 | 2,088 | `DET_B1.json`, `DET_B1@sha256:355b4c59f7110cdd` |
| H1 | kNN distance, k 5 (log1p + median/IQR) | 0.52764 | 3,584 | `DET_H1.json`, `DET_H1@sha256:ff7ca787837bee3e` |

B3 keeps its Isolation Forest filter; G1a and B2 are unchanged (no filter). A `DET_*` artifact replaces
its type's forest only because it declares `replaces: iforest` (the scorer refuses otherwise).
The choice came from development data where the comparison's own rule found every type NOT TESTABLE
(too few labelled findings); the held-out run is its test, with the mlB3 setting reported beside it.
`gamma` of B1/H1 in the file is unused (`or_path` false).

