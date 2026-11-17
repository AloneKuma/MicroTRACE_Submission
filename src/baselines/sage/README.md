# SAGE baseline: pinned upstream and our patch

SAGE (Nadeem, Verwer, Moskal, Yang, "Alert-Driven Attack Graph Generation Using
S-PDFA", IEEE TDSC 19(2), 2022) is the alert-level baseline of Exp. 2 and 3
(evaluation-plan.md section 6). Its code is not vendored.
`src/scripts/baselines/fetch-sage.sh` fetches it at a pinned commit, applies the
patch below, and builds FlexFringe on the test host.

| Upstream | Pin | Licence |
|---|---|---|
| github.com/tudelft-cda-lab/SAGE | `707a190e7ace8ebbe0800c68f3bd934e58006b50` (2024-06-28, last commit on `main`) | MIT |
| github.com/tudelft-cda-lab/FlexFringe | `1a87e3b` (the commit SAGE's own Dockerfile builds) | see the FlexFringe repository |

## `patches/0001-microtrace-export.patch`

It changes how SAGE takes input and writes output, but not how it builds
episodes, the S-PDFA or attack graphs. There is one exception: a bug fix,
listed below.

| Change | Why |
|---|---|
| The alert ID (`microtrace_finding_id`) is carried through parsing, episodes, state sequences and attack-graph vertices | SAGE keeps only counts and signatures per episode. Without the IDs, its paths can't be mapped back to our findings. |
| It writes `exp-teams.json`, `exp-sequences.json` (every episode subsequence) and `exp.txt-paths.json` (every attack-graph path), each with alert IDs per episode | These are the inputs of `mtcore.baselines.sage.project`. |
| It reads extra signature-to-stage entries from `$SAGE_EXTRA_SIGNATURES` (JSON) | Our 18 finding types map to stages through `spec/baselines/sage-mapping.v2.yaml` (v0 and v1 are the earlier records). An unknown signature would otherwise be NON_MALICIOUS. |
| It reads the IANA port table from `$SAGE_IANA_CSV` | SAGE downloads the table on every run. We use a pinned copy (`iana-service-names-port-numbers.csv.gz`, fetched 2026-10-24) so runs are reproducible. |
| Alert files are read in sorted order | Team IDs become deterministic. |
| Team colour falls back to black beyond 10 teams | Upstream raises a `KeyError` with more than 10 alert files. |
| `$SAGE_SKIP_RENDER` skips the PNG/SVG rendering and the histogram figure | Batch runs only need the exports. |
| **Bug fix:** `_remove_duplicates` keeps the first alert | Upstream started its loop at index 1 and so always dropped each team's first alert, contrary to its own docstring ("keeping only the first occurrence"). |

To regenerate the patch after changing it: apply the edits to a clean checkout
at the pin, made with `core.autocrlf=false`, then run `git diff >
patches/0001-microtrace-export.patch`.

## Notes for reading results

- SAGE learns one S-PDFA over all alert files in a call, so a batch (for
  example the whole SCORE half) is one call with one file per run. Endpoints
  are pseudo-IPs seeded by run, so no two runs share an attacker or victim.
- SAGE's input order matters: it reverses each file before computing gaps
  between alerts. `alerts.py` therefore writes alerts newest first.
- Attack graphs exist only for sequences of three or more episodes that reach
  a high-severity objective (stage value 100 or above). In our mapping only H1
  and H4 reach one (DATA_EXFILTRATION). The `ag` variant is SAGE as
  published. The `seq` variant drops those two filters as a sensitivity row,
  which is generous to SAGE.
