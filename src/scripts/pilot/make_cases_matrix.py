"""Run matrices of the add-on sets (exp2-conflict-origin-cases-plan).

    python src/scripts/pilot/make_cases_matrix.py --out spec/generator/run-matrix.pilot-cases-origin.yaml
    python src/scripts/pilot/make_cases_matrix.py --set cases --out spec/generator/run-matrix.pilot-cases.yaml \\
        [--precheck spec/generator/run-matrix.pilot-cases-precheck.yaml]
    python src/scripts/pilot/make_cases_matrix.py --set tactic --out spec/generator/run-matrix.pilot-cases-tactic.yaml \\
        [--precheck spec/generator/run-matrix.pilot-cases-tactic-precheck.yaml]

tactic (exp2-no-tactic-cases-plan R1): 20 runs added to pilot-cases, with
the No-Tactic overlay's two scenarios, chain_exfil_first (a backward true
chain, where the tactic weight can hurt) and two background scenarios as in
cases; 900 s, the cases flags, both overlays; TACTIC_SEEDS_PER_PROFILE runs
per profile, the first TACTIC_PRECHECK_PER_PROFILE as the pre-check.

origin (step 2 early build): the two origin_ scenarios of the catalogue
overlay plus two PILOT scenarios as background (rotated through BACKGROUND),
600 s, flag gateway_internal_listener; SEEDS_PER_PROFILE runs per profile.

cases (R1): all five overlay scenarios plus two PILOT background scenarios,
900 s (seven scenario windows), flags gateway_internal_listener and
ebpf_accept, CASES_SEEDS_PER_PROFILE runs per profile. Background: base
scenarios with no connect_internal step (D-33: under ebpf_accept a base
scenario's unbaselined connect would fire G1c on a step with no G1c
opportunity), rotated in catalogue order. Odd runs use the overlay
scenarios' v2. --precheck also writes the first CASES_PRECHECK_PER_PROFILE
runs of each profile as a sub-matrix (same run IDs).

Both on the Reference world. Run IDs are derived as mtgen build derives them
(variants and flags included), so they never equal a PILOT run ID.

--split HELD_OUT (cases and tactic): the same layout for the held-out add-on
(HELD_OUT-cases), with every seed raised by HELD_OUT_SEED_OFFSET so no seed
of any earlier matrix repeats; hidden from agents, baselines and thresholds.
The overlays have no v3, so the variants are as in PILOT.
"""
import argparse
import hashlib
import uuid
from pathlib import Path

import yaml

OVERLAY = "spec/scenarios/catalogue.pilot-cases.v0.yaml"
FLAGS = ["gateway_internal_listener"]
CASES = ["origin_request_id_graft", "origin_request_id_propagate"]
# PILOT scenarios with gateway requests or benign service traffic, so the
# origin_ requests sit among other A1/A2 requests (attack and lookalike).
BACKGROUND = ["a1_kube_ids0_sqli", "a1_benign_json_injection_token", "a2_benign_success_response",
              "a1_blocked_by_waf", "benign_service_traffic", "b1_k8ntext_benign_lookalike"]
PROFILES = ["clean", "degraded_gateway", "degraded_audit", "degraded_ebpf", "degraded_context"]
SEEDS_PER_PROFILE = 3
WORLD, SPLIT, DURATION_S, SEED0 = "Reference", "PILOT", 600, 20001

CASES_ALL = CASES + ["conflict_port_reuse", "conflict_port_reuse_unobserved", "conflict_slow_accept"]
CASES_FLAGS = ["gateway_internal_listener", "ebpf_accept"]
CASES_SEEDS_PER_PROFILE, CASES_PRECHECK_PER_PROFILE = 8, 2
CASES_DURATION_S, CASES_SEED0 = 900, 30001

TACTIC_OVERLAY = "spec/scenarios/catalogue.pilot-cases-tactic.v2.yaml"
TACTIC_ALL = ["tactic_ancestor_lookalike", "tactic_ancestor_forward", "chain_exfil_first"]
TACTIC_SEEDS_PER_PROFILE, TACTIC_PRECHECK_PER_PROFILE = 4, 1
TACTIC_SEED0 = 40001
# Held-out add-on seeds: 130001.. (cases) and 140001.. (tactic), above every
# seed of make_pilot_matrix.py's HELD_OUT (110001..120289 as frozen).
HELD_OUT_SEED_OFFSET = 100000
SEED_OFFSET = 0   # set from --split in main()


def run_id(world, profile, ids, split, seed, duration_s, flags, variants=""):
    """As mtgen.__main__ derives it (variants: its non-default string)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                          f"mtgen:{world}|{profile}|{','.join(ids)}|{split}|{seed}|{duration_s}"
                          + (f"|{variants}" if variants else "")
                          + (f"|flags={','.join(sorted(flags))}" if flags else "")))


def _sha(repo, rel):
    return hashlib.sha256((repo / rel).read_bytes()).hexdigest()


def eligible_background(repo):
    """Base scenarios with no connect_internal step (D-33), in catalogue order."""
    cat = yaml.safe_load((repo / "spec/scenarios/catalogue.v0.yaml").read_text(encoding="utf-8"))
    return [sc["id"] for sc in cat["scenarios"]
            if not any(st.get("action") == "connect_internal" for st in sc.get("steps", []))]


def overlay_v2(repo, ids):
    """Overlay scenarios among ids that have a v2 variant, in ids' order."""
    ov = yaml.safe_load((repo / OVERLAY).read_text(encoding="utf-8"))
    has = {sc["id"] for sc in ov["scenarios"] if any(v["id"] == "v2" for v in sc.get("variants", []))}
    return [i for i in ids if i in has]


def _run(ids, profile, seed, duration_s, flags, variants, description, overlays=(OVERLAY,)):
    run = {"run_id": run_id(WORLD, profile, ids, SPLIT, seed, duration_s, flags, variants),
           "split": SPLIT, "world_name": WORLD, "scenario_id": ",".join(ids),
           "scenario_variant": 1 if variants else 0, "observability_profile": profile,
           "seed_generator": seed, "seed_scenario": seed,
           "service_graph_shape": "layered_web_shop", "run_type": "full",
           "duration_s": duration_s, "catalogue_overlays": list(overlays),
           "generator_flags": flags, "description": description}
    if variants:
        run["scenario_variants"] = variants
    return run


def origin_runs():
    runs, n = [], 0
    for profile in PROFILES:
        for k in range(SEEDS_PER_PROFILE):
            ids = CASES + [BACKGROUND[(2 * n + i) % len(BACKGROUND)] for i in range(2)]
            runs.append((k, _run(ids, profile, SEED0 + n, DURATION_S, FLAGS, "",
                                 f"No-Origin add-on {profile} {k + 1}: {len(ids)} scenarios")))
            n += 1
    return runs


def cases_runs(repo):
    pool = eligible_background(repo)
    runs, n = [], 0
    for profile in PROFILES:
        for k in range(CASES_SEEDS_PER_PROFILE):
            ids = CASES_ALL + [pool[(2 * n + i) % len(pool)] for i in range(2)]
            variants = ",".join(f"{i}=v2" for i in overlay_v2(repo, ids)) if n % 2 else ""
            runs.append((k, _run(ids, profile, SEED_OFFSET + CASES_SEED0 + n, CASES_DURATION_S, CASES_FLAGS, variants,
                                 f"pilot-cases add-on {profile} {k + 1}: {len(ids)} scenarios"
                                 + (" (overlay v2)" if variants else ""))))
            n += 1
    return runs


def tactic_runs(repo):
    """The pool rotates from where cases stopped, so the background differs.
    The three case scenarios rotate too, so their window in the run does not
    give the label away (D-4 review of overlay v0)."""
    pool = [s for s in eligible_background(repo) if s not in TACTIC_ALL]
    start = 2 * len(PROFILES) * CASES_SEEDS_PER_PROFILE
    runs, n = [], 0
    for profile in PROFILES:
        for k in range(TACTIC_SEEDS_PER_PROFILE):
            r = n % len(TACTIC_ALL)
            ids = TACTIC_ALL[r:] + TACTIC_ALL[:r] + [pool[(start + 2 * n + i) % len(pool)] for i in range(2)]
            runs.append((k, _run(ids, profile, SEED_OFFSET + TACTIC_SEED0 + n, CASES_DURATION_S, CASES_FLAGS, "",
                                 f"pilot-cases No-Tactic add-on {profile} {k + 1}: {len(ids)} scenarios",
                                 overlays=(OVERLAY, TACTIC_OVERLAY))))
            n += 1
    return runs


def write(repo, out, runs, what, title, cmd, overlays=(OVERLAY,), frozen=False):
    if SPLIT == "HELD_OUT":
        what, title = f"Held-out copy of the {what}", f"HELD_OUT {title}"
    doc = {"matrix_version": "run-matrix.v0", "frozen": frozen,
           "scenario_catalogue_version": _sha(repo, "spec/scenarios/catalogue.v0.yaml"),
           "generator_spec_version": "generator-spec.v0",
           "description": f"{what}, catalogue overlay "
                          + ", ".join(f"{o} sha256 {_sha(repo, o)}" for o in overlays)
                          + ". Generated by src/scripts/pilot/make_cases_matrix.py.",
           "splits": {SPLIT: {"description": ("Held-out add-on cases, scored once with PILOT's fit parameters"
                                              if SPLIT == "HELD_OUT"
                                              else "Add-on cases, scored with PILOT's fit parameters"),
                              "run_count": len(runs), "visible_to_agents": SPLIT != "HELD_OUT",
                              "visible_to_baselines": SPLIT != "HELD_OUT",
                              "visible_to_thresholds": SPLIT == "PILOT",
                              "template_pool": "HELD_OUT_POOL" if SPLIT == "HELD_OUT" else "DEV"}},
           "runs": runs}
    head = (f"# MicroTRACE {title} run matrix - generated, do not edit by hand.\n"
            f"# {cmd}\n"
            "# schema: spec/generator/run-matrix.schema.json\n\n")
    out.write_text(head + yaml.safe_dump(doc, sort_keys=False, width=110), encoding="utf-8",
                   newline="\n")
    print(f"{len(runs)} runs -> {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--set", choices=("origin", "cases", "tactic"), default="origin")
    ap.add_argument("--precheck", type=Path, help="cases: also write the pre-check sub-matrix here")
    ap.add_argument("--split", choices=("PILOT", "HELD_OUT"), default="PILOT",
                    help="HELD_OUT: the held-out add-on (cases and tactic sets only)")
    ap.add_argument("--frozen", action="store_true",
                    help="write frozen: true (a matrix generated at the freeze)")
    a = ap.parse_args(argv)
    repo = Path(__file__).resolve().parents[3]
    global SPLIT, SEED_OFFSET
    SPLIT = a.split
    if SPLIT == "HELD_OUT":
        if a.set == "origin" or a.precheck:
            ap.error("--split HELD_OUT takes --set cases or tactic, without --precheck")
        SEED_OFFSET = HELD_OUT_SEED_OFFSET
    if a.set == "origin":
        write(repo, a.out, [r for _, r in origin_runs()],
              "No-Origin add-on runs (exp2-conflict-origin-cases-plan step 2 early build)", "No-Origin add-on",
              f"python src/scripts/pilot/make_cases_matrix.py --out {a.out.as_posix()}")
        return
    cmd = (f"python src/scripts/pilot/make_cases_matrix.py --set {a.set} --out {a.out.as_posix()}"
           + (f" --precheck {a.precheck.as_posix()}" if a.precheck else "")
           + (f" --split {SPLIT}" if SPLIT != "PILOT" else "")
           + (" --frozen" if a.frozen else ""))
    if a.set == "tactic":
        runs, ov = tactic_runs(repo), (OVERLAY, TACTIC_OVERLAY)
        write(repo, a.out, [r for _, r in runs], "pilot-cases No-Tactic add-on runs (exp2-no-tactic-cases-plan R1)",
              "pilot-cases No-Tactic add-on", cmd, ov, a.frozen)
        if a.precheck:
            write(repo, a.precheck, [r for k, r in runs if k < TACTIC_PRECHECK_PER_PROFILE],
                  "pilot-cases No-Tactic pre-check: the first run of each profile (R2)",
                  "pilot-cases No-Tactic pre-check", cmd, ov)
        return
    runs = cases_runs(repo)
    write(repo, a.out, [r for _, r in runs], "pilot-cases add-on runs (exp2-conflict-origin-cases-plan R1)",
          "pilot-cases add-on", cmd, frozen=a.frozen)
    if a.precheck:
        write(repo, a.precheck, [r for k, r in runs if k < CASES_PRECHECK_PER_PROFILE],
              "pilot-cases pre-check: the first runs of each profile of the pilot-cases matrix (R2)",
              "pilot-cases pre-check", cmd)


if __name__ == "__main__":
    main()
