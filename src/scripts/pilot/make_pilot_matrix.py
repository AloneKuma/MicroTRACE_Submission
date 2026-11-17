"""Write a PILOT run matrix (spec/generator/run-matrix.schema.json).

Three layouts:

  balanced (default, short runs) — every scenario runs once per round; a
          world's --passes rounds run on that world. Rounds come in blocks
          of five: in a block, scenario i runs in round r under profile
          (a_i + r * m_i) mod 5, with a_i and m_i (1-4) dealt round-robin
          over a shuffled catalogue and redrawn per block. As 5 is prime,
          each scenario meets every profile once per block, and no profile
          is tied to a finding's positives or its lookalikes; two scenarios
          with different m share a profile group in one round of the block,
          so groups (and so run partners) change every round. Each round's
          profile groups are shuffled and split into runs by scenario time
          (window + spacing; chains take longer); a run still mixes attack,
          lookalike and degraded scenarios. --fixed-groups restores the
          earlier layout (m = 1, a drawn once), whose groups never change.
  sliced  (short runs) — the catalogue is shuffled and dealt into
          slices that fit one run; each world gets --passes passes over the
          slices, reshuffled per pass, with the observability profile rotated
          across slices. Every run mixes attack, lookalike and degraded
          scenarios, so PRESENT and non-PRESENT windows share runs and the
          run's volume or profile cannot stand in for the label.
  full    (long runs) — one run per world x profile with the whole catalogue;
          the generator shuffles the order per seed and runs what fits.

Variants (balanced layout): PILOT and RESEARCH alternate v1 and v2 by
round; HELD_OUT runs v3, a variant PILOT and RESEARCH never see, where a
scenario has one, else alternates as well. Only a real variant (one with
``changes``) is used; a scenario without one runs v1. A run lists its
non-v1 choices in ``scenario_variants`` ("sid=v2,..."), which run_pilot.py
passes to ``mtgen build --variants``; ``scenario_variant`` is the round's
variant index (0 = v1).

run_id is derived exactly as `python -m mtgen build` derives it, so the
matrix names the directories the builds write.

Usage (from the repository root):
    python src/scripts/pilot/make_pilot_matrix.py --duration-s 600 \\
        --out spec/generator/run-matrix.pilot.yaml
    python src/scripts/pilot/make_pilot_matrix.py --layout full --duration-s 3600 \\
        --out spec/generator/run-matrix.pilot-3600s.yaml
"""
import argparse
import hashlib
import sys
import uuid
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[3]
CATALOGUE = REPO / "spec" / "scenarios" / "catalogue.v0.yaml"

PROFILES = ["clean", "degraded_gateway", "degraded_audit",
            "degraded_ebpf", "degraded_context"]
WORLD_SEED_BASE = {"Small": 1000, "Reference": 2000, "Large": 3000}
# Added to every seed so splits never share one (PILOT keeps its seeds).
# Seeds of all matrices so far are below 50000 (make_cases_matrix included).
SPLIT_SEED_OFFSET = {"PILOT": 0, "RESEARCH": 50000, "HELD_OUT": 100000}
# Scenario slot in the generator: 30 s spacing + 60 s window.
SLOT_S = 90
SPACING_S = 30


def run_id(world, profile, scenario_ids, split, seed, duration_s, variants=""):
    """Same derivation as mtgen.__main__._cmd_build."""
    return str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"mtgen:{world}|{profile}|{','.join(scenario_ids)}|{split}|{seed}"
        f"|{duration_s}" + (f"|{variants}" if variants else ""),
    ))


def real_variants(scenario):
    """Variant ids of a scenario that change something (have ``changes``)."""
    return {v["id"] for v in scenario.get("variants", []) if v.get("changes")}


def variant_for(sid, rnd, real, split):
    """The variant a scenario runs in round rnd (see the module docstring)."""
    if split == "HELD_OUT" and "v3" in real.get(sid, ()):
        return "v3"
    vid = f"v{rnd % 2 + 1}"
    return vid if vid == "v1" or vid in real.get(sid, ()) else "v1"


def scenarios_per_run(duration_s):
    """Scenario starts that fit: the k-th starts near 30 + 90 k seconds."""
    return max(1, (duration_s - SPACING_S) // SLOT_S + 1)


def scenario_time_s(scenario):
    """Run time a scenario takes in the generator: its window plus spacing."""
    return float(scenario.get("window_s", SLOT_S - SPACING_S)) + SPACING_S


def pack_by_time(members, time_s, duration_s):
    """Split members into the fewest runs whose scenario time fits.

    A run fits when its scenarios' time sums to at most duration + 30 s: the
    generator starts the first scenario 30 s in and clips only the last
    window, as seven 90 s scenarios in 600 s always did. Longest scenarios
    are dealt first to the least-loaded run; the result keeps the runs as
    even as the greedy deal allows.
    """
    budget = duration_s + SPACING_S
    if not members:
        return []
    n = max(1, -(-int(sum(time_s[m] for m in members)) // budget))
    while True:
        bins = [[] for _ in range(n)]
        load = [0.0] * n
        for m in sorted(members, key=lambda m: -time_s[m]):
            k = min(range(n), key=lambda i: (load[i], len(bins[i])))
            bins[k].append(m)
            load[k] += time_s[m]
        if max(load) <= budget:
            # Keep each run's scenarios in the shuffled member order.
            pos = {m: i for i, m in enumerate(members)}
            return [sorted(b, key=pos.get) for b in bins]
        n += 1


SPLIT = "PILOT"


def run_entry(world, profile, ids, scenario_arg, seed, duration_s, all_ids, note,
              variants=None, variant_index=0):
    selected = all_ids if scenario_arg == "all" else ids
    # Same order as the generator: the run's scenario order.
    chosen = ",".join(f"{sid}={(variants or {})[sid]}" for sid in selected
                      if (variants or {}).get(sid, "v1") != "v1")
    entry = {
        "run_id": run_id(world, profile, selected, SPLIT, seed, duration_s, chosen),
        "split": SPLIT,
        "world_name": world,
        "scenario_id": scenario_arg,
        "scenario_variant": variant_index,
        "observability_profile": profile,
        "seed_generator": seed,
        "seed_scenario": seed,
        "service_graph_shape": "layered_web_shop",
        "run_type": "full",
        "duration_s": duration_s,
        "description": note,
    }
    if chosen:
        entry["scenario_variants"] = chosen
    return entry


# The Large run measures capacity only. A single run of a world no other run
# shares is an outlier on every volume feature, so it carries scenarios that
# create no finding opportunity (admin and benign workload jobs): it adds no
# rows to the nuisance check.
CAPACITY_SCENARIOS = [
    "admin_rbac_mutation", "admin_kubectl_exec_debug", "admin_backup_job_read_secrets",
    "admin_ci_rbac_mutation", "admin_image_rollout", "admin_scheduled_job",
    "admin_operator_list_resources",
]


def large_capacity_run(dur, all_ids):
    ids = CAPACITY_SCENARIOS[:scenarios_per_run(dur)]
    return run_entry(
        "Large", "clean", ids, ",".join(ids),
        SPLIT_SEED_OFFSET[SPLIT] + WORLD_SEED_BASE["Large"] + 1,
        dur, all_ids, "Large/clean capacity run; admin and benign workload "
        "scenarios only (no finding opportunities)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layout", choices=["balanced", "sliced", "full"],
                    default="balanced")
    ap.add_argument("--duration-s", type=int, required=True)
    ap.add_argument("--passes", type=int, default=3,
                    help="sliced: catalogue passes per world (default 3)")
    ap.add_argument("--worlds", default="Small,Reference")
    ap.add_argument("--large", action="store_true",
                    help="add one Large capacity run (sliced layout)")
    ap.add_argument("--matrix-seed", type=int, default=7)
    ap.add_argument("--fixed-groups", action="store_true",
                    help="balanced: keep each scenario's profile group fixed "
                         "across rounds (the layout before 2026-10-20)")
    ap.add_argument("--split", choices=["PILOT", "RESEARCH", "HELD_OUT"],
                    default="PILOT")
    ap.add_argument("--frozen", action="store_true",
                    help="write frozen: true (a matrix generated at the freeze)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    global SPLIT
    SPLIT = args.split

    catalogue_bytes = CATALOGUE.read_bytes()
    catalogue = yaml.safe_load(catalogue_bytes)
    all_ids = [s["id"] for s in catalogue["scenarios"]]
    worlds = [w for w in args.worlds.split(",") if w]
    dur = args.duration_s
    runs = []

    if args.layout == "balanced":
        per_run = scenarios_per_run(dur)
        time_s = {s["id"]: scenario_time_s(s) for s in catalogue["scenarios"]}
        real = {s["id"]: real_variants(s) for s in catalogue["scenarios"]}
        rng = np.random.default_rng(args.matrix_seed)
        n_prof = len(PROFILES)

        def deal(values):
            """values dealt round-robin over a fresh shuffle of the catalogue."""
            order = [all_ids[int(i)] for i in rng.permutation(len(all_ids))]
            return {sid: values[k % len(values)] for k, sid in enumerate(order)}

        offset = deal(list(range(n_prof)))
        step = {sid: 1 for sid in all_ids}
        if args.fixed_groups:
            # A profile's group in round r and in round r+1 never share a
            # scenario, so long runs can hold several consecutive rounds' groups.
            group_size = -(-len(all_ids) // n_prof)
            per_block = max(1, min(args.passes, per_run // group_size))
        else:
            per_block = 1   # groups change every round; one round per run
        rnd = 0
        for world in worlds:
            for b0 in range(0, args.passes, per_block):
                block = range(b0, min(b0 + per_block, args.passes))
                if not args.fixed_groups and b0 % n_prof == 0:
                    # New block of five rounds: redraw offsets and steps.
                    offset = deal(list(range(n_prof)))
                    step = deal(list(range(1, n_prof)))
                j = 0
                for profile in PROFILES:
                    members = [sid for r in block for sid in all_ids
                               if PROFILES[(offset[sid] + step[sid] * (rnd + r - b0
                                            if args.fixed_groups else r % n_prof))
                                           % n_prof] == profile]
                    members = [members[int(i)] for i in rng.permutation(len(members))]
                    for k, ids in enumerate(pack_by_time(members, time_s, dur)):
                        # 10 x base keeps worlds apart for up to 400 rounds
                        if j >= 25:
                            sys.exit("more than 25 runs in a round: seeds would overlap")
                        seed = (SPLIT_SEED_OFFSET[SPLIT]
                                + 10 * WORLD_SEED_BASE[world] + 25 * b0 + j + 1)
                        j += 1
                        if len(block) == 1:
                            rounds = f"round {rnd + 1}"
                        else:
                            rounds = f"rounds {rnd + 1}-{rnd + len(block)}"
                        vids = {sid: variant_for(sid, rnd, real, SPLIT) for sid in ids}
                        runs.append(run_entry(
                            world, profile, ids, ",".join(ids), seed, dur, all_ids,
                            f"{world}/{profile}/{rounds} run {k + 1}: "
                            f"{len(ids)} scenarios", vids,
                            2 if SPLIT == "HELD_OUT" else rnd % 2))
                rnd += len(block)
        if args.large:
            runs.append(large_capacity_run(dur, all_ids))
        layout_note = (f"every scenario once per round, {args.passes} rounds per "
                       f"world, profile rotated per scenario, "
                       + ("fixed profile groups" if args.fixed_groups
                          else "profile groups redrawn every round")
                       + f", runs packed by scenario time (window + 30 s spacing, "
                         f"at most {dur + SPACING_S} s per run), "
                       + ("v3 where a scenario has one, else v1/v2 by round"
                          if SPLIT == "HELD_OUT" else "variants v1/v2 alternating by round"))
    elif args.layout == "sliced":
        per_run = scenarios_per_run(dur)
        n_slices = -(-len(all_ids) // per_run)
        rng = np.random.default_rng(args.matrix_seed)
        for world in worlds:
            for p in range(args.passes):
                order = [all_ids[int(i)] for i in rng.permutation(len(all_ids))]
                slices = [order[j::n_slices] for j in range(n_slices)]
                for j, ids in enumerate(slices):
                    profile = PROFILES[(j + p) % len(PROFILES)]
                    seed = SPLIT_SEED_OFFSET[SPLIT] + WORLD_SEED_BASE[world] + 100 * p + j + 1
                    runs.append(run_entry(
                        world, profile, ids, ",".join(ids), seed, dur, all_ids,
                        f"{world}/{profile}/pass {p + 1} slice {j + 1}: "
                        f"{len(ids)} scenarios"))
        if args.large:
            runs.append(large_capacity_run(dur, all_ids))
        layout_note = (f"{n_slices} slices of about {per_run} scenarios; "
                       f"{args.passes} passes per world; profile rotated per slice")
    else:
        for world in worlds:
            for k, profile in enumerate(PROFILES):
                seed = SPLIT_SEED_OFFSET[SPLIT] + WORLD_SEED_BASE[world] + 500 + k + 1
                runs.append(run_entry(
                    world, profile, all_ids, "all", seed, dur, all_ids,
                    f"{world}/{profile}: whole catalogue in seeded order; "
                    f"about {scenarios_per_run(dur)} scenarios fit"))
        layout_note = "one run per world x profile, whole catalogue, seeded order"

    matrix = {
        "matrix_version": "run-matrix.v0",
        "frozen": args.frozen,
        "scenario_catalogue_version": hashlib.sha256(catalogue_bytes).hexdigest(),
        "generator_spec_version": "generator-spec.v0",
        "description": (
            f"Draft {SPLIT} run matrix, {dur} s runs ({args.layout} layout: "
            f"{layout_note}). Generated by src/scripts/pilot/make_pilot_matrix.py "
            f"--matrix-seed {args.matrix_seed}."),
        "splits": {SPLIT: {
            "description": {"PILOT": "Pilot and tuning runs",
                            "RESEARCH": "Research runs",
                            "HELD_OUT": "Held-out evaluation runs"}[SPLIT],
            "run_count": len(runs),
            "visible_to_agents": SPLIT != "HELD_OUT",
            "visible_to_baselines": SPLIT != "HELD_OUT",
            "visible_to_thresholds": SPLIT == "PILOT",
            "template_pool": "HELD_OUT_POOL" if SPLIT == "HELD_OUT" else "DEV",
        }},
        "nuisance_check": {"enabled": True, "threshold": 0.65},
        "determinism": {
            "seed_allocation": f"split offset {SPLIT_SEED_OFFSET[SPLIT]} + "
                               "(10 x world base + 25 x round + run in round "
                               "(balanced); world base + 100 x pass + slice "
                               "(sliced); world base + 500 + profile index (full))",
            "seed_generation": "UUIDv5(namespace=URL, key='mtgen:{world}|"
                               "{obs_profile}|{scenario_ids_csv}|" + SPLIT
                               + "|{seed}|{dur_s}[|{non-v1 scenario_variants}]')",
        },
        "runs": runs,
    }
    header = (
        f"# MicroTRACE {SPLIT} run matrix — generated, do not edit by hand.\n"
        f"# python src/scripts/pilot/make_pilot_matrix.py {' '.join(argv or sys.argv[1:])}\n"
        "# schema: spec/generator/run-matrix.schema.json\n\n"
    )
    out = Path(args.out)
    out.write_text(header + yaml.safe_dump(matrix, sort_keys=False, width=100),
                   encoding="utf-8", newline="\n")
    print(f"Written: {out} ({len(runs)} runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
