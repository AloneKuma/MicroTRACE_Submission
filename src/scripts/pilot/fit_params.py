"""Fit the agents' PILOT parameter set from benign PILOT traffic (build step 9).

    python src/scripts/pilot/fit_params.py --pilot datasets/generated/pilot \\
        --out src/params/pilot.v0.yaml --split-out src/params/pilot-split.v0.json [--workers 6]

Split. The runs are grouped by (world, observability profile); inside each
group they are ordered by SHA-256 of the run ID and dealt alternately to FIT
and SCORE. Baselines are fitted on FIT only; SCORE runs are never opened here,
so PILOT scores on them are not inflated by the fit.

Benign traffic. From each FIT run, every event the generator rendered for a
scenario action (restricted/truth_actions.pb, rendered_event_ids) is left
out: attacks, lookalikes, admin and non-link scenarios alike, so a baseline
holds background traffic only. The answer key is read for this filter and for
nothing else; findings and labels are never read.

Fitted (each the same feature the rule computes, over the same window and key):
  Q_B1   principal name -> max distinct (group, resource, namespace) of
         successful reads per W_B1 window          (B1 fires above it)
  Q_B3   principal name -> max audit requests per W_B3 window
  N_H3   max over principals of secret list/watch requests plus distinct
         secret names read by get, per W_H3 window
  Q_H1   workload -> max external bytes out of one Pod per W_H1 window
  Q_H2   workload -> external destinations ("ip:port") connected to
  Q_G1a  [source workload, destination workload, port] of successful
         in-cluster connects
  E_D1   workload -> processes reading the workload's own projected token
  E_E2   workload -> {writer, path_prefix} of post-start writes E2 would flag
  E_F1   workload -> executables through which a privilege gain happened
Declared (copied from the spec, not fitted):
  P_A    pattern_id -> class, from spec/artifacts/p_a.v0.yaml
  I_A2   class -> indicator ids, from spec/artifacts/i_a2.v0.yaml
  C_H4   sensitive data classes of the scenario schema (credential, system)
Everything else is copied from --base.

Thresholds. --threshold max (the default) keeps the plain benign maximum
(PILOT-FIT-v0..v2). That maximum is exceeded by fresh benign traffic, and how
far depends on the dataset. With --threshold conformal, Q_B1, Q_B3 and Q_H1
are split-conformal thresholds at a declared per-window false alarm
probability alpha (--alpha, default 1e-3):
  1. The FIT runs are halved again, per (world, profile), into proper and
     calibration runs (calibration_split).
  2. Per key, from the proper runs: location = median and spread = MAD of
     its benign window values, in the symbol's score space (SCORE_SPACE:
     raw counts, log1p bytes), spread floored at the feature's resolution.
     Keys with fewer than MIN_KEY_WINDOWS proper windows, or seen only in
     calibration runs, get no entry (unbaselined: the rule abstains).
  3. Every calibration window is scored (value - location) / spread of its
     key (normalized nonconformity), pooled over keys; c is the
     ceil((n+1)(1-alpha))-th smallest of the n scores.
  4. Q = location + c * spread mapped back and floored: the rule fires iff
     the window's score > c.
For exchangeable benign windows this bounds the chance that a benign window
fires by alpha, whatever the distribution (split conformal prediction). alpha
is a declared choice, never fitted to scores; it needs n >= 1/alpha - 1.
Conformal is not the default (2026-10-24): it would change the thresholds
behind the reported pilot-multistep scores.
The rules fire strictly above the thresholds, so no FIT window would fire.
"""
import math
import statistics
import argparse
import glob
import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "python"))

from google.protobuf import json_format  # noqa: E402

import mtgen  # noqa: E402,F401  (registers generated protos)
from microtrace.v0 import dataset_pb2, envelope_pb2  # noqa: E402
from mtcore.agents.events import Ev, opt  # noqa: E402
from mtcore.agents.rules.common import (EXTERNAL, HOST_READER, SUCCESS, endpoint, ok_2xx,  # noqa: E402
                                        process_name, unique_audits)
from mtcore.agents.rules.e import MMAP, UNLINK, WRITE_OPS  # noqa: E402
from mtcore.agents.rules.g import IN_CLUSTER  # noqa: E402

READ_VERBS = {"get", "list", "watch"}
C_H4 = ["credential", "system"]
NS = 1_000_000_000


def read_ld(path, msg_type):
    data, pos, out = open(path, "rb").read(), 0, []
    while pos < len(data):
        n = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        m = msg_type()
        m.ParseFromString(data[pos:pos + n])
        pos += n
        out.append(m)
    return out


def split_runs(pilot):
    groups = defaultdict(list)
    for mf in sorted(glob.glob(os.path.join(pilot, "*", "manifest.json"))):
        m = json.load(open(mf, encoding="utf-8"))
        groups[(m["world_name"], m["observability_profile"])].append(m["run_id"])
    fit, score = [], []
    for key in sorted(groups):
        runs = sorted(groups[key], key=lambda r: hashlib.sha256(r.encode()).hexdigest())
        for i, r in enumerate(runs):
            (fit if i % 2 == 0 else score).append(r)
    return sorted(fit), sorted(score)


def scenario_event_ids(run_dir):
    ids = set()
    for a in read_ld(os.path.join(run_dir, "restricted", "truth_actions.pb"), dataset_pb2.GroundTruthAction):
        ids.update(a.rendered_event_ids)
    return ids


def events(run_dir, must=None):
    """Ev for every norm.events.v0 record (only lines containing `must`, if set)."""
    for path in sorted(glob.glob(os.path.join(run_dir, "shipper", "*.jsonl"))):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if '"norm.events.v0"' not in line or (must and must not in line):
                    continue
                obj = json.loads(line)
                if obj.get("topic") != "norm.events.v0":
                    continue
                yield Ev(json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope()))


def pod_workloads(run_dir):
    """Pod UID -> owner name, from every Pod context record (scenario Pods too)."""
    out = {}
    for e in events(run_dir, must='"owners"'):
        if e.ne.WhichOneof("record") == "context":
            c = e.ne.context
            if c.kind == "Pod" and c.pod.owners:
                out[c.uid] = c.pod.owners[0].name
    return out


CALIBRATED = ("Q_B1", "Q_B3", "Q_H1")


def fit_run(args):
    """Per-run maxima and sets over the run's benign events."""
    run_dir, windows = args
    skip = scenario_event_ids(run_dir)
    workload = pod_workloads(run_dir)
    evs = (e for e in events(run_dir) if e.id not in skip)

    def win(e, sym):
        w = windows[sym] * NS
        return (e.t // w) * w

    def wl(pod):
        return workload.get(pod) if pod else None

    b_by = defaultdict(list)          # (principal uid, name) -> audit events
    h3_by = defaultdict(list)
    h1 = defaultdict(int)             # (pod, window) -> bytes
    out = {"Q_B1": {}, "Q_B3": {}, "N_H3": 0, "Q_H1": {}, "Q_H2": defaultdict(set), "Q_G1a": set(),
           "E_D1": defaultdict(set), "E_E2": defaultdict(set), "E_F1": defaultdict(set),
           "windows": {k: defaultdict(list) for k in CALIBRATED},
           "events": 0, "skipped": len(skip), "unowned_pods": 0, "owned_pods": len(workload)}
    for e in evs:
        out["events"] += 1
        if e.audit is not None and e.principal is not None:
            b_by[(e.principal[1], e.ad.principal.name or e.principal[1])].append(e)
            o = e.audit.object_ref
            if o.api_group == "" and o.resource == "secrets":
                h3_by[e.principal[1]].append(e)
            continue
        ed, d = e.ed, e.detail
        if ed is None or d is None:
            continue
        fam = e.family
        if fam == "net.flow_bytes" and ed.remote_class == EXTERNAL:
            h1[(e.pod_uid, win(e, "W_H1"))] += d.bytes_out
        elif fam == "net.connect" and ed.remote_class == EXTERNAL:
            w = wl(e.pod_uid)
            if w:
                out["Q_H2"][w].add(endpoint(d.remote))
        elif fam == "net.connect" and ed.remote_class in IN_CLUSTER and e.ebpf.result == SUCCESS:
            src, remote = wl(e.pod_uid), opt(ed, "remote_pod_uid")
            dst = wl(remote)
            if src and dst:
                out["Q_G1a"].add((src, dst, d.remote.port))
        elif fam == "file.read" and e.ebpf.result == SUCCESS and d.bytes:
            tf = opt(ed, "token_file")
            reader = process_name(e)
            if tf is not None and reader and e.ebpf.reader_class != HOST_READER:
                w = wl(tf.owner_pod_uid)
                if w:
                    out["E_D1"][w].add(reader)
        elif fam == "file.mutation" and d.op not in (UNLINK, MMAP):
            path = d.file.resolved_path or d.file.path_as_opened
            writer = process_name(e)
            if writer and (d.executable_after or d.op in WRITE_OPS):
                w = wl(e.pod_uid)
                if w:
                    out["E_E2"][w].add((writer, path.rsplit("/", 1)[0] + "/"))
        elif fam == "priv.creds" and d.HasField("before") and d.HasField("via_executable"):
            b, a = d.before, d.after
            if (b.euid != 0 and a.euid == 0) or (a.cap_effective & ~b.cap_effective):
                w = wl(e.pod_uid)
                if w:
                    out["E_F1"][w].add(d.via_executable.resolved_path)

    for (_uid, name), group in b_by.items():
        by_w1, by_w3 = defaultdict(list), defaultdict(list)
        for e in group:
            by_w1[win(e, "W_B1")].append(e)
            by_w3[win(e, "W_B3")].append(e)
        for ws in by_w1.values():
            reads = [e for e in unique_audits(ws) if e.audit.verb in READ_VERBS
                     and ok_2xx(e.audit.response_code) and e.audit.object_ref.resource]
            kinds = {(e.audit.object_ref.api_group, e.audit.object_ref.resource, e.audit.object_ref.namespace)
                     for e in reads}
            if reads:
                out["Q_B1"][name] = max(out["Q_B1"].get(name, 0), len(kinds))
                out["windows"]["Q_B1"][name].append(len(kinds))
        for ws in by_w3.values():
            n = len(unique_audits(ws))
            if n:
                out["Q_B3"][name] = max(out["Q_B3"].get(name, 0), n)
                out["windows"]["Q_B3"][name].append(n)
    for group in h3_by.values():
        by_w = defaultdict(list)
        for e in group:
            by_w[win(e, "W_H3")].append(e)
        for ws in by_w.values():
            reqs = [e for e in unique_audits(ws) if ok_2xx(e.audit.response_code)]
            lists = sum(e.audit.verb in ("list", "watch") for e in reqs)
            gets = {(e.audit.object_ref.namespace, e.audit.object_ref.name) for e in reqs
                    if e.audit.verb == "get" and e.audit.object_ref.name}
            out["N_H3"] = max(out["N_H3"], lists + len(gets))
    for (pod, _w), total in h1.items():
        w = wl(pod)
        if w is None:
            out["unowned_pods"] += 1
            continue
        out["Q_H1"][w] = max(out["Q_H1"].get(w, 0), total)
        out["windows"]["Q_H1"][w].append(total)
    out["windows"] = {k: dict(v) for k, v in out["windows"].items()}
    return os.path.basename(run_dir), out


def calibration_split(pilot, fit):
    """FIT runs -> (proper, calibration): per (world, profile), SHA-256("calib:" + run ID) order, dealt alternately."""
    groups = defaultdict(list)
    for r in fit:
        m = json.load(open(os.path.join(pilot, r, "manifest.json"), encoding="utf-8"))
        groups[(m["world_name"], m["observability_profile"])].append(r)
    proper, calib = [], []
    for key in sorted(groups):
        runs = sorted(groups[key], key=lambda r: hashlib.sha256(("calib:" + r).encode()).hexdigest())
        for i, r in enumerate(runs):
            (proper if i % 2 == 0 else calib).append(r)
    return set(proper), set(calib)


# Per symbol: the space the feature is scored in, and the spread floor (the
# feature's resolution there, so a key with constant benign values gets
# spread > 0). Counts: raw, one unit. Byte volumes are multiplicative: log1p,
# 5 % of the value.
SCORE_SPACE = {"Q_B1": ("raw", 1.0), "Q_B3": ("raw", 1.0), "Q_H1": ("log", 0.05)}
# A median and MAD from fewer benign windows than this are not a baseline.
MIN_KEY_WINDOWS = 10


def calibrate(proper, calib, alpha, space="raw", floor=1.0, min_windows=MIN_KEY_WINDOWS):
    """Normalized split-conformal threshold for one symbol (see the docstring).

    proper, calib: lists of {key: [benign value per window]} (one dict per run).
    Returns ({key: Q}, stats). A window's score is (t(v) - median_k) / spread_k,
    t = identity or log1p, spread_k = max(MAD_k, floor), both from the proper runs.
    Q = floor(t^-1(median_k + c * spread_k)): for integer values v > Q iff score > c.
    """
    t, inv = (math.log1p, math.expm1) if space == "log" else ((lambda v: v), (lambda v: v))
    pooled = defaultdict(list)
    for r in proper:
        for key, vs in r.items():
            pooled[key].extend(t(v) for v in vs)
    loc, spread = {}, {}
    thin = 0
    for key, xs in pooled.items():
        if len(xs) < min_windows:
            thin += 1
            continue
        loc[key] = statistics.median(xs)
        spread[key] = max(statistics.median(abs(x - loc[key]) for x in xs), floor)
    scores = sorted((t(v) - loc[key]) / spread[key] for r in calib for key, vs in r.items() if key in loc for v in vs)
    n = len(scores)
    k = math.ceil((n + 1) * (1 - alpha))
    if k > n:
        raise ValueError(f"{n} calibration windows cannot certify alpha={alpha} (need >= {math.ceil(1 / alpha) - 1})")
    c = scores[k - 1]
    # 1e-9: the inverse may land just under an integer
    q = {key: math.floor(inv(loc[key] + c * spread[key]) + 1e-9) for key in sorted(loc)}
    calib_keys = {key for r in calib for key in r}
    return q, {"alpha": alpha, "space": space, "spread_floor": floor, "calibration_windows": n,
               "factor": round(c, 6), "keys": len(q), "keys_too_few_windows": thin,
               "keys_only_in_calibration": len(calib_keys - set(pooled)),
               "calibration_max_factor": round(scores[-1], 6) if scores else None}


def merge(results):
    m = {"Q_B1": {}, "Q_B3": {}, "N_H3": 0, "Q_H1": {}, "Q_H2": defaultdict(set), "Q_G1a": set(),
         "E_D1": defaultdict(set), "E_E2": defaultdict(set), "E_F1": defaultdict(set)}
    stats = {"runs": 0, "events": 0, "scenario_events_skipped": 0, "unowned_pod_windows": 0,
             "runs_without_owners": 0}
    for _run, r in results:
        stats["runs"] += 1
        stats["runs_without_owners"] += r["owned_pods"] == 0
        stats["events"] += r["events"]
        stats["scenario_events_skipped"] += r["skipped"]
        stats["unowned_pod_windows"] += r["unowned_pods"]
        for k in ("Q_B1", "Q_B3", "Q_H1"):
            for key, v in r[k].items():
                m[k][key] = max(m[k].get(key, 0), v)
        m["N_H3"] = max(m["N_H3"], r["N_H3"])
        m["Q_G1a"] |= r["Q_G1a"]
        for k in ("Q_H2", "E_D1", "E_E2", "E_F1"):
            for key, v in r[k].items():
                m[k][key] |= v
    return m, stats


def spec_artifacts():
    p = yaml.safe_load(open(REPO / "spec" / "artifacts" / "p_a.v0.yaml", encoding="utf-8"))
    i = yaml.safe_load(open(REPO / "spec" / "artifacts" / "i_a2.v0.yaml", encoding="utf-8"))
    p_a = {x["pattern_id"]: x["class"] for x in p["patterns"]}
    i_a2 = defaultdict(list)
    for x in i["indicators"]:
        i_a2[x["class"]].append(x["indicator_id"])
    return p_a, {k: sorted(v) for k, v in sorted(i_a2.items())}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fit the PILOT parameter set from benign PILOT traffic.")
    ap.add_argument("--pilot", required=True, help="the PILOT dataset directory")
    ap.add_argument("--base", default=str(REPO / "src" / "params" / "dev.v0.yaml"))
    ap.add_argument("--out", required=True, help="parameter set to write")
    ap.add_argument("--split-out", required=True, help="FIT/SCORE run lists to write (JSON)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--version", default="PILOT-FIT-v0", help="parameter_set_version to write")
    ap.add_argument("--threshold", choices=("conformal", "max"), default="max",
                    help="Q_B1/Q_B3/Q_H1: split-conformal at --alpha, or the plain benign max (PILOT-FIT-v0..v2)")
    ap.add_argument("--alpha", type=float, default=1e-3,
                    help="conformal: per-window false alarm probability bound on benign traffic")
    a = ap.parse_args(argv)

    base = yaml.safe_load(open(a.base, encoding="utf-8"))
    fit, score = split_runs(a.pilot)
    with open(a.split_out, "w", encoding="utf-8") as fh:
        json.dump({"pilot": os.path.abspath(a.pilot), "rule": "per (world, profile): SHA-256(run_id) order, "
                   "even positions FIT, odd SCORE", "fit": fit, "score": score}, fh, indent=1)
        fh.write("\n")
    windows = base["windows_s"]
    jobs = [(os.path.join(a.pilot, r), windows) for r in fit]
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        results = []
        for i, res in enumerate(pool.map(fit_run, jobs), 1):
            results.append(res)
            print(f"{i}/{len(jobs)} {res[0]} events={res[1]['events']}", file=sys.stderr, flush=True)
    out = build(base, results, a.pilot, fit, a.threshold, a.alpha, a.version,
                os.path.basename(a.split_out), len(score))
    header = ("# PILOT parameter set, fitted by src/scripts/pilot/fit_params.py (see its docstring).\n"
              "# Generated file: refit instead of editing. NOT frozen; the freeze happens after\n"
              "# the PILOT scores are reviewed (docs/design/parameter-register.md).\n")
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(header)
        yaml.safe_dump(out, fh, sort_keys=False, allow_unicode=True, width=120)
    print(json.dumps(out["fit"], indent=1), file=sys.stderr)
    return 0


def build(base, results, pilot, fit, threshold, alpha, version, split_name, score_runs):
    """The parameter set from fit_run results [(run, result)] over the runs `fit`
    (crossfit_ml.py calls this on one fold)."""
    results = [(run, r) for run, r in results if run in set(fit)]
    m, stats = merge(results)
    if threshold == "conformal":
        proper, calib = calibration_split(pilot, fit)
        stats["calibration"] = {"proper_runs": len(proper), "calibration_runs": len(calib)}
        for k in CALIBRATED:
            m[k], stats["calibration"][k] = calibrate([r["windows"][k] for run, r in results if run in proper],
                                                      [r["windows"][k] for run, r in results if run in calib],
                                                      alpha, *SCORE_SPACE[k])

    p_a, i_a2 = spec_artifacts()
    art = dict(base["artifacts"])
    art.update({
        "P_A": p_a,
        "I_A2": i_a2,
        "E_D1": {w: sorted(v) for w, v in sorted(m["E_D1"].items())},
        "E_E2": {w: [{"writer": wr, "path_prefix": p} for wr, p in sorted(v)] for w, v in sorted(m["E_E2"].items())},
        "E_F1": {w: sorted(v) for w, v in sorted(m["E_F1"].items())},
        "Q_B1": dict(sorted(m["Q_B1"].items())),
        "Q_B3": dict(sorted(m["Q_B3"].items())),
        "Q_G1a": [list(e) for e in sorted(m["Q_G1a"])],
        "Q_H1": dict(sorted(m["Q_H1"].items())),
        "Q_H2": {w: sorted(v) for w, v in sorted(m["Q_H2"].items())},
        "C_H4": C_H4,
    })
    out = dict(base)
    out["parameter_set_version"] = version
    out["thresholds"] = dict(base["thresholds"], N_H3=m["N_H3"])
    out["artifacts"] = art
    out["fit"] = dict(stats, split=split_name, fit_runs=len(fit), score_runs=score_runs,
                      method="benign maximum per rule feature, window and key; scenario events excluded"
                      + ("; Q_B1/Q_B3/Q_H1 split-conformal at alpha" if threshold == "conformal" else ""))
    return out


if __name__ == "__main__":
    sys.exit(main())
