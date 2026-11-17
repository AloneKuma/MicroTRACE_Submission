"""Exp. 3 conditions and fault plans: committed templates to per-run, per-node plans.

    python -m mtcore.exp3.plans --conditions C.tsv --base BASE_ROOT --runs RUNS.json \
        --out PLANS_ROOT [--only COND,...] [--outputs-root DETECT_ROOT]

A condition (experiments/exp3/configs/conditions.tsv) names a template under
experiments/exp3/plans/. A template is a faultplan.v0 file
(spec/faults/fault-contract.md) with a few extension keys that make it fit
every run; instantiation resolves them from the run's base.json (the stream
itself, mtcore.exp3.base) and, for contradiction suppression, from an earlier
detection output on the same run. Truth is never read. The extension keys:

  target: first-priority-ebpf | largest-worker | control-plane
      the run's target node (top level). first-priority-ebpf is the node of
      the run's earliest PRIORITY-lane eBPF record (an escape-class family:
      ns.change, ipc.runtime_socket, proc.ptrace, bpf.call; mtgen.emit routes
      them there); largest-worker the worker with the most records. A run
      without a target gets no node-targeted fault (meta.json says so).
  nodes: all | target | worker | control-plane | off-node    (per fault; default all)
      which node streams get the fault; each node has its own faultinject,
      so node-targeted faults need no node selector in the plan format.
  times: "start+240s", "start+40%", "target+1s" for select.from, select.to, after
      start = the run's first event time (all nodes), target = the event time
      of the target record (first-priority-ebpf only). Absolute RFC 3339 is kept.
  select.logical_ids: "@decisive_contradictions"
      the evidence event IDs of every decisive contradiction of a REJECTED
      witness in the condition's `needs` output (the no-fault Full pass on the
      same run). A run with none gets no such fault.
  base_variant: no_history    (top level)
      the condition is sent from the run's No-History identity variant
      (mtcore.exp3.nohistory, W/base-no_history) instead of its base stream;
      the faults (if any) apply to that stream as usual.

Output per (condition, run): PLANS_ROOT/<condition>/<run_id>/<node>.yaml (plain
faultplan.v0: the shipper applies its transit faults, faultinject its source
faults) and meta.json (template hash, faults per node, applied, reasons).
Instantiation is deterministic: the same template and base give the same bytes.
"""
import argparse
import copy
import csv
import fnmatch
import gzip
import hashlib
import json
import os
import re
import sys

import yaml

from mtcore import REPO
from mtcore.exp3.base import ns_rfc3339

EXT_FAULT_KEYS = ("nodes",)
BASE_VARIANTS = ("no_history",)
TIME_RE = re.compile(r"^(start|target)\+(\d+(?:\.\d+)?)(s|%)$")
COND_COLUMNS = ("condition", "template", "mode", "pace", "tier", "needs", "note")
MODES = ("offline", "live")


# --- config ------------------------------------------------------------------------------
def read_tsv(path, columns):
    """Rows of a tab-separated config ('#' comments, blank lines skipped) as dicts."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(columns) - 1:
                raise SystemExit(f"{path}:{n}: {len(parts)} columns, want {len(columns)}: {columns}")
            row = dict(zip(columns, parts + [""] * (len(columns) - len(parts))))
            row["_line"] = n
            rows.append(row)
    return rows


def load_conditions(path, max_tier=None, only=None):
    rows = read_tsv(path, COND_COLUMNS)
    seen = set()
    out = []
    for r in rows:
        if r["condition"] in seen:
            raise SystemExit(f"{path}: duplicate condition {r['condition']}")
        seen.add(r["condition"])
        if r["mode"] not in MODES:
            raise SystemExit(f"{path}:{r['_line']}: mode {r['mode']!r} not in {MODES}")
        r["pace"] = float(r["pace"])
        r["tier"] = int(r["tier"])
        r["needs"] = "" if r["needs"] in ("", "-") else r["needs"]
        if max_tier is not None and r["tier"] > max_tier:
            continue
        if only and not any(fnmatch.fnmatch(r["condition"], p) for p in only):
            continue
        out.append(r)
    return out


def template_path(conditions_path, name):
    """Templates live in experiments/exp3/plans/ (relative to the conditions file's ../plans)."""
    p = os.path.join(os.path.dirname(os.path.abspath(conditions_path)), "..", "plans", name)
    return os.path.normpath(p)


def template_base_variant(template_file):
    """The template's base_variant (None for the ordinary base stream)."""
    with open(template_file, encoding="utf-8") as fh:
        v = (yaml.safe_load(fh) or {}).get("base_variant")
    if v is not None and v not in BASE_VARIANTS:
        raise SystemExit(f"{template_file}: base_variant {v!r} not in {BASE_VARIANTS}")
    return v


# --- resolution ------------------------------------------------------------------------------
def pick_target(rule, base):
    """(node name, anchor event ns or None, reason) for a target rule; node None if none."""
    nodes = base["nodes"]
    if rule == "first-priority-ebpf":
        cands = [(n["first_priority_ebpf"]["event_ns"], n["first_priority_ebpf"]["logical_id"], n["node"])
                 for n in nodes if n.get("first_priority_ebpf")]
        if not cands:
            return None, None, "no PRIORITY-lane eBPF record in the run"
        ns, _, node = min(cands)
        return node, ns, "node of the first PRIORITY-lane eBPF record"
    if rule == "largest-worker":
        ws = sorted(((n["records"], n["node"]) for n in nodes if n["role"] == "worker"), key=lambda x: (-x[0], x[1]))
        if not ws:
            return None, None, "no worker node"
        return ws[0][1], None, "worker with the most records"
    if rule == "control-plane":
        cp = sorted(n["node"] for n in nodes if n["role"] == "control-plane")
        if not cp:
            return None, None, "no control-plane node"
        return cp[0], None, "control-plane node"
    raise ValueError(f"unknown target rule {rule!r}")


def resolve_time(value, base, target_ns):
    """An extension time string to RFC 3339; None when it needs a missing target."""
    if not isinstance(value, str):
        return value
    m = TIME_RE.match(value.strip())
    if not m:
        return value
    anchor, num, unit = m.group(1), float(m.group(2)), m.group(3)
    if anchor == "target":
        if target_ns is None:
            return None
        if unit == "%":
            raise ValueError("target+N% is not defined; use seconds")
        return ns_rfc3339(target_ns + int(num * 1e9))
    start, end = base["stream_start_ns"], base["stream_end_ns"]
    off = int(num * 1e9) if unit == "s" else int((end - start) * num / 100)
    return ns_rfc3339(start + off)


def decisive_contradictions(output_path):
    """Evidence event IDs of the decisive contradictions of REJECTED witnesses (last record per
    witness) in a detection output (output.jsonl[.gz]); sorted."""
    op = gzip.open if output_path.endswith(".gz") else open
    last = {}
    with op(output_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            o = json.loads(line)
            if o.get("topic") != "witness.decisions.v0" or "record" not in o:
                continue
            r = o["record"]
            last[r.get("witnessId") or r.get("witness_id")] = r
    ids = set()
    for r in last.values():
        if r.get("status") != "REJECTED":
            continue
        for c in r.get("contradictions") or []:
            if c.get("decisive"):
                ids.update(c.get("evidenceEventIds") or c.get("evidence_event_ids") or [])
    return sorted(ids)


def node_matches(spec, node, target):
    if spec in (None, "all"):
        return True
    if spec == "target":
        return target is not None and node["node"] == target
    if spec in ("worker", "control-plane", "off-node"):
        return node["role"] == spec
    raise ValueError(f"unknown nodes value {spec!r}")


def instantiate(template, base, needs_output=None):
    """{node name: plan dict} and meta for one run. template is the parsed template."""
    t = copy.deepcopy(template)
    rule = t.pop("target", None)
    variant = t.pop("base_variant", None)
    target, target_ns, why = (None, None, None)
    if rule:
        target, target_ns, why = pick_target(rule, base)
    contra = None
    reasons, kept = [], []
    for f in t.get("faults") or []:
        f = copy.deepcopy(f)
        nodes_spec = f.pop("nodes", "all")
        sel = f.get("select") or {}
        if sel.get("logical_ids") == "@decisive_contradictions":
            if contra is None:
                if not needs_output or not os.path.exists(needs_output):
                    raise SystemExit(f"fault {f['id']}: needs the earlier output {needs_output}")
                contra = decisive_contradictions(needs_output)
            if not contra:
                reasons.append(f"{f['id']}: no decisive contradiction in the needed output")
                continue
            sel["logical_ids"] = list(contra)
        missing = False
        for k in ("from", "to"):
            if k in sel:
                sel[k] = resolve_time(sel[k], base, target_ns)
                missing |= sel[k] is None
        if "after" in f:
            f["after"] = resolve_time(f["after"], base, target_ns)
            missing |= f["after"] is None
        if nodes_spec == "target" and target is None:
            missing = True
        if missing:
            reasons.append(f"{f['id']}: no target ({why})")
            continue
        if sel:
            f["select"] = sel
        kept.append((f, nodes_spec))
    plans, per_node = {}, {}
    for n in base["nodes"]:
        faults = [f for f, spec in kept if node_matches(spec, n, target)]
        plans[n["node"]] = {"version": t["version"], "seed": t["seed"], "faults": faults}
        per_node[n["node"]] = [f["id"] for f in faults]
    meta = {"target_rule": rule, "target": target, "target_event": ns_rfc3339(target_ns) if target_ns else None,
            "target_reason": why, "faults_per_node": per_node,
            "applied": any(per_node.values()) or not (template.get("faults") or []),
            "skipped": reasons, "contradiction_ids": contra}
    if variant:
        meta["base_variant"] = variant
    return plans, meta


def dump_plan(plan):
    return yaml.safe_dump(plan, sort_keys=True, default_flow_style=False)


def write_run_plans(template_file, base, out_dir, needs_output=None):
    with open(template_file, "rb") as fh:
        raw = fh.read()
    template = yaml.safe_load(raw)
    if template.get("version") != "faultplan.v0":
        raise SystemExit(f"{template_file}: version {template.get('version')!r}, want faultplan.v0")
    plans, meta = instantiate(template, base, needs_output)
    os.makedirs(out_dir, exist_ok=True)
    for node, plan in plans.items():
        tmp = os.path.join(out_dir, node + ".yaml.tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dump_plan(plan))
        os.replace(tmp, os.path.join(out_dir, node + ".yaml"))
    try:
        tname = os.path.relpath(template_file, REPO).replace("\\", "/")
    except ValueError:                              # another drive (Windows)
        tname = os.path.abspath(template_file)
    meta.update(template=tname,
                template_sha256=hashlib.sha256(raw).hexdigest(), run_id=base["run_id"],
                needs_output=needs_output)
    with open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    return meta


def load_runs(spec):
    """RUNS.json[:key] -> run IDs (a list file or a dict of lists)."""
    path, key = spec, ""
    if not os.path.exists(spec):                    # FILE:key (rpartition: a Windows drive has a colon too)
        path, _, key = spec.rpartition(":")
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if isinstance(d, list):
        return d
    return d[key or "runs"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conditions", required=True)
    ap.add_argument("--base", required=True, help="BASE_ROOT of mtcore.exp3.base")
    ap.add_argument("--runs", required=True, help="RUNS.json[:key]")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="", help="comma-separated condition patterns")
    ap.add_argument("--max-tier", type=int, default=None)
    ap.add_argument("--outputs-root", default=None,
                    help="detection outputs: <root>/<condition>/<pass>/runs/<run>/output.jsonl.gz (for needs)")
    a = ap.parse_args(argv)
    conds = load_conditions(a.conditions, a.max_tier, [p for p in a.only.split(",") if p])
    runs = load_runs(a.runs)
    for c in conds:
        tf = template_path(a.conditions, c["template"])
        for r in runs:
            base = json.load(open(os.path.join(a.base, r, "base.json"), encoding="utf-8"))
            need = None
            if c["needs"]:
                cond, _, pas = c["needs"].partition(":")
                need = os.path.join(a.outputs_root or "", cond, pas, "runs", r, "output.jsonl.gz")
            m = write_run_plans(tf, base, os.path.join(a.out, c["condition"], r), need)
            print(json.dumps({"condition": c["condition"], "run": r, "applied": m["applied"],
                              "target": m["target"], "skipped": m["skipped"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
