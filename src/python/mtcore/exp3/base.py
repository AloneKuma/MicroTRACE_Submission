"""Exp. 3 base stream for the sender nodes, without ground truth.

    python -m mtcore.exp3.base RUN_DIR [RUN_DIR ...] --out BASE_ROOT

heldout-aws-plan.md section 8: "Exp. 3 senders need a base stream without the
ground-truth envelopes (base.pb is now on the sealed side); write it with the
Exp. 3 runner." The base stream of a run is its shipper input files (one per
sending node, mtgen.emit), the format faultinject and the shipper read. This
module copies them with every ground.truth.v0 line and every envelope that
carries a ground-truth payload removed, so it accepts both a sealed run's
readable part (heldout/runs/<set>/<run>/, where seal.py already removed them)
and a full development run. It opens only RUN_DIR/shipper/*.jsonl and
RUN_DIR/manifest.json; restricted/ and base.pb are never opened.

Output, per run, BASE_ROOT/<run_id>/:
  nodes/<file>.jsonl  the node streams, other lines byte-for-byte unchanged
  manifest.json       the run manifest with the truth fields removed (seal.redact_manifest)
  base.json           what the plan instantiation needs, read from the stream only:
                      per node its record counts by source and lane, event-time span,
                      whether it carries control-plane sources, the first PRIORITY-lane
                      (escape-class) eBPF record; the run's stream start and end.
An export is skipped when base.json exists with the same input digests.

--variant no_history writes the No-History identity variant instead (mtcore.exp3.nohistory: every
identity a record resolves takes the key's latest mapping for the whole run); a separate BASE_ROOT
(the runner uses W/base-no_history), base.json says "variant" and how many records changed.
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

from mtcore.harness.seal import redact_manifest

TRUTH_TOPIC = "ground.truth.v0"
TRUTH_KEYS = ("ground_truth_action", "groundTruthAction")
CONTROL_PLANE_SOURCES = ("GATEWAY", "AUDIT", "KYVERNO", "CLUSTER_CONTEXT")
OFF_NODE_SOURCES = ("DB_AUDIT", "PATH_FLOW")
VERSION = "exp3-base.v2"


def ts_ns(s):
    """RFC 3339 (protojson Timestamp, any number of fractional digits) -> Unix ns."""
    if not s:
        return None
    s = s.rstrip("Z")
    frac = 0
    if "." in s:
        s, f = s.split(".", 1)
        frac = int((f + "000000000")[:9])
    if s[-6:-5] in "+-" and s[-3:-2] == ":":       # an explicit offset (protojson always writes Z)
        raise ValueError(f"timestamp with offset not supported: {s}")
    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp()) * 1_000_000_000 + frac


def ns_rfc3339(ns):
    sec, frac = divmod(int(ns), 1_000_000_000)
    base = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{frac:09d}Z"


def is_truth(obj):
    """A ground.truth.v0 line, or any envelope that carries a ground-truth payload."""
    if obj.get("topic") == TRUTH_TOPIC:
        return True
    env = obj.get("envelope")
    return isinstance(env, dict) and any(k in env for k in TRUTH_KEYS)


def _event_time(env):
    ne = env.get("normalized_event") or env.get("normalizedEvent")
    if not ne:
        return None
    t = ne.get("time") or {}
    return ts_ns(t.get("event_time") or t.get("eventTime"))


def _source(env):
    ne = env.get("normalized_event") or env.get("normalizedEvent")
    if ne and ne.get("source"):
        return ne["source"]
    return env.get("source") or "SOURCE_UNSPECIFIED"


def export_node(src, dst, line_fn=None):
    """Copy one node stream without truth lines; return its statistics. line_fn(obj) returns a
    replacement line (bytes) for a record it changes, else None (the line is kept byte for byte)."""
    st = {"lines": 0, "records": 0, "watermarks": 0, "heartbeats": 0, "truth_removed": 0,
          "by_source": {}, "by_lane": {}, "by_topic": {}, "first_event_ns": None, "last_event_ns": None,
          "first_priority_ebpf": None, "ebpf_node_ids": set(), "variant_changed": 0}
    h_in, h_out = hashlib.sha256(), hashlib.sha256()
    tmp = dst + ".tmp"
    with open(src, "rb") as fin, open(tmp, "wb") as fout:
        for raw in fin:
            h_in.update(raw)
            if not raw.strip():
                continue
            obj = json.loads(raw)
            if is_truth(obj):
                st["truth_removed"] += 1
                continue
            new = line_fn(obj) if line_fn is not None else None
            if new is not None:
                raw = new
                obj = json.loads(raw)
                st["variant_changed"] += 1
            fout.write(raw)
            h_out.update(raw)
            st["lines"] += 1
            if "watermark" in obj:
                st["watermarks"] += 1
                continue
            env = obj.get("envelope") or {}
            if "heartbeat" in env:
                st["heartbeats"] += 1
                continue
            st["records"] += 1
            src_name, lane, topic = _source(env), obj.get("lane") or "NORMAL", obj.get("topic", "")
            for key, val in (("by_source", src_name), ("by_lane", lane), ("by_topic", topic)):
                st[key][val] = st[key].get(val, 0) + 1
            et = _event_time(env)
            if et is None:
                continue
            if st["first_event_ns"] is None or et < st["first_event_ns"]:
                st["first_event_ns"] = et
            if st["last_event_ns"] is None or et > st["last_event_ns"]:
                st["last_event_ns"] = et
            if src_name == "EBPF":
                ne = env.get("normalized_event") or env.get("normalizedEvent") or {}
                nid = (ne.get("ebpf") or {}).get("node_id") or (ne.get("ebpf") or {}).get("nodeId")
                if nid:
                    st["ebpf_node_ids"].add(nid)
            if lane == "PRIORITY" and src_name == "EBPF":
                fp = st["first_priority_ebpf"]
                lid = env.get("logical_id") or env.get("logicalId") or ""
                if fp is None or (et, lid) < (fp["event_ns"], fp["logical_id"]):
                    ne = env.get("normalized_event") or env.get("normalizedEvent") or {}
                    fam = (ne.get("ebpf") or {}).get("event_family") or (ne.get("ebpf") or {}).get("eventFamily")
                    st["first_priority_ebpf"] = {"event_ns": et, "logical_id": lid, "event_family": fam}
    os.replace(tmp, dst)
    st["input_sha256"], st["sha256"] = h_in.hexdigest(), h_out.hexdigest()
    st["ebpf_node_ids"] = sorted(st["ebpf_node_ids"])
    return st


def shipper_node_id(name, st):
    """The node ID a node stream is shipped under: the eBPF node_id of its records (the agents
    tie a receiver gap's "node=<id>" scope to eBPF events by it, agents/completeness.py), or
    the file name for a stream without eBPF (the off-node observers)."""
    ids = st["ebpf_node_ids"]
    if len(ids) > 1:
        raise SystemExit(f"{name}: eBPF records of several nodes {ids[:3]}; one shipper per node expected")
    return ids[0] if ids else name


def node_role(name, st):
    srcs = set(st["by_source"])
    if name == "off-node" or (srcs and srcs <= set(OFF_NODE_SOURCES)):
        return "off-node"
    if srcs & set(CONTROL_PLANE_SOURCES):
        return "control-plane"
    return "worker"


def export_run(run_dir, out_root, variant=None):
    """Export one run (variant None or "no_history"); returns base.json's content."""
    if variant not in (None, "", "no_history"):
        raise SystemExit(f"unknown base variant {variant!r}")
    variant = variant or None
    run_dir = os.path.abspath(run_dir)
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    run_id = manifest.get("run_id") or os.path.basename(run_dir.rstrip("/\\"))
    shipper = os.path.join(run_dir, "shipper")
    files = sorted(f for f in os.listdir(shipper) if f.endswith(".jsonl"))
    if not files:
        raise SystemExit(f"{run_dir}: no shipper files")
    out = os.path.join(out_root, run_id)
    meta_path = os.path.join(out, "base.json")
    in_digest = {}
    for f in files:
        h = hashlib.sha256()
        with open(os.path.join(shipper, f), "rb") as fh:
            for b in iter(lambda: fh.read(1 << 20), b""):
                h.update(b)
        in_digest[f] = h.hexdigest()
    if os.path.exists(meta_path):
        old = json.load(open(meta_path, encoding="utf-8"))
        if (old.get("version") == VERSION and old.get("variant") == variant
                and {n["file"]: n["input_sha256"] for n in old["nodes"]} == in_digest):
            return old
    os.makedirs(os.path.join(out, "nodes"), exist_ok=True)
    line_fn, vinfo = None, None
    if variant == "no_history":
        from mtcore.exp3 import nohistory as NH
        latest = NH.build_map([os.path.join(shipper, f) for f in files], keep=lambda o: not is_truth(o))

        def line_fn(obj):
            new = NH.transform_line(obj, latest)
            return None if new is None else NH.dump_line(new)
        vinfo = latest.summary()
    nodes = []
    for f in files:
        st = export_node(os.path.join(shipper, f), os.path.join(out, "nodes", f), line_fn)
        name = f[:-len(".jsonl")]
        nodes.append({"file": f, "node": name, "node_id": shipper_node_id(name, st), "role": node_role(name, st),
                      **st})
    firsts = [n["first_event_ns"] for n in nodes if n["first_event_ns"] is not None]
    lasts = [n["last_event_ns"] for n in nodes if n["last_event_ns"] is not None]
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(redact_manifest(manifest), fh, indent=2, sort_keys=True)
    meta = {"version": VERSION, "variant": variant, "run_id": run_id, "source_dir": run_dir,
            "observability_profile": manifest.get("observability_profile"),
            "world": manifest.get("world_name") or manifest.get("world"),
            "stream_start_ns": min(firsts) if firsts else None, "stream_end_ns": max(lasts) if lasts else None,
            "truth_removed": sum(n["truth_removed"] for n in nodes), "nodes": nodes}
    if variant:
        meta["variant_info"] = {**vinfo, "records_changed": sum(n["variant_changed"] for n in nodes)}
    meta["stream_start"] = ns_rfc3339(meta["stream_start_ns"]) if firsts else None
    meta["stream_end"] = ns_rfc3339(meta["stream_end_ns"]) if lasts else None
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    os.replace(tmp, meta_path)                   # base.json last: it marks the export done
    return meta


def verify_export(out_dir):
    """Problems on the exported side: truth lines, restricted/ or base.pb present."""
    bad = [n for n in ("restricted", "base.pb") if os.path.exists(os.path.join(out_dir, n))]
    nd = os.path.join(out_dir, "nodes")
    for f in sorted(os.listdir(nd)):
        with open(os.path.join(nd, f), "rb") as fh:
            for i, raw in enumerate(fh, 1):
                if raw.strip() and is_truth(json.loads(raw)):
                    bad.append(f"{f}:{i}")
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--out", required=True, help="BASE_ROOT; one folder per run")
    ap.add_argument("--variant", default=None, choices=("no_history",),
                    help="write this identity variant (mtcore.exp3.nohistory) instead of the stream as is")
    a = ap.parse_args(argv)
    failed = 0
    for d in a.run_dirs:
        m = export_run(d, a.out, a.variant)
        bad = verify_export(os.path.join(a.out, m["run_id"]))
        if bad:
            print(f"EXPORT FAILED {m['run_id']}: truth on the sender side {bad[:5]}", file=sys.stderr)
            failed += 1
            continue
        print(json.dumps({"run_id": m["run_id"], "nodes": len(m["nodes"]), "truth_removed": m["truth_removed"],
                          "records": sum(n["records"] for n in m["nodes"])}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
