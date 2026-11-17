"""Replay one run's node streams through the fault injector to a receiver (one Exp. 3 job).

Each node stream of the run gets its own pair, as a real node would:

    faultinject -plan <node>.yaml -input nodes/<node>.jsonl -node <id> -log <node>.source.jsonl -pace P
        | shipper -node-id <id> -faults <node>.yaml -fault-log <node>.transit.jsonl -drain ...

faultinject applies the plan's source-stage faults (before sequencing), the
shipper its transit-stage faults (after sequencing, reported to the receiver as
GapNotices). With pace > 0 every node of the run is paced on one clock
(-pace-origin = the run's first event time, -start-at-ms = one shared wall
start), so node streams keep their event-time alignment. The fault logs are
truth-side material: they are written to faultlog_dir, never next to what
the detectors read. faults.jsonl is every node's source and transit log,
concatenated in node order (mtcore.harness.score --fault-log reads it).
"""
import json
import os
import shutil
import subprocess
import time

from mtcore.exp3.slot import binary, rmtree, spawn, stop


def merge_logs(faultlog_dir, nodes):
    """Concatenate the per-node logs into faults.jsonl (headers included; the scorer skips them)."""
    tmp = os.path.join(faultlog_dir, "faults.jsonl.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as out:
        for n in nodes:
            for stage in ("source", "transit"):
                p = os.path.join(faultlog_dir, f"{n}.{stage}.jsonl")
                if os.path.exists(p):
                    with open(p, encoding="utf-8") as fh:
                        shutil.copyfileobj(fh, out)
    os.replace(tmp, os.path.join(faultlog_dir, "faults.jsonl"))


def send_job(job, base_dir, plan_dir, cert_dir, work_dir, faultlog_dir, timeout_s=None):
    """Ship every node stream of job["run"]; returns per-node exit codes, stats and wall time.
    job: receiver, server_name, pace, boot (and optional start_at_ms)."""
    base = json.load(open(os.path.join(base_dir, "base.json"), encoding="utf-8"))
    for d in (work_dir, faultlog_dir):
        rmtree(d)
        os.makedirs(d)
    pace = float(job.get("pace") or 0)
    if timeout_s is None:
        span = (base["stream_end_ns"] - base["stream_start_ns"]) / 1e9 if base["stream_start_ns"] else 0
        timeout_s = 1800 + (span / pace if pace > 0 else 0)
    start_at = job.get("start_at_ms") or int((time.time() + 3) * 1000)
    procs = []
    t0 = time.time()
    for n in base["nodes"]:
        name, nid = n["node"], n["node_id"]
        plan = os.path.join(plan_dir, name + ".yaml")
        log = open(os.path.join(work_dir, f"{name}.log"), "w")
        fi_argv = [binary("faultinject"), "-plan", plan, "-input", os.path.join(base_dir, "nodes", n["file"]),
                   "-node", nid, "-log", os.path.join(faultlog_dir, f"{name}.source.jsonl"), "-pace", str(pace)]
        if pace > 0:
            fi_argv += ["-pace-origin", base["stream_start"], "-start-at-ms", str(start_at)]
        fi = spawn(fi_argv, log, stdout=subprocess.PIPE)
        sh = spawn([binary("shipper"), "-receiver", job["receiver"], "-server-name", job["server_name"],
                    "-cert", os.path.join(cert_dir, f"node-cert-{nid}.crt"),
                    "-key", os.path.join(cert_dir, f"node-cert-{nid}.key"), "-ca", os.path.join(cert_dir, "ca.crt"),
                    "-node-id", nid, "-boot-id", job["boot"], "-instance", f"exp3-shipper-{name}",
                    "-spool", os.path.join(work_dir, f"spool-{name}"), "-input", "-", "-drain",
                    "-stats", os.path.join(work_dir, f"stats-{name}.json"),
                    "-faults", plan, "-fault-log", os.path.join(faultlog_dir, f"{name}.transit.jsonl")],
                   log, stdin=fi.stdout)
        fi.stdout.close()                               # the shipper holds the pipe now
        log.close()
        procs.append((name, fi, sh))
    codes = {}
    deadline = t0 + timeout_s
    for name, fi, sh in procs:
        for tag, p in (("shipper", sh), ("faultinject", fi)):
            try:
                p.wait(max(1.0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                stop(p, 10)
            codes[f"{name}.{tag}"] = p.returncode
    wall = round(time.time() - t0, 3)
    merge_logs(faultlog_dir, [n["node"] for n in base["nodes"]])
    stats = {}
    for n in base["nodes"]:
        p = os.path.join(work_dir, f"stats-{n['node']}.json")
        if os.path.exists(p):
            stats[n["node"]] = json.load(open(p, encoding="utf-8"))
    ok = all(c == 0 for c in codes.values())
    return {"ok": ok, "exit": codes, "wall_s": wall, "pace": pace, "start_at_ms": start_at, "shipper_stats": stats}
