"""Exp. 5 recovery metrics from timestamped samples, and a lag sampler.

    python -m mtcore.harness.recovery sample --group orchestrator --component go \
        --topics findings.v0,norm.events.v0 --out lag.jsonl [--interval 1] [--duration 600]

Metrics take plain samples, so they need no Kafka:

- recovery time per component: from restart until consumer lag is within
  the reference run's steady-state p99 and stays there for `hold_s`
  (default 30 s); None if that never holds for a full hold.
- added sealing delay per incident: seal wall time in X minus in A, each
  relative to its run's start, matched by incident ID.
- peak CPU and memory over the catch-up window.
- outage: kill (failpoint log time) to the first heartbeat after it.

Sampler lines: {"t", "component", "lag", "partitions": {"topic/partition": lag}};
lag = end offset - committed offset (low watermark when nothing is
committed). Committed offsets show a GO that commits at the oldest offset
its state needs (run C) as lagging while it is caught up; such a component
should report its read positions (`lag_from_positions`). The crash runner
does: `read_lag_series` joins the runners' positions log ($MT_POSITIONS_LOG,
one line per commit) with sampled end offsets, and recovery time is
measured on that read lag.
"""
import argparse
import json
import math
import sys
import time


def percentile(values, q):
    """Nearest-rank percentile, q in (0, 1]."""
    v = sorted(values)
    if not v:
        raise ValueError("no values")
    return v[max(0, math.ceil(q * len(v)) - 1)]


def steady_band(samples, start=None, end=None, q=0.99):
    """p99 (or q) of the lag in [start, end] of a reference series [(t, lag)]."""
    return percentile([lag for t, lag in samples if (start is None or t >= start) and (end is None or t <= end)], q)


def recovered_at(samples, restart_t, threshold, hold_s=30.0):
    """First sample time >= restart_t from which lag <= threshold for hold_s,
    proven by a sample at or after the end of the hold; else None."""
    cand = None
    for t, lag in sorted(samples):
        if t < restart_t:
            continue
        if lag > threshold:
            cand = None
            continue
        if cand is None:
            cand = t
        if t - cand >= hold_s:
            return cand
    return None


def recovery_times(run, reference, restart_t, hold_s=30.0, ref_window=(None, None), q=0.99):
    """run, reference: {component: [(t, lag)]}. Returns {component: {...}}."""
    out = {}
    for comp, samples in sorted(run.items()):
        thr = steady_band(reference[comp], *ref_window, q=q)
        at = recovered_at(samples, restart_t, thr, hold_s)
        out[comp] = {"threshold": thr, "recovered_at": at, "recovery_s": None if at is None else at - restart_t}
    return out


def added_seal_delay(ref_ms, run_ms, ref_start_ms=0, run_start_ms=0):
    """ref_ms, run_ms: {incident_id: seal wall time ms} (project.seal_times_ms)."""
    both = sorted(set(ref_ms) & set(run_ms))
    per = {i: ((run_ms[i] - run_start_ms) - (ref_ms[i] - ref_start_ms)) / 1000 for i in both}
    vals = list(per.values())
    return {"per_incident_s": per, "missing": sorted(set(ref_ms) - set(run_ms)),
            "extra": sorted(set(run_ms) - set(ref_ms)),
            "max_s": max(vals) if vals else None, "p50_s": percentile(vals, 0.5) if vals else None}


def peak_usage(samples, start, end):
    """samples: [(t, cpu, mem)]; peaks over [start, end] (None if no sample)."""
    win = [(c, m) for t, c, m in samples if start <= t <= end]
    return {"cpu_peak": max((c for c, _ in win), default=None), "mem_peak": max((m for _, m in win), default=None),
            "samples": len(win)}


def outage_s(kill_time_ns, heartbeat_lines, instance=None):
    """Kill to the first heartbeat after it, from dump lines with --heartbeats;
    `instance` restricts to one producer instance. None if none came."""
    best = None
    for line in heartbeat_lines:
        hb = line.get("heartbeat")
        if hb is None or (instance is not None and hb.get("producerInstance") != instance):
            continue
        t = line["timestamp_ms"] * 1_000_000
        if t > kill_time_ns and (best is None or t < best):
            best = t
    return None if best is None else (best - kill_time_ns) / 1e9


def lag_from_positions(positions, ends):
    """positions: {(topic, partition): next offset to read} (None: unread);
    ends: {(topic, partition): (low, high)}. Returns (total, per partition)."""
    per = {}
    for k, (lo, hi) in ends.items():
        pos = positions.get(k)
        per[k] = max(0, hi - (lo if pos is None or pos < 0 else pos))
    return sum(per.values()), per


def sample_group(consumer, topics, tp=None, timeout=10.0):
    """One lag sample of the group `consumer` was created with (it must not
    subscribe). Returns (total, per partition)."""
    if tp is None:
        from confluent_kafka import TopicPartition as tp
    md = consumer.list_topics(timeout=timeout).topics
    parts = [tp(t, p) for t in topics for p in sorted(md[t].partitions)]
    committed = {(x.topic, x.partition): x.offset for x in consumer.committed(parts, timeout=timeout)}
    ends = {(x.topic, x.partition): consumer.get_watermark_offsets(x, timeout=timeout, cached=False) for x in parts}
    return lag_from_positions(committed, ends)


def _jsonl(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]
    except FileNotFoundError:
        return []


def read_lag_series(positions_path, ends_path, inputs):
    """Read lag per component from the positions log and sampled end offsets.

    positions lines: {"t" (ns), "positions": {"topic/partition": next offset}}
    (restream.log_positions; the agents and the GO share the file). ends
    lines: {"t" (s), "ends": {"topic/partition": high watermark}}. inputs:
    {component: [input topics]}; a positions line belongs to the component
    whose inputs it covers most. At each ends sample, a component's lag is
    the sum over its input partitions of end - its latest read position at
    or before that time (a partition it has not read counts from 0);
    samples before its first positions line are left out. Returns
    {component: [(t seconds, lag)]}."""
    topics = {c: set(ts) for c, ts in inputs.items()}
    pos = {c: [] for c in inputs}
    for line in _jsonl(positions_path):
        seen = {k.rsplit("/", 1)[0] for k in line.get("positions", {})}
        comp = max(topics, key=lambda c: (len(topics[c] & seen), c))
        if topics[comp] & seen:
            pos[comp].append((line["t"] / 1e9, line["positions"]))
    out = {c: [] for c in inputs}
    for c in inputs:
        pos[c].sort(key=lambda x: x[0])
    for e in sorted(_jsonl(ends_path), key=lambda x: x["t"]):
        for c, series in pos.items():
            cur = None
            for t, p in series:
                if t > e["t"]:
                    break
                cur = p
            if cur is None:
                continue
            lag = sum(max(0, hi - cur.get(k, 0)) for k, hi in e["ends"].items() if k.rsplit("/", 1)[0] in topics[c])
            out[c].append((e["t"], lag))
    return out


def load_series(path):
    """Sampler output -> {component: [(t, lag)]}."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                s = json.loads(line)
                out.setdefault(s["component"], []).append((s["t"], s["lag"]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sample a consumer group's lag for Exp. 5.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--bootstrap", default="127.0.0.1:9092")
    s.add_argument("--group", required=True)
    s.add_argument("--component", required=True)
    s.add_argument("--topics", required=True, help="comma-separated input topics")
    s.add_argument("--out", required=True)
    s.add_argument("--interval", type=float, default=1.0)
    s.add_argument("--duration", type=float, default=None, help="stop after this many seconds")
    a = ap.parse_args(argv)
    try:
        from confluent_kafka import Consumer, KafkaException
    except ImportError:
        print("sample: confluent_kafka is not installed", file=sys.stderr)
        return 2
    c = Consumer({"bootstrap.servers": a.bootstrap, "group.id": a.group, "enable.auto.commit": False,
                  "socket.connection.setup.timeout.ms": 10000})
    topics, start = a.topics.split(","), time.time()
    try:
        with open(a.out, "a", encoding="utf-8") as fh:
            while a.duration is None or time.time() - start < a.duration:
                t = time.time()
                total, per = sample_group(c, topics)
                fh.write(json.dumps({"t": t, "component": a.component, "lag": total,
                                     "partitions": {f"{k[0]}/{k[1]}": v for k, v in sorted(per.items())}}) + "\n")
                fh.flush()
                time.sleep(max(0.0, a.interval - (time.time() - t)))
    except KafkaException as e:
        print(f"sample: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        pass
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
