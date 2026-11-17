"""Exp. 5 part A crash runner (build step 8f): runs on isolated stacks.

    python -m mtcore.harness.crashrun --input node-1=stream.jsonl --out runs/ \
        [--parallel 3] [--reps 5] [--points go.after_flush_before_commit,...] [--outage-s 2] [--seed 1] \
        [--pace 1] [--prefill node-1=history.jsonl --history-s 3600] [--hold-s 30]

Every run uses the same input (shipper JSON lines per node), parameters and
heartbeat interval, on a fresh stack (stack.py). The matrix:

- A and A' (no crash, GO commit mode oldest-needed): reference and noise floor;
- for each GO failpoint, runs B (full-replay), C (oldest-needed) and D
  (read-position): the GO is killed at the point and restarted in that mode;
- for each receiver, agent and TGS failpoint, and pg.server_crash, run X
  (oldest-needed): that component is killed (Postgres: immediate shutdown)
  and restarted.

Each crash cell is repeated --reps times; repetition r arms the failpoint's
n-th qualifying hit, n drawn from 1..--max-nth with a seeded RNG. A process
that exits 137 with its failpoint logged is restarted --outage-s later with
the failpoint off; any other exit fails the run. A run whose failpoint never
fired is "not_fired" and discarded (evaluation-plan.md: a kill with no open
state is not counted).

A run ends when every shipper has drained, at least the receiver's max_idle
plus --settle-s has passed since the last shipper drained (so the idle
coverage and the seals it releases are in every run, A included), and no new
finding, evaluation, witness or incident has appeared for --settle-s. The
same rule ends a history prefill. The producers are then
stopped in pipeline order (SIGTERM: flush and commit), the TGS is left to
apply every record to the topic ends, and the run directory receives:

    output.jsonl      GO and agent outputs with heartbeats (harness.dump)
    tgs.json          {"edges": TGS edge hash}, compared (graph_hash is in meta.json:
                      it also covers timing-dependent intermediate records)
    lag.jsonl         per-second committed lag of the agents and the GO
    usage.jsonl       per-second CPU (%) and RSS (bytes) per process
    failpoint.jsonl   the failpoint log
    meta.json         the cell, start/kill/restart times, exits, status
    compare.json      compare.compare() against A with A' as noise (crash runs)

The outage (kill to the component's first heartbeat after it, or to its
restart when it writes none to the dumped topics) picks the band
(compare.band_for, with the GO parameters' max_idle and posting horizon).
summary.json tallies k of N identical per (run type, point).

Sweeps (sweep.py drives them; definitions of 2026-10-12):

- --pace p feeds each input through faultinject -pace p (event-time speed
  times p; 0, the default, writes it at once). The run timeout grows with
  the input's event-time span / p.
- --prefill NODE=PATH ships a history first, at once, and waits until the
  pipeline is quiet; only then are failpoints counted (MT_FAILPOINT_AFTER)
  and the measured input shipped. --history-s H keeps the last H seconds of
  the prefill's event time (lines without an event time, context and
  watermarks, are all kept). A and A' get the same prefill.
- --outage-s sets how long a killed process stays down.

Each crash run's compare.json also holds "recovery" (recovery.py): per
component (agents, go) the recovery time on read lag (positions log joined
with ends.jsonl, end offsets sampled each second) against A's p99 over A's
measured part, held for --hold-s (a run lasts at least that long after the
restart); added sealing delay per incident against A; peak CPU and memory
per process from the restart to the end of catch-up; for a GO kill, the
records C must re-read at the kill (read position - committed, over the GO
inputs) and the longest span of an incident open at the kill.
"""
import argparse
import concurrent.futures as cf
import json
import os
import queue
import random
import threading
import time

from mtcore import failpoint as FP
from mtcore.harness import compare as C
from mtcore.harness import project as P
from mtcore.harness import recovery as R
from mtcore.harness.dump import dump
from mtcore.harness.stack import EXIT_FAILPOINT, Stack

GO_MODES = {"B": "full-replay", "C": "oldest-needed", "D": "read-position"}
PROC_OF = {"receiver": "receiver", "agent": "agents", "go": "go", "tgs": "tgs", "pg": "tgs"}
PG_CRASH = "pg.server_crash"
DATA_TOPICS = ["findings.v0", "rule.evaluations.v0", "witness.decisions.v0", "incidents.v0"]
GROUPS = {"agents": ("agents-ABCDEFGH", None), "go": ("orchestrator", None)}
INSTANCE = {"go": "orchestrator", "agents": "agents-1"}
GO_INPUTS = ["findings.v0", "norm.events.v0"]


def lag_inputs():
    """{component: input topics} for the lag series."""
    from mtcore.agents.rules import ALL, input_topics
    return {"agents": list(input_topics(ALL)), "go": list(GO_INPUTS)}


# --- inputs ------------------------------------------------------------------------------
def _event_time_s(obj):
    """NormalizedEvent event time (s) of a shipper input line, or None."""
    env = obj.get("envelope") or {}
    ne = env.get("normalizedEvent") or env.get("normalized_event") or {}
    t = ne.get("time") or {}
    v = t.get("eventTime") or t.get("event_time")
    if not v:
        return None
    from google.protobuf.timestamp_pb2 import Timestamp
    ts = Timestamp()
    ts.FromJsonString(v)
    return ts.seconds + ts.nanos / 1e9


def _times(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield line, _event_time_s(json.loads(line))


def input_span_s(paths):
    """Event-time span (s) over the input files; 0 if none carries a time."""
    ts = [t for p in paths for _, t in _times(p) if t is not None]
    return max(ts) - min(ts) if ts else 0.0


def cut_history(src, dst, seconds):
    """Write src's lines to dst, keeping events of the last `seconds` of its
    event time and every line without an event time; returns lines kept."""
    end = max((t for _, t in _times(src) if t is not None), default=None)
    n = 0
    with open(dst, "w", encoding="utf-8") as out:
        for line, t in _times(src):
            if t is None or end is None or t >= end - seconds:
                out.write(line if line.endswith("\n") else line + "\n")
                n += 1
    return n


class RunError(RuntimeError):
    pass


def cells(points, reps, max_nth, seed, modes=None):
    """The matrix: [{"name", "run", "point", "rep", "nth"}], A and A' first.
    modes limits the GO restart modes (subset of B, C, D); every cell's nth is
    still drawn, so a limited matrix arms the same occurrences as the full one."""
    rng = random.Random(seed)
    out = [{"name": "A", "run": "A", "point": None}, {"name": "A2", "run": "A2", "point": None}]
    for point in points:
        runs = list(GO_MODES) if point.startswith("go.") else ["X"]
        for run in runs:
            for rep in range(reps):
                nth = rng.randint(1, max_nth)
                if modes and run in GO_MODES and run not in modes:
                    continue
                out.append({"name": f"{run}-{point}-r{rep}", "run": run, "point": point, "rep": rep, "nth": nth})
    return out


def _proc_usage(pid, last):
    """(cpu %, rss bytes) of pid since the last call; last: {pid: (t, ticks)}."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            f = fh.read().rsplit(")", 1)[1].split()
        ticks = int(f[11]) + int(f[12])
        with open(f"/proc/{pid}/status") as fh:
            rss = next(int(x.split()[1]) * 1024 for x in fh if x.startswith("VmRSS:"))
    except (OSError, StopIteration, ValueError, IndexError):
        return None
    now, hz = time.time(), os.sysconf("SC_CLK_TCK")
    t0, k0 = last.get(pid, (now, ticks))
    last[pid] = (now, ticks)
    cpu = 100.0 * (ticks - k0) / hz / (now - t0) if now > t0 else 0.0
    return cpu, rss


class Sampler(threading.Thread):
    """Per-second lag (committed, per group) and process usage."""

    def __init__(self, stack, run_dir, interval=1.0):
        super().__init__(daemon=True)
        self.st, self.dir, self.interval = stack, run_dir, interval
        self.stop_ev = threading.Event()

    def run(self):
        from confluent_kafka import Consumer
        from mtcore.agents.rules import ALL, input_topics
        from confluent_kafka import TopicPartition
        topics = {"agents": input_topics(ALL), "go": GO_INPUTS}
        cons = {k: Consumer({"bootstrap.servers": self.st.bootstrap, "group.id": g, "enable.auto.commit": False})
                for k, (g, _) in GROUPS.items()}
        ends_c = Consumer({"bootstrap.servers": self.st.bootstrap, "group.id": "crashrun-ends-sampler",
                           "enable.auto.commit": False})
        last, parts = {}, None
        with open(os.path.join(self.dir, "lag.jsonl"), "a") as lag, \
                open(os.path.join(self.dir, "usage.jsonl"), "a") as use, \
                open(os.path.join(self.dir, "ends.jsonl"), "a") as ends:
            while not self.stop_ev.wait(self.interval):
                t = time.time()
                try:
                    if parts is None:
                        md = ends_c.list_topics(timeout=5).topics
                        parts = [(tp, p) for tp in sorted(set(topics["agents"]) | set(GO_INPUTS))
                                 for p in sorted(md[tp].partitions)]
                    hi = {f"{tp}/{p}": ends_c.get_watermark_offsets(TopicPartition(tp, p), timeout=5,
                                                                     cached=False)[1] for tp, p in parts}
                    ends.write(json.dumps({"t": t, "ends": hi}) + "\n")
                    ends.flush()
                except Exception:            # broker busy: skip this sample
                    pass
                for comp, c in cons.items():
                    try:
                        total, per = R.sample_group(c, topics[comp], timeout=5)
                    except Exception:            # broker busy or group not yet known
                        continue
                    lag.write(json.dumps({"t": t, "component": comp, "lag": total,
                                          "partitions": {f"{a}/{b}": v for (a, b), v in per.items()}}) + "\n")
                for name, p in list(self.st.procs.items()):
                    pid = p.pid()
                    u = _proc_usage(pid, last) if pid else None
                    if u:
                        use.write(json.dumps({"t": t, "process": name, "pid": pid, "cpu": u[0], "mem": u[1]}) + "\n")
                lag.flush()
                use.flush()
        for c in [*cons.values(), ends_c]:
            c.close()


class Watcher(threading.Thread):
    """Time of the newest finding, evaluation, witness or incident record."""

    def __init__(self, bootstrap):
        super().__init__(daemon=True)
        self.bootstrap, self.last, self.count = bootstrap, time.time(), 0
        self.stop_ev = threading.Event()

    def run(self):
        from confluent_kafka import Consumer, TopicPartition
        from microtrace.v0 import envelope_pb2
        c = Consumer({"bootstrap.servers": self.bootstrap, "group.id": "crashrun-watch", "enable.auto.commit": False})
        md = c.list_topics(timeout=30).topics
        c.assign([TopicPartition(t, p, 0) for t in DATA_TOPICS for p in md[t].partitions])
        while not self.stop_ev.is_set():
            for m in c.consume(500, timeout=0.5):
                if m.error():
                    continue
                env = envelope_pb2.Envelope()
                env.ParseFromString(m.value())
                if not env.HasField("heartbeat"):
                    self.count += 1
                    self.last = time.time()
        c.close()


def run_one(cell, slot, inputs, out_dir, outage_s=2.0, settle_s=15.0, timeout_s=900.0, params=None, keep=False,
            pace=0.0, prefill=None, hold_s=30.0):
    """One run on stack `slot`; returns its meta dict (also in meta.json).
    prefill: {node: path} shipped and settled before the measured input."""
    run_dir = os.path.join(out_dir, cell["name"])
    os.makedirs(run_dir, exist_ok=True)
    meta = {"cell": cell, "slot": slot, "status": "error", "kills": [], "restarts": [], "exits": [],
            "pace": pace, "outage_s": outage_s, "prefill": sorted(prefill) if prefill else None}
    point, proc_name = cell.get("point"), None
    fp_log = os.path.join(run_dir, "failpoint.jsonl")
    arm = os.path.join(run_dir, "armed") if prefill else None
    if arm and os.path.exists(arm):
        os.remove(arm)
    env = {}
    if point:
        proc_name = PROC_OF[point.split(".")[0]]
        if point != PG_CRASH:
            env[proc_name] = {"MT_FAILPOINT": point, "MT_FAILPOINT_NTH": str(cell["nth"]), "MT_FAILPOINT_LOG": fp_log}
            if arm:
                env[proc_name]["MT_FAILPOINT_AFTER"] = arm
    mode = GO_MODES.get(cell["run"], "oldest-needed")
    st = Stack(slot, root=os.path.join(run_dir, "stack"), keep=keep, heartbeat_ms=500, params=params)
    sampler = watcher = None
    try:
        st.up()
        st.start_pipeline(sorted(inputs), commit_mode=mode, env=env)
        sampler, watcher = Sampler(st, run_dir), Watcher(st.bootstrap)
        sampler.start()
        watcher.start()
        meta["pipeline_start_ns"] = time.time_ns()
        if prefill:
            st.ship(prefill)
            _settle(st, watcher, settle_s, time.time() + timeout_s)
            meta["prefill_done_ns"] = time.time_ns()
            open(arm, "w").close()                    # failpoints count from here
        meta["start_ns"] = time.time_ns()
        st.ship(inputs, pace=pace)
        _drive(st, cell, proc_name, meta, watcher, outage_s, settle_s, timeout_s, hold_s)
        _shutdown(st)
        meta["finished_ns"] = time.time_ns()
        _collect(st, run_dir, meta)
        if point and not meta["kills"]:
            meta["status"] = "not_fired"
        else:
            meta["status"] = "ok"
    except Exception as e:                    # recorded; the matrix goes on
        meta["error"] = f"{type(e).__name__}: {e}"
    finally:
        for th in (sampler, watcher):
            if th is not None:
                th.stop_ev.set()
                th.join(10)
        st.down()
        meta["failpoint_log"] = FP.read_log(fp_log)
        with open(os.path.join(run_dir, "meta.json"), "w") as fh:
            json.dump(meta, fh, indent=2, sort_keys=True, default=str)
    return meta


def _idle_s(st):
    """The receiver's max_idle ("10s", "500ms") in seconds."""
    v = str(st.max_idle)
    return float(v[:-2]) / 1000 if v.endswith("ms") else float(v.rstrip("s"))


class _Drain:
    """When every shipper drained; done() once max_idle + settle_s have passed
    since then and the outputs have been quiet for settle_s. Without the
    max_idle wait a run could stop before the receiver reports the idle
    source and the GO seals what that releases; a short run (A) would then
    miss records a longer one (a crash run) keeps (shakedown 2026-11-16)."""

    def __init__(self, st, watcher, settle_s):
        self.st, self.watcher, self.settle_s, self.at = st, watcher, settle_s, None
        self.wait_s = _idle_s(st) + settle_s

    def done(self, now=None):
        now = time.time() if now is None else now
        if any(p.alive() for p in self.st.shippers()):
            self.at = None
            return False
        if self.at is None:
            self.at = now
        return now - self.at >= self.wait_s and now - self.watcher.last >= self.settle_s


def _settle(st, watcher, settle_s, deadline):
    """Wait until every shipper has drained and the outputs are quiet (a
    history prefill; _Drain); any exit other than a drained shipper is an error."""
    drain = _Drain(st, watcher, settle_s)
    while True:
        if time.time() > deadline:
            raise RunError("timed out in the prefill")
        for name, p in list(st.procs.items()):
            code = p.poll()
            if code is not None and not (name.startswith("shipper-") and code == 0):
                raise RunError(f"{name} exited {code} in the prefill; see {p.log_path}")
        if drain.done():
            return
        time.sleep(0.2)


def _drive(st, cell, proc_name, meta, watcher, outage_s, settle_s, timeout_s, hold_s=0.0):
    deadline = time.time() + timeout_s
    drain = _Drain(st, watcher, settle_s)
    pending = {}                                     # process name -> restart time
    pg_done = cell.get("point") != PG_CRASH
    while True:
        if time.time() > deadline:
            raise RunError("timed out")
        if not pg_done and st.tgs_offsets():         # the TGS has applied something
            meta["kills"].append({"process": "postgres", "t": time.time_ns()})
            st.pg_crash()
            time.sleep(outage_s)
            st.pg_start()
            meta["restarts"].append({"process": "postgres", "t": time.time_ns()})
            pg_done = True
        for name, p in list(st.procs.items()):
            code = p.poll()
            if code is None:
                continue
            meta["exits"].append({"process": name, "code": code, "t": time.time_ns()})
            if name.startswith("shipper-") and code == 0:
                continue
            crashed = name == proc_name and (code == EXIT_FAILPOINT or cell.get("point") == PG_CRASH)
            if not crashed:
                raise RunError(f"{name} exited {code}; see {p.log_path}")
            if code == EXIT_FAILPOINT:
                meta["kills"].append({"process": name, "t": p.exits[-1][2]})
            pending[name] = time.time() + outage_s
        for name, at in list(pending.items()):
            if time.time() >= at:
                st.procs[name].start()               # failpoint off
                meta["restarts"].append({"process": name, "t": time.time_ns()})
                del pending[name]
        held = not meta["restarts"] or time.time() - meta["restarts"][-1]["t"] / 1e9 >= hold_s
        if drain.done() and not pending and pg_done and held:
            return
        time.sleep(0.2)


def _shutdown(st):
    """Producers in pipeline order, then the TGS once it has applied the ends."""
    from confluent_kafka import Consumer, TopicPartition
    from mtcore.tgs.run import INPUTS
    for name in ("receiver", "restreamer", "agents", "go"):
        st.procs[name].stop()
    c = Consumer({"bootstrap.servers": st.bootstrap, "group.id": "crashrun-ends"})
    md = c.list_topics(timeout=30).topics
    ends = {(t, p): c.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)[1]
            for t in INPUTS for p in md[t].partitions}
    c.close()
    want = {k: hi - 1 for k, hi in ends.items() if hi > 0}
    deadline = time.time() + 300
    while time.time() < deadline:
        done = st.tgs_offsets()
        if all(done.get(k, -1) >= v for k, v in want.items()):
            break
        if not st.procs["tgs"].alive():
            raise RunError("tgs exited before applying the topic ends")
        time.sleep(0.5)
    else:
        raise RunError("tgs did not reach the topic ends")
    st.procs["tgs"].stop()


def _collect(st, run_dir, meta):
    from confluent_kafka import Consumer, TopicPartition
    c = Consumer({"bootstrap.servers": st.bootstrap, "group.id": "crashrun-dump", "enable.auto.commit": False})
    with open(os.path.join(run_dir, "output.jsonl"), "w", encoding="utf-8") as fh:
        meta["output_lines"] = dump(c, fh, topics=DATA_TOPICS + ["norm.events.v0"], heartbeats=True, events=True)
    md = c.list_topics(timeout=30).topics
    # Run B's premise: retention kept every record (earliest offset 0).
    meta["earliest_offsets_zero"] = all(
        c.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)[0] == 0
        for t in ("findings.v0", "norm.events.v0") for p in md[t].partitions)
    c.close()
    hashes = st.tgs_hashes()
    meta["tgs_graph_hash"] = hashes["graph"]
    with open(os.path.join(run_dir, "tgs.json"), "w") as fh:
        json.dump({"edges": hashes["edges"]}, fh)


# --- scoring ---------------------------------------------------------------------------
def _heartbeat_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if '"heartbeat"' in x]


def outage_seconds(meta, run_dir):
    if not meta["kills"]:
        return None
    kill = meta["kills"][0]
    inst = INSTANCE.get(kill["process"])
    if inst:
        o = R.outage_s(kill["t"], _heartbeat_lines(os.path.join(run_dir, "output.jsonl")), inst)
        if o is not None:
            return o
    after = [r["t"] for r in meta["restarts"] if r["t"] >= kill["t"]]
    return (after[0] - kill["t"]) / 1e9 if after else None


def _usage(path):
    out = {}
    for line in R._jsonl(path):
        out.setdefault(line["process"], []).append((line["t"], line["cpu"], line["mem"]))
    return out


def go_backlog(positions_path, kill_t, inputs=GO_INPUTS):
    """Records the GO must re-read after a kill at kill_t (s): read position
    minus committed offset over its inputs, from its last positions line
    before the kill; None without one."""
    last = None
    for line in R._jsonl(positions_path):
        keys = line.get("positions", {})
        if line["t"] / 1e9 <= kill_t and any(k.startswith("findings.v0/") for k in keys):
            last = line
    if last is None:
        return None
    com = last.get("committed", {})
    return sum(max(0, pos - com.get(k, pos)) for k, pos in last["positions"].items()
               if k.rsplit("/", 1)[0] in inputs)


def longest_open_span_s(records, at_ms):
    """Longest event span (s) of an incident whose latest record before at_ms is OPEN."""
    from microtrace.v0 import incident_pb2
    latest = {}
    for r in records:
        if r.topic == P.INCIDENT_TOPIC and r.timestamp_ms is not None and r.timestamp_ms <= at_ms:
            latest[r.msg.incident_id] = r.msg
    spans = [(m.event_end.ToNanoseconds() - m.event_start.ToNanoseconds()) / 1e9 for m in latest.values()
             if m.status == incident_pb2.IncidentStatus.Value("INCIDENT_OPEN")]
    return max(spans, default=None)


def recovery_metrics(out_dir, meta, hold_s=30.0):
    """Recovery of one crash run against A (module doc); None without a kill."""
    if not meta["kills"]:
        return None
    run_dir, a_dir = os.path.join(out_dir, meta["cell"]["name"]), os.path.join(out_dir, "A")
    with open(os.path.join(a_dir, "meta.json")) as fh:
        a_meta = json.load(fh)
    kill_ns = meta["kills"][0]["t"]
    after = [r["t"] for r in meta["restarts"] if r["t"] >= kill_ns]
    restart_t = after[0] / 1e9 if after else None
    inputs = lag_inputs()
    run = R.read_lag_series(os.path.join(run_dir, "stack", "positions.jsonl"), os.path.join(run_dir, "ends.jsonl"),
                            inputs)
    ref = R.read_lag_series(os.path.join(a_dir, "stack", "positions.jsonl"), os.path.join(a_dir, "ends.jsonl"),
                            inputs)
    window = (a_meta["start_ns"] / 1e9, a_meta["finished_ns"] / 1e9)
    rec = {}
    for comp in inputs:
        try:
            rec[comp] = R.recovery_times({comp: run[comp]}, {comp: ref[comp]}, restart_t, hold_s, window)[comp]
        except (ValueError, TypeError):      # no reference samples in A's window, or no restart
            rec[comp] = {"threshold": None, "recovered_at": None, "recovery_s": None}
    done = [r["recovered_at"] for r in rec.values() if r["recovered_at"] is not None]
    end_t = max(done) if done and len(done) == len(rec) else meta["finished_ns"] / 1e9
    usage = {proc: R.peak_usage(samples, restart_t, end_t) for proc, samples in sorted(
        _usage(os.path.join(run_dir, "usage.jsonl")).items())} if restart_t is not None else {}
    a_recs, recs = P.load(os.path.join(a_dir, "output.jsonl")), P.load(os.path.join(run_dir, "output.jsonl"))
    seal = R.added_seal_delay(P.seal_times_ms(a_recs), P.seal_times_ms(recs), a_meta["start_ns"] / 1e6,
                              meta["start_ns"] / 1e6)
    out = {"restart_t": restart_t, "hold_s": hold_s, "components": rec, "peak_usage": usage,
           "seal_delay": {k: v for k, v in seal.items() if k != "per_incident_s"},
           "seal_delay_per_incident_s": seal["per_incident_s"]}
    if meta["kills"][0]["process"] == "go":
        out["go_backlog_records"] = go_backlog(os.path.join(run_dir, "stack", "positions.jsonl"), kill_ns / 1e9)
        out["longest_open_span_s"] = longest_open_span_s(recs, kill_ns / 1e6)
    return out


def score_run(out_dir, meta, max_idle_s, horizon_s, hold_s=30.0):
    run_dir = os.path.join(out_dir, meta["cell"]["name"])

    def load(name):
        d = os.path.join(out_dir, name)
        with open(os.path.join(d, "tgs.json")) as fh:
            return P.project_file(os.path.join(d, "output.jsonl"), json.load(fh))
    outage = outage_seconds(meta, run_dir)
    comp = meta["kills"][0]["process"] if meta["kills"] else None
    band = C.band_for(outage or 0.0, max_idle_s, horizon_s,
                      component={"go": "go", "tgs": "tgs", "postgres": "tgs"}.get(comp, "receiver"))
    res = C.compare(load("A"), load(meta["cell"]["name"]), load("A2"), band)
    res["outage_s"] = outage
    res["recovery"] = recovery_metrics(out_dir, meta, hold_s)
    with open(os.path.join(run_dir, "compare.json"), "w") as fh:
        json.dump(res, fh, indent=2, sort_keys=True)
    return res


def _aggregate(results):
    """Recovery values over a cell's runs: lists, for the summary."""
    agg = {"recovery_s": {}, "seal_delay_max_s": [], "go_backlog_records": [], "longest_open_span_s": []}
    for r in results:
        rec = r.get("recovery") or {}
        for comp, v in (rec.get("components") or {}).items():
            agg["recovery_s"].setdefault(comp, []).append(v["recovery_s"])
        agg["seal_delay_max_s"].append((rec.get("seal_delay") or {}).get("max_s"))
        for k in ("go_backlog_records", "longest_open_span_s"):
            if k in rec:
                agg[k].append(rec[k])
    return agg


def run_matrix(matrix, inputs, out_dir, parallel=3, params=None, **kw):
    """Run every cell (A and A' first, then the rest) on `parallel` stacks."""
    os.makedirs(out_dir, exist_ok=True)
    slots = queue.Queue()
    for s in range(parallel):
        slots.put(s)

    def job(cell):
        s = slots.get()
        try:
            return run_one(cell, s, inputs, out_dir, params=params, **kw)
        finally:
            slots.put(s)
    metas = {}
    with cf.ThreadPoolExecutor(parallel) as ex:
        for m in ex.map(job, matrix[:2]):
            metas[m["cell"]["name"]] = m
        if any(metas[n]["status"] != "ok" for n in ("A", "A2")):
            raise RunError(f"reference runs failed: {[metas[n].get('error') for n in ('A', 'A2')]}")
        for m in ex.map(job, matrix[2:]):
            metas[m["cell"]["name"]] = m
    from mtcore.orchestrator.params import OrchParams
    op = OrchParams.load(params)
    max_idle_s, horizon_s = op.max_idle_ns / 1e9, op.max_horizon_ns() / 1e9
    groups = {}
    for name, m in metas.items():
        if m["cell"]["point"] is None:
            continue
        key = f"{m['cell']['run']}|{m['cell']['point']}"
        g = groups.setdefault(key, {"results": [], "not_fired": 0, "errors": []})
        if m["status"] == "ok":
            g["results"].append(score_run(out_dir, m, max_idle_s, horizon_s, kw.get("hold_s", 30.0)))
        elif m["status"] == "not_fired":
            g["not_fired"] += 1
        else:
            g["errors"].append({"run": name, "error": m.get("error")})
    summary = {k: {"tally": C.tally(g["results"]) if g["results"] else None, "not_fired": g["not_fired"],
                   "errors": g["errors"], "recovery": _aggregate(g["results"])} for k, g in sorted(groups.items())}
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
    return summary


def run_setting(inputs, out_dir, points, reps=5, max_nth=5, seed=1, parallel=3, params=None, outage_s=2.0,
                settle_s=15.0, timeout_s=900.0, keep=False, pace=0.0, prefill=None, history_s=0.0, hold_s=30.0,
                modes=None):
    """One sweep setting: cut the prefill to history_s, size the timeout for
    the paced input and the outage, and run the matrix into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    pre = None
    if prefill:
        pre = {}
        d = os.path.join(out_dir, "prefill")
        os.makedirs(d, exist_ok=True)
        for node, path in sorted(prefill.items()):
            if history_s > 0:
                pre[node] = os.path.join(d, f"{node}.jsonl")
                cut_history(path, pre[node], history_s)
            else:
                pre[node] = path
    if pace > 0:
        timeout_s = max(timeout_s, input_span_s(list(inputs.values())) / pace + outage_s + hold_s + 900)
    else:
        timeout_s = max(timeout_s, outage_s + hold_s + 900)
    with open(os.path.join(out_dir, "setting.json"), "w") as fh:
        json.dump({"inputs": inputs, "points": points, "reps": reps, "pace": pace, "outage_s": outage_s,
                   "history_s": history_s, "prefill": pre, "hold_s": hold_s, "timeout_s": timeout_s,
                   "seed": seed, "modes": modes}, fh, indent=2, sort_keys=True)
    return run_matrix(cells(points, reps, max_nth, seed, modes), inputs, out_dir, parallel, params=params,
                      outage_s=outage_s, settle_s=settle_s, timeout_s=timeout_s, keep=keep, pace=pace,
                      prefill=pre, hold_s=hold_s)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Exp. 5 part A crash runner on isolated stacks.")
    ap.add_argument("--input", action="append", required=True, help="NODE=PATH shipper input (repeatable)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--max-nth", type=int, default=5)
    ap.add_argument("--points", default=",".join(FP.POINTS + (PG_CRASH,)), help="comma-separated points")
    ap.add_argument("--outage-s", type=float, default=2.0)
    ap.add_argument("--settle-s", type=float, default=15.0)
    ap.add_argument("--timeout-s", type=float, default=900.0)
    ap.add_argument("--params", default=None, help="GO parameter set (default the dev set)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep each stack's Kafka and Postgres data")
    ap.add_argument("--pace", type=float, default=0.0, help="event-time speed factor (0: at once)")
    ap.add_argument("--prefill", action="append", default=[], help="NODE=PATH history shipped first (repeatable)")
    ap.add_argument("--history-s", type=float, default=0.0, help="keep the prefill's last H s of event time (0: all)")
    ap.add_argument("--hold-s", type=float, default=30.0, help="recovery hold (s)")
    ap.add_argument("--modes", default="", help="GO restart modes to run, e.g. C (default: B,C,D)")
    a = ap.parse_args(argv)
    summary = run_setting(dict(x.split("=", 1) for x in a.input), a.out, [p for p in a.points.split(",") if p],
                          reps=a.reps, max_nth=a.max_nth, seed=a.seed, parallel=a.parallel, params=a.params,
                          outage_s=a.outage_s, settle_s=a.settle_s, timeout_s=a.timeout_s, keep=a.keep,
                          pace=a.pace, prefill=dict(x.split("=", 1) for x in a.prefill), history_s=a.history_s,
                          hold_s=a.hold_s, modes=[m for m in a.modes.split(",") if m] or None)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
