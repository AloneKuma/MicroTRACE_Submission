"""Exp. 4 (scalability and bounded reconstruction): archived-finding replay of the GO.

    python -m mtcore.harness.exp4 plan     --passes P.tsv [--repeats 3]
    python -m mtcore.harness.exp4 units    --runs ID,ID,... | --split S --half H  --overlay M
    python -m mtcore.harness.exp4 replay   --runs-dir D --findings-dir F --members R1,R2 --params P
                                           [--overrides JSON] --out DIR [--keep-output] [--check-archive]
    python -m mtcore.harness.exp4 pass     --runs-dir D --findings-dir F --split S --half H --params P
                                           --configs C.tsv --config NAME --workloads W.tsv --workload NAME
                                           --caps CAPS.tsv --workers N --out PASSDIR [--keep-output] [--check-archive]
    python -m mtcore.harness.exp4 score    --session OUT --plan-json plan.json [--k 10] [--reference exhaustive]

What it does (docs/plans/evaluation-plan.md section 4, row 4; heldout-aws-plan.md section 8, T1-T5):
the agents' findings of an earlier run (the archive: score_pilot.py's runs/<run>/output.jsonl.gz, or
twin safety's <run>.output.jsonl[.gz]) and the run's GO inputs (shipper files: norm.events.v0,
source.completeness.v0, context.cluster.v0) are fed to a new GO in mtcore.harness.offline's order (every
shipper record first, then the findings), so correlation cost is measured apart from detection. With
the Full configuration and one run per unit the replay must give the archived GO records exactly
(--check-archive; replay_scores.py --check does the same for Exp. 2).

Configurations (configs.tsv) are orchestrator overrides on one frozen parameter file: Full, No-Index
(ablation no_index), unbounded paths, reduced K, L, T, and the exhaustive reference (No-Index and
unbounded paths). No frozen file is changed. Workloads (workloads.tsv) set the finding rate by overlay:
a unit is M runs of the set (sorted by run ID, consecutive groups of M; every run is in exactly one
unit, none chosen by hand) replayed into one GO. Every generated run starts at the same time base, so M
runs in one GO are M times the finding and event rate over the same span. Their IDs are distinct (per
run seeds); a shared finding or event ID stops the unit (status "collision") rather than merging two
records. Entity names and addresses may repeat across runs (the same topology), which adds candidate
pairs: that is part of the load, and the reference is computed on the same unit.

Time caps (caps.tsv) are per unit: a unit that does not finish within its cap is stopped and recorded
as capped; a configuration is then infeasible on that unit and its path recall is reported only over
the units where it and the reference finished ("feasible workloads only").

Per unit, stats.json: GO seconds (time inside feed, finish and the incident hook; parsing and writing
excluded), per-finding processing times (Engine.process), candidate-pair examinations
(Engine.stats pairs_tested), findings, records, confirmed links, incidents, retained paths, the digest
of the GO output lines (determinism checks) and, on Linux, the process's peak resident memory.
time.json (pass driver): wall, CPU user/system and peak RSS from /usr/bin/time -f '%M %U %S'.

Scoring (score): no truth is read. Path recall of each configuration against the exhaustive
reference's K best paths per incident is mtcore.harness.score.reference_path_recall (the existing Exp. 4
definition), counts summed over the feasible units; confirmed-link sets are compared with No-Index and
the reference (Property 3: equal); timed repeats must give the accuracy pass's digests.
"""
import argparse
import gzip
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

from google.protobuf import json_format

from microtrace.v0 import envelope_pb2, finding_pb2, witness_pb2

from mtcore.orchestrator import ablations
from mtcore.orchestrator.engine import Engine, SCHEMA_MAJOR
from mtcore.orchestrator.params import OrchParams

FINDINGS, WITNESSES, INCIDENTS = "findings.v0", "witness.decisions.v0", "incidents.v0"
GO_TOPICS = (WITNESSES, INCIDENTS)
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
GO_INPUTS = ("norm.events.v0", "source.completeness.v0", "context.cluster.v0")
TRUTH_TOPIC = "ground.truth.v0"
TIME = "/usr/bin/time"
PY = Path(__file__).resolve().parents[2]          # src/python
REPO = PY.parents[1]


# --- config files -------------------------------------------------------------------------
def read_tsv(path):
    """Rows of a tab-separated file as dicts: '#' lines are comments, the first other line
    is the header. Empty cells are ''."""
    rows, header = [], None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cells = line.split("\t")
            if header is None:
                header = cells
                continue
            cells += [""] * (len(header) - len(cells))
            rows.append(dict(zip(header, cells)))
    return rows


def configs(path):
    """name -> orchestrator overrides (dict) from configs.tsv (columns config, overrides)."""
    out = {}
    for r in read_tsv(path):
        ov = json.loads(r["overrides"] or "{}")
        if not isinstance(ov, dict):
            raise ValueError(f"{path}: overrides of {r['config']} must be a JSON object")
        ablations.validate(ov.get("ablations") or [])
        out[r["config"]] = ov
    return out


def workloads(path):
    """name -> overlay M from workloads.tsv (columns workload, overlay)."""
    out = {}
    for r in read_tsv(path):
        m = int(r["overlay"])
        if m < 1:
            raise ValueError(f"{path}: overlay of {r['workload']} must be at least 1")
        out[r["workload"]] = m
    return out


def caps(path):
    """(config, workload) -> per-unit cap in seconds from caps.tsv (columns config, workload,
    unit_cap_s); '*' matches any workload. Missing entries are an error at lookup."""
    return {(r["config"], r["workload"]): float(r["unit_cap_s"]) for r in read_tsv(path)}


def cap_for(table, config, workload):
    for key in ((config, workload), (config, "*")):
        if key in table:
            return table[key]
    raise KeyError(f"no time cap for configuration {config!r} on workload {workload!r} in caps.tsv")


def oparams_for(params_path, overrides):
    """The frozen parameter file with the configuration's orchestrator overrides (never written)."""
    base = OrchParams.load(params_path)
    return base.with_overrides(**overrides) if overrides else base


# --- schedule (T3, T4) ----------------------------------------------------------------------
def schedule(passes, repeats=3):
    """Steps of the timing session from the pass list (passes.tsv rows: unit, system, config,
    workload, workers, timed, train).

    Phase "accuracy": every unit once, in file order, untimed; its outputs are the accuracy results,
    and for timed units it is the one untimed warm-up (T3). A unit with train=yes (ORTHRUS) first
    gets a "train" step, timed once (T4), then its detection warm-up.
    Phases "rep1".."repN": the timed units only, the order rotated per repeat by (r-1) * max(1, n // N)
    places for n timed units and N repeats (ABC, BCA, CAB for three units and three repeats; for more
    units each repeat starts a third of the list further on), so no unit always runs first or last.
    Returns [{step, unit, phase, rep, timed, action, ...row}]."""
    units = [dict(r) for r in passes]
    names = [u["unit"] for u in units]
    if len(set(names)) != len(names):
        raise ValueError(f"duplicate unit names in the pass list: {sorted(n for n, c in Counter(names).items() if c > 1)}")
    steps = []

    def add(u, phase, rep, timed, action):
        steps.append({**u, "step": f"{phase}.{u['unit']}" + (".train" if action == "train" else ""),
                      "phase": phase, "rep": rep, "timed": timed, "action": action})
    for u in units:
        if u.get("prep", "no") == "yes":
            add(u, "prep", 0, False, "prep")
    for u in units:
        if u.get("train", "no") == "yes":
            add(u, "accuracy", 0, True, "train")
        add(u, "accuracy", 0, False, "detect" if u["system"] != "go" else "replay")
    timed = [u for u in units if u.get("timed", "yes") == "yes"]
    for r in range(1, repeats + 1):
        k = ((r - 1) * max(1, len(timed) // repeats)) % len(timed) if timed else 0
        for u in timed[k:] + timed[:k]:
            add(u, f"rep{r}", r, True, "detect" if u["system"] != "go" else "replay")
    return steps


def commands(path):
    """name -> {"prep", "train", "detect": shell command} from commands.tsv (columns command, prep_cmd,
    train_cmd, detect_cmd). Commands run with bash in the repo folder; CODE, OUT, STEP and REP are set."""
    return {r["command"]: {"prep": r.get("prep_cmd", ""), "train": r.get("train_cmd", ""),
                           "detect": r.get("detect_cmd", "")} for r in read_tsv(path)}


def complete_plan(steps, configs_path=None, workloads_path=None, caps_path=None, commands_path=None):
    """Check every name a step uses and add its cap (cap_s) and, for command steps, its command
    (cmd), so a missing setting stops the session before any work starts."""
    cfg = configs(configs_path) if configs_path else None
    wl = workloads(workloads_path) if workloads_path else None
    cp = caps(caps_path) if caps_path else None
    cm = commands(commands_path) if commands_path else None
    out = []
    for s in steps:
        s = dict(s)
        if s["system"] == "go":
            if cfg is not None and s["config"] not in cfg:
                raise ValueError(f"step {s['step']}: configuration {s['config']!r} not in {configs_path}")
            if wl is not None and s["workload"] not in wl:
                raise ValueError(f"step {s['step']}: workload {s['workload']!r} not in {workloads_path}")
        else:
            if cm is not None:
                if s["config"] not in cm or not cm[s["config"]].get(s["action"]):
                    raise ValueError(f"step {s['step']}: no {s['action']} command {s['config']!r} in {commands_path}")
                s["cmd"] = cm[s["config"]][s["action"]]
        if cp is not None:
            name = s["config"] if s["system"] == "go" else f"{s['config']}:{s['action']}"
            s["cap_s"] = cap_for(cp, name, s.get("workload") or "*")
        out.append(s)
    return out


def rotation(steps):
    """Per repeat phase, the order of its units (for logs and tests)."""
    out = {}
    for s in steps:
        if s["phase"].startswith("rep"):
            out.setdefault(s["phase"], []).append(s["unit"])
    return out


# --- units (finding-rate workloads) -----------------------------------------------------------
def make_units(run_ids, overlay):
    """Consecutive groups of `overlay` runs in run-ID order: (units, left-over runs). Every run is
    in at most one unit; a remainder smaller than `overlay` is left out and reported."""
    ids = sorted(run_ids)
    n = len(ids) // overlay * overlay
    units = [ids[i:i + overlay] for i in range(0, n, overlay)]
    return [{"unit": f"u{i:03d}", "members": u} for i, u in enumerate(units)], ids[n:]


def split_runs(split, half):
    with open(split, encoding="utf-8") as fh:
        return json.load(fh)[half]


# --- archive readers --------------------------------------------------------------------------
def archived_output(findings_dir, run_id):
    """The archived offline output of a run: score_pilot.py's runs/<id>/output.jsonl[.gz] or twin
    safety's <id>.output.jsonl[.gz] (plain wins)."""
    d = Path(findings_dir)
    for p in (d / "runs" / run_id / "output.jsonl", d / "runs" / run_id / "output.jsonl.gz",
              d / f"{run_id}.output.jsonl", d / f"{run_id}.output.jsonl.gz"):
        if p.exists():
            return p
    raise FileNotFoundError(f"no archived output for {run_id} under {findings_dir}")


def open_text(path):
    return gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else open(path, encoding="utf-8")


def archived_findings(path):
    """(finding envelopes in file order, archived GO lines) of one archived output."""
    envs, go_lines = [], []
    with open_text(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("topic") == FINDINGS:
                f = json_format.ParseDict(obj["record"], finding_pb2.Finding())
                env = envelope_pb2.Envelope(schema_major=SCHEMA_MAJOR, logical_id=f.finding_id,
                                            kind=envelope_pb2.RecordKind.Value("FINDING"))
                env.finding.CopyFrom(f)
                envs.append(env)
            elif obj.get("topic") in GO_TOPICS:
                go_lines.append(line if line.endswith("\n") else line + "\n")
    return envs, go_lines


def shipper_inputs(run_dir):
    """(topic, envelope) for the GO inputs of a run's shipper files, in mtcore.harness.offline's
    order (sorted files, file order); ground truth lines and lane watermarks are skipped."""
    files = sorted(Path(run_dir, "shipper").glob("*.jsonl"))
    if not files:
        raise SystemExit(f"no shipper files under {run_dir}")
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                obj = json.loads(line)
                if "envelope" not in obj or obj.get("topic") == TRUTH_TOPIC or obj["topic"] not in GO_INPUTS:
                    continue
                yield obj["topic"], json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())


# --- binary input cache (prep, untimed) ---------------------------------------------------------
# Parsing the shipper's JSON costs about 30 times the GO's own time, and it is the same for every
# configuration, so the session converts each run once: the GO inputs and the archived findings, in
# replay order, as (topic index, length, serialized Envelope) records. The replay then reads the same
# envelopes in the same order (test_exp4: equal digests); only the decoding is faster.
CACHE_TOPICS = GO_INPUTS + (FINDINGS,)
CACHE_FILE = "go_inputs.bin"


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _read_varint(buf, i):
    shift = n = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, i
        shift += 7


def write_cache(run_dir, findings_path, out_path):
    """One run's GO inputs then its archived findings, in replay order. Returns record counts."""
    counts = Counter()
    tmp = str(out_path) + ".tmp"
    with open(tmp, "wb") as fh:
        for topic, env in shipper_inputs(run_dir):
            b = env.SerializeToString(deterministic=True)
            fh.write(_varint(CACHE_TOPICS.index(topic)) + _varint(len(b)) + b)
            counts[topic] += 1
        envs, _go = archived_findings(findings_path)
        for env in envs:
            b = env.SerializeToString(deterministic=True)
            fh.write(_varint(CACHE_TOPICS.index(FINDINGS)) + _varint(len(b)) + b)
            counts[FINDINGS] += 1
    os.replace(tmp, out_path)
    return dict(counts)


def read_cache(path):
    """(topic, Envelope) records of a cache file, in order."""
    with open(path, "rb") as fh:
        buf = fh.read()
    i, n = 0, len(buf)
    while i < n:
        t, i = _read_varint(buf, i)
        ln, i = _read_varint(buf, i)
        yield CACHE_TOPICS[t], envelope_pb2.Envelope.FromString(buf[i:i + ln])
        i += ln


def cache_one(run_id, a):
    out = Path(a.cache) / run_id
    done = out / "cache.json"
    src = archived_output(a.findings_dir, run_id)
    stamp = {"run_dir": os.path.join(a.runs_dir, run_id), "archive": str(src), "archive_bytes": src.stat().st_size}
    if done.exists() and all(json.loads(done.read_text()).get(k) == v for k, v in stamp.items()):
        return run_id, "cached"
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    counts = write_cache(os.path.join(a.runs_dir, run_id), src, out / CACHE_FILE)
    done.write_text(json.dumps({**stamp, "counts": counts, "seconds": round(time.monotonic() - t0, 1)}, sort_keys=True))
    return run_id, "ok"


def _cache_safe(r, a):
    try:
        return cache_one(r, a)
    except Exception as e:                     # noqa: BLE001 - reported per run, the rest go on
        return r, f"FAILED ({type(e).__name__}: {e})"


def run_cache(a):
    a.runs_dir, a.findings_dir, a.cache = map(os.path.abspath, (a.runs_dir, a.findings_dir, a.cache))
    ids = [r for r in a.run_list.split(",") if r] if a.run_list else split_runs(a.split, a.half)
    failed = 0
    with ProcessPoolExecutor(max_workers=a.workers) as pool:       # JSON parsing is CPU-bound
        for i, (r, status) in enumerate(pool.map(_cache_safe, ids, [a] * len(ids)), 1):
            failed += status.startswith("FAILED")
            print(f"{i}/{len(ids)} {r} {status}", flush=True)
    return 1 if failed else 0


# --- the replay -------------------------------------------------------------------------------
class TimedEngine(Engine):
    """The GO engine with per-finding processing times recorded; decisions are the Engine's."""

    def __init__(self, oparams):
        super().__init__(oparams)
        self.process_ns = []

    def process(self, finding, t):
        t0 = time.perf_counter_ns()
        super().process(finding, t)
        self.process_ns.append(time.perf_counter_ns() - t0)


def _stats_ms(ns_values):
    from mtcore.harness.score import _stats
    return _stats([v / 1e6 for v in ns_values])


def _proc_mem():
    """(VmRSS MB, VmHWM MB) of this process on Linux; (None, None) elsewhere."""
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            st = dict(line.split(":", 1) for line in fh if ":" in line)
        return round(int(st["VmRSS"].split()[0]) / 1024, 1), round(int(st["VmHWM"].split()[0]) / 1024, 1)
    except (OSError, KeyError, ValueError):
        pass
    if os.name == "nt":                # development laptops: the working set (no /proc)
        try:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
            c = PMC()
            c.cb = ctypes.sizeof(PMC)
            k32 = ctypes.windll.kernel32
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            gpmi = ctypes.windll.psapi.GetProcessMemoryInfo
            gpmi.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
            gpmi(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
            return round(c.WorkingSetSize / 1048576, 1), round(c.PeakWorkingSetSize / 1048576, 1)
        except (OSError, AttributeError, ValueError, TypeError):
            pass
    return None, None


class Collision(ValueError):
    """Two runs of one unit share a finding or event ID."""


def replay(run_dirs, findings_paths, oparams, out=None, check_archive=False, cache_files=None):
    """Feed every run's GO inputs (in order), then every run's archived findings, to one GO;
    write the GO's output lines to `out` (a text file or None). With cache_files (one per run,
    write_cache), the same envelopes come from the cache. Returns stats."""
    ablations.validate(oparams.ablations)
    eng = TimedEngine(oparams)
    offsets = Counter()
    go_ns = 0
    t_start = time.perf_counter()
    n_records = 0
    seen_events, seen_findings = {}, {}

    def feed(env, topic):
        nonlocal go_ns
        t0 = time.perf_counter_ns()
        eng.feed(env, topic, 0, offsets[topic])
        go_ns += time.perf_counter_ns() - t0
        offsets[topic] += 1

    cached_findings = []
    for i, rd in enumerate(run_dirs):
        mine = []
        source = read_cache(cache_files[i]) if cache_files else shipper_inputs(rd)
        for topic, env in source:
            if topic == FINDINGS:
                mine.append(env)
                continue
            if topic == "norm.events.v0" and env.HasField("normalized_event"):
                eid = env.normalized_event.event_id
                if seen_events.setdefault(eid, i) != i:
                    raise Collision(f"event {eid} is in runs {run_dirs[seen_events[eid]]} and {rd}")
            n_records += 1
            feed(env, topic)
        cached_findings.append(mine)
    archived = []
    for i, fp in enumerate(findings_paths):
        if cache_files and not check_archive:
            envs, go_lines = cached_findings[i], []
        else:
            envs, go_lines = archived_findings(fp)
        archived.append(go_lines)
        for env in envs:
            fid = env.finding.finding_id
            if seen_findings.setdefault(fid, i) != i:
                raise Collision(f"finding {fid} is in archives {findings_paths[seen_findings[fid]]} and {fp}")
            feed(env, FINDINGS)
    n_findings = offsets[FINDINGS]
    t0 = time.perf_counter_ns()
    eng.finish()
    finish_ns = time.perf_counter_ns() - t0
    t0 = time.perf_counter_ns()
    hook = getattr(eng, "incidents_hook", None)
    if hook is not None:
        now = eng.watermarks.now
        hook(now if now is not None else 0)
    hook_ns = time.perf_counter_ns() - t0
    go_ns += finish_ns + hook_ns
    digest = hashlib.sha256()
    last_status, incidents, n_lines = {}, {}, 0
    replayed = []
    for topic, _key, env in eng.drain():
        msg = env.witness if env.HasField("witness") else env.incident
        line = json.dumps({"topic": topic, "record": json_format.MessageToDict(msg)}, sort_keys=True) + "\n"
        digest.update(line.encode("utf-8"))
        n_lines += 1
        if check_archive:
            replayed.append(line)
        if out is not None:
            out.write(line)
        if env.HasField("witness"):
            last_status[env.witness.witness_id] = env.witness.status       # a witness keeps its last record
        else:
            incidents[env.incident.incident_id] = len(env.incident.ranked_paths)
    rss, hwm = _proc_mem()
    stats = {"runs": [str(r) for r in run_dirs], "records": n_records, "findings": n_findings,
             "go_seconds": round(go_ns / 1e9, 6), "finish_seconds": round(finish_ns / 1e9, 6),
             "hook_seconds": round(hook_ns / 1e9, 6), "total_seconds": round(time.perf_counter() - t_start, 3),
             "process_ms": _stats_ms(eng.process_ns), "pairs_tested": eng.stats.get("pairs_tested", 0),
             "go_stats": dict(eng.stats), "output_lines": n_lines, "incidents": len(incidents),
             "confirmed_witnesses": sum(1 for v in last_status.values() if v == CONFIRMED),
             "retained_paths": sum(incidents.values()), "digest": digest.hexdigest(),
             "rss_mb": rss, "peak_rss_mb": hwm,
             "throughput_findings_per_s": round(n_findings / (go_ns / 1e9), 3) if go_ns else None}
    if check_archive:
        stats["archive_equal"] = replayed == [ln for g in archived for ln in g]
    return stats


# --- the pass driver ----------------------------------------------------------------------------
def code_commit():
    try:
        return subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip() or None
    except OSError:
        return None


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def parse_time(text):
    """/usr/bin/time -f '%M %U %S' (last line; earlier lines are notes such as a signal) ->
    peak RSS MB and CPU user and system seconds; fields it cannot read stay None."""
    lines = text.strip().splitlines()
    parts = lines[-1].split() if lines else []
    out = {"peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None}
    if len(parts) == 3:
        try:
            out = {"peak_rss_mb": round(int(parts[0]) / 1024, 1), "cpu_user_s": float(parts[1]),
                   "cpu_sys_s": float(parts[2])}
        except ValueError:
            pass
    return out


def timed_run(cmd, cwd, log, cap_s, time_file, shell=False):
    """Run cmd under /usr/bin/time (when it exists) in its own process group and stop the whole
    group once cap_s passes. Returns (exit code, wall seconds, capped, time fields)."""
    if shell:
        # PATH order, not the Windows system folder first (where bash.exe is WSL's launcher)
        import shutil
        cmd = [os.environ.get("EXP4_SHELL") or shutil.which("bash") or "bash", "-c", cmd]
    wrap = [TIME, "-f", "%M %U %S", "-o", str(time_file)] if os.path.exists(TIME) else []
    kw = {"start_new_session": True} if os.name == "posix" else {}
    t0 = time.monotonic()
    p = subprocess.Popen(wrap + cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, **kw)
    capped = False
    try:
        rc = p.wait(timeout=cap_s)
    except subprocess.TimeoutExpired:
        capped = True
        if os.name == "posix":
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            p.kill()
        rc = p.wait()
    wall = round(time.monotonic() - t0, 3)
    fields = {"peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None}
    if wrap and Path(time_file).exists():
        if not capped:                # a killed /usr/bin/time writes nothing useful
            fields = parse_time(Path(time_file).read_text())
        Path(time_file).unlink()
    return rc, wall, capped, fields


def unit_done(out, stamp, keep_output):
    """A finished (or capped) unit made with this stamp; a capped unit is final for the same cap."""
    t = out / "time.json"
    if not t.exists():
        return False
    rec = json.loads(t.read_text())
    if any(rec.get(k) != v for k, v in stamp.items()):
        return False
    if rec.get("capped"):
        return True
    return rec.get("exit") == 0 and (out / "stats.json").exists() and \
        (not keep_output or (out / "output.jsonl.gz").exists())


def run_unit(unit, a, stamp, cap_s):
    out = Path(a.out) / "units" / unit["unit"]
    if unit_done(out, stamp, a.keep_output):
        return unit["unit"], "cached"
    out.mkdir(parents=True, exist_ok=True)
    for stale in ("stats.json", "output.jsonl.gz", "time.json"):
        if (out / stale).exists():
            (out / stale).unlink()
    cmd = [sys.executable, "-m", "mtcore.harness.exp4", "replay", "--runs-dir", a.runs_dir,
           "--findings-dir", a.findings_dir, "--members", ",".join(unit["members"]), "--params", a.params,
           "--overrides", json.dumps(a._overrides, sort_keys=True), "--out", str(out)]
    if a.cache:
        cmd += ["--cache", a.cache]
    if a.keep_output:
        cmd.append("--keep-output")
    if a.check_archive and len(unit["members"]) == 1:
        cmd.append("--check-archive")
    with open(out / "replay.log", "w", encoding="utf-8") as log:
        rc, wall, capped, fields = timed_run(cmd, str(PY), log, cap_s, out / "time.txt")
    rec = {"wall_s": wall, "exit": rc, "capped": capped, **fields, **stamp}
    (out / "time.json").write_text(json.dumps(rec, sort_keys=True))
    if capped:
        for stale in ("stats.json", "output.jsonl.gz", "output.jsonl.gz.tmp"):
            if (out / stale).exists():
                (out / stale).unlink()
        return unit["unit"], f"CAPPED after {cap_s:g} s"
    if rc != 0:
        return unit["unit"], f"FAILED (exit {rc}, see {out / 'replay.log'})"
    return unit["unit"], "ok"


def summarize_pass(out, units):
    """Sums over the units of one pass: wall, CPU, findings, GO seconds, the largest peak RSS,
    per-unit digests, and the capped and failed units."""
    rows = []
    for u in units:
        d = Path(out) / "units" / u["unit"]
        t = json.loads((d / "time.json").read_text()) if (d / "time.json").exists() else {}
        s = json.loads((d / "stats.json").read_text()) if (d / "stats.json").exists() else {}
        rows.append((u, t, s))
    ok = [(u, t, s) for u, t, s in rows if t.get("exit") == 0 and not t.get("capped") and s]
    cpu = [t["cpu_user_s"] + t["cpu_sys_s"] for _u, t, _s in rows
           if t.get("cpu_user_s") is not None and t.get("cpu_sys_s") is not None]
    rss = [t["peak_rss_mb"] for _u, t, _s in rows if t.get("peak_rss_mb") is not None]
    go_s = sum(s["go_seconds"] for _u, _t, s in ok)
    findings = sum(s["findings"] for _u, _t, s in ok)
    proc_mean = [s["process_ms"]["mean_ms"] for _u, _t, s in ok if s.get("process_ms")]
    return {"units": len(units), "finished": len(ok),
            "capped": [u["unit"] for u, t, _s in rows if t.get("capped")],
            "failed": [u["unit"] for u, t, _s in rows if not t.get("capped") and t.get("exit") != 0],
            "sum_unit_wall_s": round(sum(t.get("wall_s", 0) for _u, t, _s in rows), 3),
            "sum_unit_cpu_s": round(sum(cpu), 3) if cpu else None,
            "max_unit_rss_mb": max(rss) if rss else None,
            "go_seconds": round(go_s, 6), "findings": findings,
            "records": sum(s["records"] for _u, _t, s in ok),
            "pairs_tested": sum(s["pairs_tested"] for _u, _t, s in ok),
            "confirmed_witnesses": sum(s["confirmed_witnesses"] for _u, _t, s in ok),
            "retained_paths": sum(s["retained_paths"] for _u, _t, s in ok),
            "throughput_findings_per_s": round(findings / go_s, 3) if go_s else None,
            "go_ms_per_finding": round(1000 * go_s / findings, 6) if findings else None,
            "max_process_ms": max((s["process_ms"]["max_ms"] for _u, _t, s in ok if s.get("process_ms")), default=None),
            "mean_process_ms_unit_median": sorted(proc_mean)[len(proc_mean) // 2] if proc_mean else None,
            "digests": {u["unit"]: s["digest"] for u, _t, s in ok},
            "archive_equal": {u["unit"]: s["archive_equal"] for u, _t, s in ok if "archive_equal" in s}}


def run_pass(a):
    a.runs_dir, a.findings_dir = os.path.abspath(a.runs_dir), os.path.abspath(a.findings_dir)
    a.params, a.out = os.path.abspath(a.params), os.path.abspath(a.out)
    a.cache = os.path.abspath(a.cache) if a.cache else None
    cfg = configs(a.configs)
    if a.config not in cfg:
        raise SystemExit(f"configuration {a.config!r} is not in {a.configs}")
    a._overrides = cfg[a.config]
    m = workloads(a.workloads)[a.workload]
    cap_s = cap_for(caps(a.caps), a.config, a.workload)
    run_ids = [r for r in a.run_list.split(",") if r] if a.run_list else split_runs(a.split, a.half)
    units, left = make_units(run_ids, m)
    stamp = {"params_sha256": sha256_file(a.params), "overrides": a._overrides, "overlay": m, "cap_s": cap_s,
             "code": code_commit()}
    Path(a.out).mkdir(parents=True, exist_ok=True)
    (Path(a.out) / "units.json").write_text(json.dumps(
        {"config": a.config, "workload": a.workload, "overlay": m, "units": units, "left_out": left,
         "stamp": stamp}, indent=1, sort_keys=True))
    failed = 0
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        for i, (u, status) in enumerate(pool.map(lambda u: run_unit(u, a, stamp, cap_s), units), 1):
            failed += status.startswith("FAILED")
            print(f"{i}/{len(units)} {u} {status}", flush=True)
    summary = summarize_pass(a.out, units)
    summary.update({"config": a.config, "workload": a.workload, "overlay": m, "cap_s": cap_s,
                    "workers": a.workers, "pass_wall_s": round(time.monotonic() - t0, 3), "left_out": left,
                    "stamp": stamp})
    (Path(a.out) / "pass.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    print(json.dumps({k: summary[k] for k in ("config", "workload", "units", "finished", "capped", "failed",
                                              "go_seconds", "findings", "sum_unit_cpu_s", "max_unit_rss_mb")}),
          flush=True)
    return 1 if failed else 0


def run_replay(a):
    members = [m for m in a.members.split(",") if m]
    run_dirs = [os.path.join(a.runs_dir, m) for m in members]
    paths = [archived_output(a.findings_dir, m) for m in members]
    cache_files = [os.path.join(a.cache, m, CACHE_FILE) for m in members] if a.cache else None
    if cache_files:
        missing = [c for c in cache_files if not os.path.exists(c)]
        if missing:
            raise SystemExit(f"no input cache {missing[0]} (exp4 cache)")
    oparams = oparams_for(a.params, json.loads(a.overrides or "{}"))
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / "output.jsonl.gz.tmp"
    try:
        if a.keep_output:
            with gzip.open(tmp, "wt", encoding="utf-8") as fh:
                stats = replay(run_dirs, paths, oparams, fh, a.check_archive, cache_files)
            os.replace(tmp, out_dir / "output.jsonl.gz")
        else:
            stats = replay(run_dirs, paths, oparams, None, a.check_archive, cache_files)
    except Collision as e:
        if tmp.exists():
            tmp.unlink()
        print(f"collision: {e}", file=sys.stderr)
        return 3
    stats["members"] = members
    stats["parameter_set_version"] = oparams.version
    stats["K"], stats["L"], stats["T_s"] = oparams.K, oparams.L, oparams.T_ns / 1e9
    stats["ablations"] = sorted(oparams.ablations)
    (out_dir / "stats.json.tmp").write_text(json.dumps(stats, indent=1, sort_keys=True))
    os.replace(out_dir / "stats.json.tmp", out_dir / "stats.json")
    if a.check_archive and not stats.get("archive_equal"):
        print("replayed GO records differ from the archived ones", file=sys.stderr)
        return 4
    return 0


def run_cmdstep(a):
    """A non-GO step (ORTHRUS training or detection): the command under /usr/bin/time with its cap."""
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    own = out / "cmd_time.json"
    if own.exists():
        own.unlink()
    os.environ["EXP4_STEP_JSON"] = str(own)
    with open(out / "step.log", "w", encoding="utf-8") as log:
        rc, wall, capped, fields = timed_run(a.cmd, a.cwd or os.getcwd(), log, a.cap, out / "time.txt", shell=True)
    rec = {"wall_s": wall, "exit": rc, "capped": capped, "cap_s": a.cap, "cmd": a.cmd, "command": a.name, **fields,
           "measured_by": "/usr/bin/time" if fields.get("cpu_user_s") is not None else None}
    # A command whose work runs elsewhere (ORTHRUS inside its container: /usr/bin/time would see only
    # the docker client) writes its own wall, CPU and peak memory to $EXP4_STEP_JSON; those win.
    if own.exists() and not capped:
        mine = json.loads(own.read_text())
        rec.update({k: mine[k] for k in ("wall_s", "cpu_user_s", "cpu_sys_s", "peak_rss_mb") if k in mine})
        rec["measured_by"] = mine.get("measured_by", "command")
        rec["outer_wall_s"] = wall
    (out / "time.json").write_text(json.dumps(rec, sort_keys=True))
    print(json.dumps(rec, sort_keys=True), flush=True)
    return 0 if rc == 0 and not capped else (5 if capped else 1)


# --- scoring (no truth) ------------------------------------------------------------------------
def _load_output(path):
    from mtcore.harness.score import Output
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return Output.parse(fh)


def confirmed_links(output):
    """(source finding, target finding) of every witness whose last record is CONFIRMED."""
    return {(w.source_finding_id, w.target_finding_id) for w in output.witnesses.values() if w.status == CONFIRMED}


def _unit_state(pass_dir, unit):
    d = Path(pass_dir) / "units" / unit
    t = json.loads((d / "time.json").read_text()) if (d / "time.json").exists() else {}
    if t.get("capped"):
        return "capped", None
    if t.get("exit") != 0 or not (d / "output.jsonl.gz").exists():
        return "failed", None
    return "ok", d / "output.jsonl.gz"


def _median(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def score_session(session, steps, k, reference="exhaustive", no_index="no_index"):
    """Exp. 4 results of one session (OUT): per (configuration, workload) accuracy pass, path recall
    against the reference pass's K best paths per incident (score.reference_path_recall, counts summed
    over units where both finished), confirmed-link set equality with the No-Index and reference passes,
    and the timed repeats' determinism and timing (median over repeats). No truth is read."""
    from mtcore.harness.score import reference_path_recall
    root = Path(session) / "passes"
    acc = {(s["config"], s["workload"]): root / s["step"] for s in steps
           if s["phase"] == "accuracy" and s["system"] == "go"}
    reps = {}
    for s in steps:
        if s["phase"].startswith("rep") and s["system"] == "go":
            reps.setdefault((s["config"], s["workload"]), []).append(root / s["step"])
    rows = []
    for (cfg, wl), pdir in sorted(acc.items()):
        if not (pdir / "units.json").exists():
            rows.append({"config": cfg, "workload": wl, "status": "not run"})
            continue
        units = [u["unit"] for u in json.loads((pdir / "units.json").read_text())["units"]]
        ref_dir, ni_dir = acc.get((reference, wl)), acc.get((no_index, wl))
        row = {"config": cfg, "workload": wl, "units": len(units), "feasible_units": 0, "capped_units": 0,
               "failed_units": 0, "no_reference_units": 0, "reference_paths": 0, "retained": 0,
               "links_equal_no_index": 0, "links_compared_no_index": 0, "links_equal_reference": 0,
               "links_compared_reference": 0, "links_missing_vs_reference": 0, "links_extra_vs_reference": 0}
        for u in units:
            st, out = _unit_state(pdir, u)
            if st != "ok":
                row[f"{st}_units"] += 1
                continue
            o = _load_output(out)
            mine = confirmed_links(o)
            if ni_dir is not None and cfg != no_index:
                st2, out2 = _unit_state(ni_dir, u)
                if st2 == "ok":
                    row["links_compared_no_index"] += 1
                    row["links_equal_no_index"] += mine == confirmed_links(_load_output(out2))
            if ref_dir is None:
                row["no_reference_units"] += 1
                continue
            st3, out3 = _unit_state(ref_dir, u)
            if st3 != "ok":
                row["no_reference_units"] += 1
                continue
            ref = _load_output(out3)
            r = reference_path_recall(ref, o, k)
            row["feasible_units"] += 1
            row["reference_paths"] += r["reference_paths"]
            row["retained"] += r["retained"]
            theirs = confirmed_links(ref)
            row["links_compared_reference"] += 1
            row["links_equal_reference"] += mine == theirs
            row["links_missing_vs_reference"] += len(theirs - mine)
            row["links_extra_vs_reference"] += len(mine - theirs)
        row["path_recall"] = round(row["retained"] / row["reference_paths"], 6) if row["reference_paths"] else None
        acc_pass = json.loads((pdir / "pass.json").read_text()) if (pdir / "pass.json").exists() else {}
        timed = [json.loads((p / "pass.json").read_text()) for p in reps.get((cfg, wl), []) if (p / "pass.json").exists()]
        same = sum(1 for t in timed for uu, dg in t.get("digests", {}).items() if acc_pass.get("digests", {}).get(uu) == dg)
        compared = sum(1 for t in timed for uu in t.get("digests", {}) if uu in acc_pass.get("digests", {}))
        row.update({"repeats": len(timed), "repeat_units_equal": same, "repeat_units_compared": compared,
                    "archive_equal_units": sum(1 for v in acc_pass.get("archive_equal", {}).values() if v),
                    "archive_checked_units": len(acc_pass.get("archive_equal", {}))})
        for key in ("pass_wall_s", "sum_unit_wall_s", "sum_unit_cpu_s", "max_unit_rss_mb", "go_seconds",
                    "throughput_findings_per_s", "go_ms_per_finding", "pairs_tested", "findings"):
            row[f"median_{key}"] = _median([t.get(key) for t in timed])
        row["status"] = "ok"
        rows.append(row)
    cmd_rows = []
    for s in steps:
        if s["system"] != "go":
            t = root / s["step"] / "time.json"
            rec = json.loads(t.read_text()) if t.exists() else {}
            cmd_rows.append({"step": s["step"], "unit": s["unit"], "phase": s["phase"], "action": s["action"],
                             **{x: rec.get(x) for x in ("exit", "capped", "wall_s", "cpu_user_s", "cpu_sys_s", "peak_rss_mb")}})
    return {"k": k, "reference": reference, "rows": rows, "commands": cmd_rows}


SUMMARY_COLS = ("config", "workload", "status", "units", "feasible_units", "capped_units", "failed_units",
                "path_recall", "reference_paths", "retained", "links_equal_no_index", "links_compared_no_index",
                "links_equal_reference", "links_compared_reference", "repeats", "repeat_units_equal",
                "repeat_units_compared", "archive_equal_units", "archive_checked_units", "median_pass_wall_s",
                "median_sum_unit_cpu_s", "median_max_unit_rss_mb", "median_go_seconds",
                "median_throughput_findings_per_s", "median_go_ms_per_finding", "median_pairs_tested")


def write_summary(session, result):
    p = Path(session)
    (p / "exp4_summary.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    with open(p / "exp4_summary.tsv", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(SUMMARY_COLS) + "\n")
        for r in result["rows"]:
            fh.write("\t".join("-" if r.get(c) is None else str(r.get(c)) for c in SUMMARY_COLS) + "\n")


# --- settings from development data (PROPOSED rules; worklog section 4) -----------------------
def derive_caps(session, factor=20.0, floor_s=600.0):
    """Per (configuration, workload): the largest unit wall time in any pass of a development session,
    and the cap max(floor_s, factor x it) rounded up to a minute; per command step likewise."""
    import math
    root = Path(session) / "passes"
    seen = {}
    for pj in root.glob("*/units.json"):
        meta = json.loads(pj.read_text())
        for u in meta["units"]:
            t = pj.parent / "units" / u["unit"] / "time.json"
            if t.exists():
                rec = json.loads(t.read_text())
                seen.setdefault((meta["config"], meta["workload"]), []).append(
                    (rec.get("wall_s", 0), bool(rec.get("capped"))))
    for tj in root.glob("*/time.json"):
        rec = json.loads(tj.read_text())
        step = tj.parent.name
        action = "train" if step.endswith(".train") else "prep" if step.startswith("prep.") else "detect"
        seen.setdefault((f"{rec.get('command') or step.split('.')[1]}:{action}", "*"), []).append(
            (rec.get("wall_s", 0), bool(rec.get("capped"))))
    rows = []
    for (cfg, wl), vals in sorted(seen.items()):
        worst = max(v for v, _c in vals)
        rows.append({"config": cfg, "workload": wl, "dev_units": len(vals), "dev_max_unit_wall_s": worst,
                     "dev_capped": sum(c for _v, c in vals),
                     "proposed_unit_cap_s": max(floor_s, math.ceil(factor * worst / 60.0) * 60.0)})
    return rows


def derive_path_settings(findings_dir, run_ids):
    """Lengths (findings) and spans (order time of the last finding minus the first, s) of the retained
    ranked paths with two or more findings in archived Full outputs (development data only): the inputs
    of the PROPOSED reduced-L and reduced-T rule: L = the 90th-percentile length minus one (at least 2),
    so at least a tenth of the multi-finding paths no longer fit; T = the median span rounded up to a
    minute (at least 60 s), so about half of them no longer fit."""
    import math
    from mtcore.harness.score import Output
    from mtcore.orchestrator.engine import order_time
    lengths, spans = [], []
    for r in run_ids:
        with open_text(archived_output(findings_dir, r)) as fh:
            o = Output.parse(fh)
        for _iid, p in o.retained_paths():
            ids = list(p.finding_ids)
            if len(ids) < 2 or any(f not in o.findings for f in ids):
                continue
            ts = [order_time(o.findings[f]) for f in ids]
            lengths.append(len(ids))
            spans.append((max(ts) - min(ts)) / 1e9)
    if not lengths:
        return {"paths": 0, "runs": len(run_ids)}
    lengths.sort()
    spans.sort()
    q = lambda v, x: v[min(len(v) - 1, int(x * len(v)))]  # noqa: E731
    return {"paths": len(lengths), "runs": len(run_ids),
            "length": {"min": lengths[0], "p50": q(lengths, .5), "p90": q(lengths, .9), "max": lengths[-1],
                       "histogram": {str(k): v for k, v in sorted(Counter(lengths).items())}},
            "span_s": {"min": spans[0], "p50": q(spans, .5), "p90": q(spans, .9), "max": spans[-1]},
            "proposed": {"L": max(2, q(lengths, .9) - 1), "T_s": max(60, math.ceil(q(spans, .5) / 60) * 60)}}


# --- entry ------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Exp. 4 runner core: archived-finding replay of the GO.")
    sub = ap.add_subparsers(dest="sub", required=True)
    p = sub.add_parser("plan", help="the session's steps from the pass list (JSON lines)")
    p.add_argument("--passes", required=True)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--configs", default=None)
    p.add_argument("--workloads", default=None)
    p.add_argument("--caps", default=None)
    p.add_argument("--commands", default=None)
    p.add_argument("--out", default=None, help="write plan.json here")
    p = sub.add_parser("units", help="the units of a workload (JSON)")
    p.add_argument("--run-list", default=None)
    p.add_argument("--split", default=None)
    p.add_argument("--half", default=None)
    p.add_argument("--overlay", type=int, required=True)
    p = sub.add_parser("replay", help="one unit (run by the pass driver)")
    p.add_argument("--runs-dir", required=True)
    p.add_argument("--findings-dir", required=True)
    p.add_argument("--members", required=True)
    p.add_argument("--params", required=True)
    p.add_argument("--overrides", default="{}")
    p.add_argument("--out", required=True)
    p.add_argument("--keep-output", action="store_true")
    p.add_argument("--check-archive", action="store_true")
    p.add_argument("--cache", default=None, help="input cache folder (exp4 cache)")
    p = sub.add_parser("pass", help="one configuration on one workload, units in parallel")
    p.add_argument("--runs-dir", required=True)
    p.add_argument("--findings-dir", required=True)
    p.add_argument("--split", default=None)
    p.add_argument("--half", default=None)
    p.add_argument("--run-list", default=None, help="comma-separated run IDs instead of --split/--half")
    p.add_argument("--params", required=True)
    p.add_argument("--configs", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--workloads", required=True)
    p.add_argument("--workload", required=True)
    p.add_argument("--caps", required=True)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--out", required=True)
    p.add_argument("--keep-output", action="store_true")
    p.add_argument("--check-archive", action="store_true")
    p.add_argument("--cache", default=None, help="input cache folder (exp4 cache)")
    p = sub.add_parser("cache", help="convert each run's GO inputs and archived findings once (untimed prep)")
    p.add_argument("--runs-dir", required=True)
    p.add_argument("--findings-dir", required=True)
    p.add_argument("--split", default=None)
    p.add_argument("--half", default=None)
    p.add_argument("--run-list", default=None)
    p.add_argument("--cache", required=True)
    p.add_argument("--workers", type=int, default=8)
    p = sub.add_parser("cmdstep", help="a non-GO step under /usr/bin/time with a cap")
    p.add_argument("--cmd", required=True)
    p.add_argument("--cap", type=float, required=True)
    p.add_argument("--cwd", default=None)
    p.add_argument("--name", default=None, help="the commands.tsv entry (recorded)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("score", help="Exp. 4 results of a session (no truth)")
    p.add_argument("--session", required=True)
    p.add_argument("--plan-json", required=True)
    p.add_argument("--k", type=int, default=None, help="reference paths per incident (default the frozen K)")
    p.add_argument("--params", default=None, help="parameter file whose K is the default --k")
    p.add_argument("--reference", default="exhaustive")
    p = sub.add_parser("derive-caps", help="PROPOSED caps from a development session")
    p.add_argument("--session", required=True)
    p.add_argument("--factor", type=float, default=20.0)
    p.add_argument("--floor", type=float, default=600.0)
    p = sub.add_parser("derive-paths", help="path lengths and spans of archived Full outputs (development)")
    p.add_argument("--findings-dir", required=True)
    p.add_argument("--run-list", default=None)
    p.add_argument("--split", default=None)
    p.add_argument("--half", default=None)
    a = ap.parse_args(argv)
    if a.sub == "derive-caps":
        rows = derive_caps(a.session, a.factor, a.floor)
        cols = ("config", "workload", "proposed_unit_cap_s", "dev_max_unit_wall_s", "dev_units", "dev_capped")
        print("\t".join(cols))
        for r in rows:
            print("\t".join(str(r[c]) for c in cols))
        return 0
    if a.sub == "derive-paths":
        ids = [r for r in a.run_list.split(",") if r] if a.run_list else split_runs(a.split, a.half)
        print(json.dumps(derive_path_settings(a.findings_dir, ids), indent=1))
        return 0
    if a.sub == "plan":
        steps = schedule(read_tsv(a.passes), a.repeats)
        steps = complete_plan(steps, a.configs, a.workloads, a.caps, a.commands)
        if a.out:
            Path(a.out).write_text(json.dumps(steps, indent=1))
        for s in steps:
            print(json.dumps(s, sort_keys=True))
        return 0
    if a.sub == "units":
        ids = [r for r in a.run_list.split(",") if r] if a.run_list else split_runs(a.split, a.half)
        units, left = make_units(ids, a.overlay)
        print(json.dumps({"units": units, "left_out": left}, indent=1))
        return 0
    if a.sub == "replay":
        return run_replay(a)
    if a.sub == "pass":
        if not a.run_list and not (a.split and a.half):
            ap.error("pass needs --run-list or --split and --half")
        return run_pass(a)
    if a.sub == "cmdstep":
        return run_cmdstep(a)
    if a.sub == "cache":
        if not a.run_list and not (a.split and a.half):
            ap.error("cache needs --run-list or --split and --half")
        return run_cache(a)
    if a.sub == "score":
        steps = json.loads(Path(a.plan_json).read_text())
        k = a.k if a.k is not None else OrchParams.load(a.params).K
        res = score_session(a.session, steps, k, a.reference)
        write_summary(a.session, res)
        print(json.dumps(res["rows"], indent=1))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
