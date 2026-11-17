"""Exp. 3 runner: base stream, fault plans, live transport, detection, scoring.

    # one machine (development): senders and receivers side by side
    python -m mtcore.exp3.run --role local --work W --data DATA --runs RUNS.json[:key] \
        --conditions experiments/exp3/configs/conditions.tsv --passes experiments/exp3/configs/passes.tsv \
        --main-params P [--slots 3] [--workers 3] [--only nofault,loss-*] [--max-tier 1]

    # AWS session: the analysis host, and each sender node (separate machines)
    python -m mtcore.exp3.run --role analysis ... --ctl s3://B/results/S/exp3-ctl --senders 2 \
        --listen-host 0.0.0.0 --advertise-host <private IP>
    python -m mtcore.exp3.run --role sender --sender-index i --work W --data DATA --ctl ... \
        --faultlogs s3://B/results/S-faultlogs

    # scoring session (truth readable): fault-log consistency, then every pass scored
    python -m mtcore.exp3.run --role score --work W --truth-root T --faultlogs FL ...

Stages per condition (conditions.tsv, in file order): plans (mtcore.exp3.plans), transport (one
job per run whose plan applies: a fresh Slot, the run's node streams sent through faultinject and
the shipper by mtcore.exp3.sender, what arrived dumped as W/received/<cond>/<run>/shipper/
received.jsonl), detect (every pass of passes.tsv for this condition: score_pilot.py --stage
detect on the received runs, so GO Full, each ablation and SAGE read the same degraded stream).
A live condition (mode live, pace 1) also runs agents and GO on the slot's Kafka while the run is
replayed in real time; their output, with Kafka timestamps, is the pass live_full (Exp. 1
latency per finding, heldout-aws-plan.md section 8 "Timing gaps fixed").

A condition whose template sets `base_variant: no_history` (mtcore.exp3.plans) is sent from the
No-History identity variant of each run's base (W/base-no_history/<run>, mtcore.exp3.nohistory)
instead of W/base/<run>; everything else about it is an ordinary condition, so its `full` pass is
the No-History ablation on that condition's stream.

Detection never sees truth or a fault log: the fault logs go to --faultlogs (local: W/faultlogs),
which only --role score reads. Resumable: a finished job (transport.json with ok) and a finished
pass (score_pilot's own cache) are not redone.
"""
import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from mtcore import REPO
from mtcore.exp3 import base as B
from mtcore.exp3 import plans as PL
from mtcore.exp3.ctl import make_ctl
from mtcore.exp3.sender import send_job
from mtcore.exp3.slot import Slot

PASS_COLUMNS = ("name", "correlator", "params", "ablation", "findings_from", "sage_variant", "conditions")
SCORE_PILOT = os.path.join(REPO, "src", "scripts", "pilot", "score_pilot.py")
LIVE_PASS = "live_full"
DROP = "drop:"          # ablation column "drop:PATH_FLOW": No-OffNode, score_pilot.py --drop-source (Q-4)
LOCK = threading.Lock()


def log(work, msg):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}"
    with LOCK:
        print(line, flush=True)
        with open(os.path.join(work, "STATUS"), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def code_commit():
    try:
        return subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip() or None
    except OSError:
        return None


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# --- passes --------------------------------------------------------------------------------
def load_passes(path, main_params):
    rows = PL.read_tsv(path, PASS_COLUMNS)
    names = set()
    for r in rows:
        if r["correlator"] not in ("go", "sage"):
            raise SystemExit(f"{path}:{r['_line']}: correlator {r['correlator']!r}")
        for k in ("ablation", "findings_from", "sage_variant"):
            r[k] = "" if r[k] in ("", "-") else r[k]
        if r["ablation"].startswith(DROP):
            src = r["ablation"][len(DROP):]
            if src != "PATH_FLOW" or r["correlator"] != "go":
                raise SystemExit(f"{path}:{r['_line']}: only a go pass may drop PATH_FLOW (No-OffNode), "
                                 f"not {r['ablation']!r}")
        elif r["ablation"]:
            from mtcore.orchestrator import ablations as AB
            try:
                AB.validate([r["ablation"]])
            except ValueError as e:
                raise SystemExit(f"{path}:{r['_line']}: {e}")
        r["params"] = main_params if r["params"] in ("@main", "") else os.path.join(REPO, r["params"])
        r["conditions"] = [c for c in r["conditions"].split(",") if c]
        if r["correlator"] == "sage" and r["findings_from"] not in names:
            raise SystemExit(f"{path}:{r['_line']}: sage pass needs an earlier go pass, not {r['findings_from']!r}")
        if r["name"] == LIVE_PASS or r["name"] in names:
            raise SystemExit(f"{path}:{r['_line']}: pass name {r['name']!r} reserved or repeated")
        names.add(r["name"])
    return rows


def pass_applies(p, cond):
    return any(fnmatch.fnmatch(cond, pat) for pat in p["conditions"])


def derive_params(main, ablation, work):
    """main's parameter file with orchestrator.ablations = [ablation] and nothing else changed (as the
    frozen fit-ri-on-no_<x>.K10.yaml files were made); the models folder is copied beside it, since
    model paths are relative to the parameter file."""
    from mtcore.orchestrator import ablations as AB
    AB.validate([ablation])
    with open(main, encoding="utf-8") as fh:
        text = fh.read()
    old = "  ablations: []\n"
    if text.count(old) != 1:
        raise SystemExit(f"{main}: expected exactly one '  ablations: []' line")
    new = text.replace(old, f"  ablations:\n  - {ablation}\n")
    d = os.path.join(work, "params", ablation)
    os.makedirs(d, exist_ok=True)
    out = os.path.join(d, os.path.basename(main))
    if not os.path.exists(out) or open(out, encoding="utf-8").read() != new:
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new)
    models = os.path.join(os.path.dirname(main), "models")
    if os.path.isdir(models) and not os.path.isdir(os.path.join(d, "models")):
        shutil.copytree(models, os.path.join(d, "models"))
    from mtcore.orchestrator.params import OrchParams
    if list(OrchParams.load(out).ablations) != [ablation]:
        raise SystemExit(f"{out}: ablation switch not read back")
    return out


def stamp(params):
    """score_pilot.py's detection stamp, so its score stage accepts a live output."""
    return {"params_sha256": sha256_file(params), "code": code_commit(), "no_ml": False, "drop_source": None}


# --- run selection ---------------------------------------------------------------------------
def select_runs(a):
    """--runs FILE[:key] (a list), or --select N:SALT: per observability profile (readable
    manifest), the N runs with the smallest sha256(SALT|run_id). Truth-free and results-free."""
    if a.runs:
        return PL.load_runs(a.runs)
    n, _, salt = a.select.partition(":")
    groups = {}
    for r in sorted(os.listdir(a.data)):
        mf = os.path.join(a.data, r, "manifest.json")
        if not os.path.exists(mf):
            continue
        prof = json.load(open(mf, encoding="utf-8")).get("observability_profile", "?")
        groups.setdefault(prof, []).append(r)
    out = []
    for prof in sorted(groups):
        out += sorted(groups[prof], key=lambda r: hashlib.sha256(f"{salt}|{r}".encode()).hexdigest())[:int(n)]
    return sorted(out)


# --- transport ---------------------------------------------------------------------------------
class Transport:
    def __init__(self, a, ctl=None):
        self.a, self.ctl = a, ctl
        self.free = list(range(a.slots))
        self.cv = threading.Condition()
        self.seq = 0

    def slot(self):
        with self.cv:
            while not self.free:
                self.cv.wait()
            return self.free.pop(0)

    def release(self, s):
        with self.cv:
            self.free.append(s)
            self.cv.notify()

    def dispatch(self, job, plan_dir, cert_dir):
        a = self.a
        if self.ctl is None:                            # local: the sender runs here
            cond, run = job["condition"], job["run"]
            return send_job(job, os.path.join(base_root(a, job.get("base_variant")), run), plan_dir, cert_dir,
                            os.path.join(a.work, "sendwork", cond, run), os.path.join(a.faultlogs, cond, run))
        jid = job["job_id"]
        self.ctl.put_tree(f"jobs/{jid}/certs", cert_dir)
        self.ctl.put_tree(f"jobs/{jid}/plans", plan_dir)
        self.ctl.put_json(f"jobs/{jid}/job.json", job)             # last: marks the job ready
        deadline = time.time() + job["timeout_s"]
        while time.time() < deadline:
            done = self.ctl.get_json(f"done/{jid}.json")
            if done is not None:
                return done
            time.sleep(3)
        return {"ok": False, "error": f"sender did not finish job {jid} in {job['timeout_s']} s"}

    def job(self, cond, run):
        a = self.a
        out = os.path.join(a.work, "received", cond["condition"], run)
        tj = os.path.join(out, "transport.json")
        plan_dir = os.path.join(a.work, "plans", cond["condition"], run)
        plan_meta = json.load(open(os.path.join(plan_dir, "meta.json"), encoding="utf-8"))
        plan_hash = hashlib.sha256(json.dumps(plan_meta, sort_keys=True).encode()).hexdigest()
        if os.path.exists(tj):
            old = json.load(open(tj, encoding="utf-8"))
            if old.get("ok") and old.get("plan_hash") == plan_hash:
                return "cached"
        live = cond["mode"] == "live"
        variant = cond.get("base_variant")
        base = json.load(open(os.path.join(base_root(a, variant), run, "base.json"), encoding="utf-8"))
        s = self.slot()
        t0 = time.time()
        slot = Slot(os.path.join(a.work, "slots", f"s{s}"), s, a.listen_host, a.advertise_host)
        rec = {"condition": cond["condition"], "run": run, "slot": s, "mode": cond["mode"], "pace": cond["pace"],
               "plan_hash": plan_hash, "code": code_commit()}
        try:
            slot.up()
            certs = slot.certs([n["node_id"] for n in base["nodes"]])
            rx = slot.start_receiver(a.live_max_idle if live else a.fast_max_idle)
            if live:
                slot.start_pipeline(a.main_params, idle_exit_s=a.idle_exit_s)
            with self.cv:
                self.seq += 1
                attempt = self.seq
            span = (base["stream_end_ns"] - base["stream_start_ns"]) / 1e9
            job = {"job_id": f"{cond['condition']}__{run}__{int(t0)}_{attempt}", "condition": cond["condition"],
                   "run": run, "receiver": rx, "server_name": a.advertise_host, "pace": cond["pace"],
                   "boot": f"boot-{cond['condition']}-{run[:8]}", "sender": attempt % max(1, a.senders),
                   "timeout_s": int(1800 + (span / cond["pace"] if cond["pace"] > 0 else 0)),
                   "epoch": a.epoch, "base_variant": variant}
            rec["job"] = job
            res = self.dispatch(job, plan_dir, certs)
            rec["sender"] = res
            if live:
                time.sleep(a.settle_s)                       # final heartbeats carry the last watermarks
            slot.stop_receiver()
            if live:
                rec["pipeline_exit"] = slot.wait_pipeline()
                lo = os.path.join(a.work, "detect", cond["condition"], LIVE_PASS, "runs", run)
                os.makedirs(lo, exist_ok=True)
                rec["live_output_lines"] = slot.dump_outputs(os.path.join(lo, "output.jsonl.gz"))
                ok_live = all(c == 0 for c in rec["pipeline_exit"].values())
                with open(os.path.join(lo, "time.json"), "w", encoding="utf-8") as fh:
                    json.dump({"wall_s": round(time.time() - t0, 3), "exit": 0 if ok_live else 1, "mode": "live",
                               "peak_rss_mb": None, "cpu_user_s": None, "cpu_sys_s": None,
                               **stamp(a.main_params)}, fh)
            os.makedirs(os.path.join(out, "shipper"), exist_ok=True)
            rec["received"] = slot.dump_inputs(os.path.join(out, "shipper", "received.jsonl"))
            shutil.copy2(os.path.join(base_root(a, variant), run, "manifest.json"), os.path.join(out, "manifest.json"))
            rec["ok"] = bool(res.get("ok")) and (not live or all(c == 0 for c in rec["pipeline_exit"].values()))
        except Exception as e:                                  # one job's failure must not stop the others
            import traceback
            rec["ok"], rec["error"], rec["traceback"] = False, repr(e), traceback.format_exc()
        finally:
            slot.down(keep=a.keep_slots)
            self.release(s)
        rec["wall_s"] = round(time.time() - t0, 3)
        os.makedirs(out, exist_ok=True)
        with open(tj + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(rec, fh, indent=2, sort_keys=True)
        os.replace(tj + ".tmp", tj)
        return "ok" if rec["ok"] else f"FAILED ({rec.get('error') or rec.get('sender', {}).get('exit')})"


# --- stages ---------------------------------------------------------------------------------------
def base_root(a, variant=None):
    """W/base, or W/base-<variant> for an identity variant (mtcore.exp3.base --variant)."""
    return os.path.join(a.work, f"base-{variant}" if variant else "base")


def base_ready(a, r, variant=None):
    p = os.path.join(base_root(a, variant), r, "base.json")
    if not os.path.exists(p):
        return False
    meta = json.load(open(p, encoding="utf-8"))
    if meta.get("variant") != (variant or None):
        return False
    return all(os.path.exists(os.path.join(base_root(a, variant), r, "nodes", n["file"])) for n in meta["nodes"])


def stage_base(a, runs, variant=None):
    root = base_root(a, variant)
    os.makedirs(root, exist_ok=True)
    for r in runs:
        if not base_ready(a, r, variant):
            mp = os.path.join(root, r, "base.json")
            if os.path.exists(mp):
                os.unlink(mp)                    # node files missing (not synced): export again
            B.export_run(os.path.join(a.data, r), root, variant)
            bad = B.verify_export(os.path.join(root, r))
            if bad:
                raise SystemExit(f"base export of {r} left truth on the sender side: {bad[:3]}")


def stage_plans(a, cond, runs):
    tf = PL.template_path(a.conditions, cond["template"])
    applied, need_missing = [], []
    for r in runs:
        base = json.load(open(os.path.join(base_root(a, cond.get("base_variant")), r, "base.json"),
                              encoding="utf-8"))
        need = None
        if cond["needs"]:
            nc, _, npass = cond["needs"].partition(":")
            need = os.path.join(a.work, "detect", nc, npass, "runs", r, "output.jsonl.gz")
            if not os.path.exists(need) and transport_failed(a, nc, r):
                # 2026-11-17: the needed condition lost this run at transport (exp3-b stopped here),
                # so this run has nothing to suppress against: not applied, recorded in the split.
                need_missing.append(r)
                continue
        m = PL.write_run_plans(tf, base, os.path.join(a.work, "plans", cond["condition"], r), need)
        if m["applied"]:
            applied.append(r)
    if need_missing:
        log(a.work, f"PLANS {cond['condition']}: {len(need_missing)} run(s) not applied, their "
                    f"{cond['needs']} transport failed: {' '.join(need_missing)}")
    os.makedirs(os.path.join(a.work, "splits"), exist_ok=True)
    with open(os.path.join(a.work, "splits", cond["condition"] + ".json"), "w", encoding="utf-8") as fh:
        json.dump({"runs": applied, "not_applied": sorted(set(runs) - set(applied)),
                   "needed_transport_failed": need_missing}, fh, indent=2)
    return applied


def transport_failed(a, cond_name, run):
    """True when received/<cond>/<run>/transport.json records a failed transport."""
    tj = os.path.join(a.work, "received", cond_name, run, "transport.json")
    if not os.path.exists(tj):
        return False
    with open(tj, encoding="utf-8") as fh:
        return json.load(fh).get("ok") is False


def score_pilot_cmd(a, cond, p, stage):
    c = cond["condition"]
    drop = p["ablation"][len(DROP):] if p["ablation"].startswith(DROP) else None
    params = derive_params(p["params"], p["ablation"], a.work) if p["ablation"] and not drop else p["params"]
    cmd = [sys.executable, SCORE_PILOT, "--pilot", os.path.join(a.work, "received", c),
           "--split", os.path.join(a.work, "splits", c + ".json"), "--half", "runs", "--params", params,
           "--out-dir", os.path.join(a.work, "detect", c, p["name"]), "--workers", str(a.workers), "--stage", stage]
    if p["correlator"] == "sage":
        cmd += ["--correlator", "sage", "--findings-from", os.path.join(a.work, "detect", c, p["findings_from"]),
                "--sage-variant", p["sage_variant"] or "ag"]
    if drop:
        cmd += ["--drop-source", drop]           # dropped and declared not shipped at detect; its IDs join the
    if stage == "score":                         # injector's fault log at score (score_pilot.merged_log)
        cmd += ["--truth-root", a.truth_root, "--fault-log-root", os.path.join(a.faultlogs, c)]
    return cmd


def run_cmd(a, cmd, name):
    os.makedirs(os.path.join(a.work, "logs"), exist_ok=True)
    t0 = time.time()
    with open(os.path.join(a.work, "logs", name + ".log"), "w", encoding="utf-8") as fh:
        r = subprocess.run(cmd, cwd=REPO, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    wall = round(time.time() - t0, 1)
    tt = os.path.join(a.work, "timing.tsv")
    with LOCK:
        new = not os.path.exists(tt)
        with open(tt, "a", encoding="utf-8") as fh:
            if new:
                fh.write("step\texit\twall_s\n")
            fh.write(f"{name}\t{r.returncode}\t{wall}\n")
    return r.returncode


def received_files(a, cond, runs, want):
    """Keep each received dump as .jsonl (detection reads it) or .jsonl.gz (stored, synced): the
    dumps are ~0.3 GB per run and condition uncompressed."""
    import gzip
    for r in runs:
        p = os.path.join(a.work, "received", cond, r, "shipper", "received.jsonl")
        if want == "jsonl" and not os.path.exists(p) and os.path.exists(p + ".gz"):
            with gzip.open(p + ".gz", "rb") as src, open(p + ".tmp", "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.replace(p + ".tmp", p)
        elif want == "gz" and os.path.exists(p):
            with open(p, "rb") as src, gzip.open(p + ".gz.tmp", "wb", compresslevel=6) as dst:
                shutil.copyfileobj(src, dst)
            os.replace(p + ".gz.tmp", p + ".gz")
            os.unlink(p)


def stage_detect(a, cond, passes, runs):
    failed = 0
    # 2026-11-17: a run whose transport failed has no received stream; leave it out before detection
    # (as scoring does) instead of failing every pass of the condition on it.
    gone = set(prune_failed_transports(a, cond["condition"]))
    runs = [r for r in runs if r not in gone]
    received_files(a, cond["condition"], runs, "jsonl")
    for p in passes:
        if not pass_applies(p, cond["condition"]):
            continue
        name = f"detect.{cond['condition']}.{p['name']}"
        rc = run_cmd(a, score_pilot_cmd(a, cond, p, "detect"), name)
        log(a.work, f"DETECT {cond['condition']} {p['name']} exit {rc}")
        failed += rc != 0
    if not failed and not a.keep_jsonl:
        received_files(a, cond["condition"], runs, "gz")
    return failed


def prune_failed_transports(a, c):
    """Leave runs whose transport failed out of scoring: a run with received/<c>/<run>/transport.json
    "ok": false never reached the detectors (2026-11-16: slot setup failed when the random Kafka
    cluster ID started with "-", independent of the run's content). The split keeps them under
    "transport_failed", and the summary's run counts show the difference."""
    sp = os.path.join(a.work, "splits", c + ".json")
    if not os.path.exists(sp):
        return []
    with open(sp, encoding="utf-8") as fh:
        d = json.load(fh)
    gone = []
    for r in d.get("runs", []):
        tj = os.path.join(a.work, "received", c, r, "transport.json")
        if os.path.exists(tj):
            with open(tj, encoding="utf-8") as fh:
                if json.load(fh).get("ok") is False:
                    gone.append(r)
    if gone:
        d["runs"] = [r for r in d["runs"] if r not in gone]
        d["transport_failed"] = sorted(set(d.get("transport_failed", [])) | set(gone))
        with open(sp + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
        os.replace(sp + ".tmp", sp)
        log(a.work, f"TRANSPORT_FAILED {c}: {len(gone)} run(s) left out of detection and scoring: {' '.join(gone)}")
    return gone


def stage_score(a, cond, passes):
    c = cond["condition"]
    os.makedirs(os.path.join(a.work, "scored"), exist_ok=True)
    prune_failed_transports(a, c)
    chk = [sys.executable, "-m", "mtcore.exp3.check", "--base", os.path.join(a.work, "base"),
           "--received", os.path.join(a.work, "received", c), "--faultlogs", os.path.join(a.faultlogs, c),
           "--out", os.path.join(a.work, "scored", c + ".check.json"), "--workers", str(a.workers)]
    rc = subprocess.run(chk, cwd=os.path.join(REPO, "src", "python"), stdin=subprocess.DEVNULL).returncode
    log(a.work, f"CHECK {c} fault-log consistency {'ok' if rc == 0 else 'FAILED'}")
    failed = rc != 0
    todo = [p for p in passes if pass_applies(p, c)]
    if cond["mode"] == "live":
        todo = [{"name": LIVE_PASS, "correlator": "go", "params": a.main_params, "ablation": "",
                 "findings_from": "", "sage_variant": "", "conditions": [c]}] + todo
    for p in todo:
        if not os.path.isdir(os.path.join(a.work, "detect", c, p["name"])):
            log(a.work, f"NOT_RUN {c} {p['name']}: no detection output; not scored")
            continue
        rc = run_cmd(a, score_pilot_cmd(a, cond, p, "score"), f"score.{c}.{p['name']}")
        log(a.work, f"SCORED {c} {p['name']} exit {rc}")
        failed += rc != 0
    return failed


# --- sender role ---------------------------------------------------------------------------------
def sender_loop(a, ctl, fl):
    """Poll the control store for this sender's jobs; ship each; upload its fault logs (truth side,
    never under the detection results) and a done record."""
    busy, skip, lock = set(), set(), threading.Lock()
    pool = ThreadPoolExecutor(max_workers=a.sender_jobs)

    def one(jid):
        try:
            job = ctl.get_json(f"jobs/{jid}/job.json")
            run, cond = job["run"], job["condition"]
            d = os.path.join(a.work, "jobs", jid)
            ctl.get_tree(f"jobs/{jid}/certs", os.path.join(d, "certs"))
            ctl.get_tree(f"jobs/{jid}/plans", os.path.join(d, "plans"))
            variant = job.get("base_variant")
            with lock:
                stage_base(a, [run], variant)
            flog = os.path.join(a.work, "faultlogs", cond, run)
            res = send_job(job, os.path.join(base_root(a, variant), run), os.path.join(d, "plans"),
                           os.path.join(d, "certs"), os.path.join(d, "work"), flog)
            fl.put_tree(f"{cond}/{run}", flog)
            ctl.put_json(f"done/{jid}.json", res)
            log(a.work, f"SENT {jid} ok={res['ok']} {res['wall_s']}s")
        except Exception as e:
            ctl.put_json(f"done/{jid}.json", {"ok": False, "error": repr(e)})
            log(a.work, f"SEND FAILED {jid}: {e!r}")
        finally:
            with lock:
                busy.discard(jid)

    log(a.work, f"SENDER {a.sender_index} of {a.senders} polling {a.ctl}")
    while ctl.get_json("stop.json") is None:
        # A job of an earlier analysis start (before a resume) has no receiver any more: skip it.
        epoch = (ctl.get_json("epoch.json") or {}).get("epoch")
        for jid in ctl.list_jobs():
            with lock:
                if jid in busy or os.path.exists(os.path.join(a.work, "jobs", jid, "sent")):
                    continue
            if jid in skip:
                continue
            job = ctl.get_json(f"jobs/{jid}/job.json")
            if job is None:
                continue
            if epoch is None or job.get("epoch", 0) > epoch:
                continue                       # posted after the epoch we read: look again next round
            if (job.get("sender") != a.sender_index or job.get("epoch") != epoch
                    or ctl.get_json(f"done/{jid}.json") is not None):
                skip.add(jid)                  # another sender's, an old start's, or finished: never ours
                continue
            with lock:
                busy.add(jid)
            os.makedirs(os.path.join(a.work, "jobs", jid), exist_ok=True)
            open(os.path.join(a.work, "jobs", jid, "sent"), "w").close()
            pool.submit(one, jid)
        time.sleep(3)
    pool.shutdown(wait=True)
    log(a.work, "SENDER stop")


# --- main ------------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", choices=("local", "analysis", "sender", "score"), required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--data", help="readable run folders of the set (heldout/runs/<set>, or development runs)")
    ap.add_argument("--runs", default=None, help="RUNS.json[:key]")
    ap.add_argument("--select", default=None, help="N:SALT, N runs per observability profile (instead of --runs)")
    ap.add_argument("--conditions", default=os.path.join(REPO, "experiments", "exp3", "configs", "conditions.tsv"))
    ap.add_argument("--passes", default=os.path.join(REPO, "experiments", "exp3", "configs", "passes.tsv"))
    ap.add_argument("--main-params", default=None, help="the set's frozen GO/agent parameter file (@main)")
    ap.add_argument("--only", default="", help="comma-separated condition patterns")
    ap.add_argument("--max-tier", type=int, default=None)
    ap.add_argument("--stages", default="base,plans,transport,detect")
    ap.add_argument("--slots", type=int, default=3)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--senders", type=int, default=1)
    ap.add_argument("--sender-index", type=int, default=0)
    ap.add_argument("--sender-jobs", type=int, default=4, help="sender role: jobs at once")
    ap.add_argument("--ctl", default=None, help="control store (dir or s3://...) for --role analysis/sender")
    ap.add_argument("--faultlogs", default=None, help="fault-log root (truth side; default W/faultlogs)")
    ap.add_argument("--truth-root", default=None, help="score role: <run_id>/restricted per run")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--advertise-host", default="127.0.0.1")
    ap.add_argument("--fast-max-idle", default="1h", help="receiver -max-idle for pace-0 replays (wall-clock idleness is meaningless there)")
    ap.add_argument("--live-max-idle", default="10s", help="receiver -max-idle for live replays (frozen max_idle_s)")
    ap.add_argument("--settle-s", type=float, default=30.0)
    ap.add_argument("--idle-exit-s", type=float, default=30.0)
    ap.add_argument("--keep-slots", action="store_true")
    ap.add_argument("--keep-jsonl", action="store_true", help="keep received dumps uncompressed after detection")
    a = ap.parse_args(argv)
    a.work = os.path.abspath(a.work)
    os.makedirs(a.work, exist_ok=True)
    a.faultlogs = a.faultlogs or os.path.join(a.work, "faultlogs")
    if not a.faultlogs.startswith("s3://"):
        a.faultlogs = os.path.abspath(a.faultlogs)
    if a.main_params:
        a.main_params = os.path.abspath(a.main_params)
    if a.data:
        a.data = os.path.abspath(a.data)

    if a.role == "sender":
        if not a.ctl:
            ap.error("--role sender needs --ctl")
        sender_loop(a, make_ctl(a.ctl), make_ctl(a.faultlogs))
        return 0

    conds = PL.load_conditions(a.conditions, a.max_tier, [p for p in a.only.split(",") if p])
    for c in conds:
        c["base_variant"] = PL.template_base_variant(PL.template_path(a.conditions, c["template"]))
    names = [c["condition"] for c in conds]
    for c in conds:
        if c["needs"] and c["needs"].split(":")[0] not in names[:names.index(c["condition"])]:
            raise SystemExit(f"condition {c['condition']} needs {c['needs']}: list it earlier (and run it)")
    if not a.main_params:
        ap.error("--main-params is required")
    passes = load_passes(a.passes, a.main_params)
    stages = set(a.stages.split(","))

    if a.role == "score":
        if not a.truth_root:
            ap.error("--role score needs --truth-root")
        a.truth_root = os.path.abspath(a.truth_root)
        if a.data:                               # the consistency check needs the base streams
            stage_base(a, PL.load_runs(a.runs or os.path.join(a.work, "runs.json")))
        ran = [c for c in conds if os.path.isdir(os.path.join(a.work, "detect", c["condition"]))]
        for c in conds:
            if c not in ran:
                log(a.work, f"NOT_RUN {c['condition']}: no detection output; not scored")
        conds = ran
        failed = sum(stage_score(a, c, passes) for c in conds)
        from mtcore.exp3.summary import write_summary
        write_summary(a.work, [c["condition"] for c in conds],
                      None if a.faultlogs.startswith("s3://") else a.faultlogs)     # PCC reads the fault logs
        log(a.work, "ALL_SCORED" if not failed else f"SCORE_FAILED {failed}")
        return 1 if failed else 0

    if a.role == "analysis" and not a.ctl:
        ap.error("--role analysis needs --ctl (use --role local for one machine)")
    if a.faultlogs.startswith("s3://") and a.role == "local":
        ap.error("--role local keeps fault logs on this machine")
    runs = select_runs(a)
    with open(os.path.join(a.work, "runs.json"), "w", encoding="utf-8") as fh:
        json.dump({"runs": runs, "select": a.select, "from": a.runs}, fh, indent=2)
    log(a.work, f"START role {a.role}, {len(runs)} runs, {len(conds)} conditions, code {code_commit()}")
    if "base" in stages:
        stage_base(a, runs)
        log(a.work, f"BASE {len(runs)} runs exported (no truth)")
        for v in sorted({c["base_variant"] for c in conds if c["base_variant"]}):
            stage_base(a, runs, v)
            log(a.work, f"BASE {v} {len(runs)} runs exported (identity variant, no truth)")
    a.epoch = int(time.time())
    tr = Transport(a, make_ctl(a.ctl) if a.role == "analysis" else None)
    if tr.ctl is not None:
        tr.ctl.put_json("epoch.json", {"epoch": a.epoch})      # senders take only this start's jobs
    failed = 0
    for c in conds:
        cname = c["condition"]
        if "plans" in stages:
            applied = stage_plans(a, c, runs)
            log(a.work, f"PLANS {cname}: applies to {len(applied)} of {len(runs)} runs")
        else:
            applied = json.load(open(os.path.join(a.work, "splits", cname + ".json")))["runs"]
        if "transport" in stages and applied:
            with ThreadPoolExecutor(max_workers=a.slots) as pool:
                for r, st in zip(applied, pool.map(lambda r: tr.job(c, r), applied)):
                    log(a.work, f"TRANSPORT {cname} {r} {st}")
                    failed += st.startswith("FAILED")
        if "detect" in stages and applied:
            failed += stage_detect(a, c, passes, applied)
    if a.role == "analysis":
        tr.ctl.put_json("stop.json", {"t": time.time()})
    log(a.work, "ALL_DONE" if not failed else f"FAILED_STEPS {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
