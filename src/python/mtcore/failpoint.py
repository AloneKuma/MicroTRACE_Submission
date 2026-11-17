"""Named failpoints for crash injection (Exp. 5 part A).

    failpoint.hit("go.after_flush_before_commit", state=lambda: {"open_groups": n},
                  require=lambda: n > 0)

Compiled into every run, including the no-crash reference; a disabled
failpoint costs one string comparison. Environment (read at import; tests
call `configure`):

- MT_FAILPOINT       name of the one failpoint to arm (unset: all disabled)
- MT_FAILPOINT_NTH   fire on the n-th qualifying hit (default 1)
- MT_FAILPOINT_MODE  "exit" (default) or "pause"
- MT_FAILPOINT_LOG   append one JSON line per firing here, fsynced
- MT_FAILPOINT_RELEASE  pause mode: block until this file exists
- MT_FAILPOINT_AFTER    hits count only once this file exists (the crash
                        runner creates it after a history prefill, so the
                        kill lands in the measured part)

A hit qualifies when `require` is absent or true, so with MT_FAILPOINT_NTH=n
the kill lands on the n-th hit that had open state. On firing, the log line
{"failpoint", "hit", "pid", "time_ns", "mode", "state"} is written (and
fsynced) before anything else; exit mode then calls os._exit(137): no
flush, no commit, no atexit. Pause mode logs, blocks until the release file
appears, logs {"released": true, ...} and returns; it fires once.
`state` and `require` may be values or callables; callables run only for
the armed name. The Go receiver reads the same variables.
"""
import json
import os
import sys
import time

EXIT_CODE = 137

# The interruption points of evaluation-plan.md Exp. 5 part A. Not enforced:
# any name may be armed; these are the names the harness schedules.
POINTS = (
    "receiver.after_kafka_ack_before_seq_store",
    "receiver.after_store_before_ack",
    "receiver.mid_batch",
    "agent.window_open",
    "agent.after_finding_before_commit",
    "go.after_feed_before_advance",
    "go.after_produce_before_flush",
    "go.after_flush_before_commit",
    "go.mid_group_records",
    "go.sealing_pairs_pending",
    "tgs.mid_transaction",
)

_armed = None
_nth = 1
_mode = "exit"
_log = None
_release = None
_after = None
_count = 0
_done = False


def configure(env=None):
    """(Re)read the settings from `env` (default os.environ); resets the count."""
    global _armed, _nth, _mode, _log, _release, _after, _count, _done
    env = os.environ if env is None else env
    _armed = env.get("MT_FAILPOINT") or None
    _nth = int(env.get("MT_FAILPOINT_NTH") or 1)
    _mode = env.get("MT_FAILPOINT_MODE") or "exit"
    if _mode not in ("exit", "pause"):
        raise ValueError(f"MT_FAILPOINT_MODE must be exit or pause, not {_mode!r}")
    if _nth < 1:
        raise ValueError("MT_FAILPOINT_NTH must be >= 1")
    _log = env.get("MT_FAILPOINT_LOG") or None
    _release = env.get("MT_FAILPOINT_RELEASE") or None
    _after = env.get("MT_FAILPOINT_AFTER") or None
    if _mode == "pause" and _armed and not _release:
        raise ValueError("pause mode needs MT_FAILPOINT_RELEASE")
    _count, _done = 0, False


def armed():
    return _armed


def hit(name, state=None, require=None):
    """Fire if `name` is armed and this is its n-th qualifying hit."""
    if name != _armed:
        return
    _fire(name, state, require)


def _value(v):
    return v() if callable(v) else v


def _fire(name, state, require):
    global _count, _done, _after
    if _done:
        return
    if _after is not None:
        if not os.path.exists(_after):
            return
        _after = None                    # seen once; no more checks
    if require is not None and not _value(require):
        return
    _count += 1
    if _count != _nth:
        return
    _done = True
    entry = {"failpoint": name, "hit": _count, "pid": os.getpid(), "time_ns": time.time_ns(),
             "mode": _mode, "state": _value(state)}
    _write(entry)
    if _mode == "exit":
        os._exit(EXIT_CODE)
    while not os.path.exists(_release):
        time.sleep(0.01)
    _write({**entry, "released": True, "time_ns": time.time_ns()})


def _write(entry):
    line = (json.dumps(entry, sort_keys=True, default=str) + "\n").encode("utf-8")
    if _log is None:
        os.write(sys.stderr.fileno(), line)
        return
    fd = os.open(_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def read_log(path):
    """Entries of a failpoint log, oldest first ([] if absent)."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


configure()
