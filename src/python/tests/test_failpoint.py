"""Failpoints: disabled is a no-op, the n-th qualifying hit fires, the log
line is on disk before the process dies, pause mode blocks until released."""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from mtcore import failpoint

PY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def reset():
    yield
    failpoint.configure({})


def child(env, body):
    """Run `body` in a fresh interpreter with the failpoint variables set."""
    full = {**os.environ, **env, "PYTHONPATH": PY}
    code = "from mtcore import failpoint\n" + body
    return subprocess.run([sys.executable, "-c", code], env=full, capture_output=True, text=True, timeout=60)


def test_disabled_is_a_no_op():
    failpoint.configure({})
    for _ in range(1000):
        failpoint.hit("go.after_flush_before_commit", state=lambda: 1 / 0, require=lambda: 1 / 0)
    assert failpoint.armed() is None


def test_other_names_never_evaluate_their_callables():
    failpoint.configure({"MT_FAILPOINT": "go.after_feed_before_advance"})
    failpoint.hit("go.after_flush_before_commit", state=lambda: 1 / 0, require=lambda: 1 / 0)


def test_bad_settings_are_rejected():
    with pytest.raises(ValueError):
        failpoint.configure({"MT_FAILPOINT": "x", "MT_FAILPOINT_MODE": "boom"})
    with pytest.raises(ValueError):
        failpoint.configure({"MT_FAILPOINT": "x", "MT_FAILPOINT_NTH": "0"})
    with pytest.raises(ValueError):
        failpoint.configure({"MT_FAILPOINT": "x", "MT_FAILPOINT_MODE": "pause"})


def test_exit_logs_then_dies_on_the_nth_qualifying_hit(tmp_path):
    log = tmp_path / "fp.log"
    body = ("import sys\n"
            "for i in range(10):\n"
            "    print(i, flush=True)\n"
            "    failpoint.hit('go.after_flush_before_commit', state=lambda: {'open_groups': i},\n"
            "                  require=lambda: i % 2 == 1)\n"
            "print('survived', flush=True)\n")
    r = child({"MT_FAILPOINT": "go.after_flush_before_commit", "MT_FAILPOINT_NTH": "3",
               "MT_FAILPOINT_LOG": str(log)}, body)
    assert r.returncode == failpoint.EXIT_CODE
    assert "survived" not in r.stdout
    assert r.stdout.split() == ["0", "1", "2", "3", "4", "5"]     # hits on i = 1, 3, 5
    [entry] = failpoint.read_log(str(log))
    assert entry["failpoint"] == "go.after_flush_before_commit"
    assert entry["hit"] == 3 and entry["state"] == {"open_groups": 5} and entry["mode"] == "exit"
    assert entry["pid"] > 0 and entry["time_ns"] > 0


def test_exit_skips_cleanup(tmp_path):
    body = ("import atexit\n"
            "atexit.register(lambda: print('cleanup', flush=True))\n"
            "failpoint.hit('agent.window_open')\n")
    r = child({"MT_FAILPOINT": "agent.window_open", "MT_FAILPOINT_LOG": str(tmp_path / "l")}, body)
    assert r.returncode == failpoint.EXIT_CODE and "cleanup" not in r.stdout


def test_without_a_log_the_line_goes_to_stderr():
    r = child({"MT_FAILPOINT": "tgs.mid_transaction"}, "failpoint.hit('tgs.mid_transaction', state=7)\n")
    assert r.returncode == failpoint.EXIT_CODE
    assert json.loads(r.stderr.strip())["state"] == 7


def test_unarmed_child_runs_to_completion(tmp_path):
    r = child({"MT_FAILPOINT": ""}, "failpoint.hit('agent.window_open')\nprint('ok')\n")
    assert r.returncode == 0 and r.stdout.strip() == "ok"


def test_pause_blocks_until_released_and_fires_once(tmp_path):
    log, release = tmp_path / "fp.log", tmp_path / "go"
    failpoint.configure({"MT_FAILPOINT": "gre.check_to_submit", "MT_FAILPOINT_MODE": "pause",
                         "MT_FAILPOINT_LOG": str(log), "MT_FAILPOINT_RELEASE": str(release)})
    passed = []

    def worker():
        failpoint.hit("gre.check_to_submit", state={"attempt": "a1"})
        passed.append(1)
        failpoint.hit("gre.check_to_submit")          # already fired: returns at once
        passed.append(2)

    t = threading.Thread(target=worker)
    t.start()
    deadline = time.time() + 10
    while not failpoint.read_log(str(log)) and time.time() < deadline:
        time.sleep(0.01)
    time.sleep(0.1)
    assert passed == [] and t.is_alive()
    release.write_text("")
    t.join(10)
    assert passed == [1, 2]
    first, second = failpoint.read_log(str(log))
    assert first["state"] == {"attempt": "a1"} and "released" not in first
    assert second["released"] is True and second["time_ns"] >= first["time_ns"]


def test_hits_before_the_after_file_exists_do_not_count(tmp_path):
    """MT_FAILPOINT_AFTER: the crash runner arms a point for the measured part
    only, after a history prefill (Exp. 5 history sweep)."""
    after = tmp_path / "armed"
    body = ("import pathlib, sys\n"
            f"after = pathlib.Path({str(after)!r})\n"
            "for i in range(6):\n"
            "    print(i, flush=True)\n"
            "    if i == 3:\n"
            "        after.touch()\n"
            "    failpoint.hit('go.after_flush_before_commit', state=i)\n")
    r = child({"MT_FAILPOINT": "go.after_flush_before_commit", "MT_FAILPOINT_NTH": "2",
               "MT_FAILPOINT_AFTER": str(after), "MT_FAILPOINT_LOG": str(tmp_path / "fp.log")}, body)
    assert r.returncode == failpoint.EXIT_CODE
    assert r.stdout.split() == ["0", "1", "2", "3", "4"]          # counted hits: i = 3, 4
    [entry] = failpoint.read_log(str(tmp_path / "fp.log"))
    assert entry["hit"] == 2 and entry["state"] == 4
