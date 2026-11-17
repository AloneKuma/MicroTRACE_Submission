"""Integration tests T9-T12 for the Experiment 3 fault injector
(spec/faults/fault-contract.md): real faultinject, shipper and receiver
processes and the dev Kafka. Skipped when Kafka is not reachable."""
import datetime
import os
import re
import socket
import uuid

import pytest

from mtcore.kafka_topics import DEV_CONFIG, ensure_topics
from microtrace.v0 import common_pb2, envelope_pb2
from shipping_rig import (KafkaWindow, Receiver, Shipper, build_binaries, faultinject, make_certs,
                          norm_line, read_fault_log, stop_all, write_lines, write_plan)

BOOTSTRAP = os.environ.get("MT_KAFKA", "127.0.0.1:9092")
WATCH = ["norm.events.v0", "source.completeness.v0"]
T0 = datetime.datetime(2026, 10, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _kafka_up():
    host, port = BOOTSTRAP.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    build_binaries()
    _, _, _, problems = ensure_topics(BOOTSTRAP, DEV_CONFIG)
    assert not problems, problems
    return make_certs(str(tmp_path_factory.mktemp("certs")), ["node-1", "node-2"])


@pytest.fixture(autouse=True)
def _stop_processes():
    yield
    stop_all()


def ship(tmp, certs, node, lines, extra=(), rx_extra=()):
    """Ship lines from one node through a fresh receiver; return (records, boot, receiver)."""
    window = KafkaWindow(BOOTSTRAP, WATCH)
    rx = Receiver(tmp, certs, BOOTSTRAP, extra=rx_extra).start()
    boot = uuid.uuid4().hex
    path = write_lines(os.path.join(tmp, f"in-{boot[:6]}.jsonl"), lines)
    sh = Shipper(tmp, certs, rx.port, node, boot=boot, extra=list(extra)).start(path)
    try:
        assert sh.wait() == 0, sh.log()
        return window.read(), boot, rx
    finally:
        window.close()


def events(recs, prefix):
    return [r for r in recs if r["topic"] == "norm.events.v0" and r["env"].kind == envelope_pb2.NORMALIZED_EVENT
            and r["env"].logical_id.startswith(prefix + "-")]


def losses(recs, node, boot):
    scope = f"node={node}/boot={boot}/lane=NORMAL"
    out = set()
    for r in recs:
        sc = r["env"].source_completeness
        if r["topic"] == "source.completeness.v0" and sc.scope == scope:
            assert sc.gaps[0].reason == common_pb2.DROPPED_BEFORE
            a, b = map(int, re.search(r"transport seq (\d+)-(\d+)", sc.gaps[0].detail).groups())
            out |= set(range(a, b + 1))
    return out


# ---------------------------------------------------------------- T9

@pytest.mark.parametrize("rate", [0.0, 0.10, 0.40])
def test_t9_transit_loss_exact_reported_reproducible(certs, tmp_path, rate):
    n = 5000
    prefix = f"t9-{int(rate * 100)}"
    lines = [norm_line("node-1", prefix, i, T0) for i in range(1, n + 1)]
    plan = write_plan(str(tmp_path / "plan.yaml"), 99, [{"id": "loss", "kind": "loss", "stage": "transit", "rate": rate}])
    runs = []
    for k in range(2):  # the same plan and base stream twice
        flog = str(tmp_path / f"faults-{k}.jsonl")
        recs, boot, _ = ship(str(tmp_path), certs, "node-1", lines,
                             extra=["-faults", plan, "-fault-log", flog])
        header, entries = read_fault_log(flog)
        assert header["stage"] == "transit" and header["seed"] == 99
        dropped_ids = {e["logical_id"] for e in entries}
        dropped_seqs = {e["seq"] for e in entries}
        delivered = {r["env"].logical_id for r in events(recs, prefix)}
        everything = {f"{prefix}-{i}" for i in range(1, n + 1)}
        assert delivered == everything - dropped_ids, "delivered set is not base minus the logged drops"
        assert len(events(recs, prefix)) == len(delivered), "duplicates delivered"
        assert losses(recs, "node-1", boot) == dropped_seqs, "completeness gaps differ from the dropped sequences"
        runs.append(dropped_ids)
        stop_all()
    assert runs[0] == runs[1], "same seed and stream gave a different selection"
    got = len(runs[0]) / n
    print(f"T9: rate {rate:.2f}: dropped {len(runs[0])} of {n} ({got:.3f}), reported exactly, reproducible")
    assert abs(got - rate) < 0.03


# ---------------------------------------------------------------- T10

def test_t10_source_stage_faults(certs, tmp_path):
    n, prefix = 100, f"t10-{uuid.uuid4().hex[:6]}"
    fam = lambda i: "file.read" if i % 2 else "net.connect"  # noqa: E731
    lines = [norm_line("node-2", prefix, i, T0, family=fam(i)) for i in range(1, n + 1)]
    ts = lambda s: (T0 + datetime.timedelta(seconds=s)).isoformat().replace("+00:00", "Z")  # noqa: E731
    plan = write_plan(str(tmp_path / "plan.yaml"), 5, [
        {"id": "stop", "kind": "stop", "stage": "source", "after": ts(90)},
        {"id": "out", "kind": "outage", "stage": "source", "select": {"from": ts(20), "to": ts(30)}},
        {"id": "blind", "kind": "blind", "stage": "source", "after": ts(60), "select": {"event_families": ["file.read"]}},
        {"id": "late", "kind": "delay", "stage": "source", "delay": "5s", "select": {"logical_ids": [f"{prefix}-10"]}},
        {"id": "skew", "kind": "skew", "stage": "source", "offset": "-250ms", "declare_uncertainty": True},
    ])
    base = write_lines(str(tmp_path / "base.jsonl"), lines)
    faulted = faultinject(plan, base, str(tmp_path / "faulted.jsonl"), str(tmp_path / "src-log.jsonl"), "node-2")
    import json
    faulted_lines = [json.loads(x) for x in open(faulted) if x.strip()]
    recs, boot, rx = ship(str(tmp_path), certs, "node-2", faulted_lines,
                          rx_extra=["-heartbeat", "200ms", "-max-idle", "2s"])
    tail = KafkaWindow(BOOTSTRAP, ["source.completeness.v0"])  # for the idle record after stop

    want = [i for i in range(1, n + 1)
            if not (i >= 90 or 20 <= i < 30 or (i >= 60 and i % 2))]
    got = events(recs, prefix)
    got_ids = [r["env"].logical_id for r in got]
    assert sorted(got_ids) == sorted(f"{prefix}-{i}" for i in want), "kept set differs"
    for r in got:  # skew: both times shifted by exactly -250 ms, uncertainty declared
        i = int(r["env"].logical_id.rsplit("-", 1)[1])
        t = r["env"].normalized_event.time
        expect = T0 + datetime.timedelta(seconds=i, milliseconds=-250)
        assert t.event_time.ToDatetime(tzinfo=datetime.timezone.utc) == expect
        assert t.source_time.ToDatetime(tzinfo=datetime.timezone.utc) == expect
        assert t.clock_uncertainty_ns == 250_000_000
    pos = {lid: k for k, lid in enumerate(got_ids)}  # one partition: arrival order
    assert pos[f"{prefix}-14"] < pos[f"{prefix}-10"] < pos[f"{prefix}-15"], "delayed record did not arrive late"
    assert not losses(recs, "node-2", boot), "source-stage drops must not produce transport gaps"
    _, entries = read_fault_log(str(tmp_path / "src-log.jsonl"))
    dropped = {e["logical_id"] for e in entries if e["action"] == "dropped_unreported"}
    assert dropped == {f"{prefix}-{i}" for i in range(1, n + 1)} - set(got_ids)
    assert {e["fault_id"] for e in entries if e["action"] == "shifted"} == {"skew"}

    # stop: the node went silent and the receiver reported it idle.
    import time
    time.sleep(3)
    idle = [r for r in tail.read(timeout=60) if r["env"].source_completeness.scope == f"node=node-2/boot={boot}"]
    tail.close()
    rx.stop()
    assert idle and idle[0]["env"].source_completeness.gaps[0].reason == common_pb2.SOURCE_IDLE
    print(f"T10: {len(got)} of {n} kept; outage, blind and stop dropped {len(dropped)} unreported; "
          "skew -250 ms declared; delayed record arrived after ev-14")


# ---------------------------------------------------------------- T11

def test_t11_contradiction_suppressed_in_transit(certs, tmp_path):
    n, prefix = 100, f"t11-{uuid.uuid4().hex[:6]}"
    lines = [norm_line("node-1", prefix, i, T0) for i in range(1, n + 1)]
    target = f"{prefix}-50"
    plan = write_plan(str(tmp_path / "plan.yaml"), 1,
                      [{"id": "hide", "kind": "suppress", "stage": "transit", "select": {"logical_ids": [target]}}])
    flog = str(tmp_path / "faults.jsonl")
    recs, boot, _ = ship(str(tmp_path), certs, "node-1", lines, extra=["-faults", plan, "-fault-log", flog])
    ids = {r["env"].logical_id for r in events(recs, prefix)}
    assert target not in ids and len(ids) == n - 1
    assert losses(recs, "node-1", boot) == {50}, "the suppressed record's sequence is not reported"
    _, entries = read_fault_log(flog)
    assert [(e["logical_id"], e["seq"], e["action"]) for e in entries] == [(target, 50, "dropped_reported")]


# ---------------------------------------------------------------- T12

def test_t12_forged_records_arrive_and_are_logged(certs, tmp_path):
    n, prefix = 30, f"t12-{uuid.uuid4().hex[:6]}"
    lines = [norm_line("node-1", prefix, i, T0) for i in range(1, n + 1)]
    after = (T0 + datetime.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    plan = write_plan(str(tmp_path / "plan.yaml"), 1,
                      [{"id": "fake", "kind": "forge", "stage": "source", "after": after, "count": 4}])
    base = write_lines(str(tmp_path / "base.jsonl"), lines)
    log = str(tmp_path / "src-log.jsonl")
    faulted = faultinject(plan, base, str(tmp_path / "faulted.jsonl"), log, "node-1")
    import json
    recs, _, _ = ship(str(tmp_path), certs, "node-1", [json.loads(x) for x in open(faulted) if x.strip()])
    forged = {r["env"].logical_id for r in recs if r["topic"] == "norm.events.v0"
              and r["env"].logical_id.startswith("forged-fake-")}
    _, entries = read_fault_log(log)
    logged = {e["logical_id"] for e in entries if e["action"] == "forged"}
    assert forged == logged == {f"forged-fake-{k}" for k in range(1, 5)}
    assert len(events(recs, prefix)) == n, "originals must still arrive"
