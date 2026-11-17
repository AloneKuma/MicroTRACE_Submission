"""Helpers for the shipping integration tests: build and run the Go
receiver and shipper, cut connections, and read back what reached Kafka."""
import json
import os
import signal
import socket
import subprocess
import threading
import time
import uuid

from confluent_kafka import TIMESTAMP_LOG_APPEND_TIME, Consumer, KafkaError, KafkaException, TopicPartition
from google.protobuf import json_format

from mtcore import REPO
from microtrace.v0 import common_pb2, ebpf_pb2, envelope_pb2, normalized_pb2

# Every process a test starts, so teardown can stop it even after a failure.
RUNNING = []

MT_DEV = os.environ.get("MT_DEV", os.path.expanduser("~/microtrace-dev"))
BIN = os.environ.get("MT_BIN") or os.path.join(MT_DEV, "bin")   # MT_BIN: a private build
GO_DIR = os.path.join(REPO, "src", "go")
TOPICS_YAML = os.path.join(REPO, "spec", "kafka", "topics.yaml")


def stop_all():
    while RUNNING:
        p = RUNNING.pop()
        if p.poll() is None:
            p.send_signal(signal.SIGKILL)
            p.wait()


def build_binaries():
    os.makedirs(BIN, exist_ok=True)
    for name in ("receiver", "shipper", "devcerts", "faultinject"):
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), f"./cmd/{name}"],
                       cwd=GO_DIR, check=True, capture_output=True, text=True)


def make_certs(directory, nodes):
    subprocess.run([os.path.join(BIN, "devcerts"), "-out", directory, "-nodes", ",".join(nodes),
                    "-hosts", "127.0.0.1,localhost"], check=True, capture_output=True, text=True)
    return directory


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listening on {port}")


class Receiver:
    """The Go receiver. Unless `extra` sets -max-idle, it runs with a 10 min
    max-idle: an idle node's open-ended SOURCE_IDLE gap stays on the shared
    dev topics and covers every later window of that node until an event
    the agents see closes it, so later runs on the same node would abstain.
    Tests of idle reporting pass their own -max-idle."""

    def __init__(self, workdir, certs, bootstrap, port=None, instance=None, extra=(), env=None):
        self.workdir, self.certs, self.bootstrap = workdir, certs, bootstrap
        self.env = env            # extra environment (failpoints), for every start
        self.port = port or free_port()
        self.instance = instance or f"rx-{uuid.uuid4().hex[:8]}"
        self.state = os.path.join(workdir, "rx-state")
        self.extra = list(extra)
        self.proc = None
        self.starts = 0

    def start(self):
        self.starts += 1
        log = open(os.path.join(self.workdir, f"receiver-{self.starts}.log"), "w")
        c = self.certs
        self.proc = subprocess.Popen(
            [os.path.join(BIN, "receiver"), "-listen", f"127.0.0.1:{self.port}",
             "-cert", f"{c}/receiver.crt", "-key", f"{c}/receiver.key", "-ca", f"{c}/ca.crt",
             "-brokers", self.bootstrap, "-topics", TOPICS_YAML, "-state", self.state,
             "-instance", self.instance, "-run-id", "pytest",
             *([] if "-max-idle" in self.extra else ["-max-idle", "10m"]), *self.extra],
            stdout=log, stderr=subprocess.STDOUT, env={**os.environ, **(self.env or {})})
        RUNNING.append(self.proc)
        wait_port(self.port)
        return self

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.kill()

    def log(self):
        out = []
        for i in range(1, self.starts + 1):
            out.append(open(os.path.join(self.workdir, f"receiver-{i}.log")).read())
        return "\n".join(out)


class Shipper:
    def __init__(self, workdir, certs, port, node, boot=None, cert_node=None, extra=()):
        self.workdir, self.certs, self.port, self.node = workdir, certs, port, node
        self.boot = boot or uuid.uuid4().hex
        self.cert_node = cert_node or node
        self.spool = os.path.join(workdir, f"spool-{node}")
        self.stats_path = os.path.join(workdir, f"stats-{node}-{self.boot[:6]}.json")
        self.extra = list(extra)
        self.proc = None
        self.runs = 0

    def start(self, input_path, drain=True):
        self.runs += 1
        self.log_path = os.path.join(self.workdir, f"shipper-{self.node}-{self.runs}.log")
        c, n = self.certs, self.cert_node
        args = [os.path.join(BIN, "shipper"), "-receiver", f"127.0.0.1:{self.port}",
                "-server-name", "127.0.0.1", "-cert", f"{c}/node-cert-{n}.crt",
                "-key", f"{c}/node-cert-{n}.key", "-ca", f"{c}/ca.crt", "-node-id", self.node,
                "-boot-id", self.boot, "-spool", self.spool, "-input", input_path,
                "-stats", self.stats_path, *self.extra]
        if drain:
            args.append("-drain")
        self.proc = subprocess.Popen(args, stdout=open(self.log_path, "w"), stderr=subprocess.STDOUT)
        RUNNING.append(self.proc)
        return self

    def spooled(self):
        """Items sequenced into each lane's spool so far (from the spool itself)."""
        out = subprocess.run([os.path.join(BIN, "shipper"), "-status", "-spool", self.spool,
                              "-boot-id", self.boot], check=True, capture_output=True, text=True).stdout
        return {lane: n - 1 for lane, n in json.loads(out)["next_seq"].items()}

    def wait(self, timeout=180):
        return self.proc.wait(timeout)

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()

    def stats(self):
        return json.load(open(self.stats_path))

    def log(self):
        return open(self.log_path).read()


class CuttingProxy:
    """TCP proxy that drops every open connection at a fixed interval."""

    def __init__(self, target_port, every=0.5):
        self.target, self.every = target_port, every
        self.port = free_port()
        self.accepted = 0
        self._conns, self._lock, self._stop = [], threading.Lock(), threading.Event()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen()
        self._srv.settimeout(0.2)
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._cutter, daemon=True).start()

    def _pipe(self, a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def _accept(self):
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            u = socket.create_connection(("127.0.0.1", self.target))
            with self._lock:
                self.accepted += 1
                self._conns += [c, u]
            threading.Thread(target=self._pipe, args=(c, u), daemon=True).start()
            threading.Thread(target=self._pipe, args=(u, c), daemon=True).start()

    def _cutter(self):
        while not self._stop.wait(self.every):
            with self._lock:
                conns, self._conns = self._conns, []
            for s in conns:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                except OSError:
                    pass

    def stop_cutting(self):
        self._stop.set()

    def close(self):
        self._stop.set()
        self._srv.close()


def ebpf_line(node, boot, i, lane="NORMAL"):
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="node-sensor",
                                kind=envelope_pb2.RAW_EBPF, logical_id=f"ev-{node}-{boot}-{i}")
    env.source = 1  # EBPF
    env.raw_ebpf.CopyFrom(ebpf_pb2.RawEbpfRecord(node_id=node, boot_id=boot, node_seq=i))
    return {"lane": lane, "topic": "raw.ebpf.v0", "key_type": "KEY_NODE", "key_components": [node],
            "envelope": json_format.MessageToDict(env)}


def norm_line(node, prefix, i, t0, source="EBPF", family="net.connect", lane="NORMAL"):
    """A normalized event i seconds after t0 (datetime), logical ID <prefix>-<i>."""
    import datetime
    t = t0 + datetime.timedelta(seconds=i)
    ne = normalized_pb2.NormalizedEvent(event_id=f"{prefix}-{i}", source=common_pb2.Source.Value(source))
    ne.time.event_time.FromDatetime(t)
    ne.time.source_time.FromDatetime(t)
    ne.time.clock_uncertainty_ns = 1000
    if family:
        ne.ebpf.event_family = family
    env = envelope_pb2.Envelope(schema_major=0, schema_minor=1, producer_id="generator",
                                kind=envelope_pb2.NORMALIZED_EVENT, logical_id=f"{prefix}-{i}",
                                source=common_pb2.Source.Value(source))
    env.normalized_event.CopyFrom(ne)
    return {"lane": lane, "topic": "norm.events.v0", "key_type": "KEY_PRIMARY_ENTITY",
            "key_components": ["Pod", f"{node}-pod"], "envelope": json_format.MessageToDict(env)}


def write_plan(path, seed, faults):
    """Write a faultplan.v0 YAML file from a list of fault dicts."""
    import yaml
    yaml.safe_dump({"version": "faultplan.v0", "seed": seed, "faults": faults}, open(path, "w"))
    return path


def faultinject(plan, inp, out, log, node):
    subprocess.run([os.path.join(BIN, "faultinject"), "-plan", plan, "-input", inp, "-output", out,
                    "-log", log, "-node", node], check=True, capture_output=True, text=True)
    return out


def read_fault_log(path):
    lines = [json.loads(x) for x in open(path) if x.strip()]
    assert "header" in lines[0], "fault log has no header"
    return lines[0]["header"], lines[1:]


def write_lines(path, lines):
    with open(path, "w") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")
    return path


# What a client may see while a restarted broker is still taking its partitions back.
RESTARTING = {KafkaError.NOT_LEADER_FOR_PARTITION, KafkaError.LEADER_NOT_AVAILABLE, KafkaError._TRANSPORT,
              KafkaError._TIMED_OUT, KafkaError.UNKNOWN_TOPIC_OR_PART}


class KafkaWindow:
    """Records appended to a set of topics between two snapshots."""

    def __init__(self, bootstrap, topics):
        self.bootstrap, self.topics = bootstrap, topics
        self.c = Consumer({"bootstrap.servers": bootstrap, "group.id": f"pytest-{uuid.uuid4().hex}",
                           "enable.auto.commit": False})
        self.start = self._marks()

    def _marks(self, wait_s=60):
        """End offsets of every watched partition. Right after a broker
        restart (T5) a partition may still be without a leader; that error is
        retriable, so it is retried until wait_s."""
        deadline = time.time() + wait_s
        while True:
            try:
                md = self.c.list_topics(timeout=10)
                out = {}
                for t in self.topics:
                    for p in md.topics[t].partitions:
                        out[(t, p)] = self.c.get_watermark_offsets(TopicPartition(t, p), timeout=10)[1]
                return out
            except KafkaException as e:
                if e.args[0].code() not in RESTARTING or time.time() >= deadline:
                    raise
                time.sleep(1)

    def read(self, timeout=60):
        end = self._marks()
        want = {tp: end[tp] - self.start[tp] for tp in end if end[tp] > self.start[tp]}
        if not want:
            return []
        self.c.assign([TopicPartition(t, p, self.start[(t, p)]) for (t, p) in want])
        got, out, deadline = {tp: 0 for tp in want}, [], time.time() + timeout
        while any(got[tp] < want[tp] for tp in want) and time.time() < deadline:
            msg = self.c.poll(1.0)
            if msg is None or msg.error():
                continue
            tp = (msg.topic(), msg.partition())
            if tp in want and msg.offset() < end[tp]:
                got[tp] += 1
                env = envelope_pb2.Envelope()
                env.ParseFromString(msg.value())
                ts_type, ts = msg.timestamp()
                out.append({"topic": msg.topic(), "partition": msg.partition(), "offset": msg.offset(),
                            "key": msg.key(), "value": msg.value(), "env": env,
                            "log_append": ts_type == TIMESTAMP_LOG_APPEND_TIME, "ts": ts})
        assert all(got[tp] >= want[tp] for tp in want), "timed out reading Kafka"
        return out

    def close(self):
        self.c.close()
