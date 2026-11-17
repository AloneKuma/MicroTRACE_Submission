"""One Exp. 3 receiving slot on the analysis host: its own Kafka, receiver and (live) pipeline.

A slot serves one replayed run at a time and is made fresh for it, so runs
never share state and the slot never touches a shared Kafka (the test host's
dev Kafka hazards: stale idle gaps, cross-talk between sessions). Slot s
binds Kafka on base + 10 s (controller + 1) and the receiver on base + 10 s + 4.

    slot = Slot(dir, index=0, listen_host="0.0.0.0", advertise_host=<private IP>)
    slot.up(); slot.certs(node_ids); slot.start_receiver(max_idle="1h")
    [slot.start_pipeline(params)]            # live conditions
    ... the senders ship ...
    slot.dump_inputs(path)                   # what arrived: the degraded stream
    [slot.dump_outputs(path)]                # live: findings, witnesses, incidents, event arrivals
    slot.down()

Kafka runs from KAFKA_HOME (java -cp libs/*; no start scripts, so it also runs
on Windows), else from the kafka-server-start.sh on PATH. Go binaries come from
$MT_BIN (receiver, devcerts). Process groups are stopped as a whole.
"""
import base64
import gzip
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

from google.protobuf import json_format

from mtcore import REPO
from microtrace.v0 import common_pb2, envelope_pb2

PYDIR = os.path.join(REPO, "src", "python")
TOPICS_YAML = os.path.join(REPO, "spec", "kafka", "topics.yaml")
# The receiver's default allowlist plus source.completeness.v0: the generator's own completeness
# records (sensor-declared gaps) travel in the node streams like any other record.
ALLOW = ("raw.ebpf.v0,raw.audit.v0,raw.gateway.v0,raw.kyverno.v0,raw.dbaudit.v0,raw.pathflow.v0,"
         "context.cluster.v0,norm.events.v0,source.completeness.v0")
INPUT_TOPICS = ("norm.events.v0", "source.completeness.v0", "context.cluster.v0")
PIPELINE_PRODUCERS = frozenset({"restreamer", "agents", "orchestrator"})   # live pipeline output, never input
OUTPUT_TOPICS = ("findings.v0", "rule.evaluations.v0", "witness.decisions.v0", "incidents.v0")
BASE_PORT = int(os.environ.get("MT_EXP3_BASE_PORT", "39092"))
POSIX = os.name == "posix"
SOURCE_IDLE = common_pb2.GapReason.Value("SOURCE_IDLE")


def rmtree(path):
    """shutil.rmtree that also removes read-only files (Kafka marks its checkpoints read-only, which
    Windows refuses to delete)."""
    import stat

    def onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if os.path.exists(path):
        shutil.rmtree(path, onexc=onexc) if sys.version_info >= (3, 12) else shutil.rmtree(path, onerror=onexc)


def binary(name):
    b = os.environ.get("MT_BIN") or os.path.join(os.environ.get("MT_DEV", os.path.expanduser("~/microtrace-dev")), "bin")
    p = os.path.join(b, name + (".exe" if os.name == "nt" else ""))
    if not os.path.exists(p):
        raise FileNotFoundError(f"{p} missing (build src/go/cmd/{name} into $MT_BIN)")
    return p


def spawn(argv, log, cwd=None, env=None, stdin=None, stdout=None):
    """Start a process in its own process group; stdout and stderr to log unless stdout is given."""
    kw = {"start_new_session": True} if POSIX else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin, stdout=log if stdout is None else stdout,
                            stderr=log, **kw)


def stop(p, timeout=30.0, sig=None):
    """Stop a process group (SIGTERM, then SIGKILL after timeout); returns the exit code."""
    if p is None or p.poll() is not None:
        return None if p is None else p.returncode
    try:
        if POSIX:
            os.killpg(p.pid, sig or signal.SIGTERM)
        else:
            p.terminate()
        p.wait(timeout)
    except subprocess.TimeoutExpired:
        if POSIX:
            os.killpg(p.pid, signal.SIGKILL)
        else:
            p.kill()
        p.wait()
    except ProcessLookupError:
        pass
    return p.returncode


def wait_port(host, port, timeout=90.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"nothing listening on {host}:{port}")


def wait_line(path, proc, word="ready", timeout=180.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"{path} exited {proc.returncode} before {word!r}")
        with open(path, encoding="utf-8", errors="replace") as fh:
            if any(x.strip() == word for x in fh):
                return
        time.sleep(0.3)
    raise TimeoutError(f"{path}: no {word!r} line")


def cluster_id():
    """A random Kafka cluster ID that does not start with "-" (as Kafka's own Uuid.randomUuid): an ID
    starting with "-" is read by StorageTool as an option, so about 1 in 64 slots failed to format
    (two Exp. 3 transport jobs, 2026-11-16)."""
    while True:
        cid = base64.urlsafe_b64encode(uuid.uuid4().bytes).rstrip(b"=").decode()
        if not cid.startswith("-"):
            return cid


def kafka_home():
    h = os.environ.get("KAFKA_HOME")
    if h:
        return h
    s = shutil.which("kafka-server-start.sh")
    if s:
        return os.path.dirname(os.path.dirname(os.path.realpath(s)))
    raise FileNotFoundError("set KAFKA_HOME (or put kafka-server-start.sh on PATH)")


class Slot:
    def __init__(self, directory, index=0, listen_host="127.0.0.1", advertise_host="127.0.0.1",
                 heartbeat="1s", heap="-Xmx512m"):
        self.dir = os.path.abspath(directory)
        self.index = index
        base = BASE_PORT + 10 * index
        self.kafka_port, self.controller_port, self.rx_port = base, base + 1, base + 4
        self.bootstrap = f"127.0.0.1:{self.kafka_port}"
        self.listen_host, self.advertise_host = listen_host, advertise_host
        self.heartbeat, self.heap = heartbeat, heap
        self.kafka = self.receiver = None
        self.pipeline = {}
        self.cert_dir = os.path.join(self.dir, "certs")

    # --- Kafka ---------------------------------------------------------------------------
    def up(self):
        rmtree(self.dir)
        os.makedirs(os.path.join(self.dir, "kafka", "logs"))
        home = kafka_home()
        kd = os.path.join(self.dir, "kafka")
        conf = os.path.join(kd, "server.properties")
        data = Path(kd, "data").as_posix()
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write(f"""process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=127.0.0.1:{self.controller_port}
listeners=PLAINTEXT://127.0.0.1:{self.kafka_port},CONTROLLER://127.0.0.1:{self.controller_port}
advertised.listeners=PLAINTEXT://127.0.0.1:{self.kafka_port},CONTROLLER://127.0.0.1:{self.controller_port}
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
log.dirs={data}
auto.create.topics.enable=false
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
share.coordinator.state.topic.replication.factor=1
share.coordinator.state.topic.min.isr=1
group.initial.rebalance.delay.ms=0
log.index.size.max.bytes=1048576
""")
        java = os.environ.get("JAVA", "java")
        cp = os.path.join(home, "libs", "*")
        cid = cluster_id()
        subprocess.run([java, "-cp", cp, "kafka.tools.StorageTool", "format", "--standalone", "-t", cid, "-c", conf],
                       check=True, capture_output=True, text=True)
        log4j = Path(home, "config", "log4j2.yaml")
        props = [f"-Dlog4j2.configurationFile={log4j.as_uri()}"] if log4j.exists() else []
        log = open(os.path.join(kd, "logs", "server.out"), "w")
        self.kafka = spawn([java, "-Xms256m", self.heap, *props, f"-Dkafka.logs.dir={Path(kd, 'logs').as_posix()}",
                            "-cp", cp, "kafka.Kafka", conf], log)
        log.close()
        wait_port("127.0.0.1", self.kafka_port)
        from mtcore.kafka_topics import DEV_CONFIG, ensure_topics
        for attempt in range(10):
            try:
                _, _, _, problems = ensure_topics(self.bootstrap, DEV_CONFIG)
                if not problems:
                    break
            except Exception as e:                      # broker still starting
                problems = [str(e)]
            time.sleep(1)
        if problems:
            raise RuntimeError(f"slot {self.index}: topics: {problems}")
        return self

    # --- receiver --------------------------------------------------------------------------
    def certs(self, node_ids):
        hosts = sorted({"127.0.0.1", "localhost", self.advertise_host})
        subprocess.run([binary("devcerts"), "-out", self.cert_dir, "-nodes", ",".join(node_ids),
                        "-hosts", ",".join(hosts)], check=True, capture_output=True, text=True)
        return self.cert_dir

    def start_receiver(self, max_idle, run_id="exp3"):
        c = self.cert_dir
        log = open(os.path.join(self.dir, "receiver.log"), "w")
        self.receiver = spawn([binary("receiver"), "-listen", f"{self.listen_host}:{self.rx_port}",
                               "-cert", f"{c}/receiver.crt", "-key", f"{c}/receiver.key", "-ca", f"{c}/ca.crt",
                               "-brokers", self.bootstrap, "-topics", TOPICS_YAML, "-allow", ALLOW,
                               "-state", os.path.join(self.dir, "rx-state"), "-instance", f"exp3-receiver-{self.index}",
                               "-run-id", run_id, "-heartbeat", self.heartbeat, "-max-idle", max_idle], log)
        log.close()
        wait_port("127.0.0.1", self.rx_port, 60)
        return f"{self.advertise_host}:{self.rx_port}"

    def stop_receiver(self):
        return stop(self.receiver)

    # --- live pipeline ------------------------------------------------------------------------
    def start_pipeline(self, params, idle_exit_s=30.0, heartbeat_ms=1000):
        """Restreamer, agents A-H and the GO on this slot's Kafka, main parameters, unique names."""
        tag = f"exp3s{self.index}"
        common = ["--bootstrap", self.bootstrap, "--idle-exit-s", str(idle_exit_s)]
        env = dict(os.environ, PYTHONHASHSEED=os.environ.get("PYTHONHASHSEED", "1"),
                   MT_POSITIONS_LOG=os.path.join(self.dir, "positions.jsonl"))
        specs = {
            "restreamer": ["mtcore.restream", "--params", params, "--instance", f"{tag}-restreamer",
                           "--group", f"{tag}-restreamer", "--heartbeat-ms", str(heartbeat_ms)],
            "agents": ["mtcore.agents.run", "--params", params, "--instance", f"{tag}-agents",
                       "--group", f"{tag}-agents", "--heartbeat-ms", str(heartbeat_ms)],
            "go": ["mtcore.orchestrator.run", "--params", params, "--instance", f"{tag}-go", "--group", f"{tag}-go",
                   "--checkpoint", os.path.join(self.dir, "go.checkpoint"),
                   "--positions-log", os.path.join(self.dir, "go-positions.jsonl")],
        }
        for name, args in specs.items():
            path = os.path.join(self.dir, f"{name}.log")
            log = open(path, "w")
            p = spawn([sys.executable, "-m", *args, *common], log, cwd=PYDIR, env=env)
            log.close()
            self.pipeline[name] = (p, path)
        for name, (p, path) in self.pipeline.items():
            wait_line(path, p)

    def wait_pipeline(self, timeout=900.0):
        """Wait until every pipeline process has exited by itself (idle exit); kill on timeout."""
        end = time.time() + timeout
        codes = {}
        for name in ("restreamer", "agents", "go"):
            p, _ = self.pipeline.get(name, (None, None))
            if p is None:
                continue
            try:
                p.wait(max(1.0, end - time.time()))
            except subprocess.TimeoutExpired:
                stop(p)
            codes[name] = p.returncode
        return codes

    # --- dumps -----------------------------------------------------------------------------
    def _consumer(self):
        from confluent_kafka import Consumer
        return Consumer({"bootstrap.servers": self.bootstrap, "group.id": f"exp3-dump-{uuid.uuid4().hex[:8]}",
                         "enable.auto.commit": False})

    def _read_all(self, topics, idle_s=60.0):
        """[(timestamp_ms, topic, partition, offset, Envelope)] below the end offsets taken now."""
        from confluent_kafka import TopicPartition
        c = self._consumer()
        try:
            md = c.list_topics(timeout=30).topics
            parts = [(t, p) for t in topics for p in sorted(md[t].partitions)]
            ends = {k: c.get_watermark_offsets(TopicPartition(*k), timeout=30, cached=False) for k in parts}
            want = {k: hi for k, (lo, hi) in ends.items() if hi > lo}
            c.assign([TopicPartition(t, p, lo) for (t, p), (lo, _) in ends.items()])
            got, pos, last = [], {}, time.time()
            while any(pos.get(k, -1) + 1 < hi for k, hi in want.items()):
                if time.time() - last > idle_s:
                    raise TimeoutError(f"slot {self.index}: dump stalled at {pos}, want {want}")
                for m in c.consume(1000, timeout=0.5):
                    if m.error():
                        continue
                    k = (m.topic(), m.partition())
                    if m.offset() >= want.get(k, 0):
                        continue
                    env = envelope_pb2.Envelope()
                    env.ParseFromString(m.value())
                    got.append((m.timestamp()[1], m.topic(), m.partition(), m.offset(), env))
                    pos[k] = max(pos.get(k, -1), m.offset())
                    last = time.time()
            return got
        finally:
            c.close()

    def dump_inputs(self, path):
        """The degraded stream as it arrived, in the shipper-line format mtcore.harness.offline
        reads: {"topic", "envelope", "timestamp_ms", "partition", "offset"} in arrival order
        (Kafka LogAppendTime, then topic, partition, offset). The receiver's heartbeats are
        counted, not written: offline detection sees the end of input as its only watermark,
        as in Exp. 1-2."""
        recs = sorted(self._read_all(INPUT_TOPICS), key=lambda r: (r[0], r[1], r[2], r[3]))
        st = {"records": 0, "heartbeats": 0, "by_topic": {}, "receiver_gaps": 0, "receiver_idle": 0}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            for ts, topic, part, off, env in recs:
                if env.HasField("heartbeat"):
                    st["heartbeats"] += 1
                    continue
                if env.producer_id in PIPELINE_PRODUCERS:
                    # 2026-11-17: a live run's restreamer writes its own gap records to
                    # source.completeness.v0; they are pipeline output, not what arrived.
                    st["pipeline_records"] = st.get("pipeline_records", 0) + 1
                    continue
                if env.HasField("source_completeness") and env.producer_id == "ingest-receiver":
                    reasons = {g.reason for g in env.source_completeness.gaps}
                    st["receiver_idle" if SOURCE_IDLE in reasons else "receiver_gaps"] += 1
                d = json_format.MessageToDict(env, preserving_proto_field_name=True)
                fh.write(json.dumps({"topic": topic, "envelope": d, "timestamp_ms": ts, "partition": part,
                                     "offset": off}, sort_keys=True) + "\n")
                st["records"] += 1
                st["by_topic"][topic] = st["by_topic"].get(topic, 0) + 1
        os.replace(tmp, path)
        return st

    def dump_outputs(self, path_gz):
        """Live outputs in score.py's format, with Kafka timestamps: findings, rule evaluations,
        witnesses, incidents, and one {"topic", "event", "timestamp_ms"} line per input event
        (for latency)."""
        from mtcore.harness.dump import _line
        recs = self._read_all(OUTPUT_TOPICS + ("norm.events.v0",))
        n = 0
        tmp = path_gz + ".tmp"
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            for ts, topic, part, off, env in sorted(recs, key=lambda r: (r[1], r[2], r[3])):
                line = _line(topic, part, off, ts, env, False, events=topic == "norm.events.v0")
                if line is not None:
                    fh.write(json.dumps(line, sort_keys=True) + "\n")
                    n += 1
        os.replace(tmp, path_gz)
        return n

    def down(self, keep=False):
        for name, (p, _) in list(self.pipeline.items()):
            stop(p, 10)
        self.pipeline = {}
        stop(self.receiver, 10)
        stop(self.kafka, 60)
        if not keep:
            try:
                rmtree(os.path.join(self.dir, "kafka"))
            except OSError:
                pass
