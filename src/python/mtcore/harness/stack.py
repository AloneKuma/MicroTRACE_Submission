"""One isolated pipeline stack for the Exp. 5 crash runner (build step 8f).

A stack is its own single-node Kafka (KRaft), its own Postgres server, and
the pipeline processes on top: receiver, restreamer, agents, GO and TGS ingest
(Python CLIs and the Go binaries in $MT_BIN, default $MT_DEV/bin). Everything
lives under one directory, $MT_DEV/stacks/<id>/, and binds 127.0.0.1 ports
derived from the slot number, so stacks run side by side and never touch the
shared dev Kafka or Postgres. A stack is made fresh for a run and wiped after.

    with Stack(slot=0, root=run_dir) as st:      # Kafka + Postgres up, topics made
        st.start_pipeline(commit_mode="oldest-needed")
        st.ship({"node-1": "node-1.jsonl"})          # at once; pace=1.0: event-time speed
        ...

Ports for slot s: Kafka 29092 + 10 s (controller + 1), Postgres 29095 + 10 s,
receiver 29096 + 10 s. Kafka gets a 512 MB heap (KAFKA_HEAP_OPTS overrides).
Needs the dev toolchain on PATH (source $MT_DEV/env.sh): kafka-storage.sh,
kafka-server-start.sh, initdb, pg_ctl, psql.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

from mtcore import REPO

MT_DEV = os.environ.get("MT_DEV", os.path.expanduser("~/microtrace-dev"))
BIN = os.environ.get("MT_BIN") or os.path.join(MT_DEV, "bin")
PYDIR = os.path.join(REPO, "src", "python")
TOPICS_YAML = os.path.join(REPO, "spec", "kafka", "topics.yaml")
NO_FAULTS = os.path.join(REPO, "spec", "faults", "none.yaml")
# The receiver's default allowlist plus source.completeness.v0, as mtcore/exp3/slot.py: generator
# node streams carry the sensors' own completeness records (found 2026-11-16: the first real run
# shipped by this harness was rejected with 'topic "source.completeness.v0" not allowed').
ALLOW = ("raw.ebpf.v0,raw.audit.v0,raw.gateway.v0,raw.kyverno.v0,raw.dbaudit.v0,raw.pathflow.v0,"
         "context.cluster.v0,norm.events.v0,source.completeness.v0")
EXIT_FAILPOINT = 137


def wait_port(port, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"nothing listening on 127.0.0.1:{port}")


class Proc:
    """A pipeline process. `start` may be called again after it exits (a
    restart keeps the arguments; `env` is replaced). Logs append to
    <dir>/<name>.log with a line per start."""

    def __init__(self, stack, name, argv, cwd=None, ready=None, feed=None):
        self.stack, self.name, self.argv, self.cwd = stack, name, list(argv), cwd
        self.ready = ready              # "line" (a "ready" stderr line) or a port, or None
        self.feed = list(feed) if feed else None    # argv of a process whose stdout is our stdin
        self.proc, self.feeder, self.starts, self.exits = None, None, 0, []
        self.log_path = os.path.join(stack.dir, f"{name}.log")

    def start(self, env=None):
        self.starts += 1
        log = open(self.log_path, "a", encoding="utf-8")
        log.write(json.dumps({"start": self.starts, "t": time.time_ns(), "env": env or {}}) + "\n")
        log.flush()
        stdin = None
        if self.feed:
            self.feeder = subprocess.Popen(self.feed, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
            stdin = self.feeder.stdout
        self.proc = subprocess.Popen(self.argv, cwd=self.cwd, stdin=stdin, stdout=log, stderr=subprocess.STDOUT,
                                     env={**os.environ, **self.stack.env, **(env or {})}, start_new_session=True)
        if stdin is not None:
            stdin.close()               # the child holds the pipe now
        self.started_ns = time.time_ns()
        log.close()
        if isinstance(self.ready, int):
            wait_port(self.ready)
        elif self.ready == "line":
            self._wait_line()
        return self

    def _wait_line(self, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited {self.proc.returncode} before ready; see {self.log_path}")
            with open(self.log_path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            mark = max(i for i, x in enumerate(lines) if x.startswith('{"start": '))
            if any(x.strip() == "ready" for x in lines[mark:]):
                return
            time.sleep(0.2)
        raise TimeoutError(f"{self.name} not ready; see {self.log_path}")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def poll(self):
        """Exit code if it exited since the last poll (recorded once), else None."""
        if self.proc is None or self.proc.poll() is None:
            return None
        code = self.proc.returncode
        if not self.exits or self.exits[-1][0] is not self.proc:
            self.exits.append((self.proc, code, time.time_ns()))
            return code
        return None

    def stop(self, timeout=60):
        """SIGTERM (a graceful flush and commit), SIGKILL after timeout."""
        if not self.alive():
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()

    def kill(self):
        if self.alive():
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        if self.feeder is not None and self.feeder.poll() is None:
            os.killpg(self.feeder.pid, signal.SIGKILL)
            self.feeder.wait()

    def pid(self):
        return self.proc.pid if self.alive() else None


class Stack:
    def __init__(self, slot, root=None, keep=False, max_idle="10s", heartbeat_ms=500, params=None):
        self.slot = slot
        self.dir = os.path.abspath(root or os.path.join(MT_DEV, "stacks", f"s{slot}"))
        self.keep = keep
        base = 29092 + 10 * slot
        self.kafka_port, self.controller_port = base, base + 1
        self.pg_port, self.rx_port = base + 3, base + 4
        self.bootstrap = f"127.0.0.1:{self.kafka_port}"
        self.dsn = f"host=127.0.0.1 port={self.pg_port} dbname=tgs user=tgs"
        self.max_idle, self.heartbeat_ms, self.params = max_idle, heartbeat_ms, params
        self.env = {"MT_TGS_DSN": self.dsn, "MT_POSITIONS_LOG": os.path.join(self.dir, "positions.jsonl")}
        self.procs = {}
        self.kafka = None
        self.certs = os.path.join(self.dir, "certs")

    # --- infrastructure --------------------------------------------------------------
    def __enter__(self):
        self.up()
        return self

    def __exit__(self, *exc):
        self.down()

    def up(self):
        if os.path.exists(self.dir):
            shutil.rmtree(self.dir)
        os.makedirs(self.dir)
        self._kafka_up()
        self._pg_up()
        from mtcore.kafka_topics import DEV_CONFIG, ensure_topics
        _, _, _, problems = ensure_topics(self.bootstrap, DEV_CONFIG)
        if problems:
            raise RuntimeError(f"topics: {problems}")

    def _kafka_up(self):
        kd = os.path.join(self.dir, "kafka")
        os.makedirs(os.path.join(kd, "logs"))
        conf = os.path.join(kd, "server.properties")
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write(f"""process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=127.0.0.1:{self.controller_port}
listeners=PLAINTEXT://127.0.0.1:{self.kafka_port},CONTROLLER://127.0.0.1:{self.controller_port}
advertised.listeners=PLAINTEXT://127.0.0.1:{self.kafka_port},CONTROLLER://127.0.0.1:{self.controller_port}
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
log.dirs={kd}/data
auto.create.topics.enable=false
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
share.coordinator.state.topic.replication.factor=1
share.coordinator.state.topic.min.isr=1
group.initial.rebalance.delay.ms=0
""")
        cid = subprocess.run(["kafka-storage.sh", "random-uuid"], check=True, capture_output=True,
                             text=True).stdout.strip()
        subprocess.run(["kafka-storage.sh", "format", "--standalone", "-t", cid, "-c", conf], check=True,
                       capture_output=True, text=True)
        env = {**os.environ, "LOG_DIR": os.path.join(kd, "logs"),
               "KAFKA_HEAP_OPTS": os.environ.get("KAFKA_HEAP_OPTS", "-Xms256m -Xmx512m")}
        log = open(os.path.join(kd, "logs", "server.out"), "w")
        self.kafka = subprocess.Popen(["kafka-server-start.sh", conf], stdout=log, stderr=subprocess.STDOUT,
                                      env=env, start_new_session=True)
        wait_port(self.kafka_port, 90)

    def _pg_up(self):
        self.pg_data = os.path.join(self.dir, "pg")
        subprocess.run(["initdb", "-D", self.pg_data, "-U", "tgs", "--auth=trust", "-E", "UTF8"], check=True,
                       capture_output=True, text=True)
        with open(os.path.join(self.pg_data, "postgresql.conf"), "a", encoding="utf-8") as fh:
            # TCP only: a socket path under a long run directory exceeds the
            # 107-byte limit on Unix socket names.
            fh.write(f"listen_addresses = '127.0.0.1'\nport = {self.pg_port}\n"
                     "unix_socket_directories = ''\nfsync = on\n")
        self.pg_start()
        subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(self.pg_port), "-U", "tgs", "-d", "postgres",
                        "-q", "-c", "CREATE DATABASE tgs"], check=True, capture_output=True, text=True)

    def pg_start(self):
        subprocess.run(["pg_ctl", "-D", self.pg_data, "-l", os.path.join(self.dir, "postgres.log"), "-w", "start"],
                       check=True, capture_output=True, text=True)

    def pg_crash(self):
        """A Postgres server crash: immediate shutdown, no checkpoint."""
        subprocess.run(["pg_ctl", "-D", self.pg_data, "-m", "immediate", "stop"], check=True,
                       capture_output=True, text=True)

    def down(self):
        for p in reversed(list(self.procs.values())):
            p.kill()
        if self.kafka is not None and self.kafka.poll() is None:
            os.killpg(self.kafka.pid, signal.SIGTERM)
            try:
                self.kafka.wait(60)
            except subprocess.TimeoutExpired:
                os.killpg(self.kafka.pid, signal.SIGKILL)
                self.kafka.wait()
        if getattr(self, "pg_data", None) and os.path.exists(os.path.join(self.pg_data, "postmaster.pid")):
            subprocess.run(["pg_ctl", "-D", self.pg_data, "-m", "fast", "stop"], capture_output=True)
        if not self.keep:
            for sub in ("kafka", "pg"):
                shutil.rmtree(os.path.join(self.dir, sub), ignore_errors=True)

    # --- pipeline --------------------------------------------------------------------
    def _py(self, name, args, ready="line"):
        p = Proc(self, name, [sys.executable, "-m", *args], cwd=PYDIR, ready=ready)
        self.procs[name] = p
        return p

    def start_pipeline(self, nodes, commit_mode="oldest-needed", env=None):
        """Receiver, restreamer, agents, GO, TGS ingest; `env` maps a process
        name to extra environment for its first start (failpoints)."""
        env = env or {}
        subprocess.run([os.path.join(BIN, "devcerts"), "-out", self.certs, "-nodes", ",".join(nodes),
                        "-hosts", "127.0.0.1,localhost"], check=True, capture_output=True, text=True)
        c = self.certs
        rx = Proc(self, "receiver", [os.path.join(BIN, "receiver"), "-listen", f"127.0.0.1:{self.rx_port}",
                                     "-cert", f"{c}/receiver.crt", "-key", f"{c}/receiver.key", "-ca", f"{c}/ca.crt",
                                     "-brokers", self.bootstrap, "-topics", TOPICS_YAML, "-allow", ALLOW,
                                     "-state", os.path.join(self.dir, "rx-state"), "-instance", "receiver-1",
                                     "-run-id", "crashrun", "-heartbeat", f"{self.heartbeat_ms}ms",
                                     "-max-idle", self.max_idle], ready=self.rx_port)
        self.procs["receiver"] = rx
        hb = ["--heartbeat-ms", str(self.heartbeat_ms)]
        prm = ["--params", self.params] if self.params else []
        self._py("restreamer", ["mtcore.restream", "--bootstrap", self.bootstrap, "--instance", "restreamer-1", *hb])
        # The agents get the same parameter set as the GO (the frozen file holds both), so a
        # crash run tests the configuration Exp. 1-2 scored, not the development defaults.
        self._py("agents", ["mtcore.agents.run", "--bootstrap", self.bootstrap, "--instance", "agents-1", *hb, *prm])
        self._py("go", ["mtcore.orchestrator.run", "--bootstrap", self.bootstrap, "--instance", "orchestrator",
                        "--commit-mode", commit_mode, "--checkpoint", os.path.join(self.dir, "go.checkpoint"), *prm])
        self._py("tgs", ["mtcore.tgs.run", "--bootstrap", self.bootstrap, "--dsn", self.dsn])
        for name in ("receiver", "restreamer", "agents", "go", "tgs"):
            self.procs[name].start(env.get(name))

    def ship(self, inputs, pace=0.0):
        """Start one shipper per node {node: input path} (with -drain). pace 0
        writes the input at once; pace > 0 feeds it through faultinject -pace
        with the no-fault plan, at event-time speed times pace (Exp. 5 input
        rate). A node shipped again (a history prefill, then the measured
        part) gets a new shipper on the same spool and boot ID, so its
        sequence numbers continue."""
        c = self.certs
        for node, path in sorted(inputs.items()):
            feed = None
            src = os.path.abspath(path)
            if pace > 0:
                feed = [os.path.join(BIN, "faultinject"), "-plan", NO_FAULTS, "-input", src, "-node", node,
                        "-pace", str(pace)]
                src = "-"
            p = Proc(self, f"shipper-{node}", [
                os.path.join(BIN, "shipper"), "-receiver", f"127.0.0.1:{self.rx_port}", "-server-name", "127.0.0.1",
                "-cert", f"{c}/node-cert-{node}.crt", "-key", f"{c}/node-cert-{node}.key", "-ca", f"{c}/ca.crt",
                "-node-id", node, "-boot-id", f"boot-{node}", "-spool", os.path.join(self.dir, f"spool-{node}"),
                "-input", src, "-stats", os.path.join(self.dir, f"stats-{node}.json"), "-drain"], feed=feed)
            self.procs[p.name] = p
            p.start()

    def shippers(self):
        return [p for n, p in self.procs.items() if n.startswith("shipper-")]

    def tgs_hashes(self):
        """{"edges": edge_hash, "graph": graph_hash} of the stack's TGS."""
        import psycopg
        from mtcore.tgs.hashes import edge_hash, graph_hash
        from mtcore.tgs.store import PgStore
        with psycopg.connect(self.dsn, connect_timeout=5) as conn:
            store = PgStore(conn)
            return {"edges": edge_hash(store), "graph": graph_hash(store)}

    def tgs_offsets(self):
        import psycopg
        with psycopg.connect(self.dsn, connect_timeout=5) as conn:
            rows = conn.execute("SELECT topic, kafka_partition, last_offset FROM applied_offsets").fetchall()
        return {(t, p): o for t, p, o in rows}
