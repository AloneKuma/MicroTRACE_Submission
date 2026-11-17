"""Our eBPF events -> the DARPA-style tables of PIDSMaker 3.0.0 (KAIROS) and of
the ORTHRUS authors' code (docs/plans/kairos-orthrus-our-data-plan.md, B1).

    python -m mtcore.baselines.provenance.convert --out OUT --name MT \\
        --runs train=PILOT_DIR@SPLIT.json:fit --runs pilot=PILOT_DIR@SPLIT.json:score \\
        --runs cases=CASES_DIR@SPLIT60.json:score [--val-fraction 0.15]

Both tools read four tables (PIDSMaker dataset_preprocessing/create_database.sh,
orthrus postgres/init-create-databases.sh, identical): subject_node_table,
file_node_table and netflow_node_table (node_uuid, hash_id = sha256(node_uuid),
attributes, index_id) and event_table (src hash and index, operation, dst hash
and index, event_uuid, timestamp_rec in ns). Rows are written as CSV for COPY,
with load.sql. Built the way create_database_e3.py builds them from DARPA TC:
the subject is the acting process, and the types in EDGE_REVERSED are stored
object -> subject.

Each run is its own graph (runs are separate worlds): node UUIDs are derived
from the run ID and its day, and each run gets its own calendar day, since both tools split
data by day. Days are dealt in group order (train, val, then the --runs test
groups), one per run, from 2030-01-01 UTC; a run's events keep their offset
from the run's first event. config.json holds one dataset entry per test group
for pidsmaker/config/config.py: the same train and val days, its own test days,
the other groups' days unused.

Training runs carry background only: every event in a run's
restricted/truth_actions.pb rendered_event_ids (all scenario steps, attack or
benign) is left out, as for our own detectors' fit. Validation runs are a fixed
--val-fraction of the train group, chosen by SHA-256 of the run ID, and are
stripped the same way. Test runs keep every event.

Event types: KAIROS and ORTHRUS read the ten DARPA TC types of rel2id_darpa_tc
(pidsmaker/utils/dataset_utils.py). EDGE maps our families onto them; families
with no counterpart (proc.exit, priv.creds, ns.change, proc.ptrace, bpf.call,
token.file_index; file renames, unlinks and chmods) are not edges, as such
events are not in those tools' DARPA setups either. Every eBPF event, kept or
not, is listed in event_map.csv with its process node (and object node, if
any), so a step is scored by the nodes of its own evidence events (B2).

ground_truth/<group>/<run_id>.csv lists, per test run, the nodes of the
evidence events of PRESENT host-type finding opportunities (HOST_TYPES), in the
tools' format (node_uuid, label, index_id), for their own reports only; our
scoring reads event_map.csv and truth directly.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import uuid
from collections import Counter, defaultdict

from google.protobuf import json_format

import mtcore  # noqa: F401  (puts src/python/gen on the path)
from microtrace.v0 import dataset_pb2, ebpf_pb2, envelope_pb2

NORM_TOPIC = "norm.events.v0"
EPOCH = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
NS = uuid.UUID("6f1c2a3e-6a6b-4b7e-9a51-6d3a1c0e2b10")   # this converter's UUIDv5 namespace

# pidsmaker/utils/dataset_utils.py edge_reversed, restricted to the types we emit.
EDGE_REVERSED = {"EVENT_EXECUTE", "EVENT_OPEN", "EVENT_READ", "EVENT_RECVFROM"}
WRITE_OPS = {ebpf_pb2.WRITE, ebpf_pb2.CREATE, ebpf_pb2.MMAP_SHARED_WRITE}
# Finding types whose evidence is host events (eBPF): scored for KAIROS (B2).
HOST_TYPES = ("C1a", "C1b", "C2", "D1", "E2", "F1", "G1a", "G1c", "H1", "H2", "H4")


def _node_uuid(graph, kind, key):
    return str(uuid.uuid5(NS, f"{graph}|{kind}|{key}"))


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _pkey(pk):
    return f"{pk.node_id}:{pk.boot_id}:{pk.tgid}:{pk.start_time_ns}"


def _fkey(f):
    return f"{f.dev}:{f.ino}" if (f.dev or f.ino) else (f.resolved_path or f.path_as_opened)


def _fpath(f):
    return f.resolved_path or f.path_as_opened or "null"


def read_ebpf(run_dir):
    """(event_id, event_time_ns, RawEbpfRecord) of a run's eBPF events, in shipper order."""
    for name in sorted(os.listdir(os.path.join(run_dir, "shipper"))):
        if not name.endswith(".jsonl"):
            continue
        with open(os.path.join(run_dir, "shipper", name), encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                obj = json.loads(line)
                if obj.get("topic") != NORM_TOPIC or "envelope" not in obj:
                    continue
                env = json_format.ParseDict(obj["envelope"], envelope_pb2.Envelope())
                ne = env.normalized_event
                if not ne.HasField("ebpf"):
                    continue
                yield ne.event_id, ne.time.event_time.ToNanoseconds(), ne.ebpf


def _read_ld(path, cls):
    from mtcore.harness.score import read_ld
    return read_ld(path, cls) if os.path.exists(path) else []


def scenario_event_ids(run_dir):
    """Every event the generator rendered for a scenario step (attack or benign). The
    truth file must exist: without it nothing would be stripped and training would
    silently see attack events."""
    path = os.path.join(run_dir, "restricted", "truth_actions.pb")
    if not os.path.exists(path):
        raise FileNotFoundError(f"training run without truth (cannot strip scenario events): {path}")
    acts = _read_ld(path, dataset_pb2.GroundTruthAction)
    return {e for a in acts for e in a.rendered_event_ids}


def host_evidence_ids(run_dir):
    """Evidence event IDs of PRESENT host-type finding opportunities."""
    opps = _read_ld(os.path.join(run_dir, "restricted", "truth_findings.pb"), dataset_pb2.FindingOpportunity)
    return {e for o in opps if o.finding_type in HOST_TYPES and o.expected_state == dataset_pb2.PRESENT
            for e in o.evidence_event_ids}


def _orphan_fork(rec):
    """A fork whose parent is not recorded (a Pod's init process, started by
    the container runtime outside the sensor's view)."""
    return rec.event_family == "proc.fork" and not (rec.parent.node_id or rec.parent.tgid)


def actor(rec):
    """The acting process: a proc.fork record names the child as process and
    the forking actor as parent (mtgen.render.ebpf); every other family acts
    as its process, and so does an orphan fork (no edge, the child alone)."""
    return rec.parent if rec.event_family == "proc.fork" and not _orphan_fork(rec) else rec.process


def edges_of(rec):
    """[(operation, object kind, object key, object attributes, suffix)] for one eBPF record.

    Object kinds: subject (a process), file, netflow. An empty list means the
    family has no DARPA counterpart (the event is still mapped to its process).
    """
    fam = rec.event_family
    if fam == "proc.fork":
        return [] if _orphan_fork(rec) else [("EVENT_CLONE", "subject", _pkey(rec.process), None, "")]
    if fam == "proc.exec":
        f = rec.exec.executable
        return [("EVENT_EXECUTE", "file", _fkey(f) or rec.exec.filename, {"path": _fpath(f)}, "")]
    if fam in ("file.open", "file.read"):
        f = rec.file_access.file
        op = "EVENT_OPEN" if rec.file_access.op == ebpf_pb2.FILE_OPEN else "EVENT_READ"
        return [(op, "file", _fkey(f), {"path": _fpath(f)}, "")]
    if fam == "file.mutation":
        if rec.file_mutation.op not in WRITE_OPS:
            return []
        f = rec.file_mutation.file
        return [("EVENT_WRITE", "file", _fkey(f), {"path": _fpath(f)}, "")]
    if fam in ("net.connect", "net.accept", "ipc.runtime_socket"):
        s = rec.socket
        flow = _flow(rec, s.flow, s.local, s.remote)
        op = "EVENT_RECVFROM" if s.op == ebpf_pb2.ACCEPT else "EVENT_CONNECT"
        return [(op, "netflow", flow[0], flow[1], "")]
    if fam == "net.flow_bytes":
        fc = rec.flow_counter
        flow = _flow(rec, fc.flow, None, fc.remote)
        out = []
        if fc.bytes_out:
            out.append(("EVENT_SENDTO", "netflow", flow[0], flow[1], ":out"))
        if fc.bytes_in:
            out.append(("EVENT_RECVFROM", "netflow", flow[0], flow[1], ":in"))
        return out
    return []


def _flow(rec, flow, local, remote):
    """(key, attributes) of a socket: the socket cookie when there is one, else its endpoints."""
    if remote is not None and remote.unix_path:
        return f"unix:{rec.node_id}:{remote.unix_path}", {"src_addr": "null", "src_port": "null",
                                                          "dst_addr": remote.unix_path, "dst_port": "null"}
    la = (local.ip, str(local.port)) if local is not None and local.ip else ("null", "null")
    ra = (remote.ip, str(remote.port)) if remote is not None and remote.ip else ("null", "null")
    key = (f"cookie:{flow.node_id}:{flow.boot_id}:{flow.socket_cookie}" if flow.socket_cookie
           else f"ep:{rec.node_id}:{la[0]}:{la[1]}->{ra[0]}:{ra[1]}")
    return key, {"src_addr": la[0], "src_port": la[1], "dst_addr": ra[0], "dst_port": ra[1]}


class Writer:
    """Streams the four tables, the event map and the ground truth to CSV."""

    TABLES = {
        "subject_node_table": ["node_uuid", "hash_id", "path", "cmd", "index_id"],
        "file_node_table": ["node_uuid", "hash_id", "path", "index_id"],
        "netflow_node_table": ["node_uuid", "hash_id", "src_addr", "src_port", "dst_addr", "dst_port", "index_id"],
        "event_table": ["src_node", "src_index_id", "operation", "dst_node", "dst_index_id",
                        "event_uuid", "timestamp_rec"],
    }

    def __init__(self, out):
        self.out = out
        os.makedirs(out, exist_ok=True)
        self.fh, self.w = {}, {}
        for t, cols in self.TABLES.items():
            self.fh[t] = open(os.path.join(out, t + ".csv"), "w", newline="", encoding="utf-8")
            self.w[t] = csv.writer(self.fh[t])
        self.fh["map"] = open(os.path.join(out, "event_map.csv"), "w", newline="", encoding="utf-8")
        self.w["map"] = csv.writer(self.fh["map"])
        self.w["map"].writerow(["run_id", "event_id", "family", "kept", "operations",
                                "subject_uuid", "object_uuid"])
        self.next_index = 0
        self.counts = Counter()

    def close(self):
        for fh in self.fh.values():
            fh.close()

    def run(self, run_id, run_dir, day, strip, gt_dir=None, sealed=False):
        """Convert one run. Returns its counts. sealed: a held-out test run whose
        restricted/ truth must not be read before scoring. Its ground-truth file holds
        a placeholder chosen without truth, the run's first subject node, so that
        PIDSMaker's own evaluation runs; its metrics are never read (our scoring
        reads the truth itself, after the freeze)."""
        if sealed and strip:
            raise ValueError("a sealed run cannot be a training run")
        drop = scenario_event_ids(run_dir) if strip else set()
        events = list(read_ebpf(run_dir))
        t0 = min((t for _, t, _ in events), default=0)
        base_ns = int((EPOCH + datetime.timedelta(days=day)).timestamp()) * 1_000_000_000
        # Subject attributes: the path and argv0 of a process's last exec.
        exe = {}
        for _, _, rec in events:
            if rec.event_family == "proc.exec":
                exe[_pkey(rec.process)] = (_fpath(rec.exec.executable), rec.exec.argv0 or "null")
        nodes = {}                                   # (kind, key) -> (uuid, hash, index)
        edge_nodes = set()                           # node UUIDs that are endpoints of an edge

        def node(kind, key, attrs=None):
            k = (kind, key)
            if k not in nodes:
                u = _node_uuid(f"{run_id}@{day}", kind, key)
                h, i = _sha(u), self.next_index
                self.next_index += 1
                nodes[k] = (u, h, i)
                if kind == "subject":
                    path, cmd = exe.get(key, ("null", "null"))
                    self.w["subject_node_table"].writerow([u, h, path, cmd, i])
                elif kind == "file":
                    self.w["file_node_table"].writerow([u, h, (attrs or {}).get("path", "null"), i])
                else:
                    a = attrs or {}
                    self.w["netflow_node_table"].writerow([u, h, a.get("src_addr", "null"), a.get("src_port", "null"),
                                                           a.get("dst_addr", "null"), a.get("dst_port", "null"), i])
                self.counts["nodes_" + kind] += 1
            return nodes[k]

        c = Counter()
        for eid, t, rec in events:
            if eid in drop:
                c["stripped"] += 1
                continue
            subj = node("subject", _pkey(actor(rec)))
            edges = edges_of(rec)
            ts = base_ns + (t - t0)
            obj_uuid = ""
            for op, kind, key, attrs, suffix in edges:
                obj = node(kind, key, attrs)
                obj_uuid = obj[0]
                src, dst = (obj, subj) if op in EDGE_REVERSED else (subj, obj)
                # event_uuid carries the run's day: event IDs are unique within a run only
                # (two runs from one seed share background IDs). event_map.csv keeps ours.
                self.w["event_table"].writerow([src[1], src[2], op, dst[1], dst[2], f"{eid}{suffix}@{day}", ts])
                edge_nodes.add(src[0])
                edge_nodes.add(dst[0])
                c["edges"] += 1
                c["op_" + op] += 1
            if not edges:
                c["no_edge_" + rec.event_family] += 1
            self.w["map"].writerow([run_id, eid, rec.event_family, int(bool(edges)),
                                    "|".join(e[0] for e in edges), subj[0], obj_uuid])
            c["events"] += 1
        if gt_dir is not None and sealed:
            self._placeholder(run_id, gt_dir, nodes, edge_nodes)
        elif gt_dir is not None:
            self._ground_truth(run_id, run_dir, gt_dir, events, nodes, drop)
        self.counts.update(c)
        return c

    def _placeholder(self, run_id, gt_dir, nodes, edge_nodes):
        """The run's first subject node (lowest index) that is an endpoint of one of
        its edges, so it is in the graph PIDSMaker evaluates; chosen without truth."""
        subj = sorted((v[2], v[0], k) for k, v in nodes.items() if k[0] == "subject" and v[0] in edge_nodes)
        os.makedirs(gt_dir, exist_ok=True)
        with open(os.path.join(gt_dir, run_id + ".csv"), "w", newline="", encoding="utf-8") as fh:
            if subj:
                i, u, k = subj[0]
                csv.writer(fh).writerow((u, "{'%s': '%s'}" % (k[0], k[1]), i))

    def _ground_truth(self, run_id, run_dir, gt_dir, events, nodes, drop):
        want = host_evidence_ids(run_dir)
        rows = {}
        for eid, _, rec in events:
            if eid not in want or eid in drop:
                continue
            keys = [("subject", _pkey(actor(rec)))] + [(k, key) for _, k, key, _, _ in edges_of(rec)]
            for k in keys:
                if k in nodes:
                    u, _, i = nodes[k]
                    rows[u] = (u, "{'%s': '%s'}" % (k[0], k[1]), i)
        os.makedirs(gt_dir, exist_ok=True)
        with open(os.path.join(gt_dir, run_id + ".csv"), "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(sorted(rows.values(), key=lambda r: r[2]))


def _runs(spec):
    """'DIR@SPLIT.json:key' -> (dir, sorted run IDs)."""
    run_dir, _, rest = spec.partition("@")
    split, _, key = rest.rpartition(":")
    return run_dir, sorted(json.load(open(split))[key])


def val_runs(run_ids, fraction):
    """The fixed validation share of the train runs, by SHA-256 of the run ID."""
    ranked = sorted(run_ids, key=lambda r: hashlib.sha256(r.encode()).hexdigest())
    return set(ranked[:round(len(ranked) * fraction)])


def _date(day):
    return (EPOCH + datetime.timedelta(days=day)).strftime("%Y-%m-%d")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Our eBPF events -> DARPA-style tables for KAIROS and ORTHRUS.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", default="MT", help="dataset and database name prefix")
    ap.add_argument("--runs", action="append", required=True,
                    help="GROUP=DIR@SPLIT.json:key; group 'train' is the training set, every other is a test set")
    ap.add_argument("--val-fraction", type=float, default=0.15)
    ap.add_argument("--sealed", action="append", default=[],
                    help="test GROUP whose truth stays sealed: restricted/ is never read; each ground truth "
                         "file holds a placeholder node (the run's first subject node)")
    a = ap.parse_args(argv)
    groups = {}
    for spec in a.runs:
        g, _, rest = spec.partition("=")
        groups[g] = _runs(rest)
    if "train" not in groups:
        ap.error("a 'train' group is required")
    if "train" in a.sealed or set(a.sealed) - set(groups):
        ap.error(f"--sealed takes test groups only: {a.sealed}")
    w = Writer(a.out)
    train_dir, train_ids = groups.pop("train")
    val = val_runs(train_ids, a.val_fraction)
    plan = ([("train", train_dir, r) for r in train_ids if r not in val] +
            [("val", train_dir, r) for r in train_ids if r in val] +
            [(g, d, r) for g, (d, ids) in groups.items() for r in ids])
    days = defaultdict(list)
    manifest = {"name": a.name, "epoch": _date(0), "val_fraction": a.val_fraction, "sealed": sorted(a.sealed),
                "runs": []}
    for day, (g, d, r) in enumerate(plan):
        c = w.run(r, os.path.join(d, r), day, strip=g in ("train", "val"),
                  gt_dir=None if g in ("train", "val") else os.path.join(a.out, "ground_truth", g),
                  sealed=g in a.sealed)
        days[g].append(_date(day))
        manifest["runs"].append({"group": g, "run_id": r, "date": _date(day), **dict(c)})
        print(f"{day + 1}/{len(plan)} {g} {r} events {c['events']} edges {c['edges']} stripped {c['stripped']}",
              flush=True)
    w.close()
    all_days = [x for v in days.values() for x in v]
    config = {}
    for g in groups:
        name = f"{a.name}_{g}".upper()
        config[name] = {
            "raw_dir": "", "database": a.name.lower(), "database_all_file": a.name.lower(),
            "num_node_types": 3, "num_edge_types": 10, "timezone": "UTC",
            "start_date": min(all_days), "end_date": _date(len(plan)),
            "train_dates": days["train"], "val_dates": days["val"], "test_dates": days[g],
            "unused_dates": [x for h, v in days.items() if h not in ("train", "val", g) for x in v],
            "ground_truth_relative_path": [f"{g}/{r}.csv" for r in groups[g][1]],
            "attack_to_time_window": [[f"{g}/{r}.csv", d + " 00:00:00", d + " 23:59:59"]
                                      for r, d in zip(groups[g][1], days[g])],
        }
    with open(os.path.join(a.out, "config.json"), "w") as fh:
        json.dump(config, fh, indent=2)
    manifest["counts"] = dict(w.counts)
    with open(os.path.join(a.out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    with open(os.path.join(a.out, "load.sql"), "w") as fh:
        for t, cols in Writer.TABLES.items():
            fh.write(f"\\copy {t} ({', '.join(cols)}) FROM '{t}.csv' WITH (FORMAT csv)\n")
    print(json.dumps(dict(w.counts)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
