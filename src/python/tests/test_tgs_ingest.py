"""TGS build step 6a: extractors, merging, epochs, idempotence and the batch
transaction (spec/graph/tgs-contract.md sections 2-3).

Store tests run on MemoryStore always and on PgStore when a Postgres answers
at $MT_TGS_TEST_DSN (default 127.0.0.1:55432, started by src/scripts/pg-up.sh);
each Postgres test gets a private schema that is dropped afterwards."""
import contextlib
import os
import random
import uuid

import agent_fixtures as F
import pytest
from microtrace.v0 import (common_pb2, context_pb2, ebpf_pb2, envelope_pb2, finding_pb2, incident_pb2,
                           normalized_pb2, witness_pb2)

from mtcore.tgs import apply as A
from mtcore.tgs import extract as X
from mtcore.tgs.store import MemoryStore

NORM, FND, WIT, INC = "norm.events.v0", "findings.v0", "witness.decisions.v0", "incidents.v0"
TEST_DSN = os.environ.get("MT_TGS_TEST_DSN", "host=127.0.0.1 port=55432 dbname=tgs")


def _pg_conn():
    try:
        import psycopg
        return psycopg.connect(TEST_DSN, connect_timeout=2)
    except Exception:
        return None


@contextlib.contextmanager
def pg_store():
    """A PgStore in a private schema, dropped afterwards; skips the test when
    Postgres is not reachable."""
    conn = _pg_conn()
    if conn is None:
        pytest.skip(f"no Postgres at {TEST_DSN}")
    from mtcore.tgs.store import PgStore
    schema = "t_" + uuid.uuid4().hex[:12]
    conn.execute(f"CREATE SCHEMA {schema}")
    conn.execute(f"SET search_path TO {schema}")
    conn.commit()
    s = PgStore(conn)
    s.apply_schema()
    try:
        yield s
    finally:
        conn.rollback()
        conn.execute(f"DROP SCHEMA {schema} CASCADE")
        conn.commit()
        conn.close()


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        yield MemoryStore()
        return
    with pg_store() as s:
        yield s


# --- builders ------------------------------------------------------------------------
def pkey(tgid, node=F.NODE, boot=F.BOOT):
    return ebpf_pb2.ProcessKey(node_id=node, boot_id=boot, tgid=tgid, start_time_ns=tgid * 1000)


def file_read(t, tgid=10, path="/etc/shadow", ino=42, ingest=None, node=F.NODE, gaps=()):
    ne = F.ebpf(t, "file.read", node=node, gaps=gaps)
    ne.ebpf.process.CopyFrom(pkey(tgid, node))
    f = ne.ebpf.file_access.file
    f.dev, f.ino, f.resolved_path = 8, ino, path
    ne.time.ingest_time.CopyFrom(F.ts(ingest if ingest is not None else t + 0.2))
    return F.done(ne)


def norm_ctx(o):
    ne = normalized_pb2.NormalizedEvent(event_id=f"ctx-{o.uid}-{o.resource_version}",
                                        source=common_pb2.Source.Value("CLUSTER_CONTEXT"))
    ne.time.event_time.CopyFrom(o.observed_time)
    ne.context.CopyFrom(o)
    return ne


def witness(wid, a, b, status="CONFIRMED"):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("WITNESS"), logical_id=wid)
    w = env.witness
    w.witness_id, w.source_finding_id, w.target_finding_id = wid, a, b
    w.relationship_type = witness_pb2.WitnessType.Value("PROCESS_ANCESTRY")
    w.status = witness_pb2.WitnessStatus.Value(status)
    w.source_event_time.CopyFrom(F.ts(1))
    w.target_event_time.CopyFrom(F.ts(2))
    return env


def incident(iid, version=1, members=("f1", "f2"), epochs=(), status="INCIDENT_OPEN"):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("INCIDENT"), logical_id=iid)
    inc = env.incident
    inc.incident_id, inc.anchor_finding_id, inc.version = iid, members[0], version
    inc.status = incident_pb2.IncidentStatus.Value(status)
    inc.finding_ids.extend(members)
    for node, boot, tau, trig in epochs:
        e = inc.node_epochs.add(node_id=node, boot_id=boot, trigger_finding_id=trig,
                                kind=incident_pb2.NodeEpochKind.Value("NODE_EPOCH_CONFIRMED"))
        e.tau_n.CopyFrom(F.ts(tau))
    inc.input_frontier["norm.events.v0/0"] = 3
    return env


def finding(fid, *entities):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("FINDING"), logical_id=fid)
    f = env.finding
    f.finding_id, f.finding_type = fid, "D1"
    f.event_start.CopyFrom(F.ts(1))
    for etype, uid in entities:
        f.entities.add(type=common_pb2.EntityType.Value(etype), uid=uid, name=uid,
                       strength_class=common_pb2.StrengthClass.Value("STRENGTH_HIGH"))
    return env


def batch(*envs, topic=NORM, start=0):
    return [(topic, 0, start + i, e) for i, e in enumerate(envs)]


def observed(store):
    return sorted((e for e in store.rows("edges") if e["edge_type"] == "OBSERVED" and e["label"] != "involves"),
                  key=lambda e: e["edge_id"])


# --- extractors ----------------------------------------------------------------------
def test_ebpf_file_read_is_process_to_file_with_the_family_label():
    [ob] = X.observations(file_read(1).normalized_event)
    assert (ob.actor.type, ob.obj.type, ob.label) == ("PROCESS", "FILE_OBJECT", "file.read")
    assert ob.actor.uid == f"{F.NODE}/{F.BOOT}/10/10000" and ob.actor.status == X.RESOLVED
    assert ob.obj.status == X.WEAK and ob.obj.name == "/etc/shadow"      # inode without version: medium


def test_exec_goes_from_the_parent_to_the_new_process():
    ne = F.ebpf(1, "proc.exec")
    ne.ebpf.process.CopyFrom(pkey(11))
    ne.ebpf.parent.CopyFrom(pkey(10))
    ne.ebpf.exec.filename = "/bin/sh"
    [ob] = X.observations(ne)
    assert (ob.actor.uid.split("/")[2], ob.obj.uid.split("/")[2], ob.label) == ("10", "11", "proc.exec")


def test_a_socket_connect_reaches_a_class_only_endpoint():
    ne = F.ebpf(1, "net.connect")
    ne.ebpf.process.CopyFrom(pkey(10))
    ne.ebpf.socket.op = ebpf_pb2.SocketOp.Value("CONNECT")
    ne.ebpf.socket.remote.ip, ne.ebpf.socket.remote.port, ne.ebpf.socket.remote.protocol = "10.0.0.9", 443, 6
    [ob] = X.observations(ne)
    assert (ob.obj.type, ob.obj.name, ob.obj.status) == ("NETWORK_ENDPOINT", "10.0.0.9:443/6", X.CLASS_ONLY)


def test_no_edge_from_entities_that_merely_appear_together():
    ne = F.ebpf(1, "priv.creds", process="p1", host_process="h1")   # entities named, no actor/object fields
    ne.ebpf.privilege.op = 0
    assert X.observations(ne) == []
    bare = F.ebpf(1, "file.read", process="p1", host_process="h1")  # no process key: no actor
    # agent_fixtures.ebpf fills in a process key by default since c6682f6 (2026-10-22); clear it so
    # the event really has none, as this test means.
    for k in ("process", "parent", "lineage_root"):
        bare.ebpf.ClearField(k)
    bare.ebpf.file_access.file.resolved_path = "/x"
    assert X.observations(bare) == []


def test_audit_principal_to_object_with_verb_and_subresource():
    env = F.audit(1, verb="get", resource="secrets", namespace="shop", name="db-pass", subresource="")
    [ob] = X.observations(env.normalized_event)
    assert (ob.actor.type, ob.actor.namespace, ob.actor.name) == ("SERVICE_ACCOUNT", "shop", "checkout")
    assert (ob.obj.type, ob.obj.name, ob.label) == ("K8S_OBJECT", "db-pass", "get")
    exec_ = F.audit(1, verb="create", resource="pods", name="web-1", subresource="exec")
    assert X.observations(exec_.normalized_event)[0].label == "create/exec"


def test_a_failed_authentication_comes_from_its_observed_source():
    [ob] = X.observations(F.audit(1, failed=True, observed_source="203.0.113.7").normalized_event)
    assert (ob.actor.type, ob.actor.name) == ("UNAUTHENTICATED_SOURCE", "203.0.113.7")


def test_gateway_peer_to_request_to_route():
    env = F.gateway(1, request_id="req-9")
    g = env.normalized_event.gateway
    g.peer_ip, g.method, g.route, g.path = "198.51.100.4", "POST", "checkout", "/pay"
    a, b = X.observations(env.normalized_event)
    assert (a.actor.name, a.obj.uid, a.label) == ("198.51.100.4", "req-9", "POST")
    assert (b.actor.uid, b.obj.name, b.label) == ("req-9", "checkout", "routed_to")


def test_db_flow_and_admission_records():
    db = F.db_read(1, source="10.1.0.7")
    assert X.observations(db.normalized_event) == []           # no object named: no edge
    db.normalized_event.db_audit.database, db.normalized_event.db_audit.object_name = "shop", "customers"
    [d] = X.observations(db.normalized_event)
    assert (d.actor.name, d.obj.type, d.obj.name, d.label) == ("10.1.0.7:0/0", "DB_OBJECT", "shop.customers", "SELECT")
    [p] = X.observations(F.path_flow(1, 2).normalized_event)
    assert (p.actor.name, p.obj.name, p.label) == ("10.1.0.7:0/0", "198.51.100.9:443/0", "flow")
    kv = F.kyverno(1)
    kv.normalized_event.kyverno.resource_kind = "Pod"
    [k] = X.observations(kv.normalized_event)
    assert (k.actor.type, k.actor.uid, k.obj.type, k.label) == ("POD", "pod-checkout-1", "IMAGE", "admission:FAIL")


def test_context_pod_state_and_rbac_bindings():
    _t, env = F.pod(1)
    o = env.context_observation
    o.pod.node_name, o.pod.service_account = "node-1", "checkout"
    labels = sorted(ob.label for ob in X.observations(norm_ctx(o)))
    assert labels == ["owned_by", "runs_as", "runs_on"]
    _t, env = F.rbac_obj(1, "RoleBinding", "rb-1", "uid-rb", namespace="shop",
                         subjects=[("ServiceAccount", "checkout", "shop")], role_ref=("Role", "reader"))
    [ob] = X.observations(norm_ctx(env.context_observation))
    assert (ob.actor.type, ob.obj.type, ob.obj.name, ob.label) == ("SERVICE_ACCOUNT", "RBAC_OBJECT", "reader", "bound_to")


# --- merging ---------------------------------------------------------------------------
def test_repeats_merge_into_one_edge_and_every_event_stays(store):
    A.apply_batch(store, batch(file_read(1), file_read(5), file_read(3)))
    [e] = observed(store)
    assert (e["count"], e["first_t"], e["last_t"]) == (3, F.ns(1), F.ns(5))
    assert len([r for r in store.rows("edge_events") if r["edge_id"] == e["edge_id"]]) == 3
    assert len(store.rows("events")) == 3


def test_only_true_repeats_merge(store):
    unresolved = file_read(2, gaps=("JOIN_UNCERTAIN",))
    A.apply_batch(store, batch(file_read(1), file_read(2, path="/etc/hosts", ino=43), unresolved))
    edges = observed(store)
    assert len(edges) == 3
    assert sorted(e["identity_status"] for e in edges) == ["unresolved", "weak", "weak"]


def test_trusted_and_degraded_never_share_an_edge(store):
    A.apply_batch(store, batch(incident("in-1", epochs=[(F.NODE, F.BOOT, 10, "c1b")]), topic=INC))
    A.apply_batch(store, batch(file_read(1, ingest=2), file_read(11, ingest=12)))
    edges = {e["trust"]: e for e in observed(store)}
    assert set(edges) == {"trusted", "degraded"} and edges["trusted"]["count"] == edges["degraded"]["count"] == 1


def _shape(store):
    return sorted((e["edge_id"], e["trust"], e["count"], e["first_t"], e["last_t"], e["closed_seq"] is None)
                  for e in store.rows("edges") if e["count"])


def test_arrival_order_never_changes_the_graph(store):
    evs = [file_read(t, ingest=t + 1) for t in (1, 4, 8, 11, 15)]
    inc = incident("in-1", epochs=[(F.NODE, F.BOOT, 10, "c1b")])
    A.apply_batch(store, batch(inc, topic=INC))
    A.apply_batch(store, batch(*evs))
    want = _shape(store)
    for seed in range(3):                       # epoch after some or all events: re-split must agree
        other = MemoryStore()
        recs = [(NORM, 0, i, e) for i, e in enumerate(evs)] + [(INC, 0, 0, inc)]
        random.Random(seed).shuffle(recs)
        for r in recs:
            A.apply_batch(other, [r])
        assert _shape(other) == want


def test_witness_edges_follow_status_and_never_merge(store):
    A.apply_batch(store, batch(witness("wt-1", "f1", "f2"), witness("wt-2", "f1", "f2"), topic=WIT))
    wit = [e for e in store.rows("edges") if e["edge_type"] == "CONFIRMED_WITNESS"]
    assert len(wit) == 2                        # same findings, two witnesses: two edges
    A.apply_batch(store, batch(witness("wt-1", "f1", "f2", status="REJECTED"), topic=WIT, start=2))
    closed = {e["witness_id"]: e["closed_seq"] for e in store.rows("edges") if e["edge_type"] == "CONFIRMED_WITNESS"}
    assert closed["wt-1"] is not None and closed["wt-2"] is None
    A.apply_batch(store, batch(witness("wt-1", "f1", "f2", status="REJECTED"), topic=WIT, start=3))
    assert len(store.rows("witnesses")) == 3    # an identical republish adds nothing


def test_findings_name_their_entities(store):
    A.apply_batch(store, batch(finding("f1", ("POD", "pod-1"), ("SERVICE_ACCOUNT", "sa-1")), topic=FND))
    inv = [e for e in store.rows("edges") if e["label"] == "involves"]
    assert len(inv) == 2 and all(e["finding_id"] == "f1" for e in inv)


def test_a_finding_and_its_witnesses_share_one_node(store):
    A.apply_batch(store, batch(witness("w1", "f1", "f2"), topic=WIT))
    A.apply_batch(store, batch(finding("f1", ("POD", "pod-1")), finding("f2"), topic=FND))
    findings = [n["node_id"] for n in store.rows("nodes") if n["node_type"] == "FINDING"]
    assert len(findings) == 2
    [inv] = [e for e in store.rows("edges") if e["label"] == "involves"]
    [link] = [e for e in store.rows("edges") if e["edge_type"] == "CONFIRMED_WITNESS"]
    assert inv["src"] == link["src"]


def test_one_uid_named_differently_by_two_sources_is_one_node(store):
    gw = F.gateway(1, request_id="req-17")
    g = gw.normalized_event.gateway
    g.method, g.path, g.peer_ip = "GET", "/checkout", "10.1.0.7"
    A.apply_batch(store, batch(gw))
    A.apply_batch(store, batch(finding("f1", ("HTTP_REQUEST", "req-17")), topic=FND))     # entity has no name
    [req] = [n for n in store.rows("nodes") if n["node_type"] == "HTTP_REQUEST"]
    assert (req["uid"], req["name"]) == ("req-17", "GET /checkout")
    [inv] = [e for e in store.rows("edges") if e["label"] == "involves"]
    assert inv["dst"] == req["node_id"]
    assert {e["src"] for e in store.rows("edges") if e["label"] == "GET"} == {X.node("NETWORK_ENDPOINT",
                                                                                     name="10.1.0.7").id}
    assert req["node_id"] in {e["dst"] for e in store.rows("edges") if e["label"] == "GET"}


def _named(fid, name, strength):
    env = finding(fid)
    env.finding.entities.add(type=common_pb2.EntityType.Value("POD"), uid="pod-1", namespace="shop", name=name,
                             strength_class=common_pb2.StrengthClass.Value(strength))
    return env


def test_node_labels_do_not_depend_on_arrival_order(store):
    recs = [_named("f1", "web-b", "STRENGTH_HIGH"), _named("f2", "", "STRENGTH_HIGH"),
            _named("f3", "web-a", "STRENGTH_MEDIUM")]
    for k, env in enumerate(recs):                       # one batch each, so stored rows are merged too
        A.apply_batch(store, batch(env, topic=FND, start=k))
    [pod] = [n for n in store.rows("nodes") if n["node_type"] == "POD"]
    assert (pod["name"], pod["namespace"], pod["identity_status"]) == ("web-a", "shop", "weak")
    other = MemoryStore()
    A.apply_batch(other, batch(*reversed(recs), topic=FND))
    assert [n for n in other.rows("nodes") if n["node_type"] == "POD"] == [dict(pod, first_seq=1)]


def test_open_incident_changes_are_kept_as_separate_records(store):
    A.apply_batch(store, batch(incident("in-1", members=("f1", "f2")), incident("in-1", members=("f1", "f2", "f3")),
                               incident("in-1", members=("f1", "f2", "f3")), topic=INC))
    rows = store.rows("incident_records")
    assert len(rows) == 2 and {r["version"] for r in rows} == {1}


# --- batches ---------------------------------------------------------------------------
def test_a_batch_applied_twice_changes_nothing(store):
    recs = batch(file_read(1), file_read(2), file_read(3))
    A.apply_batch(store, recs)
    before = (_shape(store), len(store.rows("edge_events")), len(store.rows("events")))
    A.apply_batch(store, recs)
    assert (_shape(store), len(store.rows("edge_events")), len(store.rows("events"))) == before


def test_a_failed_batch_leaves_no_rows_and_no_offsets(store, monkeypatch):
    A.apply_batch(store, batch(file_read(1)))
    real = A._finding

    def boom(*a, **k):
        raise RuntimeError("crash mid-batch")
    monkeypatch.setattr(A, "_finding", boom)
    with pytest.raises(RuntimeError):
        A.apply_batch(store, batch(file_read(2), start=1) + batch(finding("f1"), topic=FND))
    assert len(store.rows("events")) == 1 and store.offsets() == {(NORM, 0): 0}
    monkeypatch.setattr(A, "_finding", real)
    A.apply_batch(store, batch(file_read(2), start=1) + batch(finding("f1"), topic=FND))
    assert len(store.rows("events")) == 2 and store.offsets() == {(NORM, 0): 1, (FND, 0): 0}


def test_offsets_record_the_last_applied_offset_per_partition(store):
    A.apply_batch(store, [(NORM, 0, 7, file_read(1)), (NORM, 1, 3, file_read(2)), (NORM, 0, 9, file_read(3))])
    A.apply_batch(store, [(NORM, 0, 4, file_read(1))])     # an older offset never moves it back
    assert store.offsets() == {(NORM, 0): 9, (NORM, 1): 3}


def test_edge_hash_covers_edges_only():
    """Exp. 5 compares live runs by edge_hash: an extra intermediate record
    (here an open incident revised without a version bump) changes
    graph_hash, never edge_hash; a different edge changes both."""
    from mtcore.tgs.hashes import edge_hash, graph_hash
    base = [file_read(1), file_read(2, path="/etc/passwd")]
    a, b, c = MemoryStore(), MemoryStore(), MemoryStore()
    A.apply_batch(a, batch(*base))
    A.apply_batch(b, batch(*base))
    A.apply_batch(b, batch(incident("in-1", members=("f1",)), topic=INC))
    A.apply_batch(c, batch(*base, file_read(3, path="/etc/hosts")))
    assert edge_hash(a) == edge_hash(b) and graph_hash(a) != graph_hash(b)
    assert edge_hash(a) != edge_hash(c)
