"""TGS build step 6d: the Exp. 5 list and graph read interfaces and their
tool wrapper (tgs-contract.md section 6). Every test runs on the memory
store and on Postgres; the read-only role test needs $MT_TGS_READER_DSN."""
import json
import os

import agent_fixtures as F
import jsonschema
import pytest
from microtrace.v0 import common_pb2, envelope_pb2

import test_tgs_ingest as T
import test_tgs_snapshot as TS
from test_tgs_ingest import store  # noqa: F401  (memory and Postgres stores)
from mtcore.tgs import apply as A
from mtcore.tgs import interfaces as I
from mtcore.tgs import tools
from mtcore.tgs.extract import finding_node
from mtcore.tgs.hashes import graph_hash
from mtcore.tgs.hypotheses import generate
from mtcore.tgs.store import DATA_TABLES, SCHEMA_VERSION, PgStore, ReadOnlyStore

RUN = "run-leak-marker"        # Envelope.run.run_id on every record; must never reach a result
NORM, FND, WIT, INC, SC = T.NORM, T.FND, T.WIT, T.INC, "source.completeness.v0"


def iso(sec):
    return I._ts(F.ns(sec))


def mark(env):
    env.run.run_id = RUN
    return env


def fnd(fid, ftype, agent, start, entities=(), inputs=()):
    env = envelope_pb2.Envelope(schema_major=0, kind=envelope_pb2.RecordKind.Value("FINDING"), logical_id=fid)
    f = env.finding
    f.finding_id, f.finding_type, f.agent_id = fid, ftype, agent
    f.event_start.CopyFrom(F.ts(start))
    for etype, uid, ns, name in entities:
        f.entities.add(type=common_pb2.EntityType.Value(etype), uid=uid, namespace=ns, name=name,
                       strength_class=common_pb2.StrengthClass.Value("STRENGTH_HIGH"))
    f.input_event_ids.extend(inputs)
    return mark(env)


def wit(wid, a, b, t, status="CONFIRMED", contradictions=()):
    env = T.witness(wid, a, b, status)
    env.witness.source_event_time.CopyFrom(F.ts(t))
    env.witness.target_event_time.CopyFrom(F.ts(t + 1))
    for cid, detail in contradictions:
        env.witness.contradictions.add(contradiction_id=cid, decisive=True, detail=detail)
    return mark(env)


class Feed:
    """Applies records with increasing offsets per topic, one batch each."""

    def __init__(self, store):
        self.store, self.off = store, {}

    def __call__(self, topic, *envs):
        recs = []
        for env in envs:
            k = self.off.get(topic, 0)
            self.off[topic] = k + 1
            recs.append((topic, 0, k, mark(env)))
        A.apply_batch(self.store, recs)


@pytest.fixture
def world(store):
    """Three findings in one incident (v1: f1, f2; v2: f1, f2, f3), two
    confirmed witnesses and one rejected one with contradictions, three file
    reads on one edge (the third after v1), two coverage records and the
    ANALYST hypotheses for v2."""
    feed = Feed(store)
    ev1, ev2, ev3 = T.file_read(1), T.file_read(3), T.file_read(50)
    feed(NORM, ev1, ev2)
    feed(FND, fnd("f1", "D1", "agent-d", 1, [("POD", "pod-a", "shop", "web"),
                                             ("SERVICE_ACCOUNT", "sa-checkout", "shop", "checkout")],
                  [ev1.normalized_event.event_id]),
         fnd("f2", "B1", "agent-b", 5, [("POD", "pod-b", "billing", "api"), ("USER", "alice", "", "alice")]),
         fnd("f3", "G1b", "agent-g", 9, [("POD", "pod-a", "shop", "web")]))
    feed(WIT, wit("w12", "f1", "f2", 1),
         wit("wx", "f1", "f3", 2, status="REJECTED", contradictions=[("c1", "pid reused")]))
    feed(INC, TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",), version=1))
    feed(WIT, wit("w23", "f2", "f3", 5),
         wit("wx", "f1", "f3", 2, status="REJECTED", contradictions=[("c1", "pid reused"), ("c2", "late")]))
    feed(NORM, ev3)
    feed(SC, F.loss(10, 20, source="AUDIT", reason="SOURCE_IDLE")[1], F.loss(100, 110, source="GATEWAY")[1])
    feed(INC, TS.inc("in-1", members=("f1", "f2", "f3"), witnesses=("w12", "w23"), version=2))
    generate(store, "in-1")
    return store, [e.normalized_event.event_id for e in (ev1, ev2, ev3)]


def ids(result, key="finding_id"):
    return [it[key] for it in result["items"]]


# --- session layer ---------------------------------------------------------------------
@pytest.mark.parametrize("name, args", [
    ("list_findings", {"page": "x"}),
    ("list_findings", {"color": 1}),
    ("list_findings", {"time_from": "yesterday"}),
    ("list_findings", {"time_from": "2026-13-40T00:00:00Z"}),           # matches the pattern, no such date
    ("list_findings", {"time_from": "2026-01-01T00:00:00Z\n"}),         # "$" also matches before a newline
    ("list_witnesses", {"ids": ["w1"] * 2}),
    ("neighbours", {"node": "f1", "edge_types": ["ALL"]}),
    ("confirmed_path", {"finding_a": "f1", "finding_b": "f2", "as_of_version": 1}),   # version needs an incident
])
def test_bad_arguments_are_logged_as_failed_operations(world, name, args):
    s = I.Session(world[0])
    assert s.call(name, args)["error"].startswith("invalid arguments")
    [e] = s.log
    assert (e["function"], e["records"], e["arguments"]) == (name, 0, args)


def test_a_session_is_limited_to_its_interface(world):
    s = I.Session(world[0], calls=I.LIST_CALLS)
    assert "not part of this interface" in s.get_incident(incident_id="in-1")["error"]
    assert "not part of this interface" in s.call("drop_table", {})["error"]
    assert s.operations == 2


def test_the_call_budget_stops_further_calls(world):
    s = I.Session(world[0], max_calls=2)
    s.list_findings()
    s.get_finding(finding_id="nope")              # a failed call still counts
    with pytest.raises(I.BudgetExceeded):
        s.list_findings()
    assert json.loads(tools.call_tool(s, "list_findings", {}))["error"] == "call budget of 2 spent"
    assert s.operations == 2


def test_the_budget_also_stops_calls_outside_the_interface(world):
    s = I.Session(world[0], max_calls=1, calls=I.LIST_CALLS)
    s.list_findings()
    with pytest.raises(I.BudgetExceeded):
        s.get_incident(incident_id="in-1")
    assert s.operations == 1


def test_an_unexpected_error_is_logged_and_raised(world, monkeypatch):
    store, _ = world
    s = I.Session(store)

    def broken(*_a, **_k):
        raise RuntimeError("connection lost")

    monkeypatch.setattr(store, "select", broken)
    with pytest.raises(RuntimeError):
        s.list_findings()
    assert [(e["function"], e["records"], e["error"]) for e in s.log] == [
        ("list_findings", 0, "internal error: RuntimeError")]


def test_every_call_is_logged_with_its_record_count(world, tmp_path):
    log = tmp_path / "calls.jsonl"
    s = I.Session(world[0], log_path=str(log))
    s.list_findings()
    s.get_finding(finding_id="f1")
    s.confirmed_path(finding_a="f1", finding_b="nope")
    lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert lines == s.log
    assert [(e["op"], e["function"], e["records"], e["error"]) for e in lines] == [
        (1, "list_findings", 3, None), (2, "get_finding", 1, None), (3, "confirmed_path", 0, None)]
    assert all(e["duration_ms"] >= 0 for e in lines) and s.records == 4


def test_the_read_only_store_has_no_write_methods(world):
    ro = I.Session(world[0]).store
    assert isinstance(ro, ReadOnlyStore)
    for name in ("insert_record", "insert_event", "insert_node", "upsert_edge", "insert_snapshot", "apply_schema",
                 "log_apply", "set_offset", "begin", "commit", "rollback", "truncate"):
        with pytest.raises(AttributeError):
            getattr(ro, name)


def test_select_rejects_unknown_tables_and_columns(store):
    for args in (("findings; drop table x", {}), ("findings", {"1=1 or finding_id": "x"})):
        with pytest.raises(ValueError):
            store.select(args[0], equals=args[1])
    with pytest.raises(ValueError):
        store.select("findings", order_by=["-envelope; select 1"])


# --- list interface --------------------------------------------------------------------
def test_list_findings_in_event_time_order_with_each_filter(world):
    s = I.Session(world[0])
    assert ids(s.list_findings()) == ["f1", "f2", "f3"]
    assert ids(s.list_findings(agent="agent-d")) == ["f1"]
    assert ids(s.list_findings(finding_type="B1")) == ["f2"]
    assert ids(s.list_findings(time_from=iso(4))) == ["f2", "f3"]
    assert ids(s.list_findings(time_to=iso(4))) == ["f1"]
    assert ids(s.list_findings(namespace="shop")) == ["f1", "f3"]
    assert ids(s.list_findings(pod_uid="pod-a")) == ["f1", "f3"]
    assert ids(s.list_findings(identity="checkout")) == ids(s.list_findings(identity="sa-checkout")) == ["f1"]
    assert ids(s.list_findings(identity="alice")) == ["f2"]
    assert ids(s.list_findings(pod_uid="pod-a", identity="alice")) == []
    assert ids(s.list_findings(pod_uid="pod-unknown")) == []
    [f1] = s.list_findings(agent="agent-d")["items"]
    assert f1["event_start"] == iso(1) and {e["uid"] for e in f1["entities"]} == {"pod-a", "sa-checkout"}


def test_list_findings_pages_of_fifty(store):
    Feed(store)(FND, *[fnd(f"f{k:03d}", "D1", "agent-d", k) for k in range(I.PAGE + 1)])
    s = I.Session(store)
    p0, p1 = s.list_findings(), s.list_findings(page=1)
    assert len(p0["items"]) == I.PAGE and p0["more"] and ids(p1) == [f"f{I.PAGE:03d}"] and not p1["more"]
    assert [e["records"] for e in s.log] == [I.PAGE, 1]


def test_get_finding_and_get_event(world):
    store, (ev1, _ev2, _ev3) = world
    s = I.Session(store)
    r = s.get_finding(finding_id="f1")
    assert r["finding"]["finding_id"] == "f1" and r["evidence_event_ids"] == [ev1]
    assert s.get_event(event_id=ev1)["event"]["event_id"] == ev1
    assert s.get_event(event_id="nope") == {"error": "no event nope"}
    assert s.log[-1]["records"] == 0


def test_list_coverage_returns_records_overlapping_the_range(world):
    s = I.Session(world[0])
    assert [c["source"] for c in s.list_coverage()["items"]] == ["AUDIT", "GATEWAY"]
    assert [c["source"] for c in s.list_coverage(time_from=iso(15), time_to=iso(16))["items"]] == ["AUDIT"]
    assert s.list_coverage(time_from=iso(30), time_to=iso(40))["items"] == []


def test_list_witnesses_gives_the_latest_record_per_id(world):
    s = I.Session(world[0])
    assert ids(s.list_witnesses(), "witness_id") == ["w12", "wx", "w23"]          # by source event time
    [wx] = s.list_witnesses(ids=["wx"])["items"]
    assert [c["contradiction_id"] for c in wx["contradictions"]] == ["c1", "c2"]
    assert ids(s.list_witnesses(time_from=iso(4)), "witness_id") == ["w23"]


# --- graph interface -------------------------------------------------------------------
def test_get_incident_with_its_snapshot_status(world):
    s = I.Session(world[0])
    r = s.get_incident(incident_id="in-1")
    assert (r["v_c"]["version"], r["status"], r["incident"]["finding_ids"]) == (2, "current", ["f1", "f2", "f3"])
    old = s.get_incident(incident_id="in-1", as_of_version=1)
    assert (old["v_c"]["version"], old["status"]) == (1, "stale")
    assert "no record of incident in-9" in s.get_incident(incident_id="in-9")["error"]


def test_neighbours_shows_hypotheses_only_when_asked(world):
    store, _ = world
    s = I.Session(store)
    r = s.neighbours(node="f1")
    assert r["node_id"] == finding_node("f1").id
    types = {(it["edge_type"], it["label"]) for it in r["items"]}
    assert ("CONFIRMED_WITNESS", "w12") in types and ("OBSERVED", "involves") in types
    assert all(it["edge_type"] != "HYPOTHESIS" for it in r["items"])
    only = s.neighbours(node="f1", edge_types=["CONFIRMED_WITNESS"])["items"]
    assert [(it["witness_id"], it["direction"], it["other"]["uid"]) for it in only] == [("w12", "out", "f2")]
    he = next(h for h in store.select("hypothesis_edges") if h["src"].startswith("gn_") or h["dst"].startswith("gn_"))
    node = he["src"] if he["src"].startswith("gn_") else he["dst"]
    hyps = [it for it in s.neighbours(node=node, edge_types=["HYPOTHESIS"])["items"]]
    assert hyps and all(h["edge_type"] == "HYPOTHESIS" and h["unverified"] for h in hyps)
    assert s.neighbours(node=node, edge_types=["OBSERVED"], time_from=iso(1000))["items"] == []


def test_confirmed_path_follows_confirmed_witnesses_as_of_a_version(world):
    s = I.Session(world[0])
    want = {"found": True, "direction": "f1 -> f3", "finding_ids": ["f1", "f2", "f3"], "witness_ids": ["w12", "w23"]}
    assert s.confirmed_path(finding_a="f1", finding_b="f3") == want
    assert s.confirmed_path(finding_a="f3", finding_b="f1") == want            # either direction
    assert s.confirmed_path(finding_a="f1", finding_b="f3", incident_id="in-1", as_of_version=2) == want
    assert not s.confirmed_path(finding_a="f1", finding_b="f3", incident_id="in-1", as_of_version=1)["found"]
    assert s.confirmed_path(finding_a="f1", finding_b="f2", incident_id="in-1", as_of_version=1)["found"]


def test_gaps_and_contradictions(world):
    store, _ = world
    s = I.Session(store)
    r = s.gaps_and_contradictions(incident_id="in-1")
    assert (r["template"], r["status"]) == ("chain-1-token-pivot", "current")
    assert [g["stage"] for g in r["gaps"]] == ["rbac-grant"]
    [c] = r["contradictions"]
    assert (c["witness_id"], c["status"], [x["contradiction_id"] for x in c["contradictions"]]) == \
        ("wx", "REJECTED", ["c1", "c2"])
    assert [h["stage_id"] for h in r["hypotheses"]] == ["rbac-grant"] and r["hypotheses"][0]["unverified"]
    assert s.gaps_and_contradictions(incident_id="in-1", template_id="chain-3-implant")["template"] == "chain-3-implant"
    assert s.gaps_and_contradictions(incident_id="in-1", template_id="nope") == {"error": "no template nope"}


def test_graph_as_of_excludes_later_events_and_links(world):
    s = I.Session(world[0])
    v1, v2 = s.graph_as_of(incident_id="in-1", version=1), s.graph_as_of(incident_id="in-1", version=2)
    reads = [e for e in v1["edges"] if e["label"] not in ("involves",) and e["edge_type"] == "OBSERVED"]
    assert [(e["count"], e["span_last"]) for e in reads] == [(2, iso(3))]          # ev3 came after v1
    assert [e["count"] for e in v2["edges"] if e["edge_id"] == reads[0]["edge_id"]] == [3]
    assert [e["witness_id"] for e in v1["edges"] if e["edge_type"] == "CONFIRMED_WITNESS"] == ["w12"]
    assert sorted(e["witness_id"] for e in v2["edges"] if e["edge_type"] == "CONFIRMED_WITNESS") == ["w12", "w23"]
    assert finding_node("f3").id not in {n["node_id"] for n in v1["nodes"]}
    assert "no record of incident in-1 version 7" in s.graph_as_of(incident_id="in-1", version=7)["error"]


# --- security and integrity ------------------------------------------------------------
def _every_call(s, ev1):
    return [s.list_findings(), s.get_finding(finding_id="f1"), s.get_event(event_id=ev1), s.list_coverage(),
            s.list_witnesses(), s.get_incident(incident_id="in-1"), s.neighbours(node="f1", edge_types=[
                "OBSERVED", "CONFIRMED_WITNESS", "HYPOTHESIS"]),
            s.confirmed_path(finding_a="f1", finding_b="f3"), s.gaps_and_contradictions(incident_id="in-1"),
            s.graph_as_of(incident_id="in-1", version=2)]


def test_no_result_carries_the_run_id_and_no_call_changes_the_store(world):
    store, (ev1, _, _) = world
    before = graph_hash(store), store.rows("hypotheses"), store.rows("snapshots"), store.offsets()
    results = _every_call(I.Session(store), ev1)
    assert all("error" not in r for r in results)
    text = json.dumps(results, default=str)
    assert RUN not in text and "run_id" not in text
    assert (graph_hash(store), store.rows("hypotheses"), store.rows("snapshots"), store.offsets()) == before


def test_a_timed_out_query_is_a_failed_call_and_the_next_call_works(world, monkeypatch):
    store, _ = world
    if not isinstance(store, PgStore):
        pytest.skip("statement timeouts are a Postgres matter")

    def slow(*_a, **_k):
        store.conn.execute("SET LOCAL statement_timeout = 50")
        store.conn.execute("SELECT pg_sleep(2)")

    s = I.Session(store)
    monkeypatch.setattr(store, "select", slow)
    assert s.list_findings() == {"error": "query exceeded the time limit"}
    monkeypatch.undo()
    assert ids(s.list_findings()) == ["f1", "f2", "f3"]


def test_the_reader_role_can_read_and_cannot_write(world):
    store, _ = world
    if not isinstance(store, PgStore):
        pytest.skip("roles are a Postgres matter")
    dsn = os.environ.get("MT_TGS_READER_DSN")
    if not dsn:
        pytest.skip("MT_TGS_READER_DSN is not set (src/scripts/pg-up.sh)")
    import psycopg
    from psycopg import errors
    schema = store.conn.execute("SELECT current_schema()").fetchone()[0]
    store.conn.commit()
    with psycopg.connect(dsn) as conn:
        conn.execute(f"SET search_path TO {schema}")
        conn.commit()
        assert ids(I.Session(PgStore(conn)).list_findings()) == ["f1", "f2", "f3"]
        for table in DATA_TABLES:
            col = conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema = %s "
                               "AND table_name = %s ORDER BY ordinal_position LIMIT 1", (schema, table)).fetchone()[0]
            conn.rollback()
            for sql in (f"INSERT INTO {table} DEFAULT VALUES", f"UPDATE {table} SET {col} = {col}",
                        f"DELETE FROM {table}", f"TRUNCATE {table}"):
                with pytest.raises(errors.InsufficientPrivilege):
                    conn.execute(sql)
                conn.rollback()


# --- tool wrapper ----------------------------------------------------------------------
def test_tools_mirror_the_two_interfaces():
    assert [t["name"] for t in tools.LIST_TOOLS] == list(I.LIST_CALLS)
    assert [t["name"] for t in tools.GRAPH_TOOLS] == list(I.GRAPH_CALLS)
    for t in tools.LIST_TOOLS + tools.GRAPH_TOOLS:
        jsonschema.Draft202012Validator.check_schema(t["input_schema"])
        assert t["description"].endswith(tools.DATA_NOTE)


def test_call_tool_returns_json_for_results_and_errors(world):
    s = I.Session(world[0], calls=I.GRAPH_CALLS)
    r = json.loads(tools.call_tool(s, "confirmed_path", {"finding_a": "f1", "finding_b": "f3"}))
    assert r["witness_ids"] == ["w12", "w23"]
    assert "not part of this interface" in json.loads(tools.call_tool(s, "list_findings", {}))["error"]
    assert "invalid arguments" in json.loads(tools.call_tool(s, "neighbours", "not an object"))["error"]
    assert s.operations == 3



# --- review regressions ----------------------------------------------------------------
def test_a_superseded_witness_record_never_answers_a_time_query(store):
    feed = Feed(store)
    feed(WIT, wit("wy", "f1", "f2", 2))
    feed(WIT, wit("wy", "f1", "f2", 50, status="REJECTED"))
    s = I.Session(store)
    assert s.list_witnesses(time_to=iso(10))["items"] == []
    assert [w["status"] for w in s.list_witnesses(time_from=iso(40))["items"]] == ["REJECTED"]
    assert s.list_witnesses(ids=[])["items"] == []


def test_a_coverage_record_without_an_end_meets_every_later_range(store):
    Feed(store)(SC, F.loss(30, None, source="AUDIT")[1], F.loss(1, 5, source="GATEWAY")[1])
    s = I.Session(store)
    assert [c["source"] for c in s.list_coverage(time_from=iso(100), time_to=iso(200))["items"]] == ["AUDIT"]
    assert [c["source"] for c in s.list_coverage(time_to=iso(10))["items"]] == ["GATEWAY"]


def test_neighbours_are_in_time_order(store):
    feed = Feed(store)
    pod = [("POD", "pod-z", "shop", "z")]
    feed(FND, fnd("fb", "D1", "agent-d", 1.5, pod), fnd("fa", "D1", "agent-d", 1, pod), fnd("fc", "D1", "agent-d", 10, pod))
    [node] = [n["node_id"] for n in store.select("nodes", equals={"uid": "pod-z"})]
    items = I.Session(store).neighbours(node=node)["items"]
    assert [it["other"]["uid"] for it in items] == ["fa", "fb", "fc"]


def test_graph_as_of_keeps_events_on_the_edge_they_had_before_a_later_epoch(store):
    feed = Feed(store)
    ev1, ev11 = T.file_read(1, ingest=2), T.file_read(11, ingest=12)
    feed(NORM, ev1, ev11)
    feed(FND, fnd("f1", "D1", "agent-d", 1, inputs=[ev1.normalized_event.event_id, ev11.normalized_event.event_id]),
         fnd("f2", "B1", "agent-b", 5))
    feed(INC, TS.inc("in-1", members=("f1", "f2"), version=1))
    feed(INC, T.incident("in-2", members=("f8", "f9"), epochs=[(F.NODE, F.BOOT, 10, "f9")]))   # moves ev11
    feed(INC, TS.inc("in-1", members=("f1", "f2"), version=2))
    s = I.Session(store)

    def reads(version):
        g = s.graph_as_of(incident_id="in-1", version=version)
        return sorted((e["trust"], e["count"]) for e in g["edges"] if e["edge_type"] == "OBSERVED"
                      and e["label"] != "involves")

    assert reads(1) == [("trusted", 2)]
    assert reads(2) == [("degraded", 1), ("trusted", 1)]


def test_a_store_built_under_an_older_schema_is_refused_until_rebuilt(store):
    if not isinstance(store, PgStore):
        pytest.skip("schema versions are a Postgres matter")
    Feed(store)(NORM, T.file_read(1))
    store.conn.execute("INSERT INTO schema_version VALUES ('tgs-schema-3')")
    store.conn.commit()
    with pytest.raises(RuntimeError, match="--reset"):
        store.apply_schema()
    store.apply_schema(rebuilding=True)
    store.reset()
    store.apply_schema()
    assert [r["version"] for r in store._all("SELECT version FROM schema_version")] == [SCHEMA_VERSION]
