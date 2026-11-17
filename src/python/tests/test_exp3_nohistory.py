"""Exp. 3 No-History identity variant (mtcore.exp3.nohistory, mtcore.exp3.base --variant no_history).

No Kafka needed. The generator-equivalence test (a real mtgen build with the latest-mapping
resolver, tests/exp3_nohistory_gsim.py, against the transform of a normal build) builds two runs
and runs only when MT_NOHIST_EQUIV_DIR names a scratch directory for them (~30 s, ~0.3 GB).
"""
import hashlib
import json
import os
import subprocess
import sys

import pytest

import mtcore  # noqa: F401  (generated protobuf path)
from google.protobuf import json_format
from microtrace.v0 import (audit_pb2, common_pb2, context_pb2, ebpf_pb2, envelope_pb2,
                           normalized_pb2, offnode_pb2)
from google.protobuf.timestamp_pb2 import Timestamp

from mtcore.agents.context import ContextHistory
from mtcore.exp3 import base as B
from mtcore.exp3 import nohistory as NH
from mtcore.exp3 import plans as PL

T0 = 1_704_067_200_000_000_000
S = 1_000_000_000
IP = "10.9.0.5"
POD_A, POD_B = "pod-a-uid", "pod-b-uid"
NS = "ns-x"


def ts(ns):
    return Timestamp(seconds=ns // S, nanos=ns % S)


def line(topic, env, key_components, key_type="KEY_PRIMARY_ENTITY", lane="NORMAL"):
    d = json.loads(json.dumps(json_format.MessageToDict(env, preserving_proto_field_name=True), sort_keys=True))
    return {"lane": lane, "topic": topic, "key_type": key_type, "key_components": key_components, "envelope": d}


def ctx_pod(uid, name, workload, t, ip=IP, seq=1):
    o = context_pb2.ObjectObservation(kind="Pod", namespace=NS, name=name, uid=uid, resource_version=f"rv-{seq}",
                                      change_type=context_pb2.ADDED, observed_time=ts(t),
                                      watch_stream_id="watch-pods", watch_stream_seq=seq)
    o.pod.pod_ips.append(ip)
    o.pod.owners.add(namespace=NS, name=workload)
    env = envelope_pb2.Envelope(kind=envelope_pb2.CONTEXT_OBSERVATION, logical_id=f"ctx-{uid}",
                                source=common_pb2.CLUSTER_CONTEXT, context_observation=o)
    return line("context.cluster.v0", env, [uid], "KEY_OBJECT_UID")


def ne_env(ne):
    return envelope_pb2.Envelope(kind=envelope_pb2.NORMALIZED_EVENT, logical_id=ne.event_id, source=ne.source,
                                 normalized_event=ne)


def gap(scope):
    return common_pb2.Gap(reason=common_pb2.JOIN_UNCERTAIN, scope=scope, detail="ambiguous")


def ebpf_connect(eid, t, resolved, ambiguous=False):
    ne = normalized_pb2.NormalizedEvent(event_id=eid, source=common_pb2.EBPF)
    ne.time.event_time.CopyFrom(ts(t))
    ne.ebpf.event_family = "net.connect"
    ne.ebpf.node_id = "node-1"
    ne.ebpf.socket.remote.ip = IP
    ne.ebpf.socket.remote.port = 8080
    ne.ebpf_derived.pod_uid = "client-pod"
    ne.ebpf_derived.remote_class = "cluster_pod" if (resolved or ambiguous) else "external"
    if resolved:
        ne.ebpf_derived.remote_pod_uid = resolved
    if ambiguous:
        ne.completeness.gaps.append(gap("field=remote_pod_uid"))
    ne.entities.add(type=common_pb2.POD, uid="client-pod", strength_class=common_pb2.STRENGTH_HIGH)
    return line("norm.events.v0", ne_env(ne), ["POD", "client-pod"])


def audit_exec(eid, t, peer, target):
    ne = normalized_pb2.NormalizedEvent(event_id=eid, source=common_pb2.AUDIT)
    ne.time.event_time.CopyFrom(ts(t))
    ne.audit.verb = "create"
    ne.audit.object_ref.resource = "pods"
    ne.audit.object_ref.namespace = NS
    ne.audit.object_ref.name = "web-0"
    ne.audit_derived.observed_source = IP
    if peer:
        ne.audit_derived.peer_caller_pod_uid = peer
    if target:
        ne.audit_derived.resolved_target_pod_uid = target
    ne.entities.add(type=common_pb2.AUDIT_ACTION, uid=eid, strength_class=common_pb2.STRENGTH_HIGH)
    return line("norm.events.v0", ne_env(ne), ["AUDIT_ACTION", eid])


def path_flow(eid, t, pod):
    ne = normalized_pb2.NormalizedEvent(event_id=eid, source=common_pb2.PATH_FLOW)
    ne.time.event_time.CopyFrom(ts(t))
    ne.path_flow.src.ip = IP
    ne.path_flow.dst.ip = "203.0.113.7"
    d = ne.offnode_derived
    d.source_address = IP
    d.remote_class = "external"
    if pod:
        d.source_address_class = offnode_pb2.POD_ADDRESS
        d.pod_uid = pod
        ne.entities.add(type=common_pb2.POD, uid=pod, strength_class=common_pb2.STRENGTH_HIGH)
        key = ["POD", pod]
    else:
        d.source_address_class = offnode_pb2.NODE_HOST_CONTEXT
        ne.entities.add(type=common_pb2.NETWORK_ENDPOINT, uid=IP, strength_class=common_pb2.STRENGTH_HIGH)
        key = ["NETWORK_ENDPOINT", IP]
    return line("norm.events.v0", ne_env(ne), key)


def fixture_lines():
    """IP 10.9.0.5 and Pod name web-0 held by Pod A (workload wa) from t0+1 s, then reused by Pod B
    (workload wb) from t0+100 s; records resolved by history before, at and after the reuse."""
    return [
        ctx_pod(POD_A, "web-0", "wa", T0 + 1 * S, seq=1),
        ctx_pod(POD_B, "web-0", "wb", T0 + 100 * S, seq=2),
        ebpf_connect("e-before", T0 + 50 * S, POD_A),
        ebpf_connect("e-ambig", T0 + 101 * S, None, ambiguous=True),
        ebpf_connect("e-after", T0 + 150 * S, POD_B),
        ebpf_connect("e-unseen", T0, None),                 # before any Pod held the IP: external
        audit_exec("a-before", T0 + 50 * S, POD_A, POD_A),
        path_flow("f-before", T0 + 50 * S, POD_A),
        path_flow("f-unseen", T0, None),
        {"lane": "NORMAL", "watermark": "2024-01-01T00:00:00.000000000Z"},
    ]


def latest(lines):
    m = NH.LatestMap()
    for o in lines:
        m.add_line(o)
    return m


def ne_of(o):
    return o["envelope"]["normalized_event"]


def test_reused_ip_and_name_resolve_to_the_latest_pod_everywhere():
    lines = fixture_lines()
    m = latest(lines)
    out = {}
    for o in lines:
        new = NH.transform_line(o, m)
        res = new or o
        if "envelope" in res and "normalized_event" in res["envelope"]:
            out[ne_of(res)["event_id"]] = (res, new is not None)
    for eid in ("e-before", "e-ambig", "e-after", "e-unseen"):
        d = ne_of(out[eid][0])
        assert d["ebpf_derived"]["remote_pod_uid"] == POD_B, eid
        assert d["ebpf_derived"]["remote_class"] == "cluster_pod"
        assert not d.get("completeness", {}).get("gaps"), eid          # no JOIN_UNCERTAIN under latest mapping
    assert out["e-after"][1] is False                            # already the latest: kept byte for byte
    a = ne_of(out["a-before"][0])["audit_derived"]
    assert a["peer_caller_pod_uid"] == POD_B and a["resolved_target_pod_uid"] == POD_B
    for eid in ("f-before", "f-unseen"):
        o, _ = out[eid]
        d = ne_of(o)["offnode_derived"]
        assert d["pod_uid"] == POD_B and d["source_address_class"] == "POD_ADDRESS"
        assert ne_of(o)["entities"][0] == {"strength_class": "STRENGTH_HIGH", "type": "POD", "uid": POD_B}
        assert o["key_components"] == ["POD", POD_B]
    # The agents then see workload wb for every record, also before Pod B existed (as known later).
    h = ContextHistory()
    for o in lines[:2]:
        h.add_observation(json_format.ParseDict(o["envelope"], envelope_pb2.Envelope()).context_observation)
    assert h.workload(POD_B, T0 + 200 * S) == "wb"
    # Records without identity fields, context and watermark lines never change.
    assert NH.transform_line(lines[0], m) is None and NH.transform_line(lines[-1], m) is None


def test_namespace_mismatch_clears_the_target():
    lines = fixture_lines()
    lines[1] = ctx_pod(POD_B, "web-0", "wb", T0 + 100 * S, seq=2)
    lines[1]["envelope"]["context_observation"]["namespace"] = "other-ns"
    new = NH.transform_line(lines[6], latest(lines))
    assert "resolved_target_pod_uid" not in ne_of(new)["audit_derived"]


def write_run(d, lines, truth=True):
    os.makedirs(os.path.join(d, "shipper"), exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"run_id": os.path.basename(d), "observability_profile": "clean"}, fh)
    with open(os.path.join(d, "shipper", "node-cp.jsonl"), "wb") as fh:
        for o in lines:
            fh.write(NH.dump_line(o) if "watermark" not in o else (json.dumps(o, separators=(",", ":")) + "\n").encode())
        if truth:
            fh.write(b'{"lane":"NORMAL","topic":"ground.truth.v0","envelope":{"ground_truth_action":{}}}\n')


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def test_without_the_variant_nothing_changes(tmp_path):
    run = str(tmp_path / "run-1")
    write_run(run, fixture_lines())
    m = B.export_run(run, str(tmp_path / "base"))
    assert m["variant"] is None and "variant_info" not in m
    src = [l for l in open(os.path.join(run, "shipper", "node-cp.jsonl"), "rb") if b"ground.truth" not in l]
    assert open(str(tmp_path / "base" / "run-1" / "nodes" / "node-cp.jsonl"), "rb").readlines() == src
    # and records whose resolved identity already is the latest mapping are kept as they are
    lines = fixture_lines()
    assert NH.transform_line(lines[4], latest(lines)) is None


def test_variant_export_is_deterministic_and_idempotent(tmp_path):
    run = str(tmp_path / "run-1")
    write_run(run, fixture_lines())
    outs = []
    for k in ("v1", "v2"):
        m = B.export_run(run, str(tmp_path / k), "no_history")
        assert m["variant"] == "no_history" and m["truth_removed"] == 1
        assert m["variant_info"]["records_changed"] == 6          # all but e-after and the context records
        assert B.verify_export(str(tmp_path / k / "run-1")) == []
        outs.append(sha(str(tmp_path / k / "run-1" / "nodes" / "node-cp.jsonl")))
    assert outs[0] == outs[1]
    # applying it to its own output changes nothing more
    again = str(tmp_path / "run-2")
    os.makedirs(os.path.join(again, "shipper"))
    with open(os.path.join(again, "manifest.json"), "w") as fh:
        json.dump({"run_id": "run-2"}, fh)
    import shutil
    shutil.copy(str(tmp_path / "v1" / "run-1" / "nodes" / "node-cp.jsonl"), os.path.join(again, "shipper"))
    m = B.export_run(again, str(tmp_path / "v3"), "no_history")
    assert m["variant_info"]["records_changed"] == 0


def test_templates_name_the_variant():
    conds = os.path.join(mtcore.REPO, "experiments", "exp3", "configs", "conditions.tsv")
    rows = {c["condition"]: c for c in PL.load_conditions(conds)}
    assert PL.template_base_variant(PL.template_path(conds, rows["nohistory"]["template"])) == "no_history"
    assert PL.template_base_variant(PL.template_path(conds, rows["nofault"]["template"])) is None
    base = {"run_id": "r", "nodes": [{"node": "n1", "role": "worker", "records": 1}],
            "stream_start_ns": T0, "stream_end_ns": T0 + S}
    import yaml
    t = yaml.safe_load(open(PL.template_path(conds, rows["nohistory-loss-transit-20"]["template"])))
    plans, meta = PL.instantiate(t, base)
    assert meta["base_variant"] == "no_history" and "base_variant" not in plans["n1"]
    assert plans["n1"]["faults"][0]["rate"] == 0.2


@pytest.mark.skipif(not os.environ.get("MT_NOHIST_EQUIV_DIR"), reason="set MT_NOHIST_EQUIV_DIR to build two dev runs")
def test_transform_equals_the_generator_latest_mapping_build():
    root = os.environ["MT_NOHIST_EQUIV_DIR"]
    py = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = ["build", "--world", "Small", "--duration-s", "300", "--seed", "7"]
    normal, gsim = os.path.join(root, "eq-normal"), os.path.join(root, "eq-gsim")
    subprocess.run([sys.executable, "-m", "mtgen", *args, "--out", normal], cwd=py, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, os.path.join(py, "tests", "exp3_nohistory_gsim.py"), *args, "--out", gsim],
                   cwd=py, check=True, stdout=subprocess.DEVNULL)
    t = B.export_run(normal, os.path.join(root, "eq-base-t"), "no_history")
    g = B.export_run(gsim, os.path.join(root, "eq-base-g"))
    assert t["variant_info"]["records_changed"] > 0
    assert [n["sha256"] for n in t["nodes"]] == [n["sha256"] for n in g["nodes"]]
