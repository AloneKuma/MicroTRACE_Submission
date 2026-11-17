"""Which agent topics receive a normalized event, and under which key.

The restreamer uses this to copy norm.events.v0 into the keyed agent topics
(spec/kafka/topics.yaml, "finding_inputs"); the agents use the same key bytes
as the RuleEvaluation state key. A record missing a key component is not
routed to that topic (kafka-contract.md, "Record keys").
"""
import os

import yaml

from mtcore import REPO
from mtcore.agents import events as E  # noqa: F401  (sets the import path)

import mtcodec  # noqa: E402
from microtrace.v0 import keys_pb2  # noqa: E402

TOPICS_YAML = os.path.join(REPO, "spec", "kafka", "topics.yaml")

C_FAMILIES = {"ns.change", "ns.sample", "priv.creds", "ipc.runtime_socket", "bpf.call",
              "proc.exec", "proc.fork", "proc.ptrace"}
H_LINEAGE_FAMILIES = {"file.read", "file.open", "net.connect", "net.flow_bytes"}
RBAC_GROUP = "rbac.authorization.k8s.io"


def _load_topics():
    with open(TOPICS_YAML, encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    return {t["name"]: t for t in spec["topics"]}, spec["finding_inputs"]


TOPICS, FINDING_INPUTS = _load_topics()


def _components(ev):
    """Every key component value the event can supply (None when absent)."""
    ed, ad, md, od = ev.ed, ev.ad, ev.md, ev.od
    c = {}
    if ev.gateway is not None:
        c["REQUEST_ID"] = ev.gateway.request_id or None
    if ev.principal is not None:
        c["PRINCIPAL_KIND"], c["PRINCIPAL_ID"] = ev.principal
    if ad is not None:
        c["OBSERVED_SOURCE"] = ad.observed_source or None
        c["JTI"] = E.opt(ad, "used_credential_id") or None
    if ev.audit is not None:
        c["OBJECT_UID"] = ev.audit.object_ref.uid or None
    if ed is not None:
        c["LINEAGE_ID"] = ed.lineage_id or None
        c["POD_UID"] = E.opt(ed, "pod_uid") or None
        c["CONTAINER_NAME"] = ed.container_name or None
        # Token owner: the resolved token version, else the projected-volume
        # identity the sensor reported (D1 then abstains: not in the index).
        tf = E.opt(ed, "token_file")
        if tf is None:
            f = _file(ev)
            tf = E.opt(f, "projected") if f is not None else None
        c["TOKEN_OWNER_POD_UID"] = tf.owner_pod_uid if tf is not None else None
        c["VOLUME_NAME"] = tf.volume_name if tf is not None else None
    if md is not None:
        c["POD_UID"] = E.opt(md, "pod_uid") or None
        c["CONTAINER_NAME"] = md.container_name or None
    if od is not None:
        c["SOURCE_ADDRESS"] = od.source_address or None
    return c


def _file(ev):
    d = ev.detail
    if d is None:
        return None
    return d.file if hasattr(d, "file") and d.HasField("file") else None


def _token_read(ev):
    if ev.family not in ("file.read", "file.open") or ev.ed is None:
        return False
    if ev.ed.HasField("token_file"):
        return True
    f = _file(ev)
    return f is not None and f.HasField("projected")


def _audit_is(ev, group=None, resource=None, subresource=None):
    a = ev.audit
    if a is None:
        return False
    o = a.object_ref
    return ((group is None or o.api_group == group) and (resource is None or o.resource == resource)
            and (subresource is None or o.subresource == subresource))


# topic -> (selector, key override). The override maps a key component to the
# component it is read from, for topics whose key differs from the event's
# own attribution (agent.D.read.v0 is keyed by the token owner's Pod).
ROUTES = {
    "agent.A.v0": (lambda ev: ev.gateway is not None, {}),
    "agent.B.v0": (lambda ev: ev.audit is not None and ev.principal is not None, {}),
    # Every 4xx from an observed source: B2 counts 401s and reports 403s
    # separately, never adding them.
    "agent.B.authn.v0": (lambda ev: ev.audit is not None and ev.ad is not None
                         and (ev.ad.authentication_failed or 400 <= ev.audit.response_code < 500), {}),
    "agent.C.v0": (lambda ev: ev.family in C_FAMILIES, {}),
    "agent.D.read.v0": (_token_read, {"POD_UID": "TOKEN_OWNER_POD_UID"}),
    "agent.D.use.v0": (lambda ev: ev.audit is not None and ev.ad is not None
                       and ev.ad.HasField("used_credential_id"), {}),
    "agent.E.v0": (lambda ev: ev.kyverno is not None or ev.family in ("file.mutation", "proc.exec"), {}),
    "agent.F.runtime.v0": (lambda ev: ev.family == "priv.creds", {}),
    "agent.F.rbac.v0": (lambda ev: _audit_is(ev, group=RBAC_GROUP), {}),
    "agent.G.v0": (lambda ev: ev.family in ("net.connect", "net.accept", "proc.exec")
                   or _audit_is(ev, group="", resource="pods", subresource="exec"), {}),
    "agent.H.egress.v0": (lambda ev: ev.family in ("net.connect", "net.flow_bytes"), {}),
    "agent.H.lineage.v0": (lambda ev: ev.family in H_LINEAGE_FAMILIES, {}),
    "agent.H.audit.v0": (lambda ev: _audit_is(ev, group="", resource="secrets") and ev.principal is not None, {}),
    "agent.H.offnode.v0": (lambda ev: ev.db is not None or ev.flow is not None, {}),
}


def key_components(topic, ev):
    """Ordered (component_name, value) for topic, or None if any is absent."""
    spec = TOPICS[topic]
    comps = _components(ev)
    # G2: an exec audit event is keyed by its resolved target Pod.
    if topic == "agent.G.v0" and ev.audit is not None:
        comps["POD_UID"] = E.opt(ev.ad, "resolved_target_pod_uid") if ev.ad is not None else None
    override = ROUTES.get(topic, (None, {}))[1]
    out = []
    for name in spec["key_components"]:
        value = comps.get(override.get(name, name))
        if not value:
            return None
        out.append((name, value))
    return out


def encode(topic, components):
    spec = TOPICS[topic]
    kt = keys_pb2.KeyType.Value(spec["key_type"])
    return mtcodec.encode_key(kt, [(keys_pb2.KeyComponent.Value(n), v) for n, v in components])


def key_bytes(topic, ev):
    comps = key_components(topic, ev)
    return None if comps is None else encode(topic, comps)


def routes(ev):
    """[(topic, key bytes or None)] for every agent topic whose selector matches.

    key None means the event belongs on the topic but lacks a key component:
    it is not routed, and the caller records a JOIN_UNCERTAIN gap.
    """
    out = []
    for topic, (select, _) in ROUTES.items():
        if select(ev):
            out.append((topic, key_bytes(topic, ev)))
    return out
