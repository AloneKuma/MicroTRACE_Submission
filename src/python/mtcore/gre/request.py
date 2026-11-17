"""The response request R_resp and its signature (paper eq. response-request).

    R_resp = <rid, gid, sid, v_C, cluster, ns, uid, rv, act, params, exp,
              nonce, evid, approval>

- rid, gid: request and evidence group (gid is the incident ID of v_C).
- sid, v_C: the reviewed TGS snapshot and correlation version
  (incident_id, version, record_sha256).
- cluster, ns, uid, rv: the target. rv is the resource version the analyst
  reviewed; the GRE revalidates against the live object (7.2).
- act, params: one of four actions and its bounded parameters (ACTIONS).
- exp: Unix seconds; nonce: 128 random bits, hex.
- evid: finding and witness IDs the approval rests on.
- approval: {key_id, alg, sig}. The signature covers every other field and
  the key_id and alg, over the canonical serialization below, so no field
  can change and no key can be swapped without failing verification.

Canonical serialization: JSON, keys sorted, no whitespace, UTF-8, integers
only (no floats), prefixed by SIG_CONTEXT.
"""
import base64
import json
import re
import secrets

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

VERSION = "gre.r_resp.v0"
SIG_CONTEXT = b"microtrace-gre-r_resp-v0\n"
ALG = "Ed25519"

_NAME = {"type": "string", "pattern": r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?\Z", "maxLength": 253}
_ID = {"type": "string", "minLength": 1, "maxLength": 200}
_NAMESPACE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")

# One entry per supported action (design-spec section 4): the target kind,
# whether it is namespaced, and its parameters. Every parameter is required
# and no other is allowed.
ACTIONS = {
    "isolate_pod": {"kind": "Pod", "namespaced": True,
                    "params": {"pod": _NAME}},
    "cordon_node": {"kind": "Node", "namespaced": False,
                    "params": {"node": _NAME}},
    "scale_to_zero": {"kind": None, "namespaced": True,
                      "params": {"kind": {"enum": ["Deployment", "StatefulSet"]}, "name": _NAME}},
    "revoke_rolebinding": {"kind": "RoleBinding", "namespaced": True,
                           "params": {"rolebinding": _NAME}},
}

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "rid", "gid", "sid", "v_c", "cluster", "ns", "uid", "rv", "act", "params", "exp",
                 "nonce", "evid", "approval"],
    "properties": {
        "version": {"const": VERSION},
        "rid": _ID, "gid": _ID,
        "sid": {"type": "string", "pattern": r"^sn_[0-9a-f]{32}\Z"},        # snapshot.sid_of
        "v_c": {"type": "object", "additionalProperties": False,
                "required": ["incident_id", "version", "record_sha256"],
                "properties": {"incident_id": _ID, "version": {"type": "integer", "minimum": 1},
                               "record_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}\Z"}}},
        "cluster": {"type": "string", "minLength": 1, "maxLength": 63},
        "ns": {"type": "string", "maxLength": 63},
        "uid": {"type": "string", "pattern": r"^[A-Za-z0-9-]{1,64}\Z"},
        "rv": {"type": "string", "pattern": r"^[A-Za-z0-9]{1,64}\Z"},
        "act": {"enum": sorted(ACTIONS)},
        "params": {"type": "object"},
        "exp": {"type": "integer", "minimum": 0},
        "nonce": {"type": "string", "pattern": r"^[0-9a-f]{32}\Z"},
        "evid": {"type": "array", "items": _ID, "maxItems": 200, "uniqueItems": True},
        "approval": {"type": "object", "additionalProperties": False, "required": ["key_id", "alg", "sig"],
                     "properties": {"key_id": _ID, "alg": {"const": ALG},
                                    "sig": {"type": "string", "maxLength": 200}}},
    },
}
PARAM_SCHEMAS = {act: {"type": "object", "additionalProperties": False, "required": sorted(a["params"]),
                       "properties": a["params"]} for act, a in ACTIONS.items()}


class Malformed(ValueError):
    """The request does not have the R_resp shape."""


def check_shape(req):
    """Raise Malformed unless req is a well-formed R_resp (fields, types,
    the action's exact parameters, and a namespace iff the action needs one)."""
    if not isinstance(req, dict):
        raise Malformed("request is not an object")
    try:
        jsonschema.validate(req, SCHEMA)
        jsonschema.validate(req["params"], PARAM_SCHEMAS[req["act"]])
    except jsonschema.ValidationError as e:
        raise Malformed(e.message) from None
    if ACTIONS[req["act"]]["namespaced"] != bool(req["ns"]):
        raise Malformed(f"{req['act']} {'needs' if ACTIONS[req['act']]['namespaced'] else 'takes no'} namespace")
    if req["ns"] and not _valid_name(req["ns"]):
        raise Malformed(f"invalid namespace {req['ns']!r}")


def _valid_name(s):
    return _NAMESPACE.match(s) is not None


def signed_bytes(req):
    """The bytes the approval signs: every field but approval.sig."""
    body = {k: v for k, v in req.items() if k != "approval"}
    body["approval"] = {k: v for k, v in req.get("approval", {}).items() if k != "sig"}
    return SIG_CONTEXT + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                    allow_nan=False).encode("utf-8")


def sign(req, key_id, private_key):
    """Return a copy of req with approval {key_id, alg, sig} filled in."""
    out = {k: v for k, v in req.items() if k != "approval"}
    out["approval"] = {"key_id": key_id, "alg": ALG}
    out["approval"]["sig"] = base64.b64encode(private_key.sign(signed_bytes(out))).decode("ascii")
    return out


def verify(req, trusted_keys):
    """(ok, reason) of the approval signature against trusted_keys
    {key_id: Ed25519PublicKey}."""
    a = req["approval"]
    key = trusted_keys.get(a["key_id"])
    if key is None:
        return False, f"unknown approval key {a['key_id']}"
    try:
        key.verify(base64.b64decode(a["sig"], validate=True), signed_bytes(req))
    except (InvalidSignature, ValueError):
        return False, "approval signature does not match the request"
    return True, ""


def new_nonce():
    return secrets.token_hex(16)


def new_keypair():
    """A fresh Ed25519 key pair (private, public); for the scripted approver
    and tests. Real approver keys are provisioned outside the repository."""
    k = Ed25519PrivateKey.generate()
    return k, k.public_key()


def load_public_key(raw):
    """An Ed25519 public key from its 32 raw bytes."""
    return Ed25519PublicKey.from_public_bytes(raw)
