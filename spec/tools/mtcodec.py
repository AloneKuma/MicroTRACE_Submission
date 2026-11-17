"""Reference encoders for MicroTRACE v0 Kafka keys and logical IDs.

Specified in spec/kafka/kafka-contract.md. Standard library only.
"""
import hashlib
import struct

KEY_VERSION = 0
ID_VERSION = 0

# Logical-ID kinds: prefix and ordered fields. A field named in SORTED is a
# list sorted by UTF-8 byte order; one named in ORDERED keeps its order.
ID_KINDS = {
    "event": ("ev", ["source", "source_native_id", "source_stage", "payload_version"]),
    "lineage": ("ln", ["node_id", "boot_id", "tgid", "start_time_ns"]),
    "finding": ("fd", ["finding_type", "input_event_ids", "detector_version"]),
    "witness": ("wt", ["relationship_type", "source_finding_id",
                       "target_finding_id", "evidence_event_ids"]),
    "incident": ("in", ["anchor_finding_id"]),
    "path": ("pt", ["finding_ids"]),
    "ground_truth": ("gt", ["run_id", "action_seq"]),
    "evaluation": ("rv", ["rule_id", "state_key_hex", "window_end", "detector_version"]),
    "graph_node": ("gn", ["node_type", "uid", "namespace", "name"]),
    "graph_edge": ("ge", ["edge_type", "source_node", "target_node", "label", "identity_status", "trust"]),
}
SORTED = {"input_event_ids", "evidence_event_ids"}
ORDERED = {"finding_ids"}


def _u32(n):
    return struct.pack(">I", n)


def _encode_value(name, value):
    if name in SORTED or name in ORDERED:
        items = [v.encode("utf-8") for v in value]
        if name in SORTED:
            items.sort()
        return _u32(len(items)) + b"".join(_u32(len(i)) + i for i in items)
    if not isinstance(value, str):
        raise TypeError(f"field {name} must be a string, got {type(value).__name__}")
    return value.encode("utf-8")


def canonical_id_bytes(kind, fields):
    prefix, names = ID_KINDS[kind]
    missing = [n for n in names if n not in fields]
    if missing:
        raise KeyError(f"{kind} ID missing fields {missing}")
    out = b"MTID" + bytes([ID_VERSION, len(kind)]) + kind.encode("ascii")
    out += bytes([len(names)])
    for index, name in enumerate(names, start=1):
        value = _encode_value(name, fields[name])
        out += bytes([index]) + _u32(len(value)) + value
    return out


def logical_id(kind, fields):
    prefix = ID_KINDS[kind][0]
    digest = hashlib.sha256(canonical_id_bytes(kind, fields)).hexdigest()
    return f"{prefix}_{digest[:32]}"


def encode_key(key_type_code, components):
    """components: list of (component_code, str value) in declared order."""
    out = b"MT" + bytes([KEY_VERSION]) + struct.pack(">H", key_type_code)
    out += bytes([len(components)])
    for code, value in components:
        if value is None or value == "":
            raise ValueError("absent key component; record must not be routed")
        raw = value.encode("utf-8")
        out += bytes([code]) + _u32(len(raw)) + raw
    return out


def decode_key(data):
    if data[:2] != b"MT":
        raise ValueError("bad magic")
    version = data[2]
    key_type = struct.unpack(">H", data[3:5])[0]
    count = data[5]
    pos, comps = 6, []
    for _ in range(count):
        code = data[pos]
        length = struct.unpack(">I", data[pos + 1:pos + 5])[0]
        comps.append((code, data[pos + 5:pos + 5 + length].decode("utf-8")))
        pos += 5 + length
    if pos != len(data):
        raise ValueError("trailing bytes")
    return version, key_type, comps
