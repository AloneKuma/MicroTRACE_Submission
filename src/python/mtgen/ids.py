"""Deterministic UIDs and logical IDs per stream.

UIDs are allocated per stream and are deterministic based on a counter seeded
from the stream's random generator. Logical IDs for events are computed via
mtcodec.logical_id using the event's kind and fields.
"""
import uuid
from . import rng


class UIDAllocator:
    """Allocates deterministic UUID-shaped UIDs per stream."""

    def __init__(self, streams: rng.Streams, name: str):
        """Initialize with a named stream.

        Args:
            streams: Streams instance
            name: stream name (e.g., "world.pods", "world.containers")
        """
        self.streams = streams
        self.name = name
        self.counter = 0

    def next(self) -> str:
        """Allocate the next UID as a UUID string."""
        gen = self.streams.get(self.name)
        # Generate random bytes for a UUID-like string
        # Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        rand_bytes = gen.bytes(16)
        self.counter += 1
        return str(uuid.UUID(bytes=rand_bytes))


def event_logical_id(fields: dict) -> str:
    """Compute logical ID for an event via mtcodec.

    Args:
        fields: dict with event kind and required fields per mtcodec.ID_KINDS["event"]
               (source, source_native_id, source_stage, payload_version)

    Returns:
        logical ID string (ev_<32-char-hex>)
    """
    # Import here to avoid circular dependency and to ensure mtgen.__init__ has
    # set up sys.path for spec/tools.
    import mtcodec

    fields_with_kind = {**fields, "kind": "event"}
    kind = fields_with_kind.pop("kind")
    return mtcodec.logical_id(kind, fields)


def child_process_key(parent_key: str, node_uid: str, boot_id: str,
                      time_ns: int) -> tuple:
    """Key and TGID of the process a fork of ``parent_key`` creates at ``time_ns``.

    The scenario engine and the eBPF renderer both derive a child this way,
    so a later step can name the process an earlier exec step started. The
    key has the world's format, "<node8>:<boot8>:<tgid>:<start_hex>".

    Returns:
        (process_key, tgid)
    """
    import hashlib

    digest = hashlib.sha256(f"child:{parent_key}:{time_ns}".encode()).digest()
    tgid = 100_000 + int.from_bytes(digest[:4], "big") % 900_000
    return f"{node_uid[:8]}:{boot_id[:8]}:{tgid}:{time_ns:x}", tgid


def pod_init_processes(processes) -> dict:
    """Pod UID -> key of the Pod's first container-init process.

    An action whose actor is a Pod acts through this process (the renderer's
    and the scenario engine's shared reading of a Pod-level actor).
    """
    out: dict = {}
    for p in processes:
        if p.pod_uid and not p.parent_process_key and p.pod_uid not in out:
            out[p.pod_uid] = p.process_key
    return out
