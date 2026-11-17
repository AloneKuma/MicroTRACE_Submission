"""Deterministic ID minting for renderers.

Renderers need unique opaque IDs (request IDs, audit IDs, ...). Random UUIDs
would make two builds with the same arguments differ, so IDs are UUIDv5 over a
namespace, the call's identifying parts, and a per-minter counter that
separates identical calls. Activities render in a fixed order, so the counter
is reproducible.
"""
import uuid


class UuidMinter:
    def __init__(self, namespace: str):
        self._ns = namespace
        self._n = 0

    def mint(self, *parts) -> str:
        self._n += 1
        key = f"mtgen:{self._ns}:{self._n}:" + ":".join(str(p) for p in parts)
        return str(uuid.uuid5(uuid.NAMESPACE_URL, key))
