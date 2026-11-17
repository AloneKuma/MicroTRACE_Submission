"""Content-addressed generated evidence archive per run.

Raw rendered bytes are archived keyed by SHA-256. EvidenceRef carries the
archive ID, object key, SHA-256 hex, and protection class. Credential bytes
are never archived; callers must not pass them here.
"""
import hashlib
import json
from pathlib import Path

from microtrace.v0 import common_pb2


class EvidenceArchive:
    """Content-addressed in-memory evidence store for one run.

    put() returns an EvidenceRef whose object_key equals the SHA-256 of the
    bytes, so identical objects are automatically deduplicated.
    """

    def __init__(self, archive_id: str):
        self._archive_id = archive_id
        self._objects: dict = {}  # sha256_hex -> bytes

    @property
    def archive_id(self) -> str:
        return self._archive_id

    def put(self, data: bytes, protection: int) -> "common_pb2.EvidenceRef":
        """Archive bytes and return an EvidenceRef.

        Args:
            data:       bytes to archive; must not contain credential material
            protection: ProtectionClass enum value

        Returns:
            EvidenceRef with archive_id, object_key, sha256_hex, protection
        """
        sha256 = hashlib.sha256(data).hexdigest()
        self._objects[sha256] = data
        return common_pb2.EvidenceRef(
            archive_id=self._archive_id,
            object_key=sha256,
            sha256_hex=sha256,
            protection=protection,
        )

    def get(self, object_key: str) -> bytes:
        """Return archived bytes by object key. Raises KeyError if absent."""
        return self._objects[object_key]

    def verify(self, ref: "common_pb2.EvidenceRef") -> bool:
        """True when stored bytes match ref.sha256_hex."""
        data = self._objects.get(ref.object_key)
        if data is None:
            return False
        return hashlib.sha256(data).hexdigest() == ref.sha256_hex

    def write_to(self, directory) -> str:
        """Write objects as <dir>/objects/<sha[:2]>/<sha> plus index.json.

        Returns the archive SHA-256: the hash of the sorted object keys, one
        per line (objects are content-addressed, so this covers every byte).
        """
        directory = Path(directory)
        keys = sorted(self._objects)
        for k in keys:
            p = directory / "objects" / k[:2] / k
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(self._objects[k])
        index = {
            "archive_id": self._archive_id,
            "objects": [{"sha256": k, "size": len(self._objects[k])} for k in keys],
        }
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "index.json").write_text(
            json.dumps(index, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
        return hashlib.sha256("".join(k + "\n" for k in keys).encode()).hexdigest()

    def __len__(self) -> int:
        return len(self._objects)
