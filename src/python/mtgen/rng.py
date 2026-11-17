"""Deterministic named random streams.

A Streams instance creates independent numpy.random.Generator instances seeded
from SHA-256(seed, name). Adding a new stream never shifts another stream's
sequence.
"""
import hashlib
import numpy as np


class Streams:
    """Manages deterministic named random number generator streams."""

    def __init__(self, seed: str):
        """Initialize with a seed string (typically a run_id).

        Args:
            seed: seed string used for all stream derivations
        """
        self.seed = seed
        self._cache = {}

    def get(self, name: str) -> np.random.Generator:
        """Get or create a deterministic Generator for a named stream.

        Args:
            name: stream name (e.g., "world.pods", "world.namespaces")

        Returns:
            numpy.random.Generator seeded from SHA-256(seed, name)
        """
        if name in self._cache:
            return self._cache[name]

        # Hash seed + name to get a 32-byte seed for numpy
        h = hashlib.sha256()
        h.update(self.seed.encode("utf-8"))
        h.update(name.encode("utf-8"))
        seed_bytes = h.digest()

        # Convert to uint64 for numpy (first 8 bytes)
        seed_int = int.from_bytes(seed_bytes[:8], byteorder="big", signed=False)

        gen = np.random.default_rng(seed_int)
        self._cache[name] = gen
        return gen
