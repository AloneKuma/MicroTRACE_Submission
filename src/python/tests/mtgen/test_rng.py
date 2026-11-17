"""Tests for mtgen.rng: deterministic named random streams."""
import numpy as np
import pytest

import mtgen
from mtgen.rng import Streams


def test_determinism():
    """Same seed and name produce the same sequence."""
    s1 = Streams("seed-abc")
    s2 = Streams("seed-abc")
    g1 = s1.get("stream.x")
    g2 = s2.get("stream.x")
    assert g1.integers(0, 1000) == g2.integers(0, 1000)


def test_seed_independence():
    """Different seeds produce different sequences for the same name."""
    s1 = Streams("seed-abc")
    s2 = Streams("seed-xyz")
    g1 = s1.get("stream.x")
    g2 = s2.get("stream.x")
    vals1 = [int(g1.integers(0, 100000)) for _ in range(10)]
    vals2 = [int(g2.integers(0, 100000)) for _ in range(10)]
    assert vals1 != vals2


def test_name_independence():
    """Different names produce different sequences for the same seed."""
    s = Streams("seed-abc")
    g1 = s.get("stream.a")
    g2 = s.get("stream.b")
    vals1 = [int(g1.integers(0, 100000)) for _ in range(10)]
    vals2 = [int(g2.integers(0, 100000)) for _ in range(10)]
    assert vals1 != vals2


def test_stream_independence():
    """Advancing one stream does not shift another."""
    s1 = Streams("seed-abc")
    s2 = Streams("seed-abc")
    # Advance stream a in s1
    g1a = s1.get("stream.a")
    for _ in range(100):
        g1a.integers(0, 999)
    # stream b in s1 and s2 should still match
    g1b = s1.get("stream.b")
    g2b = s2.get("stream.b")
    assert g1b.integers(0, 1000000) == g2b.integers(0, 1000000)


def test_caching():
    """Same name returns the same Generator object (cached)."""
    s = Streams("seed-abc")
    g1 = s.get("stream.x")
    g2 = s.get("stream.x")
    assert g1 is g2
