"""Tests for mtgen.specs: YAML loaders and resolve_params."""
import pytest

import mtgen
from mtgen.specs import resolve_params, load_generator_spec, load_evidence_rendering
from mtgen.specs import load_scenario_catalogue, load_scenario_actions
from mtgen.specs import load_pattern_artifacts, load_indicator_artifacts


# resolve_params tests

def test_resolve_params_uses_pilot_default_when_frozen_null():
    obj = {"pilot_default": 42, "frozen": None}
    assert resolve_params(obj) == 42


def test_resolve_params_uses_frozen_when_set():
    obj = {"pilot_default": 42, "frozen": 99}
    assert resolve_params(obj) == 99


def test_resolve_params_recursive():
    obj = {"a": {"pilot_default": 1, "frozen": None}, "b": 2}
    result = resolve_params(obj)
    assert result == {"a": 1, "b": 2}


def test_resolve_params_non_param_dict_unchanged():
    obj = {"x": 1, "y": 2, "z": 3}
    assert resolve_params(obj) == {"x": 1, "y": 2, "z": 3}


# Loader tests

def test_load_generator_spec_has_worlds():
    spec = load_generator_spec()
    assert "worlds" in spec
    assert "Small" in spec["worlds"]
    assert "Reference" in spec["worlds"]
    assert "Large" in spec["worlds"]


def test_load_generator_spec_reference_workers_resolved():
    spec = load_generator_spec()
    ref = spec["worlds"]["Reference"]
    # logical_kubernetes_workers for Reference is 4
    assert ref["logical_kubernetes_workers"] == 4


def test_load_generator_spec_small_concurrent_pods():
    spec = load_generator_spec()
    small = spec["worlds"]["Small"]
    assert small["concurrent_pods"] == 24


def test_load_evidence_rendering_has_findings():
    rendering = load_evidence_rendering()
    assert "findings" in rendering
    assert len(rendering["findings"]) > 0


def test_load_scenario_catalogue_has_scenarios():
    cat = load_scenario_catalogue()
    assert "scenarios" in cat


def test_load_pattern_artifacts_has_patterns():
    pa = load_pattern_artifacts()
    assert "patterns" in pa
    assert len(pa["patterns"]) > 0
