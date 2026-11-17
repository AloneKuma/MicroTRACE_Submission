"""Loaders for specification YAML files.

Returns plain dicts from parsed YAML. Numeric parameter dicts of the form
{pilot_default: X, frozen: Y} are resolved: frozen is used when non-null,
otherwise pilot_default is used.
"""
import os
from typing import Any, Dict

import yaml


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
))))


def _load_yaml(path: str, root=None) -> Dict[str, Any]:
    """Load and parse a YAML file.

    Args:
        path: relative path from repo root
        root: repository root (default REPO_ROOT)

    Returns:
        parsed YAML as dict
    """
    full_path = os.path.join(root or REPO_ROOT, path)
    with open(full_path, "r") as f:
        return yaml.safe_load(f)


def resolve_params(obj: Any) -> Any:
    """Recursively resolve {pilot_default, frozen} parameter dicts.

    A dict with exactly the keys 'pilot_default' and 'frozen' is replaced by
    its frozen value (when non-null) or its pilot_default value (when frozen is
    null). All other dicts and lists are traversed recursively.

    Args:
        obj: any parsed YAML value

    Returns:
        resolved value
    """
    if isinstance(obj, dict):
        keys = set(obj)
        if {"pilot_default", "frozen"}.issubset(keys):
            return obj["frozen"] if obj["frozen"] is not None else obj["pilot_default"]
        return {k: resolve_params(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve_params(item) for item in obj]
    return obj


def load_generator_spec() -> Dict[str, Any]:
    """Load spec/generator/generator-spec.v0.yaml.

    Numeric parameter dicts ({pilot_default, frozen}) are resolved to their
    effective value: frozen when set, pilot_default otherwise.

    Returns:
        parsed YAML dict with worlds, service graphs, churn patterns, etc.
    """
    return resolve_params(_load_yaml("spec/generator/generator-spec.v0.yaml"))


def load_evidence_rendering() -> Dict[str, Any]:
    """Load spec/generator/evidence-rendering.v0.yaml.

    Returns:
        parsed YAML dict with finding-to-evidence mappings
    """
    return _load_yaml("spec/generator/evidence-rendering.v0.yaml")


def load_scenario_catalogue(overlays=(), root=None) -> Dict[str, Any]:
    """Load spec/scenarios/catalogue.v0.yaml and append the scenarios of each
    overlay (repository-relative paths; exp2-conflict-origin-cases-plan D-31).
    An overlay adds scenarios and never replaces one: PILOT's scenarios keep
    their content and the base file its hash. root: repository root (default
    REPO_ROOT; verify passes its spec tree's).

    Returns:
        parsed YAML dict with scenarios (attack, lookalike, degraded, etc.)
    """
    cat = _load_yaml("spec/scenarios/catalogue.v0.yaml", root)
    seen = {sc["id"] for sc in cat.get("scenarios", [])}
    for rel in overlays:
        for sc in _load_yaml(rel, root).get("scenarios", []):
            if sc["id"] in seen:
                raise ValueError(f"{rel}: scenario {sc['id']!r} is already in the catalogue")
            seen.add(sc["id"])
            cat["scenarios"].append(sc)
    return cat


def catalogue_of_runs(runs) -> Dict[str, Any]:
    """The catalogue some runs were built with: the base file and every
    overlay their build manifests (or run-matrix entries) name in
    ``catalogue_overlays``, for gate scripts that read scenario definitions."""
    overlays = sorted({o for r in runs for o in r.get("catalogue_overlays", [])})
    return load_scenario_catalogue(overlays)


def load_scenario_actions() -> Dict[str, Any]:
    """Load spec/scenarios/actions.v0.yaml.

    Returns:
        parsed YAML dict with action vocabulary definitions
    """
    return _load_yaml("spec/scenarios/actions.v0.yaml")


def load_pattern_artifacts() -> Dict[str, Any]:
    """Load spec/artifacts/p_a.v0.yaml.

    Returns:
        parsed YAML dict with injection pattern set for A1
    """
    return _load_yaml("spec/artifacts/p_a.v0.yaml")


def load_indicator_artifacts() -> Dict[str, Any]:
    """Load spec/artifacts/i_a2.v0.yaml.

    Returns:
        parsed YAML dict with response indicators for A2
    """
    return _load_yaml("spec/artifacts/i_a2.v0.yaml")
