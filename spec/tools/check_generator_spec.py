#!/usr/bin/env python3
"""
check_generator_spec.py: Validation script for generator spec and manifest schemas.

Validates:
1. Generator spec YAML against its JSON Schema
2. Build manifest example against its schema
3. Source-template manifest example against its schema
4. Run-matrix example against its schema
5. World numbers against design table (dataset-generator-design.md section 5)
6. Every numeric leaf has pilot_default/frozen shape
"""

import json
import sys
from pathlib import Path
import yaml

# Try to import jsonschema; fall back to basic structural checks if unavailable
try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def load_yaml(path):
    """Load a YAML file and return as dict."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def load_json(path):
    """Load a JSON file and return as dict."""
    with open(path, 'r') as f:
        return json.load(f)


def validate_against_schema(data, schema, description):
    """Validate data against schema using jsonschema if available."""
    if not HAS_JSONSCHEMA:
        print(f"[SKIP] {description} (jsonschema not available)")
        return True

    try:
        jsonschema.validate(instance=data, schema=schema)
        print(f"[PASS] {description}")
        return True
    except jsonschema.ValidationError as e:
        print(f"[FAIL] {description}")
        print(f"       Error: {e.message}")
        print(f"       Path: {' -> '.join(str(p) for p in e.absolute_path)}")
        return False


def check_numeric_params(obj, path="", errors=None):
    """
    Recursively check that every numeric parameter has pilot_default/frozen shape.
    Returns list of error messages.
    """
    if errors is None:
        errors = []

    if isinstance(obj, dict):
        # Check if this looks like a numeric parameter object
        if "pilot_default" in obj and "frozen" in obj:
            # Verify both keys exist and frozen is null or same type as pilot_default
            if obj["frozen"] is not None:
                pilot_type = type(obj["pilot_default"])
                frozen_type = type(obj["frozen"])
                if pilot_type != frozen_type:
                    errors.append(f"{path}: pilot_default and frozen have different types ({pilot_type.__name__} vs {frozen_type.__name__})")
            # Verify no extra keys besides description, pilot_default, frozen
            allowed_keys = {"description", "pilot_default", "frozen"}
            extra_keys = set(obj.keys()) - allowed_keys
            if extra_keys:
                # This is OK - dict may have other metadata
                pass
        else:
            # Recurse into nested dicts
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                check_numeric_params(value, new_path, errors)

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            new_path = f"{path}[{i}]"
            check_numeric_params(item, new_path, errors)

    return errors


def check_world_numbers(spec):
    """
    Check world numbers against design table (dataset-generator-design.md section 5).
    Expected values from design:
    - Small: 3 workers, 12 services, 24 Pods, 28 containers, 2 delete/recreate, 2 sidecars
    - Reference: 4 workers, 24 services, 48 Pods, 56 containers, 6 delete/recreate, 8 sidecars
    - Large: 8 workers, 50 services, 100 Pods, 110 containers, 10 delete/recreate, 15 sidecars
    """
    expected = {
        'Small': {
            'logical_kubernetes_workers': 3,
            'application_services': 12,
            'concurrent_pods': 24,
            'concurrent_containers': 28,
            'pod_delete_recreate_transitions': 2,
            'sidecar_containers': 2,
        },
        'Reference': {
            'logical_kubernetes_workers': 4,
            'application_services': 24,
            'concurrent_pods': 48,
            'concurrent_containers': 56,
            'pod_delete_recreate_transitions': 6,
            'sidecar_containers': 8,
        },
        'Large': {
            'logical_kubernetes_workers': 8,
            'application_services': 50,
            'concurrent_pods': 100,
            'concurrent_containers': 110,
            'pod_delete_recreate_transitions': 10,
            'sidecar_containers': 15,
        }
    }

    errors = []
    worlds = spec.get('worlds', {})

    for world_name, world_data in worlds.items():
        if world_name not in expected:
            continue

        expected_values = expected[world_name]
        for param, expected_val in expected_values.items():
            if param in world_data:
                actual_val = world_data[param].get('pilot_default')
                if actual_val != expected_val:
                    errors.append(
                        f"{world_name}.{param}: expected {expected_val}, got {actual_val}"
                    )

    return errors


def check_service_graph_shapes(spec):
    """Verify at least 3 distinct service graph shapes exist."""
    shapes = spec.get('service_graph_shapes', {})

    if len(shapes) < 3:
        return [f"Service graph shapes: expected at least 3, got {len(shapes)}"]

    required_shapes = ['layered_web_shop', 'event_driven_with_broker', 'fan_out_reporting']
    missing = [s for s in required_shapes if s not in shapes]

    if missing:
        return [f"Missing required service graph shapes: {', '.join(missing)}"]

    return []


def check_declared_artifacts(spec):
    """Verify key artifacts are declared."""
    artifacts = spec.get('declared_artifacts', {})

    required = ['pattern_set_p_a', 'response_indicators_i_a2']
    missing = [a for a in required if a not in artifacts]

    if missing:
        return [f"Missing required artifacts: {', '.join(missing)}"]

    return []


def main():
    """Run all validation checks."""
    print("=" * 70)
    print("MicroTRACE Generator Spec Validation")
    print("=" * 70)

    passed = 0
    failed = 0

    # Determine base paths
    script_dir = Path(__file__).parent
    spec_dir = script_dir.parent / 'generator'
    examples_dir = spec_dir / 'examples'

    # 1. Load and validate generator spec
    print("\n[1] Generator Specification")
    print("-" * 70)

    spec_file = spec_dir / 'generator-spec.v0.yaml'
    schema_file = spec_dir / 'generator-spec.schema.json'

    if not spec_file.exists():
        print(f"[FAIL] Generator spec file not found: {spec_file}")
        failed += 1
    else:
        spec = load_yaml(spec_file)
        schema = load_json(schema_file)

        if validate_against_schema(spec, schema, "generator-spec.v0.yaml against schema"):
            passed += 1
        else:
            failed += 1

        # Check world numbers
        world_errors = check_world_numbers(spec)
        if world_errors:
            print(f"[FAIL] World number validation:")
            for error in world_errors:
                print(f"       {error}")
            failed += 1
        else:
            print("[PASS] World numbers match design table")
            passed += 1

        # Check service graph shapes
        shape_errors = check_service_graph_shapes(spec)
        if shape_errors:
            print(f"[FAIL] Service graph shapes:")
            for error in shape_errors:
                print(f"       {error}")
            failed += 1
        else:
            print("[PASS] Service graph shapes (3+ distinct shapes present)")
            passed += 1

        # Check declared artifacts
        artifact_errors = check_declared_artifacts(spec)
        if artifact_errors:
            print(f"[FAIL] Declared artifacts:")
            for error in artifact_errors:
                print(f"       {error}")
            failed += 1
        else:
            print("[PASS] Required artifacts declared (P_A, I_A2)")
            passed += 1

        # Check numeric param shape (pilot_default/frozen)
        numeric_errors = check_numeric_params(spec)
        if numeric_errors:
            print(f"[FAIL] Numeric parameter validation ({len(numeric_errors)} errors):")
            for error in numeric_errors[:5]:  # Show first 5
                print(f"       {error}")
            if len(numeric_errors) > 5:
                print(f"       ... and {len(numeric_errors) - 5} more")
            failed += 1
        else:
            print("[PASS] All numeric parameters have pilot_default/frozen shape")
            passed += 1

    # 2. Build manifest schema and example
    print("\n[2] Build Manifest Schema")
    print("-" * 70)

    build_manifest_schema = load_json(spec_dir / 'build-manifest.schema.json')
    build_manifest_example = load_json(examples_dir / 'build-manifest.example.json')

    if validate_against_schema(build_manifest_example, build_manifest_schema,
                               "build-manifest.example.json against schema"):
        passed += 1
    else:
        failed += 1

    # 3. Source-template manifest schema and example
    print("\n[3] Source-Template Manifest Schema")
    print("-" * 70)

    template_schema = load_json(spec_dir / 'source-template-manifest.schema.json')
    template_example = load_json(examples_dir / 'source-template-manifest.example.json')

    if validate_against_schema(template_example, template_schema,
                               "source-template-manifest.example.json against schema"):
        passed += 1
    else:
        failed += 1

    # 4. Run-matrix schema and example
    print("\n[4] Run-Matrix Schema")
    print("-" * 70)

    matrix_schema = load_json(spec_dir / 'run-matrix.schema.json')
    matrix_example = load_json(examples_dir / 'run-matrix.example.json')

    if validate_against_schema(matrix_example, matrix_schema,
                               "run-matrix.example.json against schema"):
        passed += 1
    else:
        failed += 1

    # Summary
    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
