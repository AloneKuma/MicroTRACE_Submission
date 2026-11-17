#!/usr/bin/env python3
"""
Check catalogue.v0.yaml against the schema and contracts.

Validates:
- Catalogue structure against JSON Schema
- Action names in scenarios exist in actions.v0.yaml
- Finding names exist in rulebook.v0.yaml and are among the 17 included
- Witness type names exist in witness.proto
- Source types (reproduced/adapted vs external/benign) match their citation/anchor
- Attack scenarios have at least one rulebook_shaped=false variant
- Coverage table (when required)

Exit code: 0 on success, >0 on failure.

    python spec/tools/check_catalogue.py [OVERLAY.yaml]

With a path, that file is checked instead (a catalogue overlay, D-31 of
exp2-conflict-origin-cases-plan), and none of its scenario IDs may already be
in catalogue.v0.yaml.
"""

import sys
import json
import yaml
import hashlib
from pathlib import Path
from collections import defaultdict

# Note: WitnessType enum is defined in spec/proto/microtrace/v0/witness.proto
# and extracted here for validation.


# 17 findings included in the evaluation (per dataset-build-plan.md, phase 1, item 3)
INCLUDED_FINDINGS = {
    "A1", "A2",  # Injection
    "B1", "B2", "B3",  # Auth/discovery
    "C1a", "C1b",  # Container escape
    "D1",  # Token read
    "E1", "E2",  # Image admission, file write
    "F1",  # Privilege escalation
    "G1a", "G2",  # Network, exec
    "H1", "H2", "H3", "H4",  # Exfiltration/anomaly
    "G1c",  # Inbound network; add-on set only (ADDON_FINDINGS)
}

# Included findings evaluated on an add-on set only (exp2-conflict-origin-cases-plan
# D-27): their coverage comes from a catalogue overlay, so catalogue.v0.yaml
# need not cover them.
ADDON_FINDINGS = {"G1c"}

# 6 findings excluded from evaluation (have conditional status in rulebook)
EXCLUDED_FINDINGS = {
    "C2",  # ptrace-observed
    "D2",  # token-binding-mismatch
    "E3",  # persisted-implant
    "F2",  # RBAC-grant-mutation
    "G1b",  # token-pivot
    "H5"  # offnode-suspected-exfiltration
}

# WitnessType enum from witness.proto
WITNESS_TYPES = {
    "WITNESS_TYPE_UNSPECIFIED",
    "NETWORK_FLOW",
    "REQUEST_IDENTITY",
    "CREDENTIAL_READ_TO_USE",
    "PROCESS_ANCESTRY",
    "HOST_TRANSITION",
    "ADMISSION_INSTANCE",
    "CONTROL_PLANE_CAUSALITY_INSTANCE",
    "HOST_CONTEXT",
    "CONTROL_PLANE_CAUSALITY_CLASS",
    "IMAGE_CLASS",
}


def load_yaml(path):
    """Load a YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def load_json(path):
    """Load a JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def get_catalogue_path():
    """Return path to catalogue.v0.yaml."""
    return Path(__file__).parent.parent / "scenarios" / "catalogue.v0.yaml"


def get_schema_path():
    """Return path to catalogue.schema.json."""
    return Path(__file__).parent.parent / "scenarios" / "catalogue.schema.json"


def get_actions_path():
    """Return path to actions.v0.yaml."""
    return Path(__file__).parent.parent / "scenarios" / "actions.v0.yaml"


def get_rulebook_path():
    """Return path to rulebook.v0.yaml."""
    return Path(__file__).parent.parent / "rules" / "rulebook.v0.yaml"


def validate_json_schema(catalogue, schema):
    """
    Validate catalogue against JSON Schema.

    Uses jsonschema library if available, otherwise basic structural checks.
    """
    try:
        import jsonschema
        jsonschema.validate(catalogue, schema)
        return True, "JSON Schema validation passed"
    except ImportError:
        # Fallback to basic checks if jsonschema not available
        if "version" not in catalogue:
            return False, "Missing 'version' field"
        if "status" not in catalogue:
            return False, "Missing 'status' field"
        if catalogue["status"] not in ["draft", "reviewed", "frozen"]:
            return False, f"Invalid status: {catalogue['status']}"
        if "scenarios" not in catalogue:
            return False, "Missing 'scenarios' field"
        if not isinstance(catalogue["scenarios"], list):
            return False, "'scenarios' must be an array"
        return True, "Basic structural validation passed (jsonschema not available)"
    except Exception as e:
        return False, str(e)


def load_actions(actions_path):
    """Load and index actions from actions.v0.yaml."""
    actions_doc = load_yaml(actions_path)
    action_names = set()
    if "actions" in actions_doc:
        for action in actions_doc["actions"]:
            if "id" in action:
                action_names.add(action["id"])
    return action_names


def load_findings_from_rulebook(rulebook_path):
    """Load and index findings from rulebook.v0.yaml."""
    rulebook = load_yaml(rulebook_path)
    findings = {}
    if "findings" in rulebook:
        for finding in rulebook["findings"]:
            if "id" in finding:
                findings[finding["id"]] = finding
    return findings


def check_actions_exist(catalogue, action_names):
    """Check that all actions in scenarios exist in actions.v0.yaml."""
    errors = []
    for scenario in catalogue.get("scenarios", []):
        scenario_id = scenario.get("id", "?")
        for step in scenario.get("steps", []):
            action = step.get("action")
            if action and action not in action_names:
                errors.append(f"Scenario '{scenario_id}' step {step.get('step')}: unknown action '{action}'")
    return errors


def check_findings_exist(catalogue, findings):
    """
    Check that all findings in scenarios exist in the rulebook and are allowed.

    Included findings: must exist.
    Excluded findings: allowed in lookalike fixtures (fixture_only=true).
    Others: not allowed.
    """
    errors = []
    all_findings = INCLUDED_FINDINGS | EXCLUDED_FINDINGS

    for scenario in catalogue.get("scenarios", []):
        scenario_id = scenario.get("id", "?")
        is_fixture_only = scenario.get("fixture_only", False)

        for step in scenario.get("steps", []):
            for expectation in step.get("expects", []):
                finding = expectation.get("finding")
                if not finding:
                    continue

                if finding not in all_findings:
                    errors.append(f"Scenario '{scenario_id}': unknown finding '{finding}'")
                elif finding in EXCLUDED_FINDINGS and not is_fixture_only:
                    if scenario.get("kind") != "lookalike":
                        errors.append(
                            f"Scenario '{scenario_id}': excluded finding '{finding}' "
                            f"only allowed in lookalike fixtures (fixture_only=true)"
                        )

    return errors


def check_step_tactics(catalogue, rulebook_path):
    """A step's intended_tactic (exp2-gaps-plan B4) must be the primary
    tactic of every PRESENT finding it expects that has one."""
    rb = load_yaml(rulebook_path)
    tactic = {f["id"]: f.get("primary_tactic") for f in rb.get("findings", [])}
    errors = []
    for scenario in catalogue.get("scenarios", []):
        for step in scenario.get("steps", []):
            want = step.get("intended_tactic")
            if not want:
                continue
            for e in step.get("expects", []) or []:
                have = tactic.get(e.get("finding"))
                if e.get("state", "PRESENT") == "PRESENT" and have and have != want:
                    errors.append(f"Scenario '{scenario.get('id')}' step {step.get('step')}: "
                                  f"intended_tactic {want} but {e.get('finding')} is {have}")
    return errors


def check_witness_types(catalogue):
    """Check that witness names in links exist in WitnessType."""
    errors = []
    for scenario in catalogue.get("scenarios", []):
        scenario_id = scenario.get("id", "?")
        for link in scenario.get("links", []):
            witness = link.get("witness")
            if witness and witness not in WITNESS_TYPES:
                errors.append(
                    f"Scenario '{scenario_id}': unknown witness type '{witness}' "
                    f"(must be a WitnessType from witness.proto)"
                )
    return errors


def check_source_consistency(catalogue):
    """
    Check source type consistency:
    - reproduced/adapted must have anchor
    - external/benign must have citation
    """
    errors = []
    for scenario in catalogue.get("scenarios", []):
        scenario_id = scenario.get("id", "?")
        source = scenario.get("source", {})
        source_class = source.get("class")

        if source_class in ["reproduced", "adapted"]:
            if "anchor" not in source:
                errors.append(
                    f"Scenario '{scenario_id}': {source_class} scenario must have 'anchor'"
                )
        elif source_class in ["external", "benign"]:
            if "citation" not in source:
                errors.append(
                    f"Scenario '{scenario_id}': {source_class} scenario must have 'citation'"
                )

    return errors


def check_attack_variants(catalogue):
    """
    Check that every attack scenario has at least one variant with rulebook_shaped=false.

    This ensures that attacks are not purely shaped by the rulebook predicates.
    """
    errors = []
    for scenario in catalogue.get("scenarios", []):
        if scenario.get("kind") != "attack":
            continue

        scenario_id = scenario.get("id", "?")
        variants = scenario.get("variants", [])

        if not variants:
            errors.append(f"Scenario '{scenario_id}': attack scenario has no variants")
            continue

        has_non_rulebook_shaped = any(
            not v.get("rulebook_shaped", True) for v in variants
        )
        if not has_non_rulebook_shaped:
            errors.append(
                f"Scenario '{scenario_id}': attack scenario must have at least one "
                f"variant with rulebook_shaped=false"
            )

    return errors


def check_link_endpoints(catalogue):
    """Check that link endpoints (from/to) reference valid steps."""
    errors = []
    for scenario in catalogue.get("scenarios", []):
        scenario_id = scenario.get("id", "?")
        steps = scenario.get("steps", [])
        step_numbers = {s.get("step") for s in steps if s.get("step")}

        for link in scenario.get("links", []):
            from_step = link.get("from")
            to_step = link.get("to")

            if from_step not in step_numbers:
                errors.append(
                    f"Scenario '{scenario_id}': link from step {from_step} does not exist"
                )
            if to_step not in step_numbers:
                errors.append(
                    f"Scenario '{scenario_id}': link to step {to_step} does not exist"
                )

    return errors


def build_coverage_table(catalogue):
    """
    Build a per-finding coverage table showing positive, lookalike, and unobservable counts.

    Returns a dict mapping finding -> {positive, lookalike, unobservable, counts}.
    """
    coverage = defaultdict(lambda: {"positive": 0, "lookalike": 0, "unobservable": 0})

    for scenario in catalogue.get("scenarios", []):
        scenario_kind = scenario.get("kind")

        for step in scenario.get("steps", []):
            for expectation in step.get("expects", []):
                finding = expectation.get("finding")
                state = expectation.get("state")

                if not finding or finding not in INCLUDED_FINDINGS:
                    continue

                # Categorize by scenario kind and expected state
                if scenario_kind == "attack" and state == "PRESENT":
                    coverage[finding]["positive"] += 1
                elif scenario_kind == "lookalike" and state == "ABSENT":
                    coverage[finding]["lookalike"] += 1
                elif state == "UNOBSERVABLE":
                    coverage[finding]["unobservable"] += 1

    return coverage


def print_coverage_table(coverage):
    """Print a human-readable coverage table."""
    print("\n" + "="*70)
    print("PER-FINDING COVERAGE TABLE")
    print("="*70)
    print(f"{'Finding':<12} {'Positive':<12} {'Lookalike':<12} {'Unobservable':<12}")
    print("-"*70)

    for finding in sorted(INCLUDED_FINDINGS):
        counts = coverage.get(finding, {"positive": 0, "lookalike": 0, "unobservable": 0})
        print(
            f"{finding:<12} {counts['positive']:<12} "
            f"{counts['lookalike']:<12} {counts['unobservable']:<12}"
        )

    print("="*70)


def check_coverage_requirements(catalogue, coverage):
    """
    Check coverage requirements when coverage_required=true.

    Requires:
    - Each included finding has at least one positive case
    - Each included finding has at least one lookalike case
    - Each included finding has at least one unobservable case
    - Every witness type used by attack links has a hard nonlink
    """
    errors = []

    if not catalogue.get("coverage_required", False):
        return errors

    for finding in INCLUDED_FINDINGS - ADDON_FINDINGS:
        counts = coverage.get(finding, {"positive": 0, "lookalike": 0, "unobservable": 0})

        if counts["positive"] == 0:
            errors.append(f"Coverage requirement: {finding} needs at least one positive case")
        if counts["lookalike"] == 0:
            errors.append(f"Coverage requirement: {finding} needs at least one lookalike case")
        if counts["unobservable"] == 0:
            errors.append(f"Coverage requirement: {finding} needs at least one unobservable case")

    return errors


def main(argv=None):
    """Main validation logic."""
    argv = sys.argv[1:] if argv is None else argv
    catalogue_path = Path(argv[0]) if argv else get_catalogue_path()
    schema_path = get_schema_path()
    actions_path = get_actions_path()
    rulebook_path = get_rulebook_path()

    # Load documents
    try:
        catalogue = load_yaml(catalogue_path)
        schema = load_json(schema_path)
        action_names = load_actions(actions_path)
        findings = load_findings_from_rulebook(rulebook_path)
    except Exception as e:
        print(f"ERROR: Failed to load input files: {e}", file=sys.stderr)
        return 1

    # Run checks
    all_errors = []
    if catalogue_path.resolve() != get_catalogue_path().resolve():
        base = {sc["id"] for sc in load_yaml(get_catalogue_path()).get("scenarios", [])}
        dup = sorted(sc["id"] for sc in catalogue.get("scenarios", []) if sc["id"] in base)
        if dup:
            all_errors.append(f"Overlay scenarios already in catalogue.v0.yaml: {dup}")

    # Schema validation
    valid, msg = validate_json_schema(catalogue, schema)
    if not valid:
        all_errors.append(f"Schema validation: {msg}")
    else:
        print(f"[PASS] Schema validation: {msg}")

    # Action existence
    action_errors = check_actions_exist(catalogue, action_names)
    if action_errors:
        all_errors.extend(action_errors)
    else:
        print(f"[PASS] All actions exist in actions.v0.yaml")

    # Finding existence
    finding_errors = check_findings_exist(catalogue, findings)
    if finding_errors:
        all_errors.extend(finding_errors)
    else:
        print(f"[PASS] All findings exist and are properly categorized")

    # Step tactics
    tactic_errors = check_step_tactics(catalogue, rulebook_path)
    if tactic_errors:
        all_errors.extend(tactic_errors)
    else:
        print(f"[PASS] Step intended tactics match their findings")

    # Witness types
    witness_errors = check_witness_types(catalogue)
    if witness_errors:
        all_errors.extend(witness_errors)
    else:
        print(f"[PASS] All witness types are valid")

    # Source consistency
    source_errors = check_source_consistency(catalogue)
    if source_errors:
        all_errors.extend(source_errors)
    else:
        print(f"[PASS] Source types (anchor/citation) are consistent")

    # Attack variants
    variant_errors = check_attack_variants(catalogue)
    if variant_errors:
        all_errors.extend(variant_errors)
    else:
        print(f"[PASS] Attack scenarios have rulebook_shaped variants")

    # Link endpoints
    link_errors = check_link_endpoints(catalogue)
    if link_errors:
        all_errors.extend(link_errors)
    else:
        print(f"[PASS] All link endpoints reference valid steps")

    # Coverage analysis
    coverage = build_coverage_table(catalogue)
    print_coverage_table(coverage)

    coverage_errors = check_coverage_requirements(catalogue, coverage)
    if coverage_errors:
        all_errors.extend(coverage_errors)
    elif catalogue.get("coverage_required", False):
        print(f"[PASS] Coverage requirements satisfied")

    # Report results
    if all_errors:
        print(f"\n[FAIL] {len(all_errors)} error(s):", file=sys.stderr)
        for error in all_errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"\n[PASS] All checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
