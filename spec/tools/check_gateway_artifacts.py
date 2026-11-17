"""Validation checks for gateway artifacts P_A and I_A2.

Usage (from the repository root):
    python spec/tools/check_gateway_artifacts.py

Validates:
- Structure of P_A (patterns) and I_A2 (indicators) YAML files
- Every regex compiles in Python and is RE2-compatible (no backreferences/lookbehind)
- Every positive test vector matches its pattern
- Every negative test vector does not match its pattern
- pattern_id and indicator_id are globally unique
- Required fields are present and well-formed
"""
import os
import re
import sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
GAP1 = os.path.dirname(HERE)
ROOT = os.path.dirname(GAP1)

RESULTS = []


def record(name, problems, detail=""):
    """Record a check result."""
    RESULTS.append((name, not problems, problems, detail))
    return not bool(problems)


def load_yaml(rel):
    """Load YAML file from spec/ directory."""
    path = os.path.join(GAP1, rel)
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception as e:
        return None, f"Failed to load {path}: {e}"


def check_re2_compat(regex_str):
    """Check if regex is compatible with RE2 (no backreferences, no lookbehind).

    Returns: (bool, str) - (compatible, error_message)
    """
    problems = []

    # Check for backreferences (\1, \2, etc.)
    if re.search(r'\\[1-9]\d*', regex_str):
        problems.append("Contains backreferences (\\1, \\2, etc.) - not RE2-compatible")

    # Check for lookbehind assertions
    if re.search(r'\(\?<[=!]', regex_str):
        problems.append("Contains lookbehind assertions (?<=, ?<!) - not RE2-compatible")

    # Check for lookahead assertions (lookahead is OK in RE2)
    # (?=, ?! are allowed

    # Check for named groups ((?P<name>) is allowed in RE2)

    return not bool(problems), problems


def compile_and_test_pattern(pattern_id, regex_str, positive_tests, negative_tests):
    """Compile regex and test positive/negative vectors.

    Returns: (compiled, error_list)
    """
    problems = []

    # Test RE2 compatibility
    compatible, compat_problems = check_re2_compat(regex_str)
    if not compatible:
        problems.append(f"RE2 incompatibility in {pattern_id}: {', '.join(compat_problems)}")
        return False, problems

    # Try to compile in Python
    try:
        compiled = re.compile(regex_str)
    except re.error as e:
        problems.append(f"Pattern {pattern_id} failed to compile: {e}")
        return False, problems

    # Test positive vectors
    for positive in (positive_tests or []):
        if not compiled.search(positive):
            problems.append(
                f"Pattern {pattern_id}: positive test failed: "
                f"regex does not match '{positive[:50]}...'" if len(positive) > 50 else f"'{positive}'"
            )

    # Test negative vectors
    for negative in (negative_tests or []):
        if compiled.search(negative):
            problems.append(
                f"Pattern {pattern_id}: negative test failed: "
                f"regex should not match '{negative[:50]}...'" if len(negative) > 50 else f"'{negative}'"
            )

    return len(problems) == 0, problems


def validate_p_a_structure(data):
    """Validate P_A (patterns) YAML structure and content."""
    problems = []
    seen_pattern_ids = {}

    if not data:
        return [f"P_A file is empty or invalid"]

    # Check top-level required fields
    if data.get("status") != "UNFROZEN":
        problems.append("P_A status must be 'UNFROZEN'")

    if not data.get("version"):
        problems.append("P_A must have a version field")

    if not data.get("sources") or not isinstance(data["sources"], list):
        problems.append("P_A must have a 'sources' list")

    # Validate each source
    for i, source in enumerate(data.get("sources", [])):
        if not source.get("name"):
            problems.append(f"Source {i}: missing 'name'")
        if not source.get("url"):
            problems.append(f"Source {i}: missing 'url'")
        if not source.get("version"):
            problems.append(f"Source {i}: missing 'version'")
        if not source.get("license"):
            problems.append(f"Source {i}: missing 'license'")

    # Validate patterns
    patterns = data.get("patterns", [])
    if not patterns:
        problems.append("P_A must have at least one pattern")

    for i, pattern in enumerate(patterns):
        # Required fields
        if not pattern.get("pattern_id"):
            problems.append(f"Pattern {i}: missing 'pattern_id'")
            continue

        pattern_id = pattern["pattern_id"]

        # Check uniqueness
        if pattern_id in seen_pattern_ids:
            problems.append(f"Duplicate pattern_id: '{pattern_id}'")
        seen_pattern_ids[pattern_id] = i

        # Check required fields
        if not pattern.get("class"):
            problems.append(f"Pattern {pattern_id}: missing 'class'")

        if not pattern.get("locations"):
            problems.append(f"Pattern {pattern_id}: missing 'locations'")
        elif not isinstance(pattern["locations"], list):
            problems.append(f"Pattern {pattern_id}: 'locations' must be a list")
        else:
            # Validate location values
            valid_locs = {"PATH", "QUERY", "REQUEST_BODY"}
            for loc in pattern["locations"]:
                if loc not in valid_locs:
                    problems.append(
                        f"Pattern {pattern_id}: invalid location '{loc}' "
                        f"(must be one of {valid_locs})"
                    )

        if not pattern.get("regex"):
            problems.append(f"Pattern {pattern_id}: missing 'regex'")
        else:
            # Compile and test
            regex_str = pattern["regex"]
            positive = pattern.get("positive_tests", [])
            negative = pattern.get("negative_tests", [])
            compiled, test_problems = compile_and_test_pattern(
                pattern_id, regex_str, positive, negative
            )
            if not compiled:
                problems.extend(test_problems)

        if not pattern.get("source"):
            problems.append(f"Pattern {pattern_id}: missing 'source'")

        if not pattern.get("positive_tests"):
            problems.append(f"Pattern {pattern_id}: missing 'positive_tests'")

        if not pattern.get("negative_tests"):
            problems.append(f"Pattern {pattern_id}: missing 'negative_tests'")

    return problems


def validate_i_a2_structure(data):
    """Validate I_A2 (indicators) YAML structure and content."""
    problems = []
    seen_indicator_ids = {}

    if not data:
        return [f"I_A2 file is empty or invalid"]

    # Check top-level required fields
    if data.get("status") != "UNFROZEN":
        problems.append("I_A2 status must be 'UNFROZEN'")

    if not data.get("version"):
        problems.append("I_A2 must have a version field")

    if not data.get("sources") or not isinstance(data["sources"], list):
        problems.append("I_A2 must have a 'sources' list")

    # Validate each source
    for i, source in enumerate(data.get("sources", [])):
        if not source.get("name"):
            problems.append(f"Source {i}: missing 'name'")
        if not source.get("url"):
            problems.append(f"Source {i}: missing 'url'")
        if not source.get("version"):
            problems.append(f"Source {i}: missing 'version'")
        if not source.get("license"):
            problems.append(f"Source {i}: missing 'license'")

    # Validate indicators
    indicators = data.get("indicators", [])
    if not indicators:
        problems.append("I_A2 must have at least one indicator")

    for i, indicator in enumerate(indicators):
        # Required fields
        if not indicator.get("indicator_id"):
            problems.append(f"Indicator {i}: missing 'indicator_id'")
            continue

        indicator_id = indicator["indicator_id"]

        # Check uniqueness
        if indicator_id in seen_indicator_ids:
            problems.append(f"Duplicate indicator_id: '{indicator_id}'")
        seen_indicator_ids[indicator_id] = i

        # Check required fields
        if not indicator.get("class"):
            problems.append(f"Indicator {indicator_id}: missing 'class'")

        if not indicator.get("rule"):
            problems.append(f"Indicator {indicator_id}: missing 'rule'")

        if not indicator.get("pattern_type"):
            problems.append(f"Indicator {indicator_id}: missing 'pattern_type'")
        else:
            # Validate pattern_type
            valid_types = {
                "status", "body_marker", "reflection", "response_header", "temporal"
            }
            if indicator["pattern_type"] not in valid_types:
                problems.append(
                    f"Indicator {indicator_id}: invalid pattern_type "
                    f"(must be one of {valid_types})"
                )

        if not indicator.get("source"):
            problems.append(f"Indicator {indicator_id}: missing 'source'")

        # Validate body_regexes if present
        if "body_regexes" in indicator:
            body_regexes = indicator["body_regexes"]
            if not isinstance(body_regexes, list):
                problems.append(f"Indicator {indicator_id}: 'body_regexes' must be a list")
            else:
                for j, regex_str in enumerate(body_regexes):
                    compatible, compat_problems = check_re2_compat(regex_str)
                    if not compatible:
                        problems.append(
                            f"Indicator {indicator_id} body_regexes[{j}]: "
                            f"{', '.join(compat_problems)}"
                        )
                    # Try to compile
                    try:
                        re.compile(regex_str)
                    except re.error as e:
                        problems.append(
                            f"Indicator {indicator_id} body_regexes[{j}] "
                            f"failed to compile: {e}"
                        )

        # Validate positive/negative test structure
        if "positive_tests" in indicator and indicator["positive_tests"]:
            for test in indicator["positive_tests"]:
                if isinstance(test, dict) and "body_snippet" in test:
                    # Body marker test - validate if body_regexes present
                    if "body_regexes" in indicator:
                        body_matched = False
                        for regex_str in indicator["body_regexes"]:
                            if re.search(regex_str, test["body_snippet"]):
                                body_matched = True
                                break
                        if not body_matched:
                            problems.append(
                                f"Indicator {indicator_id}: positive test "
                                f"'{test['body_snippet'][:50]}' "
                                "does not match any body_regex"
                            )

    return problems


def main():
    """Run all checks."""
    print("Validating gateway artifacts P_A and I_A2...\n")

    # Load P_A
    p_a_data = load_yaml("artifacts/p_a.v0.yaml")
    if isinstance(p_a_data, tuple):
        record("Load P_A artifact", [p_a_data[1]])
        return 1

    # Load I_A2
    i_a2_data = load_yaml("artifacts/i_a2.v0.yaml")
    if isinstance(i_a2_data, tuple):
        record("Load I_A2 artifact", [i_a2_data[1]])
        return 1

    # Validate P_A
    p_a_problems = validate_p_a_structure(p_a_data)
    record("Validate P_A structure", p_a_problems)

    # Validate I_A2
    i_a2_problems = validate_i_a2_structure(i_a2_data)
    record("Validate I_A2 structure", i_a2_problems)

    # Check pattern_id and indicator_id uniqueness across both artifacts
    p_a_ids = {p["pattern_id"] for p in (p_a_data.get("patterns") or [])}
    i_a2_ids = {i["indicator_id"] for i in (i_a2_data.get("indicators") or [])}

    overlap = p_a_ids & i_a2_ids
    if overlap:
        record(
            "P_A and I_A2 have disjoint ID namespaces",
            [f"Overlapping IDs: {overlap}"]
        )
    else:
        record("P_A and I_A2 have disjoint ID namespaces", [])

    # Print results
    print("\nCheck Results:")
    print("=" * 80)
    passed = 0
    failed = 0
    for name, success, problems, detail in RESULTS:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} {name}")
        if problems:
            for problem in problems[:3]:  # Show first 3 problems
                print(f"       {problem}")
            if len(problems) > 3:
                print(f"       ... and {len(problems) - 3} more problems")
        if detail:
            print(f"       {detail}")
        if success:
            passed += 1
        else:
            failed += 1

    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
