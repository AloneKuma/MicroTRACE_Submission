"""Consistency check for spec/generator/evidence-rendering.v0.yaml.

Usage (from repository root):
    python spec/tools/check_rendering.py

Checks:
  1. The committed YAML exists.
  2. Every field path in it resolves in the compiled proto schema.
  3. Every included finding has at least one input mapped to a record or
     derived message.
  4. Regenerating the table in memory (without renderer_notes) produces the
     same result as the committed file (ignoring renderer_notes).

Exit 0 on success, 1 on any failure.
"""
import os
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
GAP1 = os.path.dirname(HERE)
ROOT = os.path.dirname(GAP1)
sys.path.insert(0, HERE)
from check_gap1 import compile_protos, resolve_field  # noqa: E402
from build_rendering import (  # noqa: E402
    INCLUDED,
    OUTPUT_PATH,
    build_reachability,
    build_finding_entry,
)

RESULTS = []


def record(name, problems, detail=""):
    RESULTS.append((name, not problems, problems, detail))


def report():
    failed = 0
    for name, ok, problems, detail in RESULTS:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" ({detail})" if detail else ""))
        for p in problems[:40]:
            print(f"       - {p}")
        failed += not ok
    print(f"\n{len(RESULTS) - failed} passed, {failed} failed")
    return 1 if failed else 0


def _strip_notes(findings):
    """Return a copy of findings with renderer_notes removed from every entry."""
    result = []
    for f in findings:
        f2 = dict(f)
        f2.pop("renderer_notes", None)
        result.append(f2)
    return result


def check_file_exists():
    if not os.path.exists(OUTPUT_PATH):
        record("rendering table: file exists at spec/generator/evidence-rendering.v0.yaml",
               [f"{OUTPUT_PATH} not found"])
        return False
    record("rendering table: file exists at spec/generator/evidence-rendering.v0.yaml", [])
    return True


def check_field_paths(pool, findings):
    """Every field path in inputs must resolve in the compiled schema."""
    problems = []
    count = 0
    for f in findings:
        for inp in f.get("inputs", []):
            count += 1
            if resolve_field(pool, inp["field"]) is None:
                problems.append(f"{f['id']}: unresolved field {inp['field']}")
    record("rendering: every field path in inputs exists in the compiled schema",
           problems, f"{count} references checked")


def check_included_have_mapping(findings):
    """Every included finding must have at least one input mapped to record or derived."""
    problems = []
    for f in findings:
        if not f.get("included"):
            continue
        has_mapping = any(
            inp.get("record") or inp.get("derived")
            for inp in f.get("inputs", [])
        )
        if not has_mapping:
            problems.append(
                f"{f['id']}: no input mapped to a NormalizedEvent record or derived alternative"
            )
    record("rendering: every included finding has at least one input with a record or derived mapping",
           problems)


def check_table_current(rb, pool):
    """Regenerate in memory and compare to the committed file, ignoring renderer_notes."""
    record_reach, derived_reach = build_reachability(pool)

    with open(OUTPUT_PATH, encoding="utf-8") as fh:
        committed = yaml.safe_load(fh)

    committed_findings = _strip_notes(committed.get("findings", []))

    expected_findings = [
        build_finding_entry(f, pool, record_reach, derived_reach, notes={})
        for f in rb["findings"]
    ]
    expected_stripped = _strip_notes(expected_findings)

    problems = []
    if len(committed_findings) != len(expected_stripped):
        problems.append(
            f"finding count: committed {len(committed_findings)} "
            f"!= expected {len(expected_stripped)}"
        )
    else:
        for comm, exp in zip(committed_findings, expected_stripped):
            if comm != exp:
                # Report which fields differ for easier diagnosis.
                for k in set(list(comm) + list(exp)):
                    if comm.get(k) != exp.get(k):
                        problems.append(
                            f"{exp.get('id', '?')}: field '{k}' differs "
                            f"(committed={comm.get(k)!r}, expected={exp.get(k)!r})"
                        )

    n_included = sum(1 for f in expected_stripped if f.get("included"))
    record(
        "rendering: committed YAML matches regeneration (ignoring renderer_notes)",
        problems,
        f"{len(expected_stripped)} findings, {n_included} included",
    )


def main():
    rb_path = os.path.join(GAP1, "rules", "rulebook.v0.yaml")
    with open(rb_path, encoding="utf-8") as fh:
        rb = yaml.safe_load(fh)

    if not check_file_exists():
        return report()

    with open(OUTPUT_PATH, encoding="utf-8") as fh:
        committed = yaml.safe_load(fh)
    findings = committed.get("findings", [])

    with tempfile.TemporaryDirectory() as tmp:
        pool, _ = compile_protos(tmp)
    if pool is None:
        record("proto compilation for check_rendering", ["failed"])
        return report()

    check_field_paths(pool, findings)
    check_included_have_mapping(findings)
    check_table_current(rb, pool)
    return report()


if __name__ == "__main__":
    sys.exit(main())
