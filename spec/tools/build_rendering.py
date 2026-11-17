"""Build spec/generator/evidence-rendering.v0.yaml from spec/rules/rulebook.v0.yaml.

Usage (from repository root):
    python spec/tools/build_rendering.py [--dry-run]

Requires grpcio-tools, protobuf, and PyYAML. --dry-run prints the YAML without
writing the file. On regeneration the builder preserves any existing
renderer_notes entries in the output file.
"""
import argparse
import os
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
GAP1 = os.path.dirname(HERE)
ROOT = os.path.dirname(GAP1)
sys.path.insert(0, HERE)
from check_gap1 import compile_protos  # noqa: E402

PKG = "microtrace.v0"

INCLUDED = frozenset({
    "A1", "A2", "B1", "B2", "B3", "C1a", "C1b", "C2",
    "D1", "E1", "E2", "F1", "G1a", "H1", "H2", "H3", "H4",
    "G1c",   # add-on set only (exp2-conflict-origin-cases-plan D-27)
})

EXCLUDED_REASONS = {
    "D2": ("status conditional; AUD-POD-BINDING-EXTRA and CRED-CALLER-ATTRIBUTION "
           "Gap 2 tests not yet passed"),
    "E3": ("status conditional; E3-ARTIFACT-IDENTITY and E3-REEXEC-RESTART "
           "Gap 2 tests not yet passed"),
    "F2": ("status conditional; F2-HISTORICAL-RIGHTS and AUD-RBAC-BODY "
           "Gap 2 tests not yet passed; unresolved Stage 3 evidence requirement"),
    "G1b": ("status conditional; CRED-JTI-VERSION-INDEX and G1B-TARGET-EFFECT "
            "Gap 2 tests not yet passed"),
    "G2": ("G2-TARGET-PROCESS-JOIN not yet passed; "
           "unresolved Stage 3 evidence requirement"),
    "H5": ("OFFNODE-DBAUDIT-SOURCE, OFFNODE-PATH-COVERAGE, and OFFNODE-FLOW-EXPORT "
           "unresolved Stage 3 evidence requirements"),
}

OUTPUT_PATH = os.path.join(GAP1, "generator", "evidence-rendering.v0.yaml")

# Initial hand-authored renderer_notes per included finding. The builder
# preserves any existing notes on regeneration; these are written only when no
# prior entry exists for that finding.
DEFAULT_NOTES = {
    "A1": (
        "PatternMatch entries in GatewayObservation.matches are sensor-computed: apply "
        "the frozen P_A pattern set to path, query, and observed body chunks; the "
        "scenario never sets pattern_id directly. body_truncated and observer_loss are "
        "sensor-observed flags driven by the simulated observability profile. "
        "PatternMatch.pattern_set_version must equal the P_A artifact version for the run."
    ),
    "A2": (
        "ResponseIndicator entries in GatewayObservation.response_indicators are "
        "sensor-computed from the frozen I_A2 set; the scenario never sets indicator_id "
        "directly. A2 requires the same request_id as A1; render both in one event. "
        "ResponseIndicator.indicator_set_version must equal the I_A2 artifact version. "
        "If the observability profile drops the response, emit only an A1 opportunity; "
        "the A2 opportunity becomes UNOBSERVABLE."
    ),
    "B1": (
        "AuditDerived.principal is normalizer-computed from AuditEvent.user; the scenario "
        "specifies the principal by identity, not by direct field assignment. The per-"
        "principal baseline Q_B1 must be built from the rendered benign workload before "
        "attack scenarios run; every authenticated principal in the generated world must "
        "have a Q_B1 entry."
    ),
    "B2": (
        "AuditDerived.authentication_failed and observed_source are normalizer-computed. "
        "Generate at least N_B2+1 consecutive 401 responses from one source IP within "
        "W_B2 for a PRESENT opportunity. Negative control: generate a burst of 403 "
        "authorization denials from the same source within W_B2; B2 must not fire."
    ),
    "B3": (
        "AuditDerived.principal is normalizer-computed. The per-principal request-rate "
        "baseline Q_B3 must be consistent with the benign request volume the generator "
        "renders; if a benign scenario sends above Q_B3, either raise the baseline or "
        "add an ABSENT opportunity for the benign lookalike."
    ),
    "C1a": (
        "EbpfDerived.pod_uid is normalizer-computed from cgroup/container identity at "
        "event time; the scenario specifies the container, not the UID directly. Z_C "
        "(declared runtime socket paths) is a declared artifact; connections to listed "
        "paths qualify. For BpfDetail records, set caller_is_sensor=true only for the "
        "MicroTRACE sensor process identity in the world model; those events are excluded."
    ),
    "C1b": (
        "EbpfDerived.host_namespace_after is sensor-computed: compare "
        "NamespaceDetail.after.mnt and .pid to NamespaceDetail.host_reference (the "
        "node init namespace inodes recorded at sensor start via NS_SAMPLE); set "
        "host_namespace_after=true only when both match. The lineage_root -> Pod UID "
        "join requires a contiguous lineage chain in the context history with no gaps."
    ),
    "C2": (
        "PtraceDetail.target is a ProcessKey; use a valid process identity from the "
        "world model. The cgroup/container -> Pod UID join (EbpfDerived.pod_uid, not a "
        "direct C2 input) must be consistent with the container lineage. Use "
        "PTRACE_ATTACH (16) or PTRACE_SEIZE (16902) as the ptrace request constant."
    ),
    "D1": (
        "EbpfDerived.token_file (a ProjectedVersion) is normalizer-computed from "
        "FileIdentity.projected, which requires a prior ProjectedIndexEntry event on "
        "family token.file_index to populate the node index; render the index event "
        "before the file.read event. E_D1 is a declared expected-reader artifact; build "
        "it from the benign workload before any D1 opportunity can be emitted. "
        "EbpfDerived.pod_uid is normalizer-computed from the reader's cgroup identity."
    ),
    "E1": (
        "AdmissionDecision.enforcement_audit_mode must be true (audit-mode policy). "
        "resource_uid must match an existing Pod UID in the context history; if the "
        "observability profile does not export it, set a JOIN_UNCERTAIN completeness gap "
        "and emit the finding with pod_uid_join_status=CONDITIONAL_JOIN_UNVALIDATED. "
        "dry_run must be false; a dry_run=true admission must not produce an E1 opportunity."
    ),
    "E2": (
        "EbpfDerived.pod_uid and container_name are normalizer-computed from cgroup "
        "identity. ContainerStatusSummary.started_at comes from a context ObjectObservation "
        "with a PodSummary; render that watch event before the mutation event time. "
        "E_E2 is a declared expected-writer artifact; build it from the world model "
        "before any E2 opportunity can be emitted."
    ),
    "F1": (
        "PrivilegeDetail.before.euid and .after.euid, and .before.cap_effective / "
        ".after.cap_effective, must be set accurately for the transition. E_F1 is a "
        "declared expected-transitions artifact (e.g. declared setuid helpers); a "
        "transition in E_F1 does not emit a F1 opportunity. Build E_F1 from the world "
        "model's declared service processes before any attack scenario runs."
    ),
    "G1a": (
        "EbpfDerived.remote_pod_uid and pod_uid are normalizer-computed from the socket "
        "remote address (time-indexed IP -> Pod) and cgroup identity respectively. Q_G1a "
        "is the frozen service-edge baseline (versioned G baseline) as (source workload, "
        "destination workload, port) triples; build from benign workload before attack "
        "scenarios. After Pod IP reuse, the interval-correct join resolves to the new Pod; "
        "a connect to a baselined workload on a reused IP does not trigger G1a."
    ),
    "H1": (
        "EbpfDerived.remote_class is normalizer-computed; H1 counts only external "
        "destinations. Q_H1 is the per-workload egress percentile baseline (versioned H "
        "baseline); build from benign egress before attack scenarios. FlowCounter records "
        "are counter-mode aggregates; render at interval boundaries declared in the capture "
        "manifest. A sensor loss interval overlapping the counter window causes abstention."
    ),
    "H2": (
        "EbpfDerived.remote_class is normalizer-computed. Q_H2 is the per-workload "
        "external destination set (versioned H baseline); any (IP, port) absent from "
        "Q_H2 triggers H2. Build Q_H2 from benign outbound connects before attack "
        "scenarios. H2 fires on the connect attempt; no flow bytes are required."
    ),
    "H3": (
        "AuditDerived.principal is normalizer-computed. Generate at least N_H3+1 "
        "qualifying secret list/get/watch events within W_H3 for a PRESENT opportunity. "
        "At Metadata level a list returns no individual secret names; count it as one "
        "request per namespace scope, not per secret."
    ),
    "H4": (
        "EbpfDerived.data_class is sensor-computed: match FileIdentity.ino against the "
        "C_H4 declared sensitive-data class set; set data_class only for a match. C_H4 "
        "must be consistent with the files the world model places in sensitive paths "
        "(tokens, config secrets, declared sensitive volumes). EbpfDerived.lineage_id is "
        "normalizer-computed from the lineage root. node_seq is the ordering authority; "
        "ensure read and connect events in the same lineage have monotonically increasing "
        "node_seq values on their node. The FlowCounter must be owned by the same process "
        "lineage as the read event."
    ),
}


def _collect_reachable(msg_type, visited):
    if msg_type is None or msg_type.full_name in visited:
        return
    visited.add(msg_type.full_name)
    for fld in msg_type.fields:
        if fld.message_type is not None:
            _collect_reachable(fld.message_type, visited)


def build_reachability(pool):
    """Return (record_reach, derived_reach): alt_name -> frozenset of reachable msg names.

    record_reach maps each NormalizedEvent.record oneof alternative field name
    (e.g. 'gateway') to the frozenset of all protobuf message full_names reachable
    from that alternative's message type (transitively through all message fields).
    derived_reach does the same for the NormalizedEvent.derived oneof.
    """
    ne = pool.FindMessageTypeByName(f"{PKG}.NormalizedEvent")
    record_reach, derived_reach = {}, {}
    for fld in ne.oneofs_by_name["record"].fields:
        s = set()
        _collect_reachable(fld.message_type, s)
        record_reach[fld.name] = frozenset(s)
    for fld in ne.oneofs_by_name["derived"].fields:
        s = set()
        _collect_reachable(fld.message_type, s)
        derived_reach[fld.name] = frozenset(s)
    return record_reach, derived_reach


def resolve_input(inp, record_reach, derived_reach):
    """Return (record_alt, derived_alt) for one rulebook input entry.

    Returns the NormalizedEvent oneof field name that carries the input's
    containing message, or None if it cannot be reached from any alternative
    (a contract gap).
    """
    msg_name = inp["field"].rpartition(".")[0]
    source = inp["source"]

    if source == "normalizer":
        for alt, reachable in derived_reach.items():
            if msg_name in reachable:
                return None, alt
        return None, None  # contract gap

    for alt, reachable in record_reach.items():
        if msg_name in reachable:
            return alt, None
    return None, None  # contract gap


def build_finding_entry(rb_finding, pool, record_reach, derived_reach, notes):
    """Build the YAML dict for one finding."""
    fid = rb_finding["id"]
    entry = {
        "id": fid,
        "name": rb_finding["name"],
        "agent": rb_finding["agent"],
        "included": fid in INCLUDED,
    }
    if fid not in INCLUDED:
        entry["reason"] = EXCLUDED_REASONS.get(fid, "excluded from evaluation plan")

    state = rb_finding["state"]
    entry["state"] = {
        "kind": state["kind"],
        "key": list(state["key"]),
        "window": state.get("window"),
    }

    inputs = []
    for inp in rb_finding["inputs"]:
        rec_alt, der_alt = resolve_input(inp, record_reach, derived_reach)
        item = {
            "field": inp["field"],
            "source": inp["source"],
            "family": inp.get("family"),
            "extra_keys": inp.get("extra_keys"),
            "record": rec_alt,
            "derived": der_alt,
            "gap2": inp.get("gap2", []),
        }
        # Inputs sharing an any_of group are alternatives: one suffices.
        if inp.get("any_of"):
            item["any_of"] = inp["any_of"]
        inputs.append(item)
    entry["inputs"] = inputs
    entry["context_joins"] = list(rb_finding["context_joins"])
    entry["parameters"] = list(rb_finding["parameters"])
    entry["abstain"] = list(rb_finding["abstain"])
    entry["negative_controls"] = list(rb_finding["negative_controls"])
    if fid in INCLUDED:
        entry["renderer_notes"] = notes.get(fid, "")
    return entry


def load_existing_notes(path):
    """Read renderer_notes from the existing output file, keyed by finding id."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "findings" not in data:
        return {}
    return {
        f["id"]: f["renderer_notes"]
        for f in data["findings"]
        if isinstance(f, dict) and f.get("renderer_notes")
    }


class _LiteralDumper(yaml.Dumper):
    pass


def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_LiteralDumper.add_representer(str, _str_representer)


def build_yaml(rb, pool):
    """Return the complete rendering table as a Python dict."""
    record_reach, derived_reach = build_reachability(pool)

    # Preserve hand-maintained notes from existing file; fall back to defaults.
    notes = dict(DEFAULT_NOTES)
    notes.update(load_existing_notes(OUTPUT_PATH))

    findings = [
        build_finding_entry(f, pool, record_reach, derived_reach, notes)
        for f in rb["findings"]
    ]
    return {
        "schema_version": "evidence-rendering.v0",
        "generated_by": "spec/tools/build_rendering.py",
        "source": "spec/rules/rulebook.v0.yaml",
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Print YAML to stdout without writing the file")
    args = ap.parse_args()

    rb_path = os.path.join(GAP1, "rules", "rulebook.v0.yaml")
    with open(rb_path, encoding="utf-8") as fh:
        rb = yaml.safe_load(fh)

    with tempfile.TemporaryDirectory() as tmp:
        pool, _ = compile_protos(tmp)
    if pool is None:
        print("ERROR: proto compilation failed", file=sys.stderr)
        return 1

    data = build_yaml(rb, pool)
    out = yaml.dump(data, Dumper=_LiteralDumper, allow_unicode=True,
                    default_flow_style=False, sort_keys=False)

    if args.dry_run:
        print(out)
    else:
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
        print(f"Written: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
