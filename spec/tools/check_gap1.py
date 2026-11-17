"""Offline consistency checks for the MicroTRACE Gap 1 artifacts.

Usage (from the repository root):
    python spec/tools/check_gap1.py [--write-traceability] [--derive]

Requires grpcio-tools (bundled protoc), protobuf, and PyYAML. Nothing here
contacts a cluster; a pass means the artifacts agree with each other and with
the current paper (paper/D3_v24.tex), not that any mechanism works on a cluster.
"""
import argparse
import os
import re
import sys
import tempfile

import yaml
from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory

HERE = os.path.dirname(os.path.abspath(__file__))
GAP1 = os.path.dirname(HERE)
ROOT = os.path.dirname(GAP1)
DESIGN = os.path.join(ROOT, "docs", "design")
PLANS = os.path.join(ROOT, "docs", "plans")
sys.path.insert(0, HERE)
import mtcodec  # noqa: E402

PKG = "microtrace.v0"
RESULTS = []


def record(name, problems, detail=""):
    RESULTS.append((name, not problems, problems, detail))


def load_yaml(rel):
    with open(os.path.join(GAP1, rel), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------- protobuf
def compile_protos(outdir):
    import grpc_tools
    from grpc_tools import protoc
    proto_root = os.path.join(GAP1, "proto")
    files = sorted(
        "microtrace/v0/" + f
        for f in os.listdir(os.path.join(proto_root, "microtrace", "v0"))
        if f.endswith(".proto"))
    desc = os.path.join(outdir, "microtrace.pb")
    args = ["protoc", "-I.",
            f"-I{os.path.join(os.path.dirname(grpc_tools.__file__), '_proto')}",
            f"--descriptor_set_out={desc}", "--include_imports", *files]
    cwd = os.getcwd()
    os.chdir(proto_root)
    try:
        rc = protoc.main(args)
    finally:
        os.chdir(cwd)
    if rc != 0:
        record("proto: compile all .proto files with protoc", [f"protoc exit {rc}"])
        return None, files
    fds = descriptor_pb2.FileDescriptorSet()
    with open(desc, "rb") as fh:
        fds.ParseFromString(fh.read())
    pool = descriptor_pool.DescriptorPool()
    for fd in fds.file:
        pool.Add(fd)
    record("proto: compile all .proto files with protoc", [],
           f"{len(files)} files, libprotoc via grpcio-tools")
    return pool, files


def resolve_field(pool, path):
    msg_name, _, field = path.rpartition(".")
    try:
        msg = pool.FindMessageTypeByName(msg_name)
    except KeyError:
        return None
    return msg.fields_by_name.get(field)


def check_no_bytes_fields(pool, files):
    problems = []
    for f in files:
        fd = pool.FindFileByName(f)
        stack = list(fd.message_types_by_name.values())
        while stack:
            m = stack.pop()
            stack.extend(m.nested_types)
            for fld in m.fields:
                if fld.type == fld.TYPE_BYTES:
                    problems.append(f"{m.full_name}.{fld.name} is bytes")
    record("proto: no raw-bytes fields (credential/body bytes cannot be carried)", problems)


# ---------------------------------------------------------------- Table I
TACTICS = {
    "Unmapped": None, "Initial Access": "INITIAL_ACCESS", "Execution": "EXECUTION",
    "Persistence": "PERSISTENCE", "Privilege Escalation": "PRIVILEGE_ESCALATION",
    "Credential Access": "CREDENTIAL_ACCESS", "Discovery": "DISCOVERY",
    "Lateral Movement": "LATERAL_MOVEMENT", "Exfiltration": "EXFILTRATION",
}


# The paper of record (the latest version; older ones are frozen).
PAPER = os.path.join("paper", "D3_v24.tex")
N_FINDINGS = 24


def parse_table_i():
    """Rows of the tab:agents table: Agent & ID: Name[dagger] & Input & Detection & Tactic & Evidence."""
    text = open(os.path.join(ROOT, PAPER), encoding="utf-8").read()
    start = text.index(r"\label{tab:agents}")
    body = text[text.index(r"\begin{tabular}", start):text.index(r"\end{tabular}", start)]
    rows = {}
    for chunk in re.split(r"\\\\\s*\\hline", body):
        cells = [" ".join(c.split()) for c in re.split(r"(?<!\\)&", chunk)]
        if len(cells) != 6:
            continue
        agent = cells[0].split()[-1] if cells[0] else ""
        # $^\dagger$ = conditional type; $^\ddagger$ = evaluated on Targeted only.
        m = re.match(r"([A-H][0-9][a-z]?): (.+?)(\$\^\{?\\(d?dagger)\}?\$)?$", cells[1])
        if not m or agent not in set("ABCDEFGH"):
            continue
        fid, name, _, mark = m.groups()
        rows[fid] = {"agent": agent, "name": name.strip(), "dagger": mark == "dagger",
                     "targeted_only": mark == "ddagger", "tactic": TACTICS[cells[4]]}
    return rows


def check_rulebook_vs_table(rb):
    table = parse_table_i()
    problems = []
    if len(table) != N_FINDINGS:
        problems.append(f"Table I parse found {len(table)} rows, expected {N_FINDINGS}")
    rules = {f["id"]: f for f in rb["findings"]}
    if set(rules) != set(table):
        problems.append(f"ID mismatch: rulebook-only {sorted(set(rules) - set(table))}, "
                        f"table-only {sorted(set(table) - set(rules))}")
    for fid, row in table.items():
        r = rules.get(fid)
        if not r:
            continue
        if r["agent"] != row["agent"]:
            problems.append(f"{fid}: agent {r['agent']} != {row['agent']}")
        if r["primary_tactic"] != row["tactic"]:
            problems.append(f"{fid}: tactic {r['primary_tactic']} != Table I {row['tactic']}")
        if (r["status"] == "conditional") != row["dagger"]:
            problems.append(f"{fid}: status {r['status']} vs dagger {row['dagger']}")
    spec = open(os.path.join(DESIGN, "design-spec.md"), encoding="utf-8").read()
    m = re.search(r"finding types are `unmapped` by default\*\* \(([^)]+)\)", spec)
    unmapped_spec = {x.strip() for x in m.group(1).split(",")} if m else set()
    unmapped_rb = {k for k, v in rules.items() if v["primary_tactic"] is None}
    if unmapped_spec != unmapped_rb:
        problems.append(f"unmapped set {sorted(unmapped_rb)} != design-spec {sorted(unmapped_spec)}")
    record(f"rulebook: {N_FINDINGS} findings match {PAPER} Table I IDs, agents, tactics, daggers; "
           "unmapped set matches design-spec", problems,
           f"{len(rules)} rules, {len(unmapped_rb)} unmapped")
    return rules


REQUIRED_RULE_KEYS = ["id", "name", "agent", "primary_tactic", "status", "inputs", "context_joins",
                      "state", "parameters", "predicate", "evidence_threshold", "weaker_output",
                      "abstain", "emits", "negative_controls", "gap2"]


def check_rule_shape(rules):
    problems = []
    for fid, r in rules.items():
        for k in REQUIRED_RULE_KEYS:
            if k not in r:
                problems.append(f"{fid}: missing {k}")
        if not r.get("negative_controls"):
            problems.append(f"{fid}: no negative control")
        if r.get("state", {}).get("kind") not in {"stateless", "keyed", "global"}:
            problems.append(f"{fid}: bad state.kind")
        if re.search(r"\b\d+(\.\d+)?\s*(ms|s|seconds|minutes|%|bytes)\b", str(r.get("predicate", ""))):
            problems.append(f"{fid}: numeric threshold in predicate")
    record("rulebook: every rule has inputs, joins, state, predicate, threshold, abstention, "
           "emits, negative control, Gap 2 tests; no numeric thresholds", problems)


# ---------------------------------------------------------------- fields
def check_field_paths(pool, rb, manifest):
    problems, count = [], 0
    paths = list(manifest["common_fields"])
    for fam in manifest["families"]:
        paths += fam.get("fields", [])
    for r in rb["findings"]:
        paths += [i["field"] for i in r["inputs"]]
    for w in rb["witnesses"]:
        paths += w["fields"]
    for p in paths:
        count += 1
        if resolve_field(pool, p) is None:
            problems.append(f"unresolved field {p}")
    record("schema: every field path in manifest and rulebook exists in the compiled schema",
           problems, f"{count} references")


SOURCES_OK = {"ebpf", "audit", "gateway", "kyverno", "context", "normalizer", "db-audit", "path-flow"}


def exported_messages(pool, paths):
    """Message types reachable from the given field paths (nested exports)."""
    out, stack = set(), []
    for p in paths:
        fld = resolve_field(pool, p)
        if fld is not None and fld.message_type is not None:
            stack.append(fld.message_type)
    while stack:
        m = stack.pop()
        if m.full_name in out:
            continue
        out.add(m.full_name)
        stack.extend(f.message_type for f in m.fields if f.message_type is not None)
    return out


def check_manifest(pool, rb, manifest, rules):
    problems = []
    fams = {f["id"]: f for f in manifest["families"]}
    common = set(manifest["common_fields"])
    common_msgs = exported_messages(pool, common)
    used = {fid: set() for fid in fams}
    for r in rb["findings"]:
        for inp in r["inputs"]:
            if inp["source"] not in SOURCES_OK:
                problems.append(f"{r['id']}: input {inp['field']} has no known producer")
            if inp["source"] == "ebpf":
                fam = fams.get(inp.get("family"))
                if not fam:
                    problems.append(f"{r['id']}: eBPF input {inp['field']} names no manifest family")
                    continue
                msgs = common_msgs | exported_messages(pool, fam.get("fields", []))
                if inp["field"] not in set(fam.get("fields", [])) | common and                         inp["field"].rpartition(".")[0] not in msgs:
                    problems.append(f"{r['id']}: {inp['field']} not exported by family {fam['id']}")
                if r["id"] not in fam["consumers"]:
                    problems.append(f"{r['id']}: family {fam['id']} does not list it as consumer")
                used[fam["id"]].add(r["id"])
    wtypes = {w["type"] for w in rb["witnesses"]}
    for fid, fam in fams.items():
        finding_consumers = {c for c in fam["consumers"] if c in rules}
        extra = finding_consumers - used[fid]
        if extra:
            problems.append(f"family {fid} lists consumers {sorted(extra)} that use none of its fields")
        if not finding_consumers and not fam.get("witnesses") and \
                not {"completeness", "research"} & set(fam["consumers"]):
            problems.append(f"family {fid} has no consumer (orphan capture)")
        for w in fam.get("witnesses", []):
            if w not in wtypes:
                problems.append(f"family {fid}: unknown witness {w}")
        if fam["record_mode"] == "counter" and not fam.get("counter_allowed_for"):
            problems.append(f"family {fid}: counter mode without declared use")
    # Profiles: research-superset is a strict superset of evaluated; rules
    # never read a research-only family, so both profiles give MicroTRACE the
    # same inputs.
    prof = manifest.get("profiles", {})
    ev = prof.get("evaluated-v0", {})
    rs = prof.get("research-superset-v0", {})
    ev_all = set(ev.get("families", [])) | set(ev.get("optional", []))
    research_only = {f for f, fam in fams.items() if fam.get("profile") == "research-superset-v0"}
    if ev_all | research_only != set(fams):
        problems.append(f"families in no profile: {sorted(set(fams) - ev_all - research_only)}")
    if set(rs.get("families", [])) != research_only or rs.get("extends") != "evaluated-v0":
        problems.append("research-superset-v0 must extend evaluated-v0 with exactly the research families")
    for r in rb["findings"]:
        for inp in r["inputs"]:
            if inp.get("family") in research_only:
                problems.append(f"{r['id']}: reads research-only family {inp['family']}")
    for f in research_only:
        if fams[f]["consumers"] != ["research"]:
            problems.append(f"{f}: research family consumed by {fams[f]['consumers']}")
    record("manifest: every eBPF rule input maps to a family that exports it and lists the rule; "
           "no orphan or unused capture; research profile is a superset no rule reads", problems,
           f"{len(fams)} families, {len(research_only)} research-only")


# ---------------------------------------------------------------- Gap 2 / params
def check_gap2(rb, manifest, catalog):
    ids = {t["id"] for t in catalog["tests"]}
    problems, refs = [], set()
    for r in rb["findings"]:
        refs.update(r["gap2"])
        for i in r["inputs"]:
            refs.update(i.get("gap2", []))
    for w in rb["witnesses"]:
        refs.update(w["gap2"])
    for f in manifest["families"]:
        refs.update(f.get("gap2_tests", []))
    # Prose references in gap1 Markdown count as references to catalog IDs.
    for dirpath, _, names in os.walk(GAP1):
        for n in names:
            if n.endswith(".md") and n != "traceability.md":
                text = open(os.path.join(dirpath, n), encoding="utf-8").read()
                refs.update(x for x in re.findall(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b", text) if x in ids)
    missing = sorted(x for x in refs if x not in ids)
    problems += [f"unknown Gap 2 test {x}" for x in missing]
    unref = sorted(ids - refs)
    problems += [f"catalog test {x} referenced by no artifact" for x in unref]
    rows = {"Node export and load", "Audit and context", "Kafka contract", "Gateway", "Kyverno",
            "Credential", "G2 and G1b effect", "E3", "Sole grant", "Off-node"}
    plan = open(os.path.join(PLANS, "section-iii-completion-plan.md"), encoding="utf-8").read()
    for t in catalog["tests"]:
        if t["stage3_row"] not in rows or f"| {t['stage3_row']} |" not in plan:
            problems.append(f"{t['id']}: stage3_row '{t['stage3_row']}' not a Stage 3 row")
        verdicts = ("not_run", "pass", "narrowed", "unsupported", "inconclusive")
        if t["status"] not in verdicts:
            problems.append(f"{t['id']}: status {t['status']} not in {verdicts}")
        for route, v in (t.get("routes") or {}).items():
            if v not in verdicts:
                problems.append(f"{t['id']}: route {route} has status {v}")
        observed = t["status"] != "not_run" or any(v != "not_run" for v in (t.get("routes") or {}).values())
        if observed:
            ev = t.get("evidence")
            if not ev or not os.path.exists(os.path.join(ROOT, ev)):
                problems.append(f"{t['id']}: an observed status needs an existing evidence record")
            if not t.get("scope"):
                problems.append(f"{t['id']}: an observed status needs a scope")
    run = sum(1 for t in catalog["tests"] if t["status"] != "not_run")
    record("gap2: every referenced test exists, every test is referenced, rows match Stage 3, "
           "every observed status cites an evidence record and scope", problems,
           f"{len(ids)} tests, {run} with an observed status")


ORIGINS = {"sensor", "workload", "gateway-minted"}


def check_witness_origins(rb):
    """Rulebook witnesses label who can set each join-key component (design-spec 2)."""
    problems = []
    for w in rb["witnesses"]:
        ko = w.get("key_origin")
        if not isinstance(ko, dict) or not ko:
            problems.append(f"{w['type']}: no key_origin")
            continue
        bad = {k: v for k, v in ko.items() if v not in ORIGINS}
        if bad:
            problems.append(f"{w['type']}: unknown origin {bad}")
        if w["class"] == "direct" and not set(ko.values()) & {"sensor", "gateway-minted"}:
            problems.append(f"{w['type']}: direct witness has no sensor-originated key component")
        if "gateway-minted" in ko.values() and                 "microtrace.v0.GatewayObservation.request_id_origin" not in w["fields"]:
            problems.append(f"{w['type']}: gateway-minted key without GatewayObservation.request_id_origin")
        if "gateway-minted" in ko.values() and w["status"] != "conditional":
            problems.append(f"{w['type']}: gateway-minted key must stay conditional until its Gap 2 test passes")
    record("witness origins: every witness labels its key components; every direct witness has a "
           "sensor-originated component; gateway-minted keys carry request_id_origin", problems,
           f"{len(rb['witnesses'])} witnesses")


# Contract field names that the schema spells differently on purpose.
WITNESS_ALIASES = {"witness_window_ms": "applied_limits", "chain_span_limit_ms": "applied_limits",
                   "clock_uncertainty_ms": "clock_uncertainty_ns"}
STATUS_ALIASES = {"enabling": "ENABLING_ONLY"}


def check_witness_contract(pool):
    """contracts.md "Witness v0" fields, contradiction items and statuses exist in witness.proto."""
    text = open(os.path.join(DESIGN, "contracts.md"), encoding="utf-8").read()
    start = text.index("## Witness v0")
    section = text[start:text.index("\n## ", start + 1)]
    msg = pool.FindMessageTypeByName("microtrace.v0.Witness")
    contra = pool.FindMessageTypeByName("microtrace.v0.Contradiction")
    statuses = {v.name for v in pool.FindEnumTypeByName("microtrace.v0.WitnessStatus").values}
    problems, n = [], 0
    for row in section.splitlines():
        if not row.startswith("| `"):
            continue
        first = row.split("|")[1]
        for name in re.findall(r"`([a-z_]+)(?:\[\])?`", first):
            n += 1
            field = WITNESS_ALIASES.get(name, name)
            if field not in msg.fields_by_name:
                problems.append(f"contract field {name} missing from Witness")
        if "`contradictions[]`" in first:
            for item in re.findall(r"\{([^}]*)\}", row)[:1]:
                for k in (x.strip() for x in item.split(",")):
                    if k not in contra.fields_by_name and k + "s" not in contra.fields_by_name:
                        problems.append(f"contradiction item {k} missing from Contradiction")
        if "`status`" in first:
            for st in re.findall(r"`([a-z-]+)`", row.split("|")[3].split("(")[0]):  # list before the note
                enum = STATUS_ALIASES.get(st, st.upper().replace("-", "_"))
                if enum not in statuses:
                    problems.append(f"witness status {st} missing from WitnessStatus")
    record("witness contract: every contracts.md Witness v0 field, contradiction item and status "
           "exists in witness.proto", problems, f"{n} contract fields")


def check_parameters(rules):
    reg = open(os.path.join(DESIGN, "parameter-register.md"), encoding="utf-8").read()
    problems = []
    names = set()
    for r in rules.values():
        names.update(r["parameters"])
        if r["state"].get("window"):
            names.add(r["state"]["window"])
    for n in sorted(names):
        if f"`{n}`" not in reg:
            problems.append(f"parameter {n} not in parameter-register.md")
    record("parameters: every rule symbol and state window is in parameter-register.md",
           problems, f"{len(names)} symbols")


# ---------------------------------------------------------------- topics/keys
def enum_values(pool, name):
    return {v.name: v.number for v in pool.FindEnumTypeByName(f"{PKG}.{name}").values}


def check_topics(pool, topics, rules):
    problems = []
    key_types, comps = enum_values(pool, "KeyType"), enum_values(pool, "KeyComponent")
    by_type = {}
    names = {t["name"] for t in topics["topics"]}
    for t in topics["topics"]:
        if t["key_type"] not in key_types:
            problems.append(f"{t['name']}: unknown key type {t['key_type']}")
        for c in t["key_components"]:
            if c not in comps:
                problems.append(f"{t['name']}: unknown component {c}")
        prev = by_type.setdefault(t["key_type"], t["key_components"])
        if prev != t["key_components"]:
            problems.append(f"{t['key_type']}: inconsistent components across topics")
        if not t.get("retention"):
            problems.append(f"{t['name']}: no retention symbol")
    for fid, r in rules.items():
        tl = topics["finding_inputs"].get(fid)
        if not tl:
            problems.append(f"{fid}: no input topic")
            continue
        for tn in tl:
            if tn not in names:
                problems.append(f"{fid}: unknown topic {tn}")
                continue
            topic = next(t for t in topics["topics"] if t["name"] == tn)
            if r["state"]["kind"] == "keyed" and not set(r["state"]["key"]) <= set(topic["key_components"]):
                problems.append(f"{fid}: state key {r['state']['key']} not covered by {tn} key "
                                f"{topic['key_components']}")
    for fid, tn in (("H4", "agent.H.lineage.v0"), ("E3", "agent.E.v0")):
        if topics["finding_inputs"].get(fid) != [tn]:
            problems.append(f"{fid} must read {tn}")
    raw = next(t for t in topics["topics"] if t["name"] == "raw.ebpf.v0")
    if raw["key_components"] != ["NODE_ID"]:
        problems.append("raw.ebpf.v0 must be keyed by node only")
    record("kafka: topic keys are defined codes, consistent per key type, and cover every keyed "
           "rule's state key (H4, E3 explicit)", problems, f"{len(names)} topics")


# ---------------------------------------------------------------- audit policy
LEVELS = ["None", "Metadata", "Request", "RequestResponse"]
STAGES = {"RequestReceived", "ResponseStarted", "ResponseComplete", "Panic"}


def rule_matches(rule, req):
    if rule.get("users") or rule.get("userGroups"):
        if not req["authenticated"]:
            return False
        return False  # policy v0 uses no user selectors; any future use needs explicit modelling
    if rule.get("verbs") and req["verb"] not in rule["verbs"]:
        return False
    if rule.get("namespaces") and req.get("namespace") not in rule["namespaces"]:
        return False
    if "resources" in rule:
        if req.get("non_resource_url"):
            return False
        combined = req["resource"] + ("/" + req["subresource"] if req["subresource"] else "")
        for gr in rule["resources"]:
            if gr.get("group", "") != req["group"]:
                continue
            rs = gr.get("resources") or []
            if not rs:
                return True
            for r in rs:
                if r in (combined, "*") or (req["subresource"] and r in
                                             (req["resource"] + "/*", "*/" + req["subresource"])):
                    return True
        return False
    if "nonResourceURLs" in rule:
        url = req.get("non_resource_url")
        return bool(url) and any(url == u or (u.endswith("*") and url.startswith(u[:-1]))
                                 for u in rule["nonResourceURLs"])
    return True


def evaluate(policy, req):
    for i, rule in enumerate(policy["rules"]):
        if rule_matches(rule, req):
            omit = set(policy.get("omitStages", [])) | set(rule.get("omitStages", []))
            return i, rule["level"], omit
    return None, "None", set()


def check_audit_policy(rules):
    problems, probes = [], 0
    policy = load_yaml("audit/audit-policy.v0.yaml")
    if policy.get("apiVersion") != "audit.k8s.io/v1" or policy.get("kind") != "Policy":
        problems.append("apiVersion/kind")
    for i, r in enumerate(policy["rules"]):
        if r.get("level") not in LEVELS:
            problems.append(f"rule {i}: bad level")
        for s in r.get("omitStages", []):
            if s not in STAGES:
                problems.append(f"rule {i}: bad stage {s}")
    for fid, r in rules.items():
        audit_inputs = [i for i in r["inputs"] if i["source"] == "audit"]
        reqs = r.get("audit_requirements", [])
        if audit_inputs and not reqs:
            problems.append(f"{fid}: audit inputs but no audit_requirements")
        for q in reqs:
            for verb in q["verbs"]:
                probes += 1
                req = {"verb": verb, "group": q["group"], "resource": q["resource"],
                       "subresource": q["subresource"], "authenticated": q["authenticated"],
                       "non_resource_url": q.get("non_resource_url")}
                idx, level, omit = evaluate(policy, req)
                if LEVELS.index(level) < LEVELS.index(q["min_level"]):
                    problems.append(f"{fid}: {verb} {q['group']}/{q['resource']}/{q['subresource']} "
                                    f"gets {level} (rule {idx}), needs {q['min_level']}")
                for st in q["stages"]:
                    if st in omit:
                        problems.append(f"{fid}: stage {st} omitted by rule {idx}")
    for res, sub, grp in (("secrets", "", ""), ("configmaps", "", ""),
                          ("serviceaccounts", "token", ""), ("tokenreviews", "", "authentication.k8s.io")):
        for verb in ("get", "list", "watch", "create", "update", "patch", "delete"):
            probes += 1
            _, level, _ = evaluate(policy, {"verb": verb, "group": grp, "resource": res,
                                            "subresource": sub, "authenticated": True})
            if LEVELS.index(level) > LEVELS.index("Metadata"):
                problems.append(f"credential cap violated: {verb} {res}/{sub} -> {level}")
    record("audit policy: parses as audit.k8s.io/v1 Policy; first-match simulation gives every "
           "audit rule its level and stages; credential objects never above Metadata "
           "(own simulator, not kube-apiserver validation)", problems, f"{probes} probes")


# ---------------------------------------------------------------- examples
def key_components(topic, env):
    """Key component values for a record on `topic`, taken from the record."""
    if env["kind"] == "HEARTBEAT":
        return "KEY_PRODUCER_INSTANCE", [("PRODUCER_INSTANCE", env["heartbeat"]["producerInstance"])]
    ne = env.get("normalizedEvent", {})
    derived = ne.get("ebpfDerived") or ne.get("admissionDerived") or {}
    ad = ne.get("auditDerived", {})
    getters = {
        "NODE_ID": lambda: env["rawEbpf"]["nodeId"],
        "AUDIT_ID": lambda: env["rawAudit"]["auditId"],
        "REQUEST_ID": lambda: (env.get("rawGateway") or ne["gateway"])["requestId"],
        "ADMISSION_UID": lambda: env["rawKyverno"]["admissionRequestUid"],
        "OBJECT_UID": lambda: env["contextObservation"]["uid"],
        "FINDING_ID": lambda: env["finding"]["findingId"],
        "WITNESS_ID": lambda: env["witness"]["witnessId"],
        "INCIDENT_ID": lambda: env["incident"]["incidentId"],
        "LINEAGE_ID": lambda: derived["lineageId"],
        "CONTAINER_NAME": lambda: derived["containerName"],
        "VOLUME_NAME": lambda: derived["tokenFile"]["volumeName"],
        "ENTITY_TYPE_NAME": lambda: ne["entities"][0]["type"],
        "ENTITY_UID": lambda: ne["entities"][0]["uid"],
        "JTI": lambda: ad.get("usedCredentialId") or ad["issuedCredentialId"],
        "SOURCE_NAME": lambda: env["sourceCompleteness"]["source"],
        "SCOPE": lambda: env["sourceCompleteness"]["scope"],
        "RUN_ID": lambda: env["groundTruthAction"]["runId"],
        "EVALUATION_ID": lambda: env["ruleEvaluation"]["evaluationId"],
        "SOURCE_ADDRESS": lambda: (ne.get("offnodeDerived", {}).get("sourceAddress")
                                   or (env.get("rawDbAudit") or {}).get("client", {}).get("ip")
                                   or env["rawPathFlow"]["src"]["ip"]),
    }
    comps = []
    for c in topic["key_components"]:
        if c == "POD_UID":
            v = (derived["tokenFile"]["ownerPodUid"] if topic["key_type"] == "KEY_TOKEN_FILE_OWNER"
                 else derived["podUid"])
        else:
            v = getters[c]()
        comps.append((c, v))
    return topic["key_type"], comps


def encoded_key(pool, topic, env):
    key_types, comp_codes = enum_values(pool, "KeyType"), enum_values(pool, "KeyComponent")
    ktype, comps = key_components(topic, env)
    return ktype, comps, mtcodec.encode_key(key_types[ktype], [(comp_codes[c], v) for c, v in comps])


def fill_keys(records):
    """Used by build_example_trace.py to fill key_hex from the record fields."""
    topics = load_yaml("kafka/topics.yaml")
    with tempfile.TemporaryDirectory() as tmp:
        pool, _ = compile_protos(tmp)
    Env = message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{PKG}.Envelope"))
    by = {t["name"]: t for t in topics["topics"]}
    for rec in records:
        env = json_format.MessageToDict(json_format.ParseDict(rec["envelope"], Env()))
        rec["key_hex"] = encoded_key(pool, by[rec["topic"]], env)[2].hex()


def check_examples(pool, topics, rules, derive):
    problems = []
    data = load_yaml("examples/trace-v0.json")
    key_types = enum_values(pool, "KeyType")
    Env = message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{PKG}.Envelope"))
    topic_by = {t["name"]: t for t in topics["topics"]}
    envs, derived_out = {}, []
    for rec in data["records"]:
        label = rec["label"]
        try:
            msg = json_format.ParseDict(rec["envelope"], Env())
        except json_format.ParseError as exc:
            problems.append(f"{label}: {exc}")
            continue
        env = json_format.MessageToDict(msg)
        envs[label] = env
        run = env.get("run", {})
        if not run.get("runId") or run.get("split") != "SYNTHETIC_EXAMPLE" or not run.get("captureProfile"):
            problems.append(f"{label}: missing run context (run_id, split SYNTHETIC_EXAMPLE, capture_profile)")
        topic = topic_by.get(rec["topic"])
        if not topic:
            problems.append(f"{label}: unknown topic {rec['topic']}")
            continue
        if env["kind"] not in topic["kinds"]:
            problems.append(f"{label}: kind {env['kind']} not allowed on {rec['topic']}")
        if env["kind"] == "HEARTBEAT" and "explicit_partition" not in rec:
            problems.append(f"{label}: heartbeat without explicit partition")
        ktype, comps, key = encoded_key(pool, topic, env)
        _, kt, back = mtcodec.decode_key(key)
        if kt != key_types[ktype] or [v for _, v in back] != [v for _, v in comps]:
            problems.append(f"{label}: key round-trip failed")
        derived_out.append((label, "key_hex", key.hex()))
        if rec.get("key_hex") != key.hex():
            problems.append(f"{label}: key_hex differs from encoding of {comps}")
    # logical IDs
    def expect(label, got, kind, fields):
        want = mtcodec.logical_id(kind, fields)
        derived_out.append((label, kind, want))
        if got != want:
            problems.append(f"{label}: {kind} id {got} != derived {want}")
    events, findings, witnesses, incidents, rv_checks = {}, {}, {}, [], []
    for label, env in envs.items():
        k = env["kind"]
        if k == "RAW_EBPF":
            r = env["rawEbpf"]
            nid = f"{r['nodeId']}/{r['bootId']}/{r['nodeSeq']}"
            expect(label, env["logicalId"], "event",
                   {"source": "EBPF", "source_native_id": nid, "source_stage": r["eventFamily"],
                    "payload_version": "raw.v0"})
        elif k == "RAW_AUDIT":
            r = env["rawAudit"]
            expect(label, env["logicalId"], "event",
                   {"source": "AUDIT", "source_native_id": r["auditId"], "source_stage": r["stage"],
                    "payload_version": "raw.v0"})
        elif k == "RAW_GATEWAY":
            r = env["rawGateway"]
            expect(label, env["logicalId"], "event",
                   {"source": "GATEWAY", "source_native_id": r["requestId"], "source_stage": "request",
                    "payload_version": "raw.v0"})
        elif k == "RAW_KYVERNO":
            r = env["rawKyverno"]
            expect(label, env["logicalId"], "event",
                   {"source": "KYVERNO",
                    "source_native_id": f"{r['admissionRequestUid']}/{r['policy']}/{r['rule']}",
                    "source_stage": "decision", "payload_version": "raw.v0"})
        elif k == "CONTEXT_OBSERVATION":
            r = env["contextObservation"]
            expect(label, env["logicalId"], "event",
                   {"source": "CLUSTER_CONTEXT",
                    "source_native_id": f"{r['uid']}/{r['resourceVersion']}/{r['changeType']}",
                    "source_stage": "watch", "payload_version": "raw.v0"})
        elif k == "NORMALIZED_EVENT":
            n = env["normalizedEvent"]
            expect(label, n["eventId"], "event",
                   {"source": n["source"], "source_native_id": n["sourceNativeId"],
                    "source_stage": n["sourceStage"], "payload_version": "norm.v0"})
            if env["logicalId"] != n["eventId"]:
                problems.append(f"{label}: envelope logical_id != event_id")
            events[n["eventId"]] = n
            if "ebpf" in n:
                pk = n["ebpf"]["lineageRoot"]
                expect(label, n["ebpfDerived"]["lineageId"], "lineage",
                       {"node_id": pk["nodeId"], "boot_id": pk["bootId"], "tgid": str(pk["tgid"]),
                        "start_time_ns": str(pk["startTimeNs"])})
        elif k == "FINDING":
            f = env["finding"]
            expect(label, f["findingId"], "finding",
                   {"finding_type": f["findingType"], "input_event_ids": f["inputEventIds"],
                    "detector_version": f["detectorVersion"]})
            findings[f["findingId"]] = f
            rule = rules.get(f["findingType"])
            if not rule:
                problems.append(f"{label}: unknown finding type")
            else:
                if f.get("primaryTactic") != rule["primary_tactic"]:
                    problems.append(f"{label}: tactic differs from rulebook")
                extra = set(f.get("attributes", {})) - set(rule["emits"])
                if extra:
                    problems.append(f"{label}: attributes {sorted(extra)} not in rule emits")
            for eid in f["inputEventIds"]:
                if eid not in events:
                    problems.append(f"{label}: input event {eid} not in trace")
        elif k == "WITNESS":
            w = env["witness"]
            expect(label, w["witnessId"], "witness",
                   {"relationship_type": w["relationshipType"], "source_finding_id": w["sourceFindingId"],
                    "target_finding_id": w["targetFindingId"],
                    "evidence_event_ids": w.get("evidenceEventIds", [])})
            witnesses[w["witnessId"]] = w
            known = set(events) | {e.get("logicalId") for e in envs.values()}
            for eid in w.get("evidenceEventIds", []):
                if eid not in known:
                    problems.append(f"{label}: evidence event {eid} not in trace")
            for lim in w.get("appliedLimits", []):
                if "valueMs" in lim:
                    problems.append(f"{label}: example invents a numeric limit {lim}")
        elif k == "INCIDENT":
            incidents.append((label, env["incident"]))
        elif k == "GROUND_TRUTH_ACTION":
            g = env["groundTruthAction"]
            expect(label, env["logicalId"], "ground_truth",
                   {"run_id": g["runId"], "action_seq": str(g["actionSeq"])})
            for t in g.get("expectedFindingTypes", []):
                if t not in rules:
                    problems.append(f"{label}: expected finding type {t} unknown")
        elif k == "RULE_EVALUATION":
            e = env["ruleEvaluation"]
            expect(label, e["evaluationId"], "evaluation",
                   {"rule_id": e["ruleId"], "state_key_hex": e["stateKeyHex"],
                    "window_end": e["windowEnd"], "detector_version": e["detectorVersion"]})
            if env["logicalId"] != e["evaluationId"]:
                problems.append(f"{label}: envelope logical_id != evaluation_id")
            if e["ruleId"] not in rules:
                problems.append(f"{label}: unknown rule")
            if (e["outcome"] == "FIRED") != ("findingId" in e):
                problems.append(f"{label}: FIRED iff finding_id")
            rv_checks.append((label, e))
    # structural trace requirements
    mapped = [f for f in findings.values() if f.get("primaryTactic")]
    unmapped = [f for f in findings.values() if not f.get("primaryTactic")]
    if not mapped or not unmapped:
        problems.append("trace needs a mapped and an unmapped finding")
    classes = {w["strengthClass"] for w in witnesses.values()}
    if classes != {"DIRECT", "ENABLING"}:
        problems.append(f"trace needs a direct and an enabling witness, has {classes}")
    for w in witnesses.values():
        for fid in (w["sourceFindingId"], w["targetFindingId"]):
            if fid not in findings:
                problems.append(f"witness refers to unknown finding {fid}")
        comps = w.get("keyOrigin", [])
        if not comps:
            problems.append(f"witness {w['witnessId']}: no keyOrigin")
        if w["status"] == "CONFIRMED" and not any(
                c.get("origin") == "SENSOR" and not c.get("degraded") for c in comps):
            problems.append(f"witness {w['witnessId']}: CONFIRMED without a non-degraded SENSOR key component")
        for c in w.get("contradictions", []):
            if c.get("decisive") and (c.get("origin") != "SENSOR" or c.get("degraded")):
                problems.append(f"witness {w['witnessId']}: decisive contradiction not SENSOR/non-degraded")
    for label, e in rv_checks:
        if "findingId" in e and e["findingId"] not in findings:
            problems.append(f"{label}: finding {e['findingId']} not in trace")
        for eid in e.get("inputEventIds", []):
            if eid not in events:
                problems.append(f"{label}: input {eid} not in trace")
    kinds = {e["kind"] for e in envs.values()}
    for need in ("GROUND_TRUTH_ACTION", "RULE_EVALUATION"):
        if need not in kinds:
            problems.append(f"trace has no {need} record")
    statuses = [i["status"] for _, i in incidents]
    if statuses != ["INCIDENT_SEALED", "INCIDENT_AMENDED"]:
        problems.append(f"trace needs sealed then amended incident, has {statuses}")
    for label, inc in incidents:
        expect(label, inc["incidentId"], "incident", {"anchor_finding_id": inc["anchorFindingId"]})
        for wid in inc.get("linkWitnessIds", []):
            w = witnesses.get(wid)
            if not w or w["strengthClass"] != "DIRECT" or w["status"] != "CONFIRMED":
                problems.append(f"{label}: link witness {wid} is not a confirmed direct witness")
        for p in inc.get("rankedPaths", []):
            expect(label, p["pathId"], "path", {"finding_ids": p["findingIds"]})
        anchor = min((findings[x]["eventStart"], x) for x in inc["findingIds"])[1]
        if anchor != inc["anchorFindingId"]:
            problems.append(f"{label}: anchor is not earliest event time then finding ID")
    if len(incidents) == 2:
        a, b = incidents[0][1], incidents[1][1]
        if a["incidentId"] != b["incidentId"] or a["sealedPredictionVersion"] != b["sealedPredictionVersion"]:
            problems.append("amendment changed incident ID or sealed prediction snapshot")
        if int(b["version"]) <= int(a["version"]):
            problems.append("amended version not newer")
    record("examples: every record parses into Envelope (unknown fields rejected); keys and "
           "logical IDs recompute; trace covers mapped+unmapped finding, direct+enabling witness "
           "(confirmed only on a non-degraded sensor key), "
           "sealed->amended incident with fixed snapshot", problems, f"{len(envs)} records")
    if derive:
        for row in derived_out:
            print("DERIVED", *row)


# ---------------------------------------------------------------- links
def check_links():
    problems, n = [], 0
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(GAP1) for f in fs if f.endswith(".md")]
    files += [os.path.join(DESIGN, f) for f in ("contracts.md", "parameter-register.md",
                                               "gap-1-specification-rationale.md", "design-spec.md")]
    files += [os.path.join(PLANS, "section-iii-completion-plan.md")]
    for path in files:
        text = open(path, encoding="utf-8").read()
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if re.match(r"^[a-z]+:", target):
                continue
            n += 1
            if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), target))):
                problems.append(f"{os.path.relpath(path, ROOT)} -> {target}")
    record("links: relative Markdown links resolve", problems, f"{n} links")


# ---------------------------------------------------------------- traceability
def write_traceability(rb, manifest, topics, catalog):
    fam_of = {}
    for fam in manifest["families"]:
        for f in fam.get("fields", []):
            fam_of.setdefault(f, []).append(fam["id"])
    wit_of = {}
    for w in rb["witnesses"]:
        for f in w["fields"]:
            wit_of.setdefault(f, []).append(w["type"])
    producer = {"ebpf": "node-sensor", "audit": "audit-collector", "gateway": "gateway-observer",
                "kyverno": "kyverno-exporter", "context": "context-collector",
                "normalizer": "normalizer", "db-audit": "db-audit-collector",
                "path-flow": "path-flow-collector"}
    source_topic = {"ebpf": "raw.ebpf.v0", "audit": "raw.audit.v0", "gateway": "raw.gateway.v0",
                    "kyverno": "raw.kyverno.v0", "context": "context.cluster.v0",
                    "normalizer": "norm.events.v0", "db-audit": "raw.dbaudit.v0",
                    "path-flow": "raw.pathflow.v0"}
    lines = [
        "# Gap 1 traceability matrix (generated)",
        "",
        "Generated by `python spec/tools/check_gap1.py --write-traceability` from",
        "[rulebook.v0.yaml](rules/rulebook.v0.yaml), [capture-manifest.v0.yaml](node/capture-manifest.v0.yaml),",
        "[topics.yaml](kafka/topics.yaml), and [gap2-tests.yaml](rules/gap2-tests.yaml). Do not edit by hand.",
        "Every row is a required input. Gap 2 test statuses, scopes and evidence records are in",
        "[gap2-tests.yaml](rules/gap2-tests.yaml).",
        "",
        "| Finding | Required field (schema) | Source → producer | Raw topic | Manifest family | Consumer topic | Witnesses using field | Gap 2 tests |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rb["findings"]:
        consumer = ", ".join(topics["finding_inputs"][r["id"]])
        for i in r["inputs"]:
            extra = f" `[{', '.join(i['extra_keys'])}]`" if i.get("extra_keys") else ""
            fam = i.get("family") or "—"
            lines.append(
                f"| {r['id']}{' †' if r['status'] == 'conditional' else ''} | `{i['field'].replace(PKG + '.', '')}`{extra} "
                f"| {i['source']} → {producer[i['source']]} | {source_topic[i['source']]} | {fam} | {consumer} "
                f"| {', '.join(wit_of.get(i['field'], [])) or '—'} | {', '.join(i['gap2'])} |")
    lines += ["", "## Witness types", "",
              "| Witness | Class | Status | Required fields | Gap 2 tests |", "|---|---|---|---|---|"]
    for w in rb["witnesses"]:
        lines.append(f"| {w['type']} | {w['class']} | {w['status']} | "
                     f"{', '.join('`' + f.replace(PKG + '.', '') + '`' for f in w['fields'])} | {', '.join(w['gap2'])} |")
    with open(os.path.join(GAP1, "traceability.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def check_traceability_current(rb, manifest, topics, catalog):
    path = os.path.join(GAP1, "traceability.md")
    before = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    tmp = before
    write_traceability(rb, manifest, topics, catalog)
    after = open(path, encoding="utf-8").read()
    if before and before != after:
        record("traceability: committed matrix matches regeneration", ["matrix was stale (rewritten)"])
    else:
        rows = sum(1 for line in after.splitlines() if line.startswith("| ") and "`" in line)
        record("traceability: committed matrix matches regeneration", [], f"{rows} rows")
    return tmp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-traceability", action="store_true")
    ap.add_argument("--derive", action="store_true")
    args = ap.parse_args()
    rb = load_yaml("rules/rulebook.v0.yaml")
    manifest = load_yaml("node/capture-manifest.v0.yaml")
    topics = load_yaml("kafka/topics.yaml")
    catalog = load_yaml("rules/gap2-tests.yaml")
    load_yaml("audit/provider-coverage.template.yaml")
    with tempfile.TemporaryDirectory() as tmp:
        pool, files = compile_protos(tmp)
    if pool is None:
        return report()
    check_no_bytes_fields(pool, files)
    rules = check_rulebook_vs_table(rb)
    check_rule_shape(rules)
    check_field_paths(pool, rb, manifest)
    check_witness_origins(rb)
    check_witness_contract(pool)
    check_manifest(pool, rb, manifest, rules)
    check_gap2(rb, manifest, catalog)
    check_parameters(rules)
    check_topics(pool, topics, rules)
    check_audit_policy(rules)
    check_examples(pool, topics, rules, args.derive)
    check_links()
    if args.write_traceability:
        write_traceability(rb, manifest, topics, catalog)
        record("traceability: matrix written", [])
    else:
        check_traceability_current(rb, manifest, topics, catalog)
    return report()


def report():
    failed = 0
    for name, ok, problems, detail in RESULTS:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" ({detail})" if detail else ""))
        for p in problems[:40]:
            print(f"       - {p}")
        failed += not ok
    print(f"\n{len(RESULTS) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
