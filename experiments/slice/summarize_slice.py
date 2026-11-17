#!/usr/bin/env python3
"""Summarize one live slice run from topic dumps (host Python, stdlib + PyYAML).

Inputs: --dumps DIR (dump.py output), --state (driver state), --facts TSV.
Outputs a redacted JSON result and Markdown record: principal labels (P, Q,
R, G) instead of identities, booleans instead of UIDs, logical IDs (hashes)
kept for replay comparison. Refuses to write output containing a JWT, a UUID,
a service-account username or synthetic secret content.
"""

import argparse
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "spec", "tools"))
import mtcodec  # noqa: E402

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FORBID = [re.compile(p) for p in (r"eyJ[A-Za-z0-9_-]{10,}", r"system:serviceaccount:", r"synthetic-[0-9a-f]{6}",
                                  r"BEGIN [A-Z ]*KEY")]
TOPICS = {t["name"]: t for t in yaml.safe_load(open(os.path.join(REPO, "spec", "kafka", "topics.yaml")))["topics"]}
KEY_TYPES = {n: i for i, n in enumerate([
    "KEY_TYPE_UNSPECIFIED", "KEY_NODE", "KEY_AUDIT_ID", "KEY_REQUEST_ID", "KEY_ADMISSION", "KEY_OBJECT_UID",
    "KEY_PRIMARY_ENTITY", "KEY_PRINCIPAL", "KEY_UNAUTH_SOURCE", "KEY_LINEAGE", "KEY_TOKEN_FILE_OWNER", "KEY_JTI",
    "KEY_POD_CONTAINER", "KEY_POD_LINEAGE", "KEY_POD", "KEY_FINDING_ID", "KEY_WITNESS_ID", "KEY_INCIDENT_ID",
    "KEY_SOURCE_SCOPE", "KEY_PRODUCER_INSTANCE", "KEY_RUN", "KEY_EVALUATION_ID"])}
COMP = {n: i for i, n in enumerate([
    "KEY_COMPONENT_UNSPECIFIED", "NODE_ID", "AUDIT_ID", "REQUEST_ID", "ADMISSION_UID", "OBJECT_UID",
    "ENTITY_TYPE_NAME", "ENTITY_UID", "PRINCIPAL_KIND", "PRINCIPAL_ID", "OBSERVED_SOURCE", "LINEAGE_ID", "POD_UID",
    "VOLUME_NAME", "JTI", "CONTAINER_NAME", "FINDING_ID", "WITNESS_ID", "INCIDENT_ID", "SOURCE_NAME", "SCOPE",
    "PRODUCER_INSTANCE", "RUN_ID", "EVALUATION_ID"])}


def murmur2(data):
    """Kafka Java client Utils.murmur2."""
    m, r = 0x5bd1e995, 24
    n = len(data)
    h = (0x9747b28c ^ n) & 0xffffffff
    for i in range(n // 4):
        k = data[4 * i] | data[4 * i + 1] << 8 | data[4 * i + 2] << 16 | data[4 * i + 3] << 24
        k = (k * m) & 0xffffffff
        k ^= k >> r
        k = (k * m) & 0xffffffff
        h = (h * m) & 0xffffffff
        h ^= k
    rem, base = n % 4, n & ~3
    if rem >= 3:
        h ^= data[base + 2] << 16
    if rem >= 2:
        h ^= data[base + 1] << 8
    if rem >= 1:
        h ^= data[base]
        h = (h * m) & 0xffffffff
    h ^= h >> 13
    h = (h * m) & 0xffffffff
    h ^= h >> 15
    return h


def java_partition(key, n):
    return (murmur2(key) & 0x7fffffff) % n


def producer_rfc3339(json_ts):
    """Protobuf JSON drops a zero fraction; the producer hashed %Y-%m-%dT%H:%M:%S.%fZ."""
    from datetime import datetime, timezone
    v = json_ts.rstrip("Z")
    head, _, frac = v.partition(".")
    dt = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + (frac + "000000")[:6] + "Z"


def load(d, topic):
    p = os.path.join(d, topic + ".jsonl")
    return [json.loads(x) for x in open(p, encoding="utf-8")] if os.path.exists(p) else []


def key_values(topic, rec):
    base = topic.removeprefix("replay.")
    if base == "raw.audit.v0":
        return {"AUDIT_ID": rec["raw_audit"]["audit_id"]}
    if base == "context.cluster.v0":
        return {"OBJECT_UID": rec["context_observation"]["uid"]}
    if base == "norm.events.v0":
        ad = rec["normalized_event"].get("audit_derived", {})
        p = ad.get("principal")
        if p:
            return {"ENTITY_TYPE_NAME": p["type"], "ENTITY_UID": p["uid"]}
        return {"ENTITY_TYPE_NAME": "UNAUTHENTICATED_SOURCE", "ENTITY_UID": ad.get("observed_source")}
    if base == "agent.H.audit.v0":
        p = rec["normalized_event"]["audit_derived"]["principal"]
        return {"PRINCIPAL_KIND": p["type"], "PRINCIPAL_ID": p["uid"]}
    if base == "findings.v0":
        return {"FINDING_ID": rec["finding"]["finding_id"]}
    if base == "incidents.v0":
        return {"INCIDENT_ID": rec["incident"]["incident_id"]}
    if base == "rule.evaluations.v0":
        return {"EVALUATION_ID": rec["rule_evaluation"]["evaluation_id"]}
    if base == "source.completeness.v0":
        s = rec["source_completeness"]
        return {"SOURCE_NAME": s["source"], "SCOPE": s["scope"]}
    return None


def check_transport(dumps, topics):
    out = {}
    for t in topics:
        spec = TOPICS[t.removeprefix("replay.")]
        recs = load(dumps, t)
        n, key_bad, part_bad, id_bad, hb, bc = 0, 0, 0, 0, 0, 0
        for r in recs:
            if r["kind"] in ("HEARTBEAT", "CONTEXT_WATCH_GAP"):
                if r["kind"] == "HEARTBEAT":
                    hb += 1
                else:
                    bc += 1
                continue
            n += 1
            vals = key_values(t, r)
            want = mtcodec.encode_key(KEY_TYPES[spec["key_type"]],
                                      [(COMP[c], vals[c]) for c in spec["key_components"]])
            if want.hex() != r["_transport"]["key_hex"]:
                key_bad += 1
            if java_partition(want, 3) != r["_transport"]["partition"]:
                part_bad += 1
            if r["kind"] in ("RAW_AUDIT",):
                a = r["raw_audit"]
                exp = mtcodec.logical_id("event", {"source": "AUDIT", "source_native_id": a["audit_id"],
                                                   "source_stage": a["stage"], "payload_version": "raw.v0"})
                id_bad += exp != r.get("logical_id")
            elif r["kind"] == "FINDING":
                f = r["finding"]
                exp = mtcodec.logical_id("finding", {"finding_type": f["finding_type"],
                                                     "input_event_ids": f["input_event_ids"],
                                                     "detector_version": f["detector_version"]})
                id_bad += exp != f["finding_id"]
            elif r["kind"] == "INCIDENT":
                i = r["incident"]
                id_bad += mtcodec.logical_id("incident", {"anchor_finding_id": i["anchor_finding_id"]}) != i["incident_id"]
            elif r["kind"] == "RULE_EVALUATION":
                e = r["rule_evaluation"]
                exp = mtcodec.logical_id("evaluation", {"rule_id": e["rule_id"], "state_key_hex": e["state_key_hex"],
                                                        "window_end": producer_rfc3339(e["window_end"]),
                                                        "detector_version": e["detector_version"]})
                id_bad += exp != e["evaluation_id"]
        out[t] = {"records": n, "heartbeats": hb, "broadcast_watch_gaps": bc, "key_mismatch": key_bad,
                  "java_murmur2_partition_mismatch": part_bad, "logical_id_mismatch": id_bad}
    return out


def evaluations(dumps, prefix, labels):
    rows = []
    for r in load(dumps, prefix + "rule.evaluations.v0"):
        if r["kind"] != "RULE_EVALUATION":
            continue
        e = r["rule_evaluation"]
        rows.append({"id": e["evaluation_id"], "label": labels.get(e["state_key_hex"], "other"),
                     "outcome": e["outcome"], "finding": e.get("finding_id"), "window_end": e["window_end"],
                     "score": int(e.get("features", {}).get("score", "0")),
                     "abstain": sorted(e.get("abstain_reasons", []))})
    return rows


def incidents(dumps, prefix):
    rows = []
    for r in load(dumps, prefix + "incidents.v0"):
        if r["kind"] != "INCIDENT":
            continue
        i = r["incident"]
        sc = i.get("source_completeness", {})
        rows.append({"id": i["incident_id"], "version": i["version"], "status": i["status"],
                     "anchor": i["anchor_finding_id"], "at_seal_excluded": sc.get("at_seal_excluded_sources", []),
                     "current_excluded": sc.get("current_excluded_sources", []),
                     "sealed_prediction_version": i.get("sealed_prediction_version"),
                     "amendments": [a["reason"] for a in i.get("amendments", [])]})
    return rows


def principal_labels(state, dumps):
    """Map agent state-key hex -> P/Q/R/G via the SA UIDs recorded by the driver."""
    by_uid = {v: k for k, v in state["sa_uid"].items()}
    labels = {}
    for r in load(dumps, "agent.H.audit.v0"):
        if r["kind"] != "NORMALIZED_EVENT":
            continue
        p = r["normalized_event"]["audit_derived"]["principal"]
        if p["uid"] in by_uid:
            labels[r["_transport"]["key_hex"]] = by_uid[p["uid"]]
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dumps", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--facts", required=True)
    ap.add_argument("--logs", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    a = ap.parse_args()
    state = json.load(open(a.state))
    facts = dict(line.rstrip("\n").split("\t", 1) for line in open(a.facts) if "\t" in line)
    labels = principal_labels(state, a.dumps)
    live, rep = evaluations(a.dumps, "", labels), evaluations(a.dumps, "replay.", labels)
    lim = min(max((r["window_end"] for r in live), default=""), max((r["window_end"] for r in rep), default=""))
    cmp = lambda rows: sorted((r["id"], r["outcome"], r["finding"] or "") for r in rows if r["window_end"] <= lim)
    inc_l, inc_r = incidents(a.dumps, ""), incidents(a.dumps, "replay.")
    seq = lambda rows: [(r["id"], r["version"], r["status"], tuple(r["at_seal_excluded"]),
                         tuple(r["current_excluded"]), len(r["amendments"])) for r in rows]

    # Findings and the token-bound Pod
    findings = []
    for r in load(a.dumps, "findings.v0"):
        if r["kind"] != "FINDING":
            continue
        f = r["finding"]
        pod_uids = [e.get("uid") for e in f.get("entities", []) if e["type"] == "POD"]
        principal = next((e for e in f["entities"] if e["type"] in ("SERVICE_ACCOUNT", "USER")), {})
        label = {v: k for k, v in state["sa_uid"].items()}.get(principal.get("uid"), "other")
        findings.append({"finding_id": f["finding_id"], "label": label, "type": f["finding_type"],
                         "tactic": f.get("primary_tactic"), "inputs": len(f["input_event_ids"]),
                         "attributes": {k: v for k, v in f.get("attributes", {}).items()
                                        if k not in ("principal", "window_start", "window_end")},
                         "token_bound_pod_matches_bound_pod": bool(pod_uids) and pod_uids ==
                         [state["pods"].get(label, {}).get("uid")],
                         "pod_entity_strength": [e.get("strength_class") for e in f["entities"] if e["type"] == "POD"],
                         "completeness_gaps": sorted({g["reason"] for g in f.get("completeness", {}).get("gaps", [])}),
                         "parameter_set_version": f["parameter_set_version"]})

    # Completeness records
    comp = {}
    for r in load(a.dumps, "source.completeness.v0"):
        s = r["source_completeness"]
        c = comp.setdefault(s["source"], {"records": 0, "statuses": {}, "gaps": []})
        c["records"] += 1
        c["statuses"][s["status"]] = c["statuses"].get(s["status"], 0) + 1
        if s["status"] != "NO_KNOWN_GAP":
            c["gaps"].append({"reasons": [g["reason"] for g in s.get("gaps", [])],
                              "interval": [s["interval_start"], s["interval_end"]]})

    # Safety scan of all dumped values
    leaks = {}
    for name in sorted(os.listdir(a.dumps)):
        text = open(os.path.join(a.dumps, name), encoding="utf-8").read()
        leaks[name] = {"jwt": len(re.findall(r"eyJ[A-Za-z0-9_-]{20,}\.", text)),
                       "synthetic_secret_value": len(re.findall(r"synthetic-[0-9a-f]{6}", text))}

    tr = check_transport(a.dumps, ["raw.audit.v0", "context.cluster.v0", "norm.events.v0", "agent.H.audit.v0",
                                   "findings.v0", "incidents.v0", "rule.evaluations.v0", "source.completeness.v0",
                                   "replay.findings.v0", "replay.incidents.v0", "replay.rule.evaluations.v0"])
    by_label = {}
    for r in live:
        by_label.setdefault(r["label"], []).append({k: r[k] for k in ("outcome", "score", "abstain", "finding")})
    result = {"run_id": a.run_id, "schema": "slice-audit-incident-result.v0",
              "claim": "pipeline integration evidence only; not a Gap 2 sensor test; no multi-finding correlation",
              "facts": {k: v for k, v in facts.items() if not k.startswith("sha256.")},
              "harness_sha256": {k[7:]: v for k, v in facts.items() if k.startswith("sha256.")},
              "evaluations_by_label": by_label, "findings": findings,
              "incident_versions_live": inc_l, "incident_versions_replay": inc_r,
              "replay": {"evaluations_compared": len(cmp(live)), "evaluations_equal": cmp(live) == cmp(rep),
                         "findings_equal": sorted(r["finding_id"] for r in findings) ==
                         sorted(r["finding"]["finding_id"] for r in load(a.dumps, "replay.findings.v0")
                                if r["kind"] == "FINDING"),
                         "incidents_equal": seq(inc_l) == seq(inc_r)},
              "completeness": comp, "transport": tr, "leak_scan": leaks,
              "driver_codes": state.get("codes"), "driver_gap_codes": {k: sorted(set(v)) if isinstance(v, list) else v
                                                                       for k, v in state.get("codes_gap", {}).items()},
              "marks": state.get("marks")}
    if result["driver_codes"]:
        result["driver_codes"] = {k: sorted(set(v)) for k, v in result["driver_codes"].items()}
    text = json.dumps(result, indent=1, sort_keys=True)
    bad = [p.pattern for p in FORBID if p.search(text)] + (["uuid"] if UUID_RE.search(text) else [])
    if bad:
        sys.exit("REDACTION CHECK FAILED: " + ", ".join(bad))
    open(a.out_json, "w").write(text + "\n")
    lines = [f"# Slice run {a.run_id}", "", "| Label | Outcomes |", "|---|---|"]
    for k in sorted(by_label):
        lines.append(f"| {k} | {sorted({r['outcome'] for r in by_label[k]})} |")
    lines += ["", f"Replay equal: {result['replay']}", ""]
    open(a.out_md, "w").write("\n".join(lines) + "\n")
    print(json.dumps({"by_label": {k: sorted({r['outcome'] for r in v}) for k, v in by_label.items()},
                      "replay": result["replay"], "incidents": [(r["version"], r["status"]) for r in inc_l]}))


if __name__ == "__main__":
    main()
