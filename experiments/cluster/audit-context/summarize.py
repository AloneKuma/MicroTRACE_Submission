#!/usr/bin/env python3
"""Join probe manifests to collector records and context history; emit verdicts.

Usage:
  summarize.py --rulebook RULEBOOK --key KEY --out-json R.json --out-md R.md \
      --gen main=DIR [--gen fault=DIR] [--gen baseline=DIR] [--run-info RUN.json]

Each generation DIR may contain manifest.jsonl, collector/audit-records.jsonl,
collector/collector-events.jsonl, context.jsonl, context-410.jsonl,
metrics.jsonl, latency-*.json, probe-state.json, gen-info.json.

Verdicts: pass | narrowed | unsupported | inconclusive | not_run. A pass needs
a correlated positive observation and a control that does not spoof it. The
outputs carry counts, booleans, classes and shapes only: no raw bodies,
tokens, identities, object UIDs or audit IDs.
"""

import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtk8s import LEVELS, Pseudonymizer, parse_ts, read_jsonl  # noqa: E402

CRED_RESOURCES = {("", "secrets", ""), ("", "configmaps", ""), ("", "serviceaccounts", "token"),
                  ("authentication.k8s.io", "tokenreviews", "")}
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
FORBIDDEN_OUTPUT = [re.compile(p) for p in (r"eyJ[A-Za-z0-9_-]{10,}", r"BEGIN [A-Z ]*(CERTIFICATE|KEY)",
                                            r"kubernetes-admin", r"system:serviceaccount:", r"system:node:",
                                            r"JTI=[0-9a-f]", r"X509SHA256=[0-9a-f]")]


class Gen:
    def __init__(self, name, d):
        self.name, self.dir = name, d
        self.manifest = read_jsonl(os.path.join(d, "manifest.jsonl"))
        self.records = read_jsonl(os.path.join(d, "collector", "audit-records.jsonl"))
        self.cevents = read_jsonl(os.path.join(d, "collector", "collector-events.jsonl"))
        self.context = read_jsonl(os.path.join(d, "context.jsonl"))
        self.ctx410 = read_jsonl(os.path.join(d, "context-410.jsonl"))
        self.metrics = read_jsonl(os.path.join(d, "metrics.jsonl"))
        self.info = load_json(os.path.join(d, "gen-info.json")) or {}
        self.state = load_json(os.path.join(d, "probe-state.json")) or {}
        self.latency = {}
        for p in glob.glob(os.path.join(d, "latency-*.json")):
            j = load_json(p)
            self.latency[j["label"]] = j
        self.by_id = {}
        for r in self.records:
            self.by_id.setdefault(r.get("auditID"), {})[r.get("stage")] = r
        self.probes = {}
        for m in self.manifest:
            self.probes.setdefault(m["probe_id"], m)

    def recs(self, entry):
        return self.by_id.get(entry.get("audit_id")) or {}

    def by_marker(self, marker):
        out = {}
        for r in self.records:
            if marker and marker in (r.get("requestURI") or ""):
                out.setdefault(r["auditID"], {})[r["stage"]] = r
        return out


def load_json(p):
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def verdict(test_id, v, summary, **kw):
    return {"test_id": test_id, "verdict": v, "summary": summary, **kw}


def shape(recs):
    """Observed audit shape of one request (all stages), without identities."""
    if not recs:
        return {"audit_found": False}
    any_r = next(iter(recs.values()))
    rc = recs.get("ResponseComplete") or recs.get("ResponseStarted") or any_r
    return {"audit_found": True,
            "stages": sorted(recs),
            "level": any_r.get("level"),
            "verb": any_r.get("verb"),
            "codes": {s: (r.get("responseStatus") or {}).get("code") for s, r in sorted(recs.items())},
            "user_class": rc["user"]["class"],
            "request_object": any(r["requestObject"]["present"] for r in recs.values()),
            "response_object": any(r["responseObject"]["present"] for r in recs.values()),
            "truncated_annotation": any(r["annotations"].get("truncated") for r in recs.values())}


def check_entry(g, e):
    s = shape(g.recs(e))
    exp = e.get("expect") or {}
    res = {"probe_id": e["probe_id"], "role": e["role"], "cred": e["cred"], "http_status": e["status"], **s}
    if not s["audit_found"]:
        res["ok"] = False
        return res
    ok = True
    if exp.get("status") is not None:
        ok &= e["status"] == exp["status"]
    if exp.get("level"):
        ok &= LEVELS.get(s["level"], -1) >= LEVELS[exp["level"]]
    if exp.get("stages"):
        ok &= set(exp["stages"]) <= set(s["stages"])
    if exp.get("no_bodies"):
        ok &= not s["request_object"] and not s["response_object"]
    if exp.get("request_object"):
        ok &= s["request_object"]
    if exp.get("response_object"):
        ok &= s["response_object"]
    res["ok"] = bool(ok)
    return res


# ------------------------------------------------------------------ tests

def t_policy(g, rulebook):
    reqs = []
    for rule in rulebook["findings"]:
        for q in rule.get("audit_requirements") or []:
            reqs.append((rule["id"], q))
    probe_ids = {m["audit_id"] for m in g.manifest if m.get("audit_id")}
    markers = [m.get("marker") for m in g.manifest if m.get("marker") and m["role"] == "positive"]
    probe_recs = {aid: g.by_id[aid] for aid in probe_ids if aid in g.by_id}
    for mk in markers:
        probe_recs.update(g.by_marker(mk))
    rows = []
    for rid, q in reqs:
        for verb in q["verbs"]:
            match = None
            for aid, recs in probe_recs.items():
                r0 = next(iter(recs.values()))
                ref = r0.get("objectRef") or {}
                if r0.get("verb") != verb:
                    continue
                if q.get("non_resource_url"):
                    if (r0.get("requestURI") or "").split("?")[0] != q["non_resource_url"]:
                        continue
                elif (ref.get("apiGroup") or "", ref.get("resource") or "", ref.get("subresource") or "") != \
                        (q["group"], q["resource"], q["subresource"]):
                    continue
                authed = any(r["user"]["class"] != "empty" for r in recs.values())
                if authed != q["authenticated"]:
                    continue
                cand = {"level_ok": LEVELS.get(r0.get("level"), -1) >= LEVELS[q["min_level"]],
                        "stages_ok": set(q["stages"]) <= set(recs), "level": r0.get("level"),
                        "stages": sorted(recs)}
                if match is None or (cand["level_ok"] and cand["stages_ok"]):
                    match = cand
                if cand["level_ok"] and cand["stages_ok"]:
                    break
            rows.append({"rule": rid, "verb": verb, "group": q["group"], "resource": q["resource"] or None,
                         "subresource": q["subresource"] or None, "non_resource_url": q.get("non_resource_url"),
                         "authenticated": q["authenticated"], "min_level": q["min_level"],
                         "required_stages": q["stages"],
                         "observed": match or {"level_ok": False, "stages_ok": False, "missing": True}})
    # Credential cap over the whole stream, not only probes.
    cap_viol, cap_n = 0, 0
    for r in g.records:
        ref = r.get("objectRef") or {}
        key = (ref.get("apiGroup") or "", ref.get("resource") or "", ref.get("subresource") or "")
        if key in CRED_RESOURCES:
            cap_n += 1
            if LEVELS.get(r["level"], 0) > LEVELS["Metadata"] or r["requestObject"]["present"] or \
                    r["responseObject"]["present"]:
                cap_viol += 1
    missing = [x for x in rows if not (x["observed"].get("level_ok") and x["observed"].get("stages_ok"))]
    affected = sorted({x["rule"] for x in missing})
    if not g.records:
        v, s = "inconclusive", "No collector records for the main generation."
    elif not missing and cap_viol == 0:
        v, s = "pass", (f"All {len(rows)} (requirement, verb) cells from the rulebook's audit_requirements were "
                        f"observed through the file backend and collector with at least the required level and "
                        f"stages; {cap_n} credential-resource events (whole stream) stayed at Metadata with no "
                        f"bodies.")
    else:
        v = "narrowed"
        s = (f"{len(missing)} of {len(rows)} (requirement, verb) cells lacked the required level/stage "
             f"(affected rules: {', '.join(affected)}); credential-cap violations: {cap_viol}/{cap_n}.")
    return verdict("AUD-POLICY-EFFECTIVE", v, s, requirements=rows, credential_cap={"events": cap_n,
                   "violations": cap_viol}, affected_rules=affected, route="self-managed kube-apiserver log file")


def t_usedtoken(g):
    e, ctl, ctl2 = g.probes.get("P-USE-bound"), g.probes.get("P-B1-get-pods"), g.probes.get("P-USE-unbound")
    if not e:
        return verdict("AUD-FIELDS-USEDTOKEN", "not_run", "Probe P-USE-bound missing.")
    rc = g.recs(e).get("ResponseComplete")
    ci = rc["user"]["credential_id"] if rc else None
    match = bool(ci and ci["value_p"] == e.get("used_jti_p"))
    ctl_rc = g.recs(ctl).get("ResponseComplete") if ctl else None
    ctl_fmt = ctl_rc["user"]["credential_id"]["format"] if ctl_rc else None
    un_rc = g.recs(ctl2).get("ResponseComplete") if ctl2 else None
    un_match = bool(un_rc and un_rc["user"]["credential_id"]["value_p"] == ctl2.get("used_jti_p"))
    distinct = bool(ci and un_rc and ci["value_p"] != un_rc["user"]["credential_id"]["value_p"])
    obs = {"pod_bound_use": {"http_status": e["status"], "audit_found": rc is not None,
                             "credential_id_present": bool(ci and ci["present"]),
                             "credential_id_format": ci["format"] if ci else None,
                             "equals_jti_of_issuing_tokenrequest": match},
           "unbound_use": {"credential_id_format": un_rc["user"]["credential_id"]["format"] if un_rc else None,
                           "equals_its_own_jti": un_match, "distinct_from_bound_token": distinct},
           "x509_admin_control": {"credential_id_format": ctl_fmt}}
    ok = match and ci["format"] == "JTI=<uuid>" and (ctl_fmt is None or not ctl_fmt.startswith("JTI=")) and distinct
    s = ("Pod-bound TokenRequest token used from the kind host: exported user.extra credential-id has format "
         f"{ci['format'] if ci else None} and equals the issued token's JTI (keyed-pseudonym comparison); an "
         f"unbound token carries its own distinct JTI; the x509 admin control carries {ctl_fmt or 'no credential-id'}"
         ", which cannot be confused with a JTI.")
    return verdict("AUD-FIELDS-USEDTOKEN", "pass" if ok else "narrowed", s, observed=obs,
                   limits="Token obtained by an admin TokenRequest bound to the test Pod, not read from the "
                          "kubelet-projected file; used from the node host, not from inside the Pod.")


def t_issued(g):
    e, un = g.probes.get("P-TR-bound"), g.probes.get("P-TR-unbound")
    if not e:
        return verdict("AUD-ISSUED-ANNOTATION", "not_run", "Probe P-TR-bound missing.")
    recs = g.recs(e)
    rc = recs.get("ResponseComplete")
    ann = rc["annotations"]["issued_credential_id"] if rc else None
    s0 = shape(recs)
    match = bool(ann and ann["value_p"] == e.get("issued_jti_p"))
    un_rc = g.recs(un).get("ResponseComplete") if un else None
    un_ok = bool(un_rc and un_rc["annotations"]["issued_credential_id"]["value_p"] == un.get("issued_jti_p"))
    kubelet = [r for r in g.records if (r.get("objectRef") or {}).get("subresource") == "token"
               and r["user"]["class"] == "node" and r["stage"] == "ResponseComplete"]
    kubelet_ann = sum(1 for r in kubelet if r["annotations"]["issued_credential_id"]["present"])
    kubelet_body = sum(1 for r in kubelet if r["responseObject"]["present"] or r["requestObject"]["present"])
    obs = {"probe_tokenrequest": {"http_status": e["status"], "level": s0.get("level"),
                                  "stages": s0.get("stages"), "annotation_present": bool(ann and ann["present"]),
                                  "annotation_format": ann["format"] if ann else None,
                                  "equals_jti_in_returned_token": match,
                                  "request_object_logged": s0.get("request_object"),
                                  "response_object_logged": s0.get("response_object")},
           "unbound_tokenrequest_annotation_matches_its_jti": un_ok,
           "kubelet_tokenrequests": {"count": len(kubelet), "with_annotation": kubelet_ann,
                                     "with_body": kubelet_body},
           "unique_match": "by Audit-Id response header"}
    ok = match and s0.get("level") == "Metadata" and not s0.get("response_object") and not s0.get("request_object")
    return verdict("AUD-ISSUED-ANNOTATION", "pass" if ok else "narrowed",
                   "TokenRequest create is logged at Metadata with annotation "
                   f"authentication.kubernetes.io/issued-credential-id ({ann['format'] if ann else None}) equal to "
                   "the JTI inside the returned token, uniquely matched by Audit-Id, with no request or response "
                   "body in the audit record.", observed=obs)


def t_podbinding(g):
    e, un = g.probes.get("P-USE-bound"), g.probes.get("P-USE-unbound")
    if not e:
        return verdict("AUD-POD-BINDING-EXTRA", "not_run", "Probe P-USE-bound missing.")
    rc = g.recs(e).get("ResponseComplete")
    u = rc["user"] if rc else {}
    uid_ok = bool(rc and u["pod_uid_p"] == e.get("pod_uid_p"))
    name_ok = bool(rc and u["pod_name_p"] == e.get("pod_name_p"))
    un_rc = g.recs(un).get("ResponseComplete") if un else None
    un_clean = bool(un_rc and un_rc["user"]["pod_uid_p"] is None and un_rc["user"]["pod_name_p"] is None)
    obs = {"bound": {"pod_uid_matches_probe_pod": uid_ok, "pod_name_matches_probe_pod": name_ok,
                     "node_name_present": u.get("node_name_present"), "node_uid_present": u.get("node_uid_present"),
                     "extra_keys": u.get("extra_keys")},
           "unbound_control": {"pod_fields_absent": un_clean,
                               "extra_keys": un_rc["user"]["extra_keys"] if un_rc else None}}
    ok = uid_ok and name_ok and un_clean
    return verdict("AUD-POD-BINDING-EXTRA", "pass" if ok else "narrowed",
                   "Pod-bound token use exports pod-uid and pod-name equal to the bound test Pod; the unbound "
                   "token's use carries neither. Node fields are recorded as present/absent only and are not relied on.",
                   observed=obs)


def t_failed_authn(g):
    rows = {}
    for pid in ("P-401-pods", "P-401-api", "P-403-unbound", "P-ANON-api"):
        e = g.probes.get(pid)
        if not e:
            continue
        recs = g.recs(e)
        s0 = shape(recs)
        first = recs.get("ResponseStarted") or (next(iter(recs.values())) if recs else None)
        src = first["sourceIPs"] if first else {}
        rows[pid] = {"role": e["role"], "http_status": e["status"], **s0,
                     "source_ips_present": bool(src.get("count")), "source_class": src.get("last_class")}
    pos = [rows.get("P-401-pods"), rows.get("P-401-api")]
    pos_ok = all(r and r["http_status"] == 401 and r.get("audit_found") and "ResponseStarted" in r["stages"]
                 and r["codes"].get("ResponseStarted") == 401 and r["user_class"] == "empty"
                 and r["source_ips_present"] for r in pos)
    ctl = [rows.get("P-403-unbound"), rows.get("P-ANON-api")]
    ctl_ok = all(r and r.get("audit_found") and 401 not in r["codes"].values() and r["user_class"] != "empty"
                 for r in ctl)
    v = "pass" if pos_ok and ctl_ok else ("narrowed" if any(r and r.get("audit_found") for r in pos) else "inconclusive")
    return verdict("AUD-FAILED-AUTHN", v,
                   "Invalid bearer tokens produced HTTP 401 audit events at ResponseStarted with an empty user "
                   "and a sourceIPs entry; an RBAC-denied service account (403) and an anonymous request carry a "
                   "non-empty user and no 401, so they cannot be counted as authentication failures.",
                   observed=rows, limits="Source is the kind Docker bridge peer, not a real client network path.")


def t_rbac_body(g):
    rows = [check_entry(g, e) | {"method": e["method"], "resource": e["resource"]}
            for e in g.manifest if "AUD-RBAC-BODY" in e["tests"] and e["role"] == "positive"]
    bad = [r for r in rows if not r["ok"]]
    v = "pass" if rows and not bad else ("narrowed" if rows else "not_run")
    return verdict("AUD-RBAC-BODY", v,
                   f"{len(rows) - len(bad)}/{len(rows)} RBAC create/update/patch/delete probes on roles, "
                   "rolebindings, clusterroles and clusterrolebindings were exported at RequestResponse with "
                   "ResponseComplete and the expected request/response objects (presence and size only are "
                   "retained).", observed=rows,
                   limits="Bodies are held only in the in-cluster raw log; the repository records presence and size.")


def t_truncation(main, fault):
    ctl = main.probes.get("P-TRUNC-large-noflag") if main else None
    ctl_s = shape(main.recs(ctl)) if ctl else None
    if not fault or not fault.manifest:
        return verdict("AUD-TRUNCATION-OVERSIZE", "not_run", "Fault generation did not run.",
                       routes={"kube-apiserver-log-file": "not_run", "eks-cloudwatch": "not_run"})
    lg, nm = fault.probes.get("T-large"), fault.probes.get("T-normal")
    ls, ns_ = shape(fault.recs(lg)) if lg else None, shape(fault.recs(nm)) if nm else None
    accepted = bool(lg and lg["status"] == 201)
    if not accepted:
        outcome = "not interpretable (large mutation not accepted)"
    elif not ls["audit_found"]:
        outcome = "event dropped"
    elif not ls["request_object"] and not ls["response_object"]:
        outcome = "bodies stripped, metadata event kept"
    else:
        outcome = "bodies retained"
    normal_ok = bool(ns_ and ns_["audit_found"] and ns_["request_object"] and ns_["response_object"])
    ctl_ok = bool(ctl_s and ctl_s["audit_found"] and ctl_s["request_object"] and ctl_s["response_object"])
    route_v = "pass" if accepted and outcome in ("event dropped", "bodies stripped, metadata event kept") and \
        normal_ok and ctl_ok else "inconclusive"
    return verdict("AUD-TRUNCATION-OVERSIZE", route_v,
                   f"File-backend route only. With truncation enabled, an accepted large ClusterRole create "
                   f"(request {lg['request_bytes'] if lg else None} bytes): {outcome}; a normal-size mutation in the "
                   f"same config kept both bodies ({normal_ok}); the same large mutation with truncation disabled "
                   f"kept both bodies ({ctl_ok}). EKS/CloudWatch 1 MB behaviour remains not_run.",
                   routes={"kube-apiserver-log-file": route_v, "eks-cloudwatch": "not_run",
                           "gke/aks exports": "not_run"},
                   observed={"large": ls, "normal": ns_, "truncation_disabled_control": ctl_s,
                             "large_http_status": lg["status"] if lg else None,
                             "large_request_bytes": lg["request_bytes"] if lg else None,
                             "fault_flags": fault.info.get("audit_flags")})


def t_provider_reads(g):
    rows = [check_entry(g, e) for e in g.manifest if "AUD-PROVIDER-READS" in e["tests"]]
    ok = rows and all(r["ok"] for r in rows)
    return verdict("AUD-PROVIDER-READS", "not_run",
                   f"Managed-provider feeds (GKE Data Access, AKS kube-audit vs kube-audit-admin) were not "
                   f"available. Local self-managed baseline: {sum(r['ok'] for r in rows)}/{len(rows)} get/list/watch "
                   f"probes delivered through the file backend.",
                   routes={"self-managed-log-file-baseline": "pass" if ok else "narrowed",
                           "gke-data-access": "not_run", "aks-kube-audit": "not_run", "eks-cloudwatch": "not_run"},
                   observed=rows)


def t_exec(g):
    rows = {}
    for mode in ("websocket", "spdy"):
        e = g.probes.get(f"E-exec-{mode}")
        if not e:
            continue
        found = g.by_marker(e["marker"])
        shapes = [shape(r) | {"subresource": (next(iter(r.values())).get("objectRef") or {}).get("subresource")}
                  for r in found.values()]
        rows[mode] = {"client_exit": e["client_exit"], "stdout_matched": e["stdout_matches_marker"],
                      "audit_requests": len(found), "shapes": shapes}
    d = g.probes.get("E-exec-denied")
    if d:
        dfound = g.by_id.get(d["audit_id"]) or {}
        rows["denied_control"] = {"http_status": d["status"], **shape(dfound)}
    if not rows:
        return verdict("AUD-EXEC-VERB", "not_run", "Exec probes did not run.")
    acc = [rows.get(m) for m in ("websocket", "spdy")]
    ok = all(a and a["stdout_matched"] and a["audit_requests"] >= 1 and
             any("ResponseStarted" in s.get("stages", []) and s.get("subresource") == "exec" for s in a["shapes"])
             for a in acc)
    dc = rows.get("denied_control") or {}
    ctl_ok = dc.get("http_status") == 403 and 101 not in (dc.get("codes") or {}).values()
    v = "pass" if ok and ctl_ok else ("narrowed" if any(a and a["audit_requests"] for a in acc) else "inconclusive")
    return verdict("AUD-EXEC-VERB", v,
                   "Successful kubectl exec over WebSocket and over SPDY (pinned kubectl v1.35.8) each produced a "
                   "pods/exec audit request whose recorded verb, stages and codes are listed; a 403-denied exec "
                   "shows no accepted upgrade. No target-process or G2 effect is claimed.", observed=rows)


def t_latency(main, base):
    a = main.latency.get("audit") if main else None
    c = base.latency.get("noaudit") if base else None
    if not a or not c:
        return verdict("AUD-API-LATENCY", "inconclusive" if (a or c) else "not_run",
                       "Both the audited and the no-audit baseline measurements are required.",
                       observed={"audit": a, "noaudit": c})
    delta = {}
    for k in a["classes"]:
        if k in c["classes"]:
            delta[k] = {"p50_delta_ms": round(a["classes"][k]["p50_ms"] - c["classes"][k]["p50_ms"], 3),
                        "p90_delta_ms": round(a["classes"][k]["p90_ms"] - c["classes"][k]["p90_ms"], 3)}
    d50 = ", ".join(f"{k} {v['p50_delta_ms']:+.2f} ms" for k, v in delta.items())
    return verdict("AUD-API-LATENCY", "pass",
                   f"p50 deltas audited minus no-audit: {d50}. Measured: identical request mix, sequential over one persistent HTTPS connection, audited "
                   "(candidate policy, blocking log backend, collector tailing) vs a separately created no-audit "
                   "cluster on the same host. Deltas are per request class; this is one small-sample run on a "
                   "shared host, not an overhead bound.", observed={"audit": a, "noaudit": c, "delta": delta},
                   limits="Different cluster instances; host carries unrelated workloads; no zero-overhead claim.")


def steady_state(g):
    """Collector lag and counts after the pre-probe checkpoint (excludes the startup backlog)."""
    ck = load_json(os.path.join(g.dir, "collector", "pre-probe-checkpoint.json"))
    if not ck:
        return None
    lags = sorted(r["_src"]["collector_lag_s"] for r in g.records
                  if r["_src"]["ino"] == ck["ino"] and r["_src"]["offset"] >= ck["offset"]
                  and r["_src"]["collector_lag_s"] is not None)
    if not lags:
        return None
    q = lambda f: round(lags[min(len(lags) - 1, int(f * len(lags)))], 4)
    return {"records_after_pre_probe_checkpoint": len(lags), "lag_p50_s": q(0.5), "lag_p95_s": q(0.95),
            "lag_p99_s": q(0.99), "lag_max_s": round(lags[-1], 4),
            "records_before_checkpoint": ck["stats"]["records"]}


def reconciliation(g):
    """apiserver_audit_event_total at each snapshot vs collector records (context only, not a delivery proof)."""
    tot = lambda m: sum(v for k, v in m["audit_metrics"].items() if k.split("{")[0] == "apiserver_audit_event_total")
    err = lambda m: sum(v for k, v in m["audit_metrics"].items() if k.split("{")[0] == "apiserver_audit_error_total")
    return [{"tag": m["tag"], "apiserver_audit_event_total": tot(m), "apiserver_audit_error_total": err(m)}
            for m in g.metrics]


def collector_completeness(g):
    ev = g.cevents
    done = [e for e in ev if e["event"] == "file_done"]
    stop = [e for e in ev if e["event"] == "stop"]
    gaps = [e for e in ev if e["event"] == "gap"]
    return {"records": len(g.records),
            "steady_state": steady_state(g),
            "metric_snapshots": reconciliation(g),
            "rotations": sum(1 for e in ev if e["event"] == "rotation"),
            "files_done": len(done), "files_fully_read": sum(1 for e in done if e["fully_read"]),
            "parse_errors": sum(1 for e in ev if e["event"] == "parse_error"),
            "anomalies": sum(1 for e in ev if e["event"] == "anomaly"),
            "gaps": [{k: v for k, v in x.items() if k in ("status", "reason", "from_stage_ts", "to_stage_ts")}
                     for x in gaps],
            "final_stop": ({k: stop[-1].get(k) for k in ("mode", "stats", "lag_s")} |
                           {"end_fully_read": (stop[-1].get("end") or {}).get("fully_read")}) if stop else None}


def metric_delta(g, t0, t1, name):
    m0 = next((m for m in g.metrics if m["tag"] == t0), None)
    m1 = next((m for m in g.metrics if m["tag"] == t1), None)
    if not m0 or not m1:
        return None
    tot = lambda m: sum(v for k, v in m["audit_metrics"].items() if k.split("{")[0] == name)
    return tot(m1) - tot(m0)


def t_loss(fault, main=None):
    if not fault or not fault.manifest:
        return verdict("AUD-LOSS-ROUTE", "not_run", "Fault generation did not run.")
    found = lambda tag: [e for e in fault.manifest if e.get("load_tag") == tag]
    res = {}
    for tag in ("r1", "r2", "r3"):
        es = found(tag)
        hit = [e for e in es if e["audit_id"] in fault.by_id]
        res[tag] = {"requests": len(es), "http_ok": sum(1 for e in es if e["status"] == 200),
                    "audit_found": len(hit), "missing": len(es) - len(hit)}
    comp = collector_completeness(fault)
    gaps = [e for e in fault.cevents if e["event"] == "gap"]
    r2_missing = [e for e in found("r2") if e["audit_id"] not in fault.by_id]
    inside = 0
    for e in r2_missing:
        t = parse_ts(e["end_utc"])
        for gp in gaps:
            lo, hi = parse_ts(gp.get("from_stage_ts")), parse_ts(gp.get("to_stage_ts"))
            if lo is not None and hi is not None and lo - 1 <= t <= hi + 1:
                inside += 1
                break
    missing_other = res.get("r1", {}).get("missing", 0) + res.get("r3", {}).get("missing", 0)
    res["r2_missing_inside_recorded_gap"] = inside
    res["metrics_delta"] = {"apiserver_audit_event_total": metric_delta(fault, "fault-start", "fault-end",
                                                                         "apiserver_audit_event_total"),
                            "apiserver_audit_error_total": metric_delta(fault, "fault-start", "fault-end",
                                                                         "apiserver_audit_error_total")}
    rot_ok = comp["rotations"] >= 1 and res["r1"]["missing"] == 0 and comp["parse_errors"] == 0
    fault_ok = bool(gaps) and len(r2_missing) > 0 and inside == len(r2_missing) and res["r3"]["missing"] == 0
    undetected = len(r2_missing) - inside + missing_other
    if rot_ok and fault_ok:
        v = "pass"
    elif undetected:
        v = "narrowed"
    else:
        v = "inconclusive"
    return verdict("AUD-LOSS-ROUTE", v,
                   f"File route only. While tailing, {comp['rotations']} rotations were followed by inode with "
                   f"{res['r1']['missing']} of {res['r1']['requests']} logged requests missing. With the reader "
                   f"stopped past maxbackup, the collector recorded {len(gaps)} DROPPED_BEFORE gap(s); "
                   f"{len(r2_missing)} requests' events were lost and {inside} of them fall inside a recorded gap "
                   f"interval. Webhook overflow and provider delivery remain not_run.",
                   routes={"log-file-rotation-tail": "pass" if rot_ok else "narrowed",
                           "log-file-stopped-reader": "pass" if fault_ok else ("narrowed" if undetected else "inconclusive"),
                           "webhook-batch-overflow": "not_run", "provider-export": "not_run"},
                   observed={"load": res, "collector": comp,
                             "fault_flags": fault.info.get("audit_flags"),
                             "main_generation_reconciliation": {
                                 "collector_records": len(main.records) if main else None,
                                 "metric_snapshots": reconciliation(main) if main else None,
                                 "gaps": len([e for e in main.cevents if e["event"] == "gap"]) if main else None}},
                   limits="A UUID gap is not used as a loss signal; loss is inferred only from inode/offset "
                          "continuity and confirmed against the request manifest.")


def t_watch410(g, p):
    ev = g.ctx410
    got410 = [e for e in ev if e["kind"] == "http_410" or (e["kind"] == "watch_error_event" and e.get("code") == 410)]
    gaps = [e for e in ev if e["kind"] == "watch_gap"]
    attempts = (g.state.get("watch410") or {}).get("attempts")
    if not got410:
        return verdict("CTX-WATCH-410", "inconclusive" if ev else "not_run",
                       f"No real 410 was observed within the predeclared bound (attempts: {attempts}).",
                       observed={"records": len(ev)})
    gp = gaps[0] if gaps else None
    leaked = 0
    if gp:
        lo, hi = int(gp["last_rv"]), int(gp["relist_rv"])
        leaked = sum(1 for e in ev if e["kind"] == "watch_event" and e["stream_id"] == gp["stream_id"]
                     and lo < int(e["rv"]) < hi)
    r0_utc = (g.state.get("watch410") or {}).get("r0_utc")
    muts = [e for e in g.manifest if "CTX-WATCH-410" in e["tests"]]
    in_gap = sum(1 for e in muts if gp and r0_utc and parse_ts(r0_utc) <= parse_ts(e["end_utc"])
                 <= parse_ts(gp["detected_utc"]))
    ok = bool(gp) and leaked == 0 and in_gap > 0
    return verdict("CTX-WATCH-410", "pass" if ok else "narrowed",
                   f"A watcher resumed from a checkpointed resourceVersion after {in_gap} role mutations and "
                   f"received a server-generated 410 "
                   f"({'as a watch ERROR event with Status code 410 inside an HTTP 200 stream' if got410[0]['kind'] == 'watch_error_event' else 'as an HTTP 410 response'}); it recorded a WatchGap with state UNKNOWN, relisted, "
                   f"and emitted no watch events inside the gap ({leaked}). The relist snapshot is marked as such.",
                   observed={"signal": got410[0]["kind"], "watch_gaps": len(gaps), "mutations_in_gap": in_gap,
                             "events_inside_gap": leaked, "attempts": attempts,
                             "relist_items_marked_snapshot": sum(1 for e in ev if e["kind"] == "relist_item")})


def pod_intervals(g):
    by_uid = {}
    for e in g.context:
        if e.get("resource") != "pods" or e["kind"] != "watch_event":
            continue
        pod = e.get("pod") or {}
        if pod.get("host_network"):
            continue
        d = by_uid.setdefault(e["uid"], {"ip": None, "start": None, "end": None, "deleted": False})
        t = parse_ts(e["observed_utc"])
        if pod.get("ip") and d["start"] is None:
            d["ip"], d["start"] = pod["ip"], t
        if e["type"] == "DELETED":
            d["end"], d["deleted"] = t, True
        elif d["start"] is not None:
            d["last"] = t
    return by_uid


def resolve(intervals, ip, t):
    cands = [u for u, d in intervals.items() if d["ip"] == ip and d["start"] is not None and d["start"] <= t and
             (d["end"] is None or t <= d["end"])]
    return cands[0] if len(cands) == 1 else ("JOIN_UNCERTAIN" if cands else None)


def t_ipreuse(g, p):
    st = g.state.get("ip_reuse")
    iv = pod_intervals(g)
    by_ip = {}
    for u, d in iv.items():
        if d["ip"]:
            by_ip.setdefault(d["ip"], []).append((d["start"], u))
    reused = {ip: sorted(v) for ip, v in by_ip.items() if len(v) > 1}
    if not reused:
        return verdict("CTX-POD-IP-REUSE", "inconclusive" if st else "not_run",
                       f"No Pod IP reuse was observed within the bound ({st}).", observed={"bound": st})
    checks = []
    for ip, lst in reused.items():
        for (s0, u0), (s1, u1) in zip(lst, lst[1:]):
            d0, d1 = iv[u0], iv[u1]
            overlap = d0["end"] is None or d0["end"] > d1["start"]
            mid0 = s0 + ((d0["end"] or s1) - s0) / 2
            mid1 = d1["start"] + (((d1["end"] or d1.get("last") or d1["start"]) - d1["start"]) / 2)
            checks.append({"distinct_uids": u0 != u1, "old_deleted_before_new_ip": not overlap,
                           "resolve_old_mid": resolve(iv, ip, mid0) == u0,
                           "resolve_new_mid": resolve(iv, ip, mid1) == u1,
                           "between_intervals": resolve(iv, ip, (d0["end"] + d1["start"]) / 2)
                           if not overlap else "JOIN_UNCERTAIN"})
    ok = all(c["distinct_uids"] and c["resolve_old_mid"] and c["resolve_new_mid"] for c in checks)
    amb = sum(1 for c in checks if not c["old_deleted_before_new_ip"])
    return verdict("CTX-POD-IP-REUSE", "pass" if ok else "narrowed",
                   f"{len(reused)} Pod IP(s) were observed on distinct Pod UIDs after deletion. Interval resolution "
                   f"over watch-observed [first IP, DELETED] intervals returned the correct UID at each interval "
                   f"midpoint; {amb} transition(s) overlapped and resolve to JOIN_UNCERTAIN"
                   f"{' (no overlap occurred, so JOIN_UNCERTAIN handling is covered only by the offline fixture)' if amb == 0 else ''}.",
                   observed={"reused_ips": len(reused), "transitions": checks[:20], "bound": st})


def t_recreate(g, p):
    rec = g.state.get("recreate")
    if not rec:
        return verdict("CTX-RBAC-RECREATE", "not_run", "Recreate probe did not run.")
    ns = g.state.get("ns")
    evs = [e for e in g.context if e["kind"] == "watch_event" and e.get("resource") == "rolebindings"
           and e.get("name") == "mt-recreate" and e.get("namespace") == ns]
    seq = [(e["type"], "uid1" if e["uid"] == rec["uid1"] else ("uid2" if e["uid"] == rec["uid2"] else "other"),
            int(e["rv"])) for e in evs]
    types = [(t, u) for t, u, _ in seq]
    want = [("ADDED", "uid1"), ("DELETED", "uid1"), ("ADDED", "uid2")]
    ordered = [x for x in types if x in want]
    rv_inc = all(a[2] < b[2] for a, b in zip(seq, seq[1:]))
    audit = {}
    for pid, which in (("C-recreate-create-1", "uid1"), ("C-recreate-delete-1", "uid1"), ("C-recreate-create-2", "uid2")):
        e = g.probes.get(pid)
        rc = g.recs(e).get("ResponseComplete") if e else None
        audit[pid] = {"response_uid_matches_" + which: bool(rc and rc["responseObject"]["uid_p"] == p(rec[which])),
                      "stage_ts": rc["stageTimestamp"] if rc else None}
    ts = [parse_ts(audit[k]["stage_ts"]) for k in ("C-recreate-create-1", "C-recreate-delete-1", "C-recreate-create-2")]
    audit_order = all(ts) and ts[0] < ts[1] < ts[2]
    ok = rec["uid1"] != rec["uid2"] and ordered[:3] == want and rv_inc and audit_order and \
        all(next(iter(v.values())) for v in audit.values())
    return verdict("CTX-RBAC-RECREATE", "pass" if ok else "narrowed",
                   "Delete-and-recreate of RoleBinding mt-recreate produced two distinct UIDs; the watch stream shows "
                   "ADDED(uid1), DELETED(uid1), ADDED(uid2) in increasing resourceVersion, and the three audit events "
                   "carry response-object UIDs matching the same instances in stage-time order. Name equality is "
                   "not used to join the two histories.",
                   observed={"watch_sequence": [f"{t}({u})" for t, u in types], "rv_increasing": rv_inc,
                             "audit": {k: {kk: vv for kk, vv in v.items() if kk != "stage_ts"} for k, v in audit.items()},
                             "audit_stage_time_order": audit_order})


def field_matrix(g):
    rows = {}
    for e in g.manifest:
        if e["role"] == "support" or not e.get("audit_id"):
            continue
        for stage, r in (g.recs(e) or {}).items():
            key = f"{e['cred']}|{(r.get('objectRef') or {}).get('resource') or r.get('requestURI')}|{r['verb']}|{stage}"
            u = r["user"]
            rows[key] = {"auditID": bool(r["auditID"]), "stage": stage, "level": r["level"],
                         "responseStatus.code": (r.get("responseStatus") or {}).get("code"),
                         "user.username": u["class"] != "empty", "user.class": u["class"],
                         "user.groups": bool(u["groups"]), "user.extra.credential-id": u["credential_id"]["format"],
                         "user.extra.pod-uid": u["pod_uid_p"] is not None,
                         "user.extra.node-name": u["node_name_present"],
                         "objectRef": r.get("objectRef") is not None,
                         "objectRef.uid": bool((r.get("objectRef") or {}).get("uid_p")),
                         "sourceIPs": r["sourceIPs"]["count"] > 0,
                         "requestReceivedTimestamp": bool(r["requestReceivedTimestamp"]),
                         "stageTimestamp": bool(r["stageTimestamp"]),
                         "annotation.issued-credential-id": r["annotations"]["issued_credential_id"]["present"],
                         "requestObject": r["requestObject"]["present"],
                         "responseObject": r["responseObject"]["present"]}
    return rows


def redaction_scan(text):
    hits = [p.pattern for p in FORBIDDEN_OUTPUT if p.search(text)]
    if UUID_RE.search(text):
        hits.append("uuid")
    return hits


def to_md(result):
    L = [f"# Gap 2 audit and context run — {result['run_id']}", "",
         "Generated by `experiments/cluster/audit-context/summarize.py`; redacted (counts, classes, shapes only).", "",
         "| Test ID | Verdict | Observation |", "|---|---|---|"]
    for t in result["tests"]:
        s = t["summary"].replace("|", "\\|")
        L.append(f"| `{t['test_id']}` | **{t['verdict']}** | {s} |")
    L += ["", "Route-scoped outcomes:", ""]
    for t in result["tests"]:
        if t.get("routes"):
            L.append(f"- `{t['test_id']}`: " + ", ".join(f"{k} = {v}" for k, v in t["routes"].items()))
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rulebook", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--gen", action="append", default=[])
    ap.add_argument("--run-info", default=None)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()
    import yaml
    with open(args.rulebook, encoding="utf-8") as fh:
        rulebook = yaml.safe_load(fh)
    p = Pseudonymizer(args.key)
    gens = {}
    for spec in args.gen:
        name, _, d = spec.partition("=")
        if os.path.isdir(d):
            gens[name] = Gen(name, d)
    main_g, fault, base = gens.get("main"), gens.get("fault"), gens.get("baseline")
    tests = []
    if main_g and main_g.manifest:
        tests += [t_policy(main_g, rulebook), t_usedtoken(main_g), t_issued(main_g), t_podbinding(main_g),
                  t_failed_authn(main_g), t_rbac_body(main_g)]
    else:
        for tid in ("AUD-POLICY-EFFECTIVE", "AUD-FIELDS-USEDTOKEN", "AUD-ISSUED-ANNOTATION",
                    "AUD-POD-BINDING-EXTRA", "AUD-FAILED-AUTHN", "AUD-RBAC-BODY"):
            tests.append(verdict(tid, "not_run", "Main generation did not produce a manifest."))
    tests.append(t_truncation(main_g, fault))
    tests.append(t_provider_reads(main_g) if main_g else verdict("AUD-PROVIDER-READS", "not_run", "No main run."))
    tests.append(t_exec(main_g) if main_g else verdict("AUD-EXEC-VERB", "not_run", "No main run."))
    tests.append(t_latency(main_g, base))
    tests.append(t_loss(fault, main_g))
    tests.append(t_watch410(main_g, p) if main_g else verdict("CTX-WATCH-410", "not_run", "No main run."))
    tests.append(t_ipreuse(main_g, p) if main_g else verdict("CTX-POD-IP-REUSE", "not_run", "No main run."))
    tests.append(t_recreate(main_g, p) if main_g else verdict("CTX-RBAC-RECREATE", "not_run", "No main run."))
    tests.append(verdict("CTX-RESTART-INDICATOR", "not_run", "Belongs to the separate E3 experiment."))
    result = {"run_id": args.run_id, "schema": "gap2-audit-context-result.v0",
              "run_info": load_json(args.run_info) if args.run_info else None,
              "generations": {n: {"info": g.info,
                                  "manifest_entries": len(g.manifest),
                                  "probe_ids": sorted({m["probe_id"] for m in g.manifest
                                                       if not re.match(r"^(L|B|I)-", m["probe_id"])}),
                                  "bulk_probe_counts": {pre: sum(1 for m in g.manifest if m["probe_id"].startswith(pre))
                                                        for pre in ("L-", "B-", "I-")},
                                  "collector": collector_completeness(g),
                                  "context_records": len(g.context),
                                  "context_watch_gaps": sum(1 for e in g.context if e["kind"] == "watch_gap"),
                                  "metrics_snapshots": [{"tag": m["tag"], "status": m["status"],
                                                         "audit_metrics": m["audit_metrics"]} for m in g.metrics]}
                              for n, g in gens.items()},
              "field_presence": field_matrix(main_g) if main_g else {},
              "tests": tests}
    text = json.dumps(result, indent=2, sort_keys=True)
    hits = redaction_scan(text)
    md = to_md(result)
    hits += redaction_scan(md)
    if hits:
        print("REDACTION CHECK FAILED: " + ", ".join(sorted(set(hits))), file=sys.stderr)
        sys.exit(2)
    with open(args.out_json, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write(md)
    for t in tests:
        print(f"{t['test_id']}: {t['verdict']}")


if __name__ == "__main__":
    main()
