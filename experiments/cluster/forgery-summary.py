#!/usr/bin/env python3
"""Join the prober's RESULT line, control-plane Pod facts and the audit log into
redacted per-field verdicts. Usage:
  forgery-summary.py RESULT_FILE FACTS_JSON < kube-apiserver-audit.log
FACTS_JSON: {"pod_uid", "pod_ip", "sa"} read with kubectl (control-plane view).
Prints JSON. No tokens, credential IDs or raw audit lines are emitted."""

import json
import sys

res = json.loads(open(sys.argv[1]).read().split("RESULT ", 1)[1])
facts = json.load(open(sys.argv[2]))
want_user = f"system:serviceaccount:{res['namespace']}:{facts['sa']}"
FORGED_XFF = "203.0.113.7"
FORGED_UA = "kubelet/v1.35.8 (forged)"

audit, malformed = {}, 0
for line in sys.stdin:
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        malformed += 1
        continue
    uri = e.get("requestURI", "")
    if e.get("stage") != "ResponseComplete" or "mtprobe%3D" not in uri:
        continue
    case = uri.split("mtprobe%3D", 1)[1].split("&", 1)[0]
    user = e.get("user") or {}
    extra = user.get("extra") or {}
    audit[case] = {
        "code": (e.get("responseStatus") or {}).get("code"),
        "username_is_sa": user.get("username") == want_user,
        "pod_uid_matches": (extra.get("authentication.kubernetes.io/pod-uid") or [None])[0] == facts["pod_uid"],
        "credential_id_present": "authentication.kubernetes.io/credential-id" in extra,
        "impersonated_user": (e.get("impersonatedUser") or {}).get("username"),
        "sourceIPs_first_is_forged": (e.get("sourceIPs") or [None])[0] == FORGED_XFF,
        "sourceIPs_last_is_pod_ip": (e.get("sourceIPs") or [None])[-1] == facts["pod_ip"],
        "sourceIPs_len": len(e.get("sourceIPs") or []),
        "sourceIPs_last_is_node_ip": (e.get("sourceIPs") or [None])[-1] in facts.get("node_ips", []),
        "userAgent_is_forged": e.get("userAgent") == FORGED_UA,
    }

ssr = res["ssr"]
echo = res.get("echo", {})
verdict = {
    # sensor-made: must NOT be changeable by the workload
    "audit_user_unforgeable": bool(audit) and all(a["username_is_sa"] for a in audit.values()),
    "audit_pod_uid_unforgeable": bool(audit) and all(a["pod_uid_matches"] for a in audit.values()),
    "impersonation_rejected": res["api"].get("impersonate") == 403
    and audit.get("impersonate", {}).get("impersonated_user") in (None, ""),
    "front_proxy_headers_ignored": ssr.get("front_proxy", {}).get("username") == want_user
    and ssr.get("front_proxy", {}).get("pod_uid") == facts["pod_uid"],
    "selfsubjectreview_pod_uid_matches": all(v.get("pod_uid") == facts["pod_uid"]
                                             for k, v in ssr.items() if v.get("code") == 201),
    "echo_tcp_peer_is_pod_ip": echo.get("tcp_peer") == facts["pod_ip"],
    "audit_sourceIPs_last_is_pod_ip": audit.get("xff", {}).get("sourceIPs_last_is_pod_ip"),
    "audit_sourceIPs_last_is_node_ip": audit.get("xff", {}).get("sourceIPs_last_is_node_ip"),
    # workload-made: expected to BE changeable by the workload
    "audit_sourceIPs_first_forgeable": audit.get("xff", {}).get("sourceIPs_first_is_forged"),
    "audit_userAgent_forgeable": audit.get("ua_trace", {}).get("userAgent_is_forged"),
    "trace_header_forgeable": (echo.get("headers") or {}).get("traceparent", "").startswith("00-4bf92f35"),
    "request_id_forgeable": (echo.get("headers") or {}).get("x-request-id") == "forged-req-1",
}
print(json.dumps({"verdict": verdict, "audit_cases": audit, "api_codes": res["api"],
                  "ssr": {k: {kk: vv for kk, vv in v.items() if kk != "pod_uid"} | {"pod_uid_matches": v.get("pod_uid") == facts["pod_uid"]}
                          for k, v in ssr.items()},
                  "malformed_audit_lines": malformed}, indent=1, sort_keys=True))
