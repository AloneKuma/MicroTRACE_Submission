#!/usr/bin/env python3
"""Runs inside the prober Pod (RBAC-less ServiceAccount). Sends API and HTTP
requests carrying forged identity and trace headers, and prints one RESULT line.
No token bytes are printed. Stdlib only."""

import json
import ssl
import urllib.error
import urllib.request

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
NS = open(f"{SA}/namespace").read().strip()
TOKEN = open(f"{SA}/token").read().strip()
CTX = ssl.create_default_context(cafile=f"{SA}/ca.crt")
TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

CASES = {
    "baseline": {},
    "impersonate": {"Impersonate-User": "system:admin", "Impersonate-Group": "system:masters"},
    "front_proxy": {"X-Remote-User": "system:admin", "X-Remote-Group": "system:masters",
                    "X-Remote-Extra-Authentication.kubernetes.io%2fpod-uid": "00000000-0000-0000-0000-000000000000"},
    "xff": {"X-Forwarded-For": "203.0.113.7", "X-Real-Ip": "203.0.113.8"},
    "ua_trace": {"User-Agent": "kubelet/v1.35.8 (forged)", "traceparent": TRACE, "X-Request-Id": "forged-req-1"},
}


def call(url, headers, method="GET", body=None, ctx=CTX):
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


out = {"namespace": NS, "api": {}, "ssr": {}, "echo": {}}
for name, extra in CASES.items():
    h = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json", **extra}
    code, _ = call(f"{API}/api/v1/namespaces/{NS}/configmaps?labelSelector=mtprobe%3D{name}", h)
    out["api"][name] = code
    body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}).encode()
    code, txt = call(f"{API}/apis/authentication.k8s.io/v1/selfsubjectreviews",
                     {**h, "Content-Type": "application/json"}, "POST", body)
    ui = {}
    if code == 201:
        ui = json.loads(txt).get("status", {}).get("userInfo", {})
    out["ssr"][name] = {"code": code, "username": ui.get("username"),
                        "groups": ui.get("groups"),
                        "extra_keys": sorted((ui.get("extra") or {}).keys()),
                        "pod_uid": ((ui.get("extra") or {}).get("authentication.kubernetes.io/pod-uid") or [None])[0],
                        "credential_id_present": "authentication.kubernetes.io/credential-id" in (ui.get("extra") or {})}

code, txt = call("http://echo:8080/", {"traceparent": TRACE, "X-Request-Id": "forged-req-1",
                                      "X-Forwarded-For": "203.0.113.7"}, ctx=None)
out["echo"] = {"code": code, **(json.loads(txt) if code == 200 else {})}
print("RESULT " + json.dumps(out, sort_keys=True))
