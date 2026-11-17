#!/usr/bin/env python3
"""Issue the Gap 2 audit/context probes and log a request manifest.

Every request is written to <private>/manifest.jsonl with probe ID, test IDs,
role (positive/negative/support), credential mode, method/path, expected
outcome, UTC start/end, latency, HTTP status, the Audit-Id response header and
the object UID. Bearer tokens obtained by TokenRequest are kept in memory
only and never written; the manifest records only a keyed pseudonym of the
issued JTI. Kubeconfig content is never printed.

Subcommands (all need --kubeconfig-json, --private, --key, --run-id):
  setup | matrix | exec | rbac-recreate | burst | watch410 | ip-reuse | latency |
  truncation | load-setup | load | metrics
"""

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtk8s import Api, JsonlWriter, KubeConfig, Pseudonymizer, utc_now, write_json_atomic  # noqa: E402

RBAC = "/apis/rbac.authorization.k8s.io/v1"
MERGE = "application/merge-patch+json"

# Request cells issued by setup/matrix/exec, as (verb, group, resource,
# subresource, authenticated, non_resource_url). tests/test_harness.py checks
# that these cover every rulebook audit_requirement and reviews them against
# the candidate policy. The exec verbs are expectations that AUD-EXEC-VERB tests.
PROBE_COVERAGE = [
    ("get", "", "pods", "", True, None), ("list", "", "pods", "", True, None),
    ("watch", "", "pods", "", True, None), ("create", "", "pods", "", True, None),
    ("list", "apps", "deployments", "", True, None),
    ("list", "rbac.authorization.k8s.io", "clusterroles", "", True, None),
    ("create", "", "configmaps", "", True, None), ("get", "", "configmaps", "", True, None),
    ("create", "", "secrets", "", True, None), ("get", "", "secrets", "", True, None),
    ("list", "", "secrets", "", True, None), ("watch", "", "secrets", "", True, None),
    ("create", "authentication.k8s.io", "tokenreviews", "", True, None),
    ("create", "", "serviceaccounts", "token", True, None),
    ("get", "", "pods", "", False, None), ("get", "", "", "", False, "/api"),
    ("get", "", "pods", "exec", True, None), ("create", "", "pods", "exec", True, None),
] + [(v, "rbac.authorization.k8s.io", r, "", True, None)
     for r in ("roles", "rolebindings", "clusterroles", "clusterrolebindings")
     for v in ("create", "update", "patch", "delete")]


class Prober:
    def __init__(self, args):
        self.args = args
        self.kc = KubeConfig(args.kubeconfig_json, args.private)
        self.admin = Api(self.kc, "admin")
        self.p = Pseudonymizer(args.key)
        self.m = JsonlWriter(os.path.join(args.private, "manifest.jsonl"))
        self.run = args.run_id
        self.short = re.sub(r"[^0-9a-z]", "", args.run_id.lower())[-10:]
        self.ns = f"mt-gap2-{self.short}"
        self.state_path = os.path.join(args.private, "probe-state.json")
        self.state = {}
        if os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                self.state = json.load(fh)

    def save_state(self):
        write_json_atomic(self.state_path, self.state)

    # ------------------------------------------------------------ recording
    def call(self, probe_id, tests, role, method, path, body=None, api=None, cred="admin", expect=None,
             ctype="application/json", resource=None, subresource=None, name=None, namespace=None,
             notes=None, extra=None):
        api = api or self.admin
        r = api.request(method, path, body=body, content_type=ctype)
        obj = r.json() or {}
        meta = obj.get("metadata") or {}
        uid = meta.get("uid") or (obj.get("details") or {}).get("uid")
        entry = {"probe_id": probe_id, "tests": tests, "role": role, "cred": cred, "method": method,
                 "path": path, "resource": resource, "subresource": subresource, "namespace": namespace,
                 "name": name, "expect": expect or {}, "status": r.status, "audit_id": r.audit_id,
                 "start_utc": r.start_utc, "end_utc": r.end_utc, "latency_ms": round(r.latency_ms, 3),
                 "object_uid": uid, "object_uid_p": self.p(uid),
                 "request_bytes": len(body if isinstance(body, (bytes, str)) else json.dumps(body))
                 if body is not None else 0,
                 "notes": notes}
        if extra:
            entry.update(extra)
        self.m.write(entry)
        return r, obj

    def stream_call(self, probe_id, tests, role, path, expect, resource, namespace, api=None, cred="admin"):
        api = api or self.admin
        start = utc_now()
        t0 = time.perf_counter()
        conn, resp = api.stream(path, timeout=30)
        audit_id = dict((k.lower(), v) for k, v in resp.getheaders()).get("audit-id")
        n = 0
        while True:
            line = resp.readline()
            if not line:
                break
            n += 1
        conn.close()
        self.m.write({"probe_id": probe_id, "tests": tests, "role": role, "cred": cred, "method": "GET",
                      "path": path, "resource": resource, "subresource": None, "namespace": namespace,
                      "name": None, "expect": expect, "status": resp.status, "audit_id": audit_id,
                      "start_utc": start, "end_utc": utc_now(),
                      "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
                      "object_uid": None, "object_uid_p": None, "request_bytes": 0,
                      "notes": f"watch stream lines={n}"})

    def meta_expect(self, status, stages, level="Metadata", **kw):
        return {"status": status, "level": level, "stages": stages, **kw}

    # ------------------------------------------------------------ helpers
    def wait_pod(self, name, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.admin.request("GET", f"/api/v1/namespaces/{self.ns}/pods/{name}")
            obj = r.json() or {}
            if (obj.get("status") or {}).get("phase") == "Running":
                return obj
            time.sleep(1)
        raise RuntimeError(f"pod {name} not Running within {timeout}s")

    def token_request(self, probe_id, tests, bound):
        spec = {"audiences": [], "expirationSeconds": 600}
        if bound:
            spec["boundObjectRef"] = {"kind": "Pod", "apiVersion": "v1", "name": "mt-target",
                                      "uid": self.state["target_pod_uid"]}
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": spec}
        r = self.admin.request("POST", f"/api/v1/namespaces/{self.ns}/serviceaccounts/mt-probe-sa/token",
                               body=body)
        token = ((r.json() or {}).get("status") or {}).get("token")
        jti = None
        if token:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            jti = claims.get("jti")
            has_pod_claim = bool((claims.get("kubernetes.io") or {}).get("pod"))
        else:
            has_pod_claim = None
        self.m.write({"probe_id": probe_id, "tests": tests, "role": "positive" if bound else "negative",
                      "cred": "admin", "method": "POST", "path": "<serviceaccounts/token>",
                      "resource": "serviceaccounts", "subresource": "token", "namespace": self.ns,
                      "name": "mt-probe-sa",
                      "expect": self.meta_expect(201, ["ResponseComplete"], annotation_issued=True,
                                                 no_bodies=True),
                      "status": r.status, "audit_id": r.audit_id, "start_utc": r.start_utc,
                      "end_utc": r.end_utc, "latency_ms": round(r.latency_ms, 3),
                      "object_uid": None, "object_uid_p": None, "request_bytes": len(json.dumps(body)),
                      "issued_jti_p": self.p("JTI=" + jti) if jti else None,
                      "token_returned": token is not None, "token_has_pod_claim": has_pod_claim,
                      "bound": bound, "notes": "token held in memory only"})
        return token, jti

    # ------------------------------------------------------------ subcommands
    def setup(self):
        ns = self.ns
        exp = self.meta_expect(201, ["ResponseComplete"])
        self.call("S-ns", ["AUD-POLICY-EFFECTIVE"], "support", "POST", "/api/v1/namespaces",
                  {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {"mt-run": self.short}}},
                  expect=exp, resource="namespaces", name=ns)
        self.call("S-sa", ["AUD-POLICY-EFFECTIVE"], "support", "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
                  {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "mt-probe-sa"}},
                  expect=exp, resource="serviceaccounts", name="mt-probe-sa", namespace=ns)
        rr = self.meta_expect(201, ["ResponseComplete"], level="RequestResponse",
                              request_object=True, response_object=True)
        self.call("S-role", ["AUD-RBAC-BODY", "AUD-POLICY-EFFECTIVE"], "positive", "POST",
                  f"{RBAC}/namespaces/{ns}/roles",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                   "metadata": {"name": "mt-pod-reader"},
                   "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]},
                  expect=rr, resource="roles", name="mt-pod-reader", namespace=ns)
        self.call("S-rb", ["AUD-RBAC-BODY", "AUD-POLICY-EFFECTIVE"], "positive", "POST",
                  f"{RBAC}/namespaces/{ns}/rolebindings",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                   "metadata": {"name": "mt-pod-reader-sa"},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "mt-pod-reader"},
                   "subjects": [{"kind": "ServiceAccount", "name": "mt-probe-sa", "namespace": ns}]},
                  expect=rr, resource="rolebindings", name="mt-pod-reader-sa", namespace=ns)
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": "mt-target", "labels": {"mt-run": self.short}},
               "spec": {"serviceAccountName": "mt-probe-sa", "terminationGracePeriodSeconds": 0,
                        "containers": [{"name": "box", "image": self.args.image,
                                        "command": ["/bin/sleep", "3600"],
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "runAsNonRoot": True, "runAsUser": 65534,
                                                            "capabilities": {"drop": ["ALL"]}},
                                        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                                      "limits": {"memory": "32Mi"}}}]}}
        _, obj = self.call("P-D2-create-pod", ["AUD-POLICY-EFFECTIVE"], "positive", "POST",
                           f"/api/v1/namespaces/{ns}/pods", pod, expect=exp, resource="pods",
                           name="mt-target", namespace=ns)
        self.state.update({"ns": ns, "target_pod_uid": obj["metadata"]["uid"]})
        running = self.wait_pod("mt-target")
        self.state["target_node"] = running["spec"]["nodeName"]
        self.save_state()
        print(f"SETUP ns={ns} target=Running")

    def matrix(self):
        ns = self.ns
        pod_path = f"/api/v1/namespaces/{ns}/pods/mt-target"
        rc = self.meta_expect(200, ["ResponseComplete"])
        watch_exp = self.meta_expect(200, ["ResponseStarted", "ResponseComplete"])
        # B1 reads
        self.call("P-B1-get-pods", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS", "AUD-FIELDS-USEDTOKEN"],
                  "positive", "GET", pod_path, expect=rc, resource="pods", name="mt-target", namespace=ns,
                  notes="admin x509 client credential; credential-id control")
        self.call("P-B1-list-pods", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive", "GET",
                  f"/api/v1/namespaces/{ns}/pods", expect=rc, resource="pods", namespace=ns)
        self.stream_call("P-B1-watch-pods", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive",
                         f"/api/v1/namespaces/{ns}/pods?watch=1&timeoutSeconds=1", watch_exp, "pods", ns)
        self.call("P-B1-list-deployments", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive", "GET",
                  f"/apis/apps/v1/namespaces/{ns}/deployments", expect=rc, resource="deployments", namespace=ns)
        self.call("P-B1-list-clusterroles", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive", "GET",
                  f"{RBAC}/clusterroles?limit=5", expect=rc, resource="clusterroles")
        # B3 / credential cap: configmaps
        cap_c = self.meta_expect(201, ["ResponseComplete"], no_bodies=True)
        cap = self.meta_expect(200, ["ResponseComplete"], no_bodies=True)
        self.call("P-CAP-create-cm", ["AUD-POLICY-EFFECTIVE"], "positive", "POST",
                  f"/api/v1/namespaces/{ns}/configmaps",
                  {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "mt-cm"},
                   "data": {"marker": "mt-cm-" + secrets.token_hex(8)}},
                  expect=cap_c, resource="configmaps", name="mt-cm", namespace=ns)
        self.call("P-B3-get-cm", ["AUD-POLICY-EFFECTIVE"], "positive", "GET",
                  f"/api/v1/namespaces/{ns}/configmaps/mt-cm", expect=cap, resource="configmaps",
                  name="mt-cm", namespace=ns)
        # H3 secrets (credential cap: no body may appear)
        self.call("P-CAP-create-secret", ["AUD-POLICY-EFFECTIVE"], "positive", "POST",
                  f"/api/v1/namespaces/{ns}/secrets",
                  {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "mt-secret"},
                   "stringData": {"k": "synthetic-" + secrets.token_hex(8)}},
                  expect=cap_c, resource="secrets", name="mt-secret", namespace=ns)
        self.call("P-H3-get-secret", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive", "GET",
                  f"/api/v1/namespaces/{ns}/secrets/mt-secret", expect=cap, resource="secrets",
                  name="mt-secret", namespace=ns)
        self.call("P-H3-list-secrets", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive", "GET",
                  f"/api/v1/namespaces/{ns}/secrets", expect=cap, resource="secrets", namespace=ns)
        self.stream_call("P-H3-watch-secrets", ["AUD-POLICY-EFFECTIVE", "AUD-PROVIDER-READS"], "positive",
                         f"/api/v1/namespaces/{ns}/secrets?watch=1&timeoutSeconds=1",
                         dict(watch_exp, no_bodies=True), "secrets", ns)
        # TokenReview with a deliberately invalid token string (no real credential in the body)
        self.call("P-CAP-tokenreview", ["AUD-POLICY-EFFECTIVE"], "positive", "POST",
                  "/apis/authentication.k8s.io/v1/tokenreviews",
                  {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                   "spec": {"token": "invalid-" + secrets.token_hex(12)}},
                  expect=cap_c, resource="tokenreviews")
        # Token issuance and use
        bound_tok, bound_jti = self.token_request("P-TR-bound", ["AUD-ISSUED-ANNOTATION", "AUD-POLICY-EFFECTIVE",
                                                                  "AUD-FIELDS-USEDTOKEN", "AUD-POD-BINDING-EXTRA"], True)
        unbound_tok, unbound_jti = self.token_request("P-TR-unbound", ["AUD-ISSUED-ANNOTATION",
                                                                        "AUD-POD-BINDING-EXTRA"], False)
        if not bound_tok or not unbound_tok:
            raise RuntimeError("TokenRequest failed; see manifest")
        pod_uid = self.state["target_pod_uid"]
        bound = Api(self.kc, "bearer", token=bound_tok)
        unbound = Api(self.kc, "bearer", token=unbound_tok)
        self.call("P-USE-bound", ["AUD-FIELDS-USEDTOKEN", "AUD-POD-BINDING-EXTRA"], "positive", "GET", pod_path,
                  api=bound, cred="sa-pod-bound", resource="pods", name="mt-target", namespace=ns,
                  expect=self.meta_expect(200, ["ResponseComplete"], credential_id="JTI",
                                          pod_binding=True),
                  extra={"used_jti_p": self.p("JTI=" + bound_jti), "pod_uid_p": self.p(pod_uid),
                         "pod_name_p": self.p("mt-target")})
        self.call("P-USE-unbound", ["AUD-FIELDS-USEDTOKEN", "AUD-POD-BINDING-EXTRA"], "negative", "GET", pod_path,
                  api=unbound, cred="sa-unbound", resource="pods", name="mt-target", namespace=ns,
                  expect=self.meta_expect(200, ["ResponseComplete"], credential_id="JTI", pod_binding=False),
                  extra={"used_jti_p": self.p("JTI=" + unbound_jti)})
        self.call("P-403-unbound", ["AUD-FAILED-AUTHN"], "negative", "GET", "/api/v1/namespaces/kube-system/secrets",
                  api=unbound, cred="sa-unbound", resource="secrets", namespace="kube-system",
                  expect=self.meta_expect(403, ["ResponseComplete"]),
                  notes="authenticated identity denied by RBAC; must not count as failed authentication")
        del bound_tok, unbound_tok
        bound.close()
        unbound.close()
        # Failed authentication (401) and anonymous controls
        bogus = Api(self.kc, "bearer", token="invalid-" + secrets.token_hex(16))
        self.call("P-401-pods", ["AUD-FAILED-AUTHN", "AUD-POLICY-EFFECTIVE"], "positive", "GET", pod_path,
                  api=bogus, cred="invalid-bearer", resource="pods", name="mt-target", namespace=ns,
                  expect=self.meta_expect(401, ["ResponseStarted"], empty_user=True))
        self.call("P-401-api", ["AUD-FAILED-AUTHN", "AUD-POLICY-EFFECTIVE"], "positive", "GET", "/api",
                  api=bogus, cred="invalid-bearer",
                  expect=self.meta_expect(401, ["ResponseStarted"], empty_user=True))
        bogus.close()
        anon = Api(self.kc, "anonymous")
        self.call("P-ANON-api", ["AUD-FAILED-AUTHN"], "negative", "GET", "/api/v1/namespaces/kube-system/pods",
                  api=anon, cred="anonymous",
                  expect=self.meta_expect(None, ["ResponseComplete"]),
                  notes="no credential: anonymous identity, not a failed authentication")
        anon.close()
        self.rbac_mutations()
        self.large_rbac("P-TRUNC-large-noflag", ["AUD-TRUNCATION-OVERSIZE", "AUD-RBAC-BODY"], "negative")
        print("MATRIX done")

    def rbac_mutations(self):
        ns = self.ns
        rr = lambda code, req=True: self.meta_expect(code, ["ResponseComplete"], level="RequestResponse",
                                                     request_object=req, response_object=True)
        tests = ["AUD-RBAC-BODY", "AUD-POLICY-EFFECTIVE"]
        cr, crb = f"mt-{self.short}-cr", f"mt-{self.short}-crb"
        self.call("P-RBAC-create-clusterrole", tests, "positive", "POST", f"{RBAC}/clusterroles",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                   "metadata": {"name": cr, "labels": {"mt-run": self.short}},
                   "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]},
                  expect=rr(201), resource="clusterroles", name=cr)
        self.call("P-RBAC-create-clusterrolebinding", tests, "positive", "POST", f"{RBAC}/clusterrolebindings",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                   "metadata": {"name": crb, "labels": {"mt-run": self.short}},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": cr},
                   "subjects": [{"kind": "ServiceAccount", "name": "mt-probe-sa", "namespace": ns}]},
                  expect=rr(201), resource="clusterrolebindings", name=crb)
        targets = [("roles", f"{RBAC}/namespaces/{ns}/roles/mt-pod-reader", ns, "mt-pod-reader"),
                   ("rolebindings", f"{RBAC}/namespaces/{ns}/rolebindings/mt-pod-reader-sa", ns, "mt-pod-reader-sa"),
                   ("clusterroles", f"{RBAC}/clusterroles/{cr}", None, cr),
                   ("clusterrolebindings", f"{RBAC}/clusterrolebindings/{crb}", None, crb)]
        for res, path, tns, name in targets:
            cur = self.admin.request("GET", path).json()
            cur["metadata"].setdefault("labels", {})["mt-update"] = "1"
            self.call(f"P-RBAC-update-{res}", tests, "positive", "PUT", path, cur, expect=rr(200),
                      resource=res, name=name, namespace=tns)
            self.call(f"P-RBAC-patch-{res}", tests, "positive", "PATCH", path,
                      {"metadata": {"labels": {"mt-patch": "1"}}}, ctype=MERGE, expect=rr(200),
                      resource=res, name=name, namespace=tns)
        # Deletes on the cluster-scoped pair (namespaced pair stays for token-use probes)
        for res, path, name in (("clusterrolebindings", f"{RBAC}/clusterrolebindings/{crb}", crb),
                                ("clusterroles", f"{RBAC}/clusterroles/{cr}", cr)):
            self.call(f"P-RBAC-delete-{res}", tests, "positive", "DELETE", path,
                      {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Background"},
                      expect=rr(200), resource=res, name=name)
        # Namespaced Role delete via a throwaway role
        self.call("P-RBAC-create-role-tmp", tests, "support", "POST", f"{RBAC}/namespaces/{ns}/roles",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "mt-tmp"},
                   "rules": []}, expect=rr(201), resource="roles", name="mt-tmp", namespace=ns)
        self.call("P-RBAC-delete-roles", tests, "positive", "DELETE", f"{RBAC}/namespaces/{ns}/roles/mt-tmp",
                  {"apiVersion": "v1", "kind": "DeleteOptions"}, expect=rr(200), resource="roles",
                  name="mt-tmp", namespace=ns)

    def large_rbac(self, probe_id, tests, role, target_bytes=40000):
        """Create then delete one accepted large ClusterRole (bounded size)."""
        name = f"mt-{self.short}-large-{probe_id.lower()[-6:].strip('-')}"
        rules, size = [], 0
        i = 0
        while size < target_bytes:
            rules.append({"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                          "resourceNames": [f"mt-bounded-name-{i:05d}-{j}-padpadpadpadpadpad" for j in range(4)]})
            i += 1
            size = len(json.dumps(rules))
        body = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": name, "labels": {"mt-run": self.short}}, "rules": rules}
        r, _ = self.call(probe_id, tests, role, "POST", f"{RBAC}/clusterroles", body,
                         expect=self.meta_expect(201, ["ResponseComplete"], level="RequestResponse",
                                                 request_object=True, response_object=True),
                         resource="clusterroles", name=name, extra={"rules_count": len(rules)})
        if r.status != 201:
            print(f"WARN {probe_id}: large mutation not accepted (HTTP {r.status}); audit result not interpretable")
        self.call(probe_id + "-delete", tests, "support", "DELETE", f"{RBAC}/clusterroles/{name}",
                  expect=self.meta_expect(200, ["ResponseComplete"], level="RequestResponse"),
                  resource="clusterroles", name=name)
        return r.status

    def truncation(self):
        """Fault config: normal-size and bounded large accepted RBAC mutation."""
        tests = ["AUD-TRUNCATION-OVERSIZE"]
        cr = f"mt-{self.short}-normal"
        self.call("T-normal", tests, "negative", "POST", f"{RBAC}/clusterroles",
                  {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                   "metadata": {"name": cr}, "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                                                        "verbs": ["get"]}]},
                  expect=self.meta_expect(201, ["ResponseComplete"], level="RequestResponse",
                                          request_object=True, response_object=True),
                  resource="clusterroles", name=cr)
        self.call("T-normal-delete", tests, "support", "DELETE", f"{RBAC}/clusterroles/{cr}",
                  expect=self.meta_expect(200, ["ResponseComplete"], level="RequestResponse"),
                  resource="clusterroles", name=cr)
        status = self.large_rbac("T-large", tests, "positive")
        print(f"TRUNCATION large_status={status}")

    def exec_probes(self):
        ns = self.ns
        kubectl, kubeconfig = self.args.kubectl, self.args.kubeconfig
        results = {}
        for mode, env_val in (("websocket", "true"), ("spdy", "false")):
            marker = f"mt-exec-{mode}-{secrets.token_hex(4)}"
            env = {"PATH": "/usr/bin:/bin", "HOME": self.args.private, "KUBECONFIG": kubeconfig,
                   "KUBECTL_REMOTE_COMMAND_WEBSOCKETS": env_val}
            start = utc_now()
            t0 = time.perf_counter()
            proc = subprocess.run([kubectl, "exec", "-n", ns, "mt-target", "-c", "box", "--", "/bin/echo", marker],
                                  env=env, capture_output=True, text=True, timeout=60)
            ok = proc.returncode == 0 and proc.stdout.strip() == marker
            self.m.write({"probe_id": f"E-exec-{mode}", "tests": ["AUD-EXEC-VERB", "AUD-POLICY-EFFECTIVE"],
                          "role": "positive", "cred": "admin", "method": "kubectl-exec", "path": None,
                          "resource": "pods", "subresource": "exec", "namespace": ns, "name": "mt-target",
                          "expect": {"status": 101 if mode == "websocket" else None,
                                     "stages": ["ResponseStarted"], "level": "Metadata", "accepted": True},
                          "status": None, "audit_id": None, "start_utc": start, "end_utc": utc_now(),
                          "latency_ms": round((time.perf_counter() - t0) * 1000, 3), "object_uid": None,
                          "object_uid_p": None, "request_bytes": 0, "marker": marker,
                          "client_exit": proc.returncode, "stdout_matches_marker": ok,
                          "kubectl_env_websockets": env_val, "notes": "correlate by marker in requestURI"})
            results[mode] = ok
        # Forbidden exec: the unbound SA identity has no pods/exec permission.
        tok, _ = self.token_request("E-exec-denied-token", ["AUD-EXEC-VERB"], False)
        denied = Api(self.kc, "bearer", token=tok)
        marker = f"mt-exec-denied-{secrets.token_hex(4)}"
        self.call("E-exec-denied", ["AUD-EXEC-VERB"], "negative", "POST",
                  f"/api/v1/namespaces/{ns}/pods/mt-target/exec?command=%2Fbin%2Fecho&command={marker}"
                  "&container=box&stdout=true", api=denied, cred="sa-unbound", resource="pods",
                  subresource="exec", name="mt-target", namespace=ns,
                  expect=self.meta_expect(403, ["ResponseComplete"]), extra={"marker": marker})
        del tok
        denied.close()
        print(f"EXEC websocket_ok={results['websocket']} spdy_ok={results['spdy']}")

    def rbac_recreate(self):
        ns = self.ns
        tests = ["CTX-RBAC-RECREATE", "AUD-RBAC-BODY"]
        body = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "mt-recreate"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "mt-pod-reader"},
                "subjects": [{"kind": "ServiceAccount", "name": "mt-probe-sa", "namespace": ns}]}
        path = f"{RBAC}/namespaces/{ns}/rolebindings"
        rr = lambda c: self.meta_expect(c, ["ResponseComplete"], level="RequestResponse", response_object=True)
        _, a = self.call("C-recreate-create-1", tests, "positive", "POST", path, body, expect=rr(201),
                         resource="rolebindings", name="mt-recreate", namespace=ns)
        time.sleep(1)
        self.call("C-recreate-delete-1", tests, "positive", "DELETE", f"{path}/mt-recreate", expect=rr(200),
                  resource="rolebindings", name="mt-recreate", namespace=ns)
        time.sleep(1)
        _, b = self.call("C-recreate-create-2", tests, "positive", "POST", path, body, expect=rr(201),
                         resource="rolebindings", name="mt-recreate", namespace=ns)
        uid1, uid2 = a["metadata"]["uid"], b["metadata"]["uid"]
        self.state["recreate"] = {"uid1": uid1, "uid2": uid2}
        self.save_state()
        print(f"RECREATE distinct_uids={uid1 != uid2}")

    def burst(self, n=None, tag=None):
        ns, n, tag = self.ns, n or self.args.count, tag or self.args.tag
        path = f"{RBAC}/namespaces/{ns}/roles"
        for i in range(n):
            name = f"mt-{tag}-{i:04d}"
            self.call(f"B-{tag}-create-{i}", ["CTX-WATCH-410"], "support", "POST", path,
                      {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": name},
                       "rules": []}, resource="roles", name=name, namespace=ns)
            self.call(f"B-{tag}-delete-{i}", ["CTX-WATCH-410"], "support", "DELETE", f"{path}/{name}",
                      resource="roles", name=name, namespace=ns)
        print(f"BURST {tag} mutations={2 * n}")

    def watch410(self):
        """Bounded attempt at a real 410: a watcher lists roles (checkpoint r0) and stops; role
        mutations are generated in two bursts separated by a wait longer than the watch cache's
        freshness window; the watcher then resumes from r0. At most --attempts rounds."""
        a = self.args
        here = os.path.dirname(os.path.abspath(__file__))
        ck = os.path.join(a.private, "ck410.json")
        ck0 = os.path.join(a.private, "ck410.r0.json")
        out = os.path.join(a.private, "context-410.jsonl")
        base = [sys.executable, os.path.join(here, "context-watch.py"), "--kubeconfig-json", a.kubeconfig_json,
                "--private", a.private, "--out", out, "--resources", "roles", "--namespace", self.ns,
                "--checkpoint", ck, "--stream-name", "resume410"]
        subprocess.run(base + ["--stop-after-list"], check=True, timeout=60)
        with open(ck, encoding="utf-8") as fh:
            saved = fh.read()
        with open(ck0, "w", encoding="utf-8") as fh:
            fh.write(saved)
        r0_utc = utc_now()
        got, attempt = False, 0
        for attempt in range(1, a.attempts + 1):
            self.burst(a.count, f"w{attempt}a")
            time.sleep(a.wait)
            self.burst(a.count, f"w{attempt}b")
            with open(ck, "w", encoding="utf-8") as fh:
                fh.write(saved)  # always resume from the original r0
            subprocess.run(base + ["--resume", "--max-seconds", "15"], timeout=120)
            recs = [json.loads(x) for x in open(out, encoding="utf-8") if x.strip()]
            got = any(r["kind"] == "http_410" or (r["kind"] == "watch_error_event" and r.get("code") == 410)
                      for r in recs)
            print(f"WATCH410 attempt={attempt} got_410={got}")
            if got:
                break
        self.state["watch410"] = {"attempts": attempt, "r0_utc": r0_utc, "got_410": got,
                                  "bound": {"attempts": a.attempts, "mutations_per_burst": 2 * a.count,
                                            "wait_s": a.wait}}
        self.save_state()

    def ip_reuse(self):
        """Bounded: at most --batches x --batch-size pod creations on one node; stop at first reuse."""
        ns, node = self.ns, self.state["target_node"]
        seen = {}  # ip -> uid
        created = 0
        found = None
        for b in range(self.args.batches):
            names = [f"mt-ip-{b:02d}-{i:03d}" for i in range(self.args.batch_size)]
            for name in names:
                pod = {"apiVersion": "v1", "kind": "Pod",
                       "metadata": {"name": name, "labels": {"mt-ip": "1", "mt-run": self.short}},
                       "spec": {"nodeName": node, "terminationGracePeriodSeconds": 0,
                                "automountServiceAccountToken": False,
                                "containers": [{"name": "c", "image": self.args.image,
                                                "command": ["/bin/sleep", "600"],
                                                "securityContext": {"allowPrivilegeEscalation": False,
                                                                    "runAsNonRoot": True, "runAsUser": 65534,
                                                                    "capabilities": {"drop": ["ALL"]}},
                                                "resources": {"requests": {"cpu": "1m", "memory": "4Mi"},
                                                              "limits": {"memory": "16Mi"}}}]}}
                self.call(f"I-create-{name}", ["CTX-POD-IP-REUSE"], "support", "POST",
                          f"/api/v1/namespaces/{ns}/pods", pod, resource="pods", name=name, namespace=ns)
                created += 1
            deadline = time.time() + 180
            ips = {}
            while time.time() < deadline:
                lst = self.admin.request("GET", f"/api/v1/namespaces/{ns}/pods?labelSelector=mt-ip%3D1").json()
                ips = {it["metadata"]["name"]: (it["metadata"]["uid"], (it.get("status") or {}).get("podIP"))
                       for it in lst["items"]}
                if all(ips.get(n, (None, None))[1] for n in names):
                    break
                time.sleep(2)
            for name in names:
                uid, ip = ips.get(name, (None, None))
                if ip and ip in seen and seen[ip] != uid and not found:
                    found = {"ip_p": self.p(ip), "old_uid_p": self.p(seen[ip]), "new_uid_p": self.p(uid),
                             "batch": b}
                if ip:
                    seen[ip] = uid
            self.admin.request("DELETE", f"/api/v1/namespaces/{ns}/pods?labelSelector=mt-ip%3D1",
                               body={"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0})
            deadline = time.time() + 180
            while time.time() < deadline:
                lst = self.admin.request("GET", f"/api/v1/namespaces/{ns}/pods?labelSelector=mt-ip%3D1").json()
                if not lst["items"]:
                    break
                time.sleep(2)
            print(f"IPREUSE batch={b} created_total={created} distinct_ips={len(seen)} reuse={bool(found)}")
            if found:
                break
        self.state["ip_reuse"] = {"created": created, "batches_run": b + 1, "distinct_ips": len(seen),
                                  "reuse_found": found, "bound": {"batches": self.args.batches,
                                                                  "batch_size": self.args.batch_size}}
        self.save_state()

    def latency(self):
        """Same request mix under each config; client-side wall time over one persistent connection."""
        label, n = self.args.label, self.args.count
        ns = f"mt-lat-{self.short}"
        self.admin.request("POST", "/api/v1/namespaces", body={"apiVersion": "v1", "kind": "Namespace",
                                                                "metadata": {"name": ns}})
        self.admin.request("POST", f"/api/v1/namespaces/{ns}/configmaps",
                           body={"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "lat-cm"},
                                 "data": {"k": "v"}})
        self.admin.request("POST", f"{RBAC}/namespaces/{ns}/roles",
                           body={"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                                 "metadata": {"name": "lat-role"}, "rules": []})
        ops = [("get-configmap", "GET", f"/api/v1/namespaces/{ns}/configmaps/lat-cm", None, None),
               ("list-pods", "GET", f"/api/v1/namespaces/{ns}/pods", None, None),
               ("create-configmap", "POST", f"/api/v1/namespaces/{ns}/configmaps", "cm", None),
               ("delete-configmap", "DELETE", f"/api/v1/namespaces/{ns}/configmaps/", "del", None),
               ("patch-role", "PATCH", f"{RBAC}/namespaces/{ns}/roles/lat-role", "patch", MERGE)]
        samples = {o[0]: [] for o in ops}
        codes = {o[0]: {} for o in ops}
        for it in range(self.args.warmup + n):
            for name, method, path, kind, ctype in ops:
                body, p = None, path
                if kind == "cm":
                    body = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"lat-{it}"}}
                elif kind == "del":
                    p = path + f"lat-{it}"
                elif kind == "patch":
                    body = {"metadata": {"labels": {"it": str(it)}}}
                r = self.admin.request(method, p, body=body, content_type=ctype or "application/json")
                if it >= self.args.warmup:
                    samples[name].append(r.latency_ms)
                    codes[name][str(r.status)] = codes[name].get(str(r.status), 0) + 1
        self.admin.request("DELETE", f"/api/v1/namespaces/{ns}")
        out = {"label": label, "iterations": n, "warmup": self.args.warmup, "utc_end": utc_now(),
               "method": "sequential requests over one persistent HTTPS connection from the kind host; "
                         "client-side wall time per request; admin x509 client credential",
               "classes": {}}
        for name, vals in samples.items():
            s = sorted(vals)
            q = lambda f: round(s[min(len(s) - 1, int(f * len(s)))], 3)
            out["classes"][name] = {"n": len(s), "p50_ms": q(0.5), "p90_ms": q(0.9), "p99_ms": q(0.99),
                                    "mean_ms": round(sum(s) / len(s), 3), "status_counts": codes[name]}
        write_json_atomic(os.path.join(self.args.private, f"latency-{label}.json"), out)
        print(f"LATENCY {label} " + " ".join(f"{k}:p50={v['p50_ms']}" for k, v in out["classes"].items()))

    def load(self):
        """Bounded Metadata-level GETs, each logged with its Audit-Id (rotation/loss experiments)."""
        ns, tag = self.ns, self.args.tag
        path = f"/api/v1/namespaces/{ns}/configmaps/mt-cm"
        for i in range(self.args.count):
            self.call(f"L-{tag}-{i}", ["AUD-LOSS-ROUTE"], "positive", "GET", path,
                      expect=self.meta_expect(200, ["ResponseComplete"]), resource="configmaps",
                      name="mt-cm", namespace=ns, extra={"load_tag": tag})
        print(f"LOAD {tag} requests={self.args.count}")

    def load_setup(self):
        ns = self.ns
        self.call("S-ns", ["AUD-LOSS-ROUTE"], "support", "POST", "/api/v1/namespaces",
                  {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}, resource="namespaces", name=ns)
        self.call("S-cm", ["AUD-LOSS-ROUTE"], "support", "POST", f"/api/v1/namespaces/{ns}/configmaps",
                  {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "mt-cm"}, "data": {"k": "v"}},
                  resource="configmaps", name="mt-cm", namespace=ns)
        self.state["ns"] = ns
        self.save_state()

    def metrics(self):
        r = self.admin.request("GET", "/metrics")
        keep = {}
        for line in r.body.decode("utf-8", "replace").splitlines():
            if line.startswith("apiserver_audit_"):
                name, _, value = line.rpartition(" ")
                keep[name] = float(value)
        path = os.path.join(self.args.private, "metrics.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"tag": self.args.tag, "utc": utc_now(), "status": r.status,
                                 "audit_metrics": keep}, sort_keys=True) + "\n")
        print(f"METRICS {self.args.tag} status={r.status} series={len(keep)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command")
    ap.add_argument("--kubeconfig-json", required=True)
    ap.add_argument("--private", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--image", default=None)
    ap.add_argument("--kubectl", default=None)
    ap.add_argument("--kubeconfig", default=None)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--tag", default="x")
    ap.add_argument("--label", default="x")
    ap.add_argument("--batches", type=int, default=8)
    ap.add_argument("--batch-size", type=int, default=40)
    ap.add_argument("--attempts", type=int, default=2)
    ap.add_argument("--wait", type=float, default=80.0)
    args = ap.parse_args()
    os.umask(0o077)
    p = Prober(args)
    fn = {"setup": p.setup, "matrix": p.matrix, "exec": p.exec_probes, "rbac-recreate": p.rbac_recreate,
          "burst": p.burst, "watch410": p.watch410, "ip-reuse": p.ip_reuse, "latency": p.latency, "truncation": p.truncation,
          "load": p.load, "load-setup": p.load_setup, "metrics": p.metrics}[args.command]
    try:
        fn()
    finally:
        p.m.close()
        p.admin.close()


if __name__ == "__main__":
    main()
