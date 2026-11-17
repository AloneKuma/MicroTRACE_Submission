#!/usr/bin/env python3
"""Live scenario driver for the audit-to-incident slice (host Python, stdlib only).

Subcommands (all need --kubeconfig-json, --private, --state):
  setup      namespaces mt-slice-{a,b,c}, secrets, four ServiceAccounts with
             token-bound Pods, and a Role/RoleBinding per namespace granting
             get/list/watch on secrets.
  positive   P (mt-enum, Pod-bound token): 3 list scopes + 10 distinct gets in
             one window -> expected FIRED. Q (mt-low, Pod-bound): 1 list + 2 gets
             -> expected NOT_FIRED. R (mt-ctrl, unbound token): list one
             namespace every 2 s for 24 s -> expected NOT_FIRED per window.
             Stops the context collector (--stop-context) 8 s after P.
  churn      bounded Pod create/delete bursts to expire the Pods watch cache
             while the context collector is down.
  gap        G (mt-gap, Pod-bound): 4 gets, then stops the audit collector
             (--stop-collector), then 3 lists + 6 gets and bounded filler GETs
             to overrun the 1 MiB / 1-backup rotation -> expected ABSTAINED.
  wait       poll a component JSONL log for a condition.

Tokens come from TokenRequest and stay in memory; nothing credential-bearing
is written. Timestamps of each phase are recorded in the state file.
"""

import argparse
import json
import math
import os
import secrets
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "cluster", "audit-context"))
from mtk8s import Api, KubeConfig, utc_now  # noqa: E402

NS = ["mt-slice-a", "mt-slice-b", "mt-slice-c"]
SAS = {"P": "mt-enum", "Q": "mt-low", "R": "mt-ctrl", "G": "mt-gap"}
RBAC = "/apis/rbac.authorization.k8s.io/v1"


class Driver:
    def __init__(self, a):
        self.a = a
        self.kc = KubeConfig(a.kubeconfig_json, a.private)
        self.admin = Api(self.kc)
        self.state = json.load(open(a.state)) if os.path.exists(a.state) else {}
        with open(os.path.join(HERE, "params.unfrozen-slice.yaml"), encoding="utf-8") as fh:
            self.W = int(next(l.split(":")[1].split("#")[0] for l in fh if l.startswith("W_H3_s")))

    def save(self):
        tmp = self.a.state + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.state, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.a.state)

    def ok(self, r, what, codes=(200, 201)):
        if r.status not in codes:
            raise RuntimeError(f"{what}: HTTP {r.status}")
        return r.json()

    def mark(self, name):
        self.state.setdefault("marks", {})[name] = utc_now()
        self.save()

    # ------------------------------------------------------------ setup
    def setup(self):
        for ns in NS:
            self.ok(self.admin.request("POST", "/api/v1/namespaces",
                                       body={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}), ns)
            for i in range(5):
                self.ok(self.admin.request("POST", f"/api/v1/namespaces/{ns}/secrets", body={
                    "apiVersion": "v1", "kind": "Secret", "metadata": {"name": f"s{i}"},
                    "stringData": {"k": "synthetic-" + secrets.token_hex(6)}}), "secret")
            self.ok(self.admin.request("POST", f"{RBAC}/namespaces/{ns}/roles", body={
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "mt-secret-reader"},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}]}), "role")
            self.ok(self.admin.request("POST", f"{RBAC}/namespaces/{ns}/rolebindings", body={
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "mt-secret-reader"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "mt-secret-reader"},
                "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": NS[0]} for sa in SAS.values()]}),
                "rolebinding")
        pods = {}
        for label, sa in SAS.items():
            obj = self.ok(self.admin.request("POST", f"/api/v1/namespaces/{NS[0]}/serviceaccounts", body={
                "apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}}), "sa")
            self.state.setdefault("sa_uid", {})[label] = obj["metadata"]["uid"]
            pod = self.ok(self.admin.request("POST", f"/api/v1/namespaces/{NS[0]}/pods", body={
                "apiVersion": "v1", "kind": "Pod", "metadata": {"name": f"{sa}-pod"},
                "spec": {"serviceAccountName": sa, "terminationGracePeriodSeconds": 0,
                         "containers": [{"name": "box", "image": self.a.image, "command": ["/bin/sleep", "7200"],
                                         "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                                                             "runAsUser": 65534, "capabilities": {"drop": ["ALL"]}},
                                         "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                                       "limits": {"memory": "32Mi"}}}]}}), "pod")
            pods[label] = {"name": f"{sa}-pod", "uid": pod["metadata"]["uid"]}
        deadline = time.time() + 240
        while time.time() < deadline:
            items = self.ok(self.admin.request("GET", f"/api/v1/namespaces/{NS[0]}/pods"), "list")["items"]
            if all(i["status"].get("phase") == "Running" for i in items if i["metadata"]["name"].endswith("-pod")):
                break
            time.sleep(2)
        else:
            raise RuntimeError("token-bound pods not Running")
        self.state["pods"] = pods
        self.mark("setup_done")
        print("SETUP done")

    # ------------------------------------------------------------ helpers
    def token(self, label, bound=True):
        spec = {"audiences": [], "expirationSeconds": 3600}
        if bound:
            p = self.state["pods"][label]
            spec["boundObjectRef"] = {"kind": "Pod", "apiVersion": "v1", "name": p["name"], "uid": p["uid"]}
        r = self.admin.request("POST", f"/api/v1/namespaces/{NS[0]}/serviceaccounts/{SAS[label]}/token",
                               body={"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": spec})
        return Api(self.kc, "bearer", token=self.ok(r, "tokenrequest")["status"]["token"])

    def align(self, offset=1.0):
        t = time.time()
        time.sleep(max(0.0, math.floor(t / self.W) * self.W + self.W + offset - t))

    def reads(self, api, lists, gets):
        codes = []
        for ns in lists:
            codes.append(api.request("GET", f"/api/v1/namespaces/{ns}/secrets").status)
        for ns, name in gets:
            codes.append(api.request("GET", f"/api/v1/namespaces/{ns}/secrets/{name}").status)
        return codes

    def docker_stop(self, name, t=60):
        subprocess.run(["/usr/bin/docker", "stop", "-t", str(t), name], check=True, capture_output=True)

    # ------------------------------------------------------------ scenarios
    def positive(self):
        p, q, r = self.token("P"), self.token("Q"), self.token("R", bound=False)
        self.align(1.0)
        self.mark("positive_start")
        cp = self.reads(p, NS, [(NS[0], f"s{i}") for i in range(4)] + [(NS[1], f"s{i}") for i in range(3)]
                        + [(NS[2], f"s{i}") for i in range(3)])
        cq = self.reads(q, [NS[0]], [(NS[0], "s0"), (NS[0], "s1")])
        self.mark("positive_end")
        rc = []

        def controller():
            for _ in range(12):
                rc.extend(self.reads(r, [NS[0]], []))
                time.sleep(2)
        th = threading.Thread(target=controller)
        th.start()
        time.sleep(8)
        self.docker_stop(self.a.stop_context)
        self.mark("context_stopped")
        th.join()
        self.state["codes"] = {"P": cp, "Q": cq, "R": rc}
        self.save()
        print(f"POSITIVE P={sorted(set(cp))} Q={sorted(set(cq))} R={sorted(set(rc))}")

    def churn(self):
        node = None
        attempt = self.state.get("churn_attempts", 0)
        for burst in range(2):
            names = [f"mt-churn-{attempt}-{burst}-{i:02d}" for i in range(self.a.pods)]
            for n in names:
                self.ok(self.admin.request("POST", f"/api/v1/namespaces/{NS[1]}/pods", body={
                    "apiVersion": "v1", "kind": "Pod", "metadata": {"name": n, "labels": {"mt-churn": "1"}},
                    "spec": {"terminationGracePeriodSeconds": 0, "automountServiceAccountToken": False,
                             "containers": [{"name": "c", "image": self.a.image, "command": ["/bin/sleep", "600"],
                                             "securityContext": {"allowPrivilegeEscalation": False,
                                                                 "runAsNonRoot": True, "runAsUser": 65534,
                                                                 "capabilities": {"drop": ["ALL"]}},
                                             "resources": {"requests": {"cpu": "1m", "memory": "4Mi"}}}]}}), "churn")
            deadline = time.time() + 120
            while time.time() < deadline:
                items = self.ok(self.admin.request("GET", f"/api/v1/namespaces/{NS[1]}/pods?labelSelector=mt-churn%3D1"),
                                "list")["items"]
                if items and all(i["status"].get("phase") == "Running" for i in items):
                    break
                time.sleep(2)
            self.admin.request("DELETE", f"/api/v1/namespaces/{NS[1]}/pods?labelSelector=mt-churn%3D1",
                               body={"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0})
            while self.ok(self.admin.request("GET", f"/api/v1/namespaces/{NS[1]}/pods?labelSelector=mt-churn%3D1"),
                          "list")["items"]:
                time.sleep(2)
            print(f"CHURN attempt={attempt} burst={burst} pods={len(names)}")
            if burst == 0:
                time.sleep(self.a.wait)
        del node
        self.state["churn_attempts"] = attempt + 1
        self.save()

    def gap(self):
        g = self.token("G")
        self.align(1.0)
        self.mark("gap_part1_start")
        c1 = self.reads(g, [], [(NS[0], f"s{i}") for i in range(4)])
        time.sleep(3)
        self.docker_stop(self.a.stop_collector, 30)
        self.mark("collector_stopped")
        c2 = self.reads(g, NS, [(NS[1], f"s{i}") for i in range(5)] + [(NS[2], "s0")])
        filler = 0
        for _ in range(self.a.filler):
            self.admin.request("GET", f"/api/v1/namespaces/{NS[0]}/configmaps/kube-root-ca.crt")
            filler += 1
        self.mark("filler_done")
        self.state["codes_gap"] = {"part1": c1, "part2": c2, "filler": filler}
        self.save()
        print(f"GAP part1={sorted(set(c1))} part2={sorted(set(c2))} filler={filler}")

    def wait(self):
        end = time.time() + self.a.timeout
        while time.time() < end:
            if os.path.exists(self.a.log):
                for line in open(self.a.log, encoding="utf-8"):
                    rec = json.loads(line)
                    if all(str(rec.get(k)) == v for k, v in (x.split("=", 1) for x in self.a.cond)):
                        print(f"WAIT ok {self.a.cond}")
                        return
            time.sleep(2)
        raise SystemExit(f"WAIT timeout {self.a.cond}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command")
    ap.add_argument("--kubeconfig-json", required=True)
    ap.add_argument("--private", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--image", default=None)
    ap.add_argument("--stop-context", default=None)
    ap.add_argument("--stop-collector", default=None)
    ap.add_argument("--pods", type=int, default=60)
    ap.add_argument("--wait", type=float, default=80)
    ap.add_argument("--filler", type=int, default=3500)
    ap.add_argument("--log", default=None)
    ap.add_argument("--cond", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=300)
    a = ap.parse_args()
    os.umask(0o077)
    d = Driver(a)
    {"setup": d.setup, "positive": d.positive, "churn": d.churn, "gap": d.gap, "wait": d.wait}[a.command]()


if __name__ == "__main__":
    main()
