"""A small Kubernetes API client for the GRE (standard library only).

The GRE makes few, exact calls: TokenRequest, GET, an exact-version LIST,
a merge PATCH and a DELETE with preconditions. A thin client keeps every
request visible, and returns the API server's Audit-Id with each response,
which the attempt record keeps as ref_audit. Bearer-token authentication
only: the executor's own token, then a minted token per action.
"""
import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

import yaml


class ApiError(Exception):
    """A non-2xx response. status 0 means no response was received (the
    request may or may not have reached the API server)."""

    def __init__(self, status, reason, body=None, audit_id=""):
        super().__init__(f"{status} {reason}")
        self.status, self.reason, self.body, self.audit_id = status, reason, body or {}, audit_id

    @property
    def message(self):
        return self.body.get("message", self.reason) if isinstance(self.body, dict) else self.reason


class Kube:
    def __init__(self, server, ca_pem, token, timeout=10.0, user_agent="microtrace-gre"):
        self.server, self.token, self.timeout, self.user_agent = server.rstrip("/"), token, timeout, user_agent
        self._ca = ca_pem
        self._ctx = ssl.create_default_context(cadata=ca_pem.decode("ascii") if isinstance(ca_pem, bytes) else ca_pem)

    @classmethod
    def from_kubeconfig(cls, path, **kw):
        with open(path, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        ctx_name = cfg["current-context"]
        ctx = next(c["context"] for c in cfg["contexts"] if c["name"] == ctx_name)
        cluster = next(c["cluster"] for c in cfg["clusters"] if c["name"] == ctx["cluster"])
        user = next(u["user"] for u in cfg["users"] if u["name"] == ctx["user"])
        if "token" not in user:
            raise ValueError("the GRE client supports token credentials only")
        return cls(cluster["server"], base64.b64decode(cluster["certificate-authority-data"]), user["token"], **kw)

    def with_token(self, token, user_agent=None):
        """The same API server, another identity; user_agent tags its requests
        in the audit log (the executor puts the intent ID there)."""
        return Kube(self.server, self._ca, token, timeout=self.timeout, user_agent=user_agent or self.user_agent)

    def request(self, method, path, body=None, params=None, content_type="application/json"):
        """(object, audit_id) of a 2xx response; ApiError otherwise."""
        url = self.server + path + ("?" + urllib.parse.urlencode(params) if params else "")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", self.user_agent)
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as resp:
                raw = resp.read()
                return (json.loads(raw) if raw else {}), resp.headers.get("Audit-Id", "")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                obj = json.loads(raw) if raw else {}
            except ValueError:
                obj = {"message": raw[:500].decode("utf-8", "replace")}
            raise ApiError(e.code, e.reason, obj, e.headers.get("Audit-Id", "")) from None
        except (urllib.error.URLError, OSError) as e:
            raise ApiError(0, f"no response: {getattr(e, 'reason', e)}") from None

    def get(self, path, params=None):
        return self.request("GET", path, params=params)[0]

    def mint_token(self, namespace, service_account, audience, seconds):
        """A TokenRequest token for one ServiceAccount (the executor's only
        standing privilege)."""
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                "spec": {"audiences": [audience], "expirationSeconds": seconds}}
        obj, _ = self.request("POST", f"/api/v1/namespaces/{namespace}/serviceaccounts/{service_account}/token",
                              body)
        return obj["status"]["token"]
