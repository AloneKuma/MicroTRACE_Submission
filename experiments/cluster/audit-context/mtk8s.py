"""Shared helpers for the Gap 2 audit/context harness (stdlib only, Python >= 3.10).

Nothing here prints credentials. Client material from the kubeconfig is written
only to the run's mode-0700 private directory and removed at teardown.
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import time
import urllib.parse
from datetime import datetime, timezone

LEVELS = {"None": 0, "Metadata": 1, "Request": 2, "RequestResponse": 3}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value):
    """Parse an RFC 3339 timestamp (audit uses microseconds) to epoch seconds."""
    if not value:
        return None
    v = value.rstrip("Z")
    if "." in v:
        head, frac = v.split(".", 1)
        frac = (frac + "000000")[:6]
        v = head + "." + frac
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc).timestamp()


def write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, sort_keys=True)
    os.replace(tmp, path)


class JsonlWriter:
    def __init__(self, path):
        self.fh = open(path, "a", encoding="utf-8")

    def write(self, obj):
        self.fh.write(json.dumps(obj, sort_keys=True) + "\n")
        self.fh.flush()

    def close(self):
        self.fh.close()


def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ---------------------------------------------------------------- pseudonyms

class Pseudonymizer:
    """Run-local keyed pseudonyms. The key lives in the private directory and
    is deleted at teardown, so published pseudonyms cannot be reversed or
    linked across runs."""

    def __init__(self, key_path):
        with open(key_path, "rb") as fh:
            self.key = fh.read()
        if len(self.key) < 32:
            raise ValueError("pseudonym key too short")

    def __call__(self, value):
        if value is None or value == "":
            return None
        mac = hmac.new(self.key, str(value).encode("utf-8"), hashlib.sha256)
        return "p:" + mac.hexdigest()[:16]


def credential_id_format(value):
    """Classify a credential-id value without retaining it."""
    if not value:
        return None
    prefix, _, rest = value.partition("=")
    if not rest:
        return "no-prefix"
    shape = "uuid" if UUID_RE.match(rest) else ("hex" if re.fullmatch(r"[0-9a-f]+", rest) else "other")
    return f"{prefix}=<{shape}>"


# ------------------------------------------------------------------ kube API

class KubeConfig:
    """Loads `kubectl config view --raw -o json` output for the current context
    and materialises client material as private files."""

    def __init__(self, json_path, private_dir):
        with open(json_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        ctx_name = cfg["current-context"]
        ctx = next(c["context"] for c in cfg["contexts"] if c["name"] == ctx_name)
        cluster = next(c["cluster"] for c in cfg["clusters"] if c["name"] == ctx["cluster"])
        user = next(u["user"] for u in cfg["users"] if u["name"] == ctx["user"])
        self.server = cluster["server"]
        self.ca_path = os.path.join(private_dir, "ca.pem")
        self.cert_path = os.path.join(private_dir, "client.pem")
        self.key_path = os.path.join(private_dir, "client-key.pem")
        old = os.umask(0o077)
        try:
            for path, field in ((self.ca_path, cluster["certificate-authority-data"]),
                                (self.cert_path, user["client-certificate-data"]),
                                (self.key_path, user["client-key-data"])):
                if not os.path.exists(path):
                    with open(path, "wb") as fh:
                        fh.write(base64.b64decode(field))
        finally:
            os.umask(old)


class Response:
    __slots__ = ("status", "headers", "body", "audit_id", "start_utc", "end_utc", "latency_ms")

    def json(self):
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None


class Api:
    """Minimal HTTPS client. Credential modes: 'admin' (kubeconfig client
    certificate), 'bearer' (token held in memory only), 'anonymous'."""

    def __init__(self, kc, mode="admin", token=None, timeout=30):
        u = urllib.parse.urlparse(kc.server)
        self.host, self.port = u.hostname, u.port or 443
        self.ctx = ssl.create_default_context(cafile=kc.ca_path)
        if mode == "admin":
            self.ctx.load_cert_chain(kc.cert_path, kc.key_path)
        self.mode = mode
        self._token = token
        self.timeout = timeout
        self.conn = None

    def _connect(self):
        self.conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=self.timeout)

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def request(self, method, path, body=None, content_type="application/json", headers=None):
        hdrs = {"Accept": "application/json", "User-Agent": "microtrace-gap2-probe/v0"}
        if headers:
            hdrs.update(headers)
        if self._token is not None:
            hdrs["Authorization"] = "Bearer " + self._token
        data = None
        if body is not None:
            data = body if isinstance(body, (bytes, str)) else json.dumps(body)
            if isinstance(data, str):
                data = data.encode("utf-8")
            hdrs["Content-Type"] = content_type
        for attempt in (0, 1):
            if self.conn is None:
                self._connect()
            r = Response()
            r.start_utc = utc_now()
            t0 = time.perf_counter()
            try:
                self.conn.request(method, path, body=data, headers=hdrs)
                resp = self.conn.getresponse()
                r.body = resp.read()
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt:
                    raise
                continue
            r.latency_ms = (time.perf_counter() - t0) * 1000.0
            r.end_utc = utc_now()
            r.status = resp.status
            r.headers = {k.lower(): v for k, v in resp.getheaders()}
            r.audit_id = r.headers.get("audit-id")
            if r.headers.get("connection", "").lower() == "close":
                self.close()
            return r
        raise RuntimeError("unreachable")

    def stream(self, path, timeout):
        """Open a streaming GET on a fresh connection; yields (status, headers, line iterator)."""
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        hdrs = {"Accept": "application/json", "User-Agent": "microtrace-gap2-watch/v0"}
        if self._token is not None:
            hdrs["Authorization"] = "Bearer " + self._token
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        return conn, resp


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
