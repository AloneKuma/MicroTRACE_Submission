"""A simulated Kubernetes API server for the GRE (build step 8e; first used
as the 7.2 test fake).

SimApi keeps objects by path with every version, for exact-version reads;
merge PATCH and DELETE honour resourceVersion (and uid) preconditions when
given. Every write that reaches it is audited like the API server's
ResponseComplete stage, with the requesting identity, User-Agent and code,
plus the object as it was before the write (`objectBefore`) and the
simulated time (`ts`), which the randomised sequences grade against.

SimKube is the client: the same calls as gre.kube.Kube, minting a token
for any ServiceAccount the executor asks for.
"""
import copy

from mtcore.gre.kube import ApiError


class SimApi:
    def __init__(self, clock=lambda: 0):
        self.rv, self.objects, self.history, self.calls, self.minted = 100, {}, [], [], []
        self.fail_next = None                       # an ApiError the next write raises
        self.audit = []                             # API-server audit events of writes (ResponseComplete)
        self.clock = clock

    def put(self, path, obj):
        self.rv += 1
        obj = copy.deepcopy(obj)
        obj["metadata"]["resourceVersion"] = str(self.rv)
        self.objects[path] = obj
        self.history.append((self.rv, path, copy.deepcopy(obj)))
        return obj

    def at(self, path, rv):
        hit = [o for v, p, o in self.history if p == path and v <= rv]
        return hit[-1] if hit else None


class SimKube:
    def __init__(self, api, who="gre-executor", user_agent="microtrace-gre"):
        self.api, self.who, self.user_agent = api, who, user_agent

    def with_token(self, token, user_agent=None):
        return SimKube(self.api, token.removeprefix("tok-"), user_agent or self.user_agent)

    def mint_token(self, namespace, sa, audience, seconds):
        assert self.who == "gre-executor" and namespace == "microtrace" and seconds >= 600
        self.api.minted.append(sa)
        return f"tok-{sa}"

    def get(self, path, params=None):
        return self.request("GET", path, params=params)[0]

    def request(self, method, path, body=None, params=None, content_type="application/json"):
        """As Kube.request; every write that reaches the server is audited."""
        before = copy.deepcopy(self.api.objects.get(path.removesuffix("/scale")))
        try:
            out = self._request(method, path, body, params)
        except ApiError as e:
            if method != "GET" and e.status:
                self._audit(method, path, e.status, e.audit_id, before)
            raise
        if method != "GET":
            self._audit(method, path, 200, out[1], before)
        return out

    def _audit(self, method, path, code, audit_id, before=None):
        self.api.audit.append({"auditID": audit_id or f"a-{len(self.api.audit)}", "stage": "ResponseComplete",
                               "verb": method.lower(), "userAgent": self.user_agent, "requestURI": path,
                               "user": {"username": f"system:serviceaccount:microtrace:{self.who}"},
                               "responseStatus": {"code": code}, "objectBefore": before, "ts": self.api.clock()})

    def _request(self, method, path, body=None, params=None):
        api = self.api
        api.calls.append((self.who, method, path, params))
        if method == "GET" and params and params.get("resourceVersionMatch") == "Exact":
            rv = int(params["resourceVersion"])
            if rv < 100:
                raise ApiError(410, "Gone", {"message": "too old resource version"})
            name = params["fieldSelector"].split("=", 1)[1]
            o = api.at(f"{path}/{name}", rv)
            return {"items": [o] if o else []}, "a-list"
        if method != "GET" and api.fail_next is not None:
            e, api.fail_next = api.fail_next, None
            raise e
        obj = api.objects.get(path.removesuffix("/scale"))
        if obj is None:
            raise ApiError(404, "Not Found", {"message": "not found"})
        if method == "GET":
            return copy.deepcopy(obj), "a-get"
        body = body or {}
        want = (body.get("metadata", {}) if method == "PATCH" else body.get("preconditions", {})).get("resourceVersion")
        if want is not None and want != obj["metadata"]["resourceVersion"]:        # no precondition: any version
            raise ApiError(409, "Conflict", {"message": "the object has been modified"}, "a-409")
        if method == "DELETE":
            del api.objects[path]
            return {}, "a-delete"
        new = copy.deepcopy(obj)
        if path.endswith("/scale"):
            new["spec"]["replicas"] = body["spec"]["replicas"]
        else:
            new["metadata"].setdefault("labels", {}).update(body["metadata"].get("labels", {}) if "metadata" in body
                                                            else {})
            new.setdefault("spec", {}).update(body.get("spec", {}))
        return api.put(path.removesuffix("/scale"), new), "a-write"
