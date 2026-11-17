"""Effective RBAC rights before and after a mutation (F2).

Rights follow Kubernetes RBAC semantics: RoleBindings grant a Role or
ClusterRole within one namespace, ClusterRoleBindings grant a ClusterRole
cluster-wide; rules allow (apiGroup, resource[/subresource], verb,
resourceName) or a non-resource URL; "*" matches anything; an aggregated
ClusterRole holds the union of the ClusterRoles its selectors match (so
controller reconciliation adds no right). Members of system:masters already
hold every right. A right is "added" when an after-set rule allows a request
no before-set rule allows, for that subject.
"""
from dataclasses import dataclass

CLUSTER = "*"


@dataclass(frozen=True)
class Subject:
    kind: str          # User | Group | ServiceAccount
    name: str
    namespace: str = ""

    def __str__(self):
        return f"{self.kind}:{self.namespace + '/' if self.namespace else ''}{self.name}"

    def groups(self):
        """Groups the API server always assigns to this subject."""
        if self.kind == "ServiceAccount":
            return {"system:serviceaccounts", f"system:serviceaccounts:{self.namespace}", "system:authenticated"}
        if self.kind == "User":
            return {"system:authenticated"}
        return set()


def subject_of(s, binding_ns):
    ns = s.namespace if s.kind == "ServiceAccount" else ""
    if s.kind == "ServiceAccount" and not ns:
        ns = binding_ns
    return Subject(s.kind, s.name, ns)


def _match(values, value):
    return "*" in values or value in values


def _resource_match(resources, resource):
    if "*" in resources or resource in resources:
        return True
    if "/" in resource:
        return f"*/{resource.split('/', 1)[1]}" in resources
    return False


def rule_allows(rule, req):
    """req: (kind, a, b, verb, name) with kind 'res' -> (group, resource) or 'url' -> (url, '')."""
    kind, a, b, verb, name = req
    if not _match(rule.verbs, verb):
        return False
    if kind == "url":
        return any(u == "*" or u == a or (u.endswith("*") and a.startswith(u[:-1]))
                   for u in rule.non_resource_urls)
    if rule.non_resource_urls and not rule.resources:
        return False
    if not _match(rule.api_groups, a) or not _resource_match(rule.resources, b):
        return False
    return not rule.resource_names or name in rule.resource_names


def probes(rule):
    """Requests that together stand for everything the rule allows. A "*"
    value is probed literally, so only a "*" in another rule covers it."""
    out = []
    for verb in rule.verbs or []:
        for url in rule.non_resource_urls:
            out.append(("url", url, "", verb, ""))
        for g in rule.api_groups:
            for r in rule.resources:
                for n in (rule.resource_names or ["*"]):
                    out.append(("res", g, r, verb, n))
    return out


def _covered(probe, rights_rules):
    for rule in rights_rules:
        if probe[0] == "res" and probe[4] == "*" and rule.resource_names:
            continue   # a named-only rule cannot cover "any name"
        if rule_allows(rule, probe):
            return True
    return False


def _labels_match(selector, labels):
    if not selector:
        return False
    for part in selector.split(","):
        k, _, v = part.partition("=")
        if labels.get(k.strip()) != v.strip():
            return False
    return True


class RbacState:
    """RBAC objects at one instant: {uid: ObjectObservation}."""

    def __init__(self, objects):
        self.roles, self.cluster_roles, self.bindings = {}, {}, []
        for o in objects.values():
            r = o.rbac
            if o.kind == "Role":
                self.roles[(o.namespace, o.name)] = list(r.rules)
            elif o.kind == "ClusterRole":
                self.cluster_roles[o.name] = (list(r.rules), dict(r.labels), list(r.aggregation_selectors))
            elif o.kind in ("RoleBinding", "ClusterRoleBinding"):
                scope = o.namespace if o.kind == "RoleBinding" else CLUSTER
                self.bindings.append((o.uid, scope, r.role_ref_kind, r.role_ref_name, list(r.subjects), o.namespace))

    def cluster_role_rules(self, name, seen=None):
        if name not in self.cluster_roles:
            return []
        seen = seen or set()
        if name in seen:
            return []
        seen.add(name)
        rules, _labels, selectors = self.cluster_roles[name]
        out = list(rules)
        for other, (_r, labels, _s) in sorted(self.cluster_roles.items()):
            if other != name and any(_labels_match(sel, labels) for sel in selectors):
                out += self.cluster_role_rules(other, seen)
        return out

    def subjects(self):
        return {subject_of(s, ns) for _uid, _scope, _k, _n, subs, ns in self.bindings for s in subs}

    def bound_subjects(self, pred):
        """Subjects of bindings matching pred(binding tuple)."""
        return {subject_of(s, b[5]) for b in self.bindings if pred(b) for s in b[4]}

    def rights(self, subj, members=None):
        """[(scope, rule)] the subject holds, or None when it is in
        system:masters (which already holds every right). members: declared
        external group membership {group: [user or SA names]}."""
        groups = subj.groups() | {g for g, names in (members or {}).items() if str(subj) in names or subj.name in names}
        if subj.kind == "Group":
            groups.add(subj.name)
        if "system:masters" in groups:
            return None
        out = []
        for _uid, scope, ref_kind, ref_name, subs, ns in self.bindings:
            if not any((s.kind == "Group" and s.name in groups) or subject_of(s, ns) == subj for s in subs):
                continue
            rules = self.roles.get((ns, ref_name), []) if ref_kind == "Role" else self.cluster_role_rules(ref_name)
            out += [(scope, r) for r in rules]
        return out


def added_rights(before, after, subj, members=None):
    """Human-readable rights subj gains from before to after ([] if none)."""
    b, a = before.rights(subj, members), after.rights(subj, members)
    if b is None or a is None:
        return []
    added = []
    for scope, rule in a:
        held = [r for s, r in b if s == CLUSTER or s == scope]
        for p in probes(rule):
            if not _covered(p, held):
                added.append(f"{scope}:{p[3]}:{p[1]}/{p[2]}{'#' + p[4] if p[4] not in ('', '*') else ''}")
    return sorted(set(added))


def unresolvable_groups(states, external):
    """Groups bound in any state whose membership the evaluator cannot know."""
    out = set()
    for st in states:
        for b in st.bindings:
            for s in b[4]:
                if s.kind == "Group" and s.name in external:
                    out.add(s.name)
    return out
