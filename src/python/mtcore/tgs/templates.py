"""Gap-analysis templates: loading, checking, selection and gap reports
(build step 6c; tgs-contract.md section 5).

A template (spec/graph/templates/*.yaml) is shared task knowledge: ordered
stages, each with the finding types that can supply it, their tactic and
whether it is required. Templates hold no instance values. The sources that
can supply a stage are derived from the rulebook's inputs, so the two never
drift apart.

Selection uses observed findings only: the score of a template is the share
of its required stages that a member finding covers. The best template wins
unless the best two tie or the best score is below `template_min_overlap`;
then no template fits and no gap report is made (gaps are reported only for
an explicit hypothesis, design-spec.md section 9).

    python -m mtcore.tgs.templates --check     # library check (exit 1 on a problem)
"""
import argparse
import hashlib
import os
import re
import sys
from dataclasses import dataclass

import yaml
from microtrace.v0 import common_pb2, envelope_pb2, stream_pb2

from mtcore import REPO
from mtcore.agents.events import ts_ns
from mtcore.agents.params import Params

TEMPLATE_DIR = os.path.join(REPO, "spec", "graph", "templates")
RULEBOOK = os.path.join(REPO, "spec", "rules", "rulebook.v0.yaml")
TEMPLATE_VERSION = "tgs-template.v0"
TEMPLATE_KEYS = {"template_version", "id", "status", "basis", "stages"}
STAGE_KEYS = {"id", "finding_types", "tactic", "required"}
# Rulebook input sources -> Source enum names (normalizer fields and context
# joins are derived, not sources a gap report can point to).
SOURCE_OF = {"ebpf": "EBPF", "gateway": "GATEWAY", "kyverno": "KYVERNO", "audit": "AUDIT",
             "context": "CLUSTER_CONTEXT", "db": "DB_AUDIT", "path": "PATH_FLOW"}
AVAILABLE, IDLE, LOSSY, UNKNOWN = "available", "idle", "lossy", "unknown"
IDLE_REASON = common_pb2.GapReason.Value("SOURCE_IDLE")
NO_KNOWN_GAP = stream_pb2.CompletenessStatus.Value("NO_KNOWN_GAP")
_INSTANCE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-|\d{4}-\d{2}-\d{2}[T ]\d{2}:|sha256:")


@dataclass(frozen=True)
class Stage:
    id: str
    finding_types: tuple
    tactic: object
    required: bool


@dataclass(frozen=True)
class Template:
    id: str
    status: str
    stages: tuple
    sha256: str

    @property
    def required(self):
        return [s for s in self.stages if s.required]


def load_rulebook(path=RULEBOOK):
    """{finding type: {"tactic": ..., "sources": [Source names]}}."""
    with open(path, encoding="utf-8") as fh:
        rb = yaml.safe_load(fh)
    out = {}
    for f in rb["findings"]:
        srcs = sorted({SOURCE_OF[i["source"]] for i in f.get("inputs") or [] if i.get("source") in SOURCE_OF})
        out[f["id"]] = {"tactic": f.get("primary_tactic"), "sources": srcs}
    return out


def load_templates(directory=TEMPLATE_DIR):
    out = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(directory, name), "rb") as fh:
            raw = fh.read().replace(b"\r\n", b"\n")   # same hash on a CRLF (Windows) checkout
        t = yaml.safe_load(raw)
        stages = tuple(Stage(s["id"], tuple(s["finding_types"]), s.get("tactic"), bool(s["required"]))
                       for s in t["stages"])
        out.append(Template(t["id"], t.get("status", ""), stages, hashlib.sha256(raw).hexdigest()))
    return out


def library_hash(templates):
    """Frozen before the Exp. 5 test set is unsealed."""
    return hashlib.sha256("".join(f"{t.id}:{t.sha256}\n" for t in sorted(templates, key=lambda t: t.id))
                          .encode("utf-8")).hexdigest()


def check_library(directory=TEMPLATE_DIR, rulebook=None):
    """Problems as strings; [] when the library is valid."""
    rb = rulebook or load_rulebook()
    problems, seen = [], set()
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            text = fh.read()
        t = yaml.safe_load(text)
        where = name
        if set(t) - TEMPLATE_KEYS:
            problems.append(f"{where}: unexpected keys {sorted(set(t) - TEMPLATE_KEYS)}")
        if t.get("template_version") != TEMPLATE_VERSION:
            problems.append(f"{where}: template_version must be {TEMPLATE_VERSION}")
        if t.get("id") in seen:
            problems.append(f"{where}: duplicate template id {t.get('id')}")
        seen.add(t.get("id"))
        stages = t.get("stages") or []
        if not any(s.get("required") for s in stages):
            problems.append(f"{where}: no required stage")
        ids = [s.get("id") for s in stages]
        if len(ids) != len(set(ids)):
            problems.append(f"{where}: duplicate stage ids")
        for s in stages:
            sw = f"{where} stage {s.get('id')}"
            if set(s) - STAGE_KEYS:
                problems.append(f"{sw}: unexpected keys {sorted(set(s) - STAGE_KEYS)} (instance fields are not allowed)")
            for ft in s.get("finding_types") or []:
                if ft not in rb:
                    problems.append(f"{sw}: finding type {ft} is not in the rulebook")
                elif rb[ft]["tactic"] != s.get("tactic"):
                    problems.append(f"{sw}: tactic {s.get('tactic')} but the rulebook maps {ft} to {rb[ft]['tactic']}")
            if not s.get("finding_types"):
                problems.append(f"{sw}: no finding types")
        values = "\n".join(line.split("#", 1)[0] for line in text.splitlines())   # comments excluded
        if _INSTANCE.search(values):
            problems.append(f"{where}: looks like it holds an instance value (UID, time or digest)")
    return problems


# --- selection and gap reports ------------------------------------------------------------
def min_overlap(params=None):
    p = params or Params.load()
    return float((p.data.get("tgs") or {}).get("template_min_overlap", 1.0))


def select(templates, finding_types, threshold):
    """(template or None, {template id: score}, reason) from observed finding
    types only."""
    have = set(finding_types)
    scores = {t.id: sum(1 for s in t.required if have & set(s.finding_types)) / len(t.required)
              for t in templates if t.required}
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked or ranked[0][1] < threshold or ranked[0][1] == 0:
        return None, scores, "no template fits: best overlap below the threshold"
    if len(ranked) > 1 and ranked[1][1] == ranked[0][1]:
        return None, scores, f"no template fits: {ranked[0][0]} and {ranked[1][0]} tie"
    return next(t for t in templates if t.id == ranked[0][0]), scores, "best overlap"


def source_status(store, source, lo, hi):
    """(status, [scopes]) of one source over [lo, hi] from source.completeness:
    idle if any overlapping record reports SOURCE_IDLE, lossy if any reports
    another gap or is not NO_KNOWN_GAP, available if all are clean, unknown
    when there is no record (never assumed healthy)."""
    rows = store.completeness_for(source, lo, hi)
    if not rows:
        return UNKNOWN, []
    idle = lossy = False
    for r in rows:
        env = envelope_pb2.Envelope()
        env.ParseFromString(bytes(r["envelope"]))
        sc = env.source_completeness
        if any(g.reason == IDLE_REASON for g in sc.gaps):
            idle = True
        elif sc.gaps or sc.status != NO_KNOWN_GAP:
            lossy = True
    scopes = sorted({r["scope"] for r in rows})
    return (IDLE if idle else LOSSY if lossy else AVAILABLE), scopes


def gap_report(store, template, incident, finding_types, rulebook):
    """One entry per stage no member finding covers: its candidate finding
    types and each candidate source's status over the incident span."""
    lo = ts_ns(incident.event_start) if incident.HasField("event_start") else None
    hi = ts_ns(incident.event_end) if incident.HasField("event_end") else lo
    have = set(finding_types)
    gaps = []
    for s in template.stages:
        if have & set(s.finding_types):
            continue
        sources = sorted({src for ft in s.finding_types for src in rulebook.get(ft, {}).get("sources", [])})
        status = {}
        for src in sources:
            st, scopes = source_status(store, src, lo, hi)
            status[src] = {"status": st, "scopes": scopes}
        gaps.append({"stage": s.id, "required": s.required, "tactic": s.tactic,
                     "finding_types": list(s.finding_types), "sources": status})
    return gaps


def main(argv=None):
    ap = argparse.ArgumentParser(description="TGS gap-analysis templates.")
    ap.add_argument("--check", action="store_true", help="check the template library")
    a = ap.parse_args(argv)
    if a.check:
        problems = check_library()
        print("\n".join(problems) or f"templates ok ({len(load_templates())}); library {library_hash(load_templates())}")
        return 1 if problems else 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
