"""SAGE's exported paths -> CONFIRMED witnesses and incidents (D3_v6, "Baselines").

Two findings are linked when they fall in consecutive episodes of one
source-destination sequence on an extracted attack-graph path: every finding
of episode i gets a witness to every finding of episode i+1, directed by the
episode order. Two variants come from one SAGE run:

- ``ag`` (the baseline as published): the paths of SAGE's attack graphs,
  which exist only for sequences of three or more episodes that reach a
  high-severity objective. Incident = one attack graph (victim, objective)
  within the run.
- ``seq`` (sensitivity row, generous to SAGE): every episode subsequence
  SAGE forms, without the length and objective filters of its graph step.
  Incident = one attacker-victim pair within the run.

Ranked paths: each path's expansions with one finding per episode (every step
is then one of the path's links), ranked by length, then first start time,
then finding IDs; the best K per incident are kept, as the GO keeps K per
incident. SAGE has no path score, so RankedPath.score stays unset.
"""
import hashlib
import itertools
import json
from collections import defaultdict

from google.protobuf import json_format

import mtcore  # noqa: F401  (puts src/python/gen on the path)
from microtrace.v0 import incident_pb2, witness_pb2

VARIANTS = ("ag", "seq")
WITNESSES, INCIDENTS = "witness.decisions.v0", "incidents.v0"
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")
SEALED = incident_pb2.IncidentStatus.Value("INCIDENT_SEALED")
MAX_EXPANSIONS = 256


def _id(prefix, *parts):
    return prefix + hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def team_of(key):
    """'t12-10.1.2.3' or 't12-10.1.2.3->10.4.5.6-0' -> 12."""
    return int(key.split("-", 1)[0][1:])


def groups(variant, paths, sequences):
    """[(team, group key, [episode lists])] for the variant; episodes are
    [{"start", "alert_ids"}] in path order."""
    out = defaultdict(list)
    if variant == "ag":
        for p in paths:
            out[(team_of(p["attacker"]), "%s|%s" % (p["victim"], p["objective"]))].append(p["episodes"])
    elif variant == "seq":
        for key, eps in sequences.items():
            pair = key.rsplit("-", 1)[0]                    # drop the subsequence number
            out[(team_of(key), pair)].append(eps)
    else:
        raise ValueError(f"unknown variant {variant!r}")
    return sorted((t, g, v) for (t, g), v in out.items())


def project(variant, run_of_team, paths, sequences, k):
    """{run_id: [(topic, record dict)]} of witnesses and incidents."""
    out = defaultdict(list)
    witnesses = defaultdict(dict)                          # run -> (src, dst) -> witness ID
    for team, gkey, attempts in groups(variant, paths, sequences):
        run = run_of_team[team]
        members, wids, cands = set(), set(), []
        for eps in attempts:
            eps = [e for e in eps if e["alert_ids"]]
            for e in eps:
                members.update(e["alert_ids"])
            for a, b in zip(eps, eps[1:]):
                for f in a["alert_ids"]:
                    for g in b["alert_ids"]:
                        if f != g:
                            wid = witnesses[run].setdefault((f, g), _id("sage-w-", variant, run, f, g))
                            wids.add(wid)
            if len(eps) < 2:
                continue
            for path in itertools.islice(itertools.product(*[sorted(e["alert_ids"]) for e in eps]), MAX_EXPANSIONS):
                cands.append((-len(path), eps[0]["start"], path))
        if not members:
            continue
        iid = _id("sage-i-", variant, run, gkey)
        inc = incident_pb2.Incident(incident_id=iid, version=1, finding_ids=sorted(members),
                                    link_witness_ids=sorted(wids), status=SEALED)
        seen = set()
        for _neg, _start, path in sorted(cands):
            if path in seen:
                continue
            seen.add(path)
            if len(seen) > k:
                break
            inc.ranked_paths.add(path_id=_id("sage-p-", iid, *path), finding_ids=list(path),
                                 witness_ids=[witnesses[run][(f, g)] for f, g in zip(path, path[1:])])
        out[run].append((INCIDENTS, json_format.MessageToDict(inc)))
    for run, pairs in witnesses.items():
        for (f, g), wid in sorted(pairs.items()):
            w = witness_pb2.Witness(witness_id=wid, source_finding_id=f, target_finding_id=g, status=CONFIRMED)
            out[run].append((WITNESSES, json_format.MessageToDict(w)))
    return out


def load_exports(prefix):
    """(team labels, paths, sequences) written by the patched SAGE for experiment prefix."""
    def read(suffix, default):
        try:
            with open(prefix + suffix, encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return default
    return read("-teams.json", []), read(".txt-paths.json", []), read("-sequences.json", {})
