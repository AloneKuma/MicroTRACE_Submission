"""Hypotheses (build step 6c; tgs-contract.md section 5).

Hypotheses live in their own tables and never enter links, scores,
membership or metrics (P4):

- origin GO: every speculative path of an applied incident record (an
  ENABLING_ONLY witness between two findings), copied at ingest.
- origin ANALYST: generate() selects a template from the incident's observed
  finding types, writes one hypothesis per stage no member finding covers,
  with its gap report entry, and returns the report. A missing stage is a
  placeholder node `stage:<template>/<stage>` between the findings of the
  nearest covered stages before and after it.

Every ID hashes what it is about (origin, incident state, template version,
stage or path), so generating twice writes nothing new.
"""
import hashlib

from microtrace.v0 import envelope_pb2

from mtcore.tgs.extract import finding_node
from mtcore.tgs.templates import gap_report, load_rulebook, load_templates, min_overlap, select

GO, ANALYST = "GO", "ANALYST"


def hyp_id(*parts):
    return "hy_" + hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def copy_speculative_paths(store, seq, inc, record_sha256):
    """Called by ingest for each applied incident record."""
    for p in inc.speculative_paths:
        hid = hyp_id(GO, inc.incident_id, record_sha256, p.path_id)
        store.insert_hypothesis({"hyp_id": hid, "incident_id": inc.incident_id, "record_sha256": record_sha256,
                                 "origin": GO, "template_id": "", "template_sha256": "", "stage_id": "",
                                 "detail": {"path_id": p.path_id, "finding_ids": list(p.finding_ids),
                                            "witness_ids": list(p.witness_ids)}, "seq": seq})
        for k in range(len(p.finding_ids) - 1):
            label = p.witness_ids[k] if k < len(p.witness_ids) else ""
            store.insert_hypothesis_edge({"hyp_id": hid, "src": finding_node(p.finding_ids[k]).id,
                                          "dst": finding_node(p.finding_ids[k + 1]).id, "label": label,
                                          "origin": GO, "seq": seq})


def _placeholder(template, stage):
    return f"stage:{template.id}/{stage.id}"


def generate(store, incident_id, templates=None, threshold=None, rulebook=None):
    """Select a template for the incident's latest record, write ANALYST
    hypotheses for its uncovered stages, and return the report:
    {incident_id, version, record_sha256, template, template_sha256, scores,
     reason, gaps, hypotheses}. With no fitting template, gaps is empty and
    nothing is written."""
    templates = templates if templates is not None else load_templates()
    threshold = min_overlap() if threshold is None else threshold
    rulebook = rulebook or load_rulebook()
    latest = store.latest_incident_record(incident_id)
    if latest is None:
        return None
    env = envelope_pb2.Envelope()
    env.ParseFromString(bytes(latest["envelope"]))
    inc = env.incident
    types = store.finding_types(inc.finding_ids)
    template, scores, reason = select(templates, types.values(), threshold)
    report = {"incident_id": incident_id, "version": inc.version, "record_sha256": latest["record_sha256"],
              "template": template.id if template else None, "template_sha256": template.sha256 if template else None,
              "scores": scores, "reason": reason, "gaps": [], "hypotheses": []}
    if template is None:
        return report
    gaps = gap_report(store, template, inc, types.values(), rulebook)
    report["gaps"] = gaps
    covered = {}                                  # stage index -> member finding IDs supplying it
    for idx, s in enumerate(template.stages):
        fs = sorted(f for f, t in types.items() if t in s.finding_types)
        if fs:
            covered[idx] = fs
    missing = {g["stage"] for g in gaps}
    store.begin()
    try:
        seq = store.next_seq() - 1
        for idx, s in enumerate(template.stages):
            if s.id not in missing:
                continue
            hid = hyp_id(ANALYST, incident_id, latest["record_sha256"], template.id, template.sha256, s.id)
            gap = next(g for g in gaps if g["stage"] == s.id)
            store.insert_hypothesis({"hyp_id": hid, "incident_id": incident_id,
                                     "record_sha256": latest["record_sha256"], "origin": ANALYST,
                                     "template_id": template.id, "template_sha256": template.sha256,
                                     "stage_id": s.id, "detail": gap, "seq": seq})
            ph = _placeholder(template, s)
            before = [covered[i] for i in sorted(covered) if i < idx][-1:]
            after = [covered[i] for i in sorted(covered) if i > idx][:1]
            for f in (before[0] if before else []):
                store.insert_hypothesis_edge({"hyp_id": hid, "src": finding_node(f).id, "dst": ph,
                                              "label": "expected_next", "origin": ANALYST, "seq": seq})
            for f in (after[0] if after else []):
                store.insert_hypothesis_edge({"hyp_id": hid, "src": ph, "dst": finding_node(f).id,
                                              "label": "expected_next", "origin": ANALYST, "seq": seq})
            report["hypotheses"].append(hid)
        store.commit()
    except BaseException:
        store.rollback()
        raise
    return report
