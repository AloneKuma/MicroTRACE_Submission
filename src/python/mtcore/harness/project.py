"""The Exp. 5 equality projection of one run's GO output.

Input: JSON lines {"topic", "record", ...} as written by the orchestrator's
offline mode or by `mtcore.harness.dump` (which adds partition, offset and
timestamp_ms). Lines without "record" (heartbeats) are skipped here.

Repeated deliveries collapse by ID: a witness keeps its last record; an
incident's sealed record is its INCIDENT_SEALED record with the highest
(version, record order), its latest record the one with the highest
(version, record order) of any status.

Each field is a set of string items, so a difference is a set difference:

- finding_ids          member findings of the projected incidents
- confirmed_witness_ids  witnesses whose last record is CONFIRMED
- groups               "<incident>|anchor|<fid>", "<incident>|member|<fid>"
- links                "<incident>|<witness>" (link_witness_ids)
- aliases              "<incident>|<alias>"
- at_seal_excluded_sources, current_excluded_sources  "<incident>|<source>"
- tgs                  "<name>=<hash>" when TGS hashes are supplied

`sealed` projects every incident ID that has a sealed record (the at-seal
prediction; an incident merged away after seal keeps its own). `latest`
projects each ID's latest record, minus IDs another latest record lists as
an alias (absorbed; their last record is never retracted). Reported, never
scored: ranked and speculative path IDs, timestamps, and the count of
INCIDENT_OPEN records.
"""
import json

from google.protobuf import json_format

from microtrace.v0 import incident_pb2, witness_pb2

WITNESS_TOPIC = "witness.decisions.v0"
INCIDENT_TOPIC = "incidents.v0"
SEALED = incident_pb2.IncidentStatus.Value("INCIDENT_SEALED")
OPEN = incident_pb2.IncidentStatus.Value("INCIDENT_OPEN")
CONFIRMED = witness_pb2.WitnessStatus.Value("CONFIRMED")

FIELDS = ("finding_ids", "confirmed_witness_ids", "groups", "links", "aliases",
          "at_seal_excluded_sources", "current_excluded_sources", "tgs")
EXCLUSION_FIELDS = ("at_seal_excluded_sources", "current_excluded_sources")
_TYPES = {WITNESS_TOPIC: witness_pb2.Witness, INCIDENT_TOPIC: incident_pb2.Incident}


class Record:
    __slots__ = ("topic", "msg", "order", "timestamp_ms")

    def __init__(self, topic, msg, order, timestamp_ms=None):
        self.topic, self.msg, self.order, self.timestamp_ms = topic, msg, order, timestamp_ms


def parse_lines(lines):
    """Records of the topics projected here, in input order."""
    out = []
    for line in lines:
        if not line.strip():
            continue
        obj = json.loads(line)
        cls = _TYPES.get(obj.get("topic"))
        if cls is None or "record" not in obj:
            continue
        msg = json_format.ParseDict(obj["record"], cls(), ignore_unknown_fields=True)
        out.append(Record(obj["topic"], msg, len(out), obj.get("timestamp_ms")))
    return out


def load(path):
    with open(path, encoding="utf-8") as fh:
        return parse_lines(fh)


def from_messages(items):
    """Records from (topic, protobuf message) pairs (tests, in-process runs)."""
    return [Record(t, m, i) for i, (t, m) in enumerate(items)]


def _ts(t):
    return t.ToNanoseconds() if t.ByteSize() else None


class Projection:
    """sealed, latest: field -> frozenset of items; report: unscored detail."""

    def __init__(self, sealed, latest, report, sealed_records, latest_records):
        self.sealed, self.latest, self.report = sealed, latest, report
        self.sealed_records, self.latest_records = sealed_records, latest_records

    def to_json(self):
        return {"sealed": {k: sorted(v) for k, v in self.sealed.items()},
                "latest": {k: sorted(v) for k, v in self.latest.items()},
                "report": self.report}


def _fields(incidents, confirmed, tgs):
    f = {k: set() for k in FIELDS}
    f["confirmed_witness_ids"] = set(confirmed)
    for iid, inc in incidents.items():
        f["finding_ids"].update(inc.finding_ids)
        f["groups"].add(f"{iid}|anchor|{inc.anchor_finding_id}")
        f["groups"].update(f"{iid}|member|{m}" for m in inc.finding_ids)
        f["links"].update(f"{iid}|{w}" for w in inc.link_witness_ids)
        f["aliases"].update(f"{iid}|{a}" for a in inc.aliases)
        sc = inc.source_completeness
        f["at_seal_excluded_sources"].update(f"{iid}|{s}" for s in sc.at_seal_excluded_sources)
        f["current_excluded_sources"].update(f"{iid}|{s}" for s in sc.current_excluded_sources)
    f["tgs"] = {f"{k}={v}" for k, v in (tgs or {}).items()}
    return {k: frozenset(v) for k, v in f.items()}


def _report(sealed, records):
    paths = set()
    for iid, inc in sealed.items():
        paths.update(f"{iid}|ranked|{p.path_id}" for p in inc.ranked_paths)
        paths.update(f"{iid}|speculative|{p.path_id}" for p in inc.speculative_paths)
    times = {iid: {"event_start": _ts(inc.event_start), "event_end": _ts(inc.event_end),
                   "watermark_time": _ts(inc.watermark_time)} for iid, inc in sealed.items()}
    open_records = sum(1 for r in records if r.topic == INCIDENT_TOPIC and r.msg.status == OPEN)
    return {"paths": sorted(paths), "timestamps": times, "open_records": open_records}


def project(records, tgs=None):
    """Projection of a run's records (list of Record); tgs: {name: hash}."""
    witnesses, sealed, latest = {}, {}, {}
    for r in records:
        if r.topic == WITNESS_TOPIC:
            witnesses[r.msg.witness_id] = r.msg
        elif r.topic == INCIDENT_TOPIC:
            m, iid = r.msg, r.msg.incident_id
            if iid not in latest or m.version >= latest[iid].version:
                latest[iid] = m
            if m.status == SEALED and (iid not in sealed or m.version >= sealed[iid].version):
                sealed[iid] = m
    confirmed = [w for w, m in witnesses.items() if m.status == CONFIRMED]
    absorbed = {a for m in latest.values() for a in m.aliases}
    current = {iid: m for iid, m in latest.items() if iid not in absorbed}
    return Projection(_fields(sealed, confirmed, tgs), _fields(current, confirmed, tgs),
                      _report(sealed, records), sealed, current)


def project_file(path, tgs=None):
    return project(load(path), tgs)


def seal_times_ms(records):
    """Incident ID -> timestamp_ms of its first sealed record (dumps only)."""
    out = {}
    for r in records:
        if r.topic == INCIDENT_TOPIC and r.msg.status == SEALED and r.timestamp_ms is not None:
            out.setdefault(r.msg.incident_id, r.timestamp_ms)
    return out
