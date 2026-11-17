"""Findings -> SAGE alerts (Suricata EVE JSON), one alert file ("team") per run.

Source and destination follow the mapping's endpoint selectors. Endpoints
become pseudo-IPs in 10.0.0.0/8, unique within the whole batch and seeded by
(run ID, endpoint), so no attacker or victim is shared between runs and the
same input always gives the same addresses. SAGE reads a file newest first
(it reverses the list before computing inter-alert gaps), so alerts are
written in descending (event_start, finding_id) order.
"""
import datetime
import hashlib
from collections import Counter

import mtcore  # noqa: F401  (puts src/python/gen on the path)
from microtrace.v0 import common_pb2

ET = common_pb2.EntityType


def _entities(finding, type_name):
    want = ET.Value(type_name)
    return [e for e in finding.entities if e.type == want]


def select(finding, selectors, source=None):
    """The endpoint key the first matching selector gives, else None."""
    for sel in selectors:
        if sel == "self":
            if source:
                return source
            continue
        kind, _, arg = sel.partition(":")
        if kind == "const":
            return "const:" + arg
        if kind == "attr":
            v = finding.attributes.get(arg, "")
            if v:
                return v
            continue
        name, _, idx = arg.partition("#")
        ents = _entities(finding, name)
        i = int(idx) if idx else 0
        if i < len(ents):
            v = ents[i].uid if ents[i].HasField("uid") and ents[i].uid else ents[i].name
            if v:
                return v
    return None


def timestamp(ts):
    """A protobuf Timestamp in SAGE's format, e.g. 2026-10-24T10:00:00.123456+0000."""
    dt = datetime.datetime.fromtimestamp(ts.seconds, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%06d+0000" % (ts.nanos // 1000)


class PseudoIPs:
    """(run ID, endpoint key) -> a 10.x.y.z address, collision-free in one batch."""

    def __init__(self):
        self.by_key, self.taken = {}, set()

    def assign(self, keys):
        for key in sorted(set(keys) - set(self.by_key)):
            h = int.from_bytes(hashlib.sha256("|".join(key).encode()).digest()[:4], "big")
            while True:
                ip = "10.%d.%d.%d" % ((h >> 16) & 255, (h >> 8) & 255, h & 255)
                if ip not in self.taken:
                    break
                h += 1
            self.by_key[key] = ip
            self.taken.add(ip)

    def __getitem__(self, key):
        return self.by_key[key]


def build(findings_by_run, mapping):
    """{run_id: [Finding]} -> ({run_id: [EVE alert dict], newest first}, PseudoIPs, Counter of skips).

    A finding whose type the mapping lacks (excluded rules) or whose endpoints
    no selector resolves is skipped and counted; SAGE never sees it."""
    skipped = Counter()
    plan = {}
    for run_id, findings in sorted(findings_by_run.items()):
        rows = []
        for f in findings:
            row = mapping.rows.get(f.finding_type)
            if row is None:
                skipped["unmapped_type:" + f.finding_type] += 1
                continue
            src = select(f, row.source)
            if src is None:
                skipped["no_source:" + f.finding_type] += 1
                continue
            dst = select(f, row.destination, source=src)
            if dst is None:
                skipped["no_destination:" + f.finding_type] += 1
                continue
            rows.append((f, src, dst, row))
        plan[run_id] = rows
    ips = PseudoIPs()
    ips.assign((run_id, k) for run_id, rows in plan.items() for _f, s, d, _r in rows for k in (s, d))
    teams = {}
    for run_id, rows in plan.items():
        alerts = []
        for f, src, dst, row in sorted(rows, key=lambda x: (x[0].event_start.ToNanoseconds(), x[0].finding_id),
                                       reverse=True):
            a = {"event_type": "alert", "timestamp": timestamp(f.event_start),
                 "src_ip": ips[(run_id, src)], "dest_ip": ips[(run_id, dst)],
                 "alert": {"signature": f.finding_type, "category": mapping.category},
                 "microtrace_finding_id": f.finding_id}
            port = f.attributes.get(row.port, "") if row.port else ""
            if port.isdigit():
                a["dest_port"] = int(port)
            alerts.append(a)
        if alerts:
            teams[run_id] = alerts
    return teams, ips, skipped
