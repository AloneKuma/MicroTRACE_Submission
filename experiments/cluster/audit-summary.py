#!/usr/bin/env python3
"""Summarize one namespace's audit events without retaining raw identities."""

import json
import sys

name = sys.argv[1]
matches = []
malformed = 0
for line in sys.stdin:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        malformed += 1
        continue
    ref = event.get("objectRef") or {}
    if ref.get("resource") == "namespaces" and ref.get("name") == name:
        matches.append(event)

stages = sorted({event.get("stage", "") for event in matches})
verbs = sorted({event.get("verb", "") for event in matches})
completed = [event for event in matches if event.get("stage") == "ResponseComplete"]
successful = [
    event for event in completed
    if 200 <= (event.get("responseStatus") or {}).get("code", 0) < 400
]
summary = {
    "probe_resource": "namespaces",
    "probe_name": name,
    "matching_events": len(matches),
    "response_complete_events": len(completed),
    "successful_response_events": len(successful),
    "verbs": verbs,
    "stages": stages,
    "audit_id_present": all(bool(event.get("auditID")) for event in successful),
    "user_present": all(bool((event.get("user") or {}).get("username")) for event in successful),
    "object_ref_present": all(bool(event.get("objectRef")) for event in successful),
    "response_status_present": all(bool(event.get("responseStatus")) for event in successful),
    "malformed_lines": malformed,
}
print(json.dumps(summary, indent=2, sort_keys=True))
if not successful or not all(
    summary[key]
    for key in (
        "audit_id_present",
        "user_present",
        "object_ref_present",
        "response_status_present",
    )
):
    sys.exit(1)
