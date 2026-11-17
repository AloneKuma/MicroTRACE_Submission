#!/usr/bin/env python3
"""Orchestrator (slice): findings.v0 + source.completeness.v0 -> incidents.v0.

Single-finding incidents only: no witnesses, links or merges are claimed.
  - incident_id = logical_id("incident", anchor_finding_id); anchor = the finding.
  - v1 INCIDENT_OPEN when the findings watermark >= event_end + lateness_s.
  - v2 INCIDENT_SEALED at seal watermark S = event_end + T_seal_s.
Completeness decisions use only recorded knowledge times (a SourceCompleteness
record is known at its interval_end), never arrival order:
  - A dependency source (AUDIT always; CLUSTER_CONTEXT when the finding names
    a context-resolved Pod) is excluded at seal if its latest record known by
    S ends before S - max_idle_s, or if a non-NO_KNOWN_GAP record known by S
    overlaps [event_start, S].
  - Sealing waits until each dependency has a record known at or after S, or
    is idle-excluded as above.
  - A non-NO_KNOWN_GAP record known after S that overlaps [event_start, S]
    produces an INCIDENT_AMENDED version; sealed_prediction_version is kept.
"""

import argparse
import os

import mtslice as M

DECISION = "orchestrator-slice-0.1"
IS = M.incident_pb2.IncidentStatus.Value


class Orchestrator:
    def __init__(self, args):
        self.args = args
        self.p = M.load_params()
        self.pre = "replay." if args.replay else ""
        self.inp = self.pre + "findings.v0"
        self.bus = M.Bus(args.bootstrap, args.instance)
        self.run_ctx = M.Run(args.run_id, args.descriptor_sha256, self.p)
        self.loop = M.Loop(args.bootstrap, args.group, [self.inp, "source.completeness.v0"],
                           os.path.join(args.out, "orchestrator.stop"), replay=args.replay)
        self.wm = M.Watermarks(self.loop.partitions())
        self.sc = {}          # source name -> list of (start, end, status, reasons)
        self.inc = {}         # incident_id -> state
        self.log = M.JsonLog(os.path.join(args.out, f"orchestrator{'-replay' if args.replay else ''}.jsonl"))

    def handle(self, topic, part, offset, env):
        if env.kind == M.RK("HEARTBEAT"):
            self.wm.update(topic, part, env.heartbeat.producer_instance, M.epoch(env.heartbeat.low_watermark))
            return
        if env.kind == M.RK("SOURCE_COMPLETENESS"):
            s = env.source_completeness
            rec = (M.epoch(s.interval_start), M.epoch(s.interval_end),
                   M.stream_pb2.CompletenessStatus.Name(s.status),
                   tuple(M.common_pb2.GapReason.Name(g.reason) for g in s.gaps))
            lst = self.sc.setdefault(M.common_pb2.Source.Name(s.source), [])
            if rec not in lst:
                lst.append(rec)
            return
        if env.kind != M.RK("FINDING"):
            return
        f = env.finding
        iid = M.mtcodec.logical_id("incident", {"anchor_finding_id": f.finding_id})
        if iid in self.inc:
            return  # replayed duplicate: same logical ID (KAFKA-REPLAY-DEDUP)
        deps = ["AUDIT"] + (["CLUSTER_CONTEXT"] if any(e.type == M.common_pb2.POD for e in f.entities) else [])
        self.inc[iid] = {"finding": f, "version": 0, "status": None, "deps": deps, "seal_w": None,
                         "at_seal": [], "current": [], "amendments": [], "applied": set(),
                         "start": M.epoch(f.event_start), "end": M.epoch(f.event_end)}

    # ------------------------------------------------------------ decisions
    def known_by(self, src, t):
        return [r for r in self.sc.get(src, []) if r[1] <= t]

    def seal_ready(self, st, S):
        excluded = []
        for src in st["deps"]:
            # Decided only from records known by S, so replay (which may already
            # hold later records) reaches the same decision as the live run.
            frontier = max((r[1] for r in self.known_by(src, S)), default=float("-inf"))
            if frontier < S - self.p["max_idle_s"]:
                excluded.append(src)
                continue
            if any(r[1] >= S for r in self.sc.get(src, [])):
                continue
            return None  # not yet decidable: wait for a record known at or after S
        return excluded

    def overlapping(self, src, lo, hi):
        return [r for r in self.sc.get(src, []) if r[2] != "NO_KNOWN_GAP" and r[0] < hi and r[1] > lo]

    def tick(self):
        w = self.wm.topic(self.inp)
        if w is None:
            return
        for iid in sorted(self.inc):
            st = self.inc[iid]
            if st["version"] == 0 and w >= st["end"] + self.p["lateness_s"]:
                self.publish(iid, st, "INCIDENT_OPEN", w)
            if st["status"] == "INCIDENT_OPEN":
                S = st["end"] + self.p["T_seal_s"]
                if w >= S:
                    idle = self.seal_ready(st, S)
                    if idle is not None:
                        st["seal_w"] = S
                        at = set(idle)
                        for src in st["deps"]:
                            for r in self.overlapping(src, st["start"], S):
                                if r[1] <= S:
                                    at.add(src)
                                    st["applied"].add((src, r))
                        st["at_seal"] = sorted(at)
                        st["current"] = sorted(at)
                        self.publish(iid, st, "INCIDENT_SEALED", S)
            if st["status"] in ("INCIDENT_SEALED", "INCIDENT_AMENDED"):
                S = st["seal_w"]
                late = sorted((r[1], src, r) for src in st["deps"] for r in self.overlapping(src, st["start"], S)
                              if r[1] > S and (src, r) not in st["applied"])
                for knowledge, src, r in late:
                    st["applied"].add((src, r))
                    if src not in st["current"]:
                        st["current"] = sorted(set(st["current"]) | {src})
                    st["amendments"].append({"reason": f"{src} completeness {r[2]} ({','.join(r[3])}) for "
                                                       f"[{M.rfc3339(r[0])}, {M.rfc3339(r[1])}] known after seal",
                                             "at": knowledge})
                    self.publish(iid, st, "INCIDENT_AMENDED", S)
        self.bus.heartbeat(self.run_ctx, "orchestrator", self.pre + "incidents.v0", w, "AUDIT")

    def publish(self, iid, st, status, wtime):
        f = st["finding"]
        st["version"] += 1
        st["status"] = status
        inc = M.incident_pb2.Incident(incident_id=iid, anchor_finding_id=f.finding_id, version=st["version"],
                                      status=IS(status), decision_version=DECISION)
        inc.anchor_entity.CopyFrom(f.entities[0])
        inc.finding_ids.append(f.finding_id)
        inc.event_start.CopyFrom(f.event_start)
        inc.event_end.CopyFrom(f.event_end)
        inc.watermark_time.CopyFrom(M.ts(wtime))
        inc.source_completeness.at_seal_excluded_sources.extend(st["at_seal"])
        inc.source_completeness.current_excluded_sources.extend(st["current"])
        if st["seal_w"] is not None:
            inc.sealed_prediction_version = f"{iid}@v2"
        for i, a in enumerate(st["amendments"]):
            am = inc.amendments.add(version=3 + i, reason=a["reason"])
            am.amended_at.CopyFrom(M.ts(a["at"]))
        self.bus.send(self.pre + "incidents.v0", M.key_for("incidents.v0", {"INCIDENT_ID": iid}),
                      M.envelope(self.run_ctx, "orchestrator", "INCIDENT", "AUDIT", "incident", inc,
                                 logical_id=iid))
        self.log.write({"incident_id": iid, "version": st["version"], "status": status,
                        "watermark_time": M.rfc3339(wtime), "at_seal_excluded": st["at_seal"],
                        "current_excluded": st["current"], "amendments": len(st["amendments"]),
                        "finding_id": f.finding_id, "principal": f.attributes.get("principal")})

    def run(self):
        self.loop.run(self.handle, tick=self.tick)
        self.tick()
        self.bus.flush()


def main():
    ap = argparse.ArgumentParser()
    for a in ("--bootstrap", "--instance", "--group", "--out", "--run-id", "--descriptor-sha256"):
        ap.add_argument(a, required=True)
    ap.add_argument("--replay", action="store_true")
    Orchestrator(ap.parse_args()).run()


if __name__ == "__main__":
    main()
