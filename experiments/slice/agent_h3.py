#!/usr/bin/env python3
"""Agent H, rule H3 bulk-secret-enumeration (rulebook.v0), UNFROZEN-SLICE parameters.

Input: agent.H.audit.v0 (keyed by principal) and source.completeness.v0.
Windows are epoch-aligned tumbling windows of W_H3_s in event time. A window
[ws, we) of one principal is evaluated only when
  (1) the input watermark >= we + lateness_s, and
  (2) AUDIT completeness coverage (contiguous SourceCompleteness intervals)
      has reached we, so every gap relevant to the window is already known.
If any AUDIT interval overlapping the window is not NO_KNOWN_GAP, the outcome
is ABSTAINED. Otherwise the score is the number of distinct namespace scopes of
successful secret list/watch requests plus distinct secret names read by a
successful get (ResponseComplete, 2xx), and the rule fires when score > N_H3.
Every evaluation is published to rule.evaluations.v0; a firing also publishes
a Finding to findings.v0.
"""

import argparse
import math
import os

import mtslice as M

RULE, NAME = "H3", "bulk-secret-enumeration"
DETECTOR = "H3-slice-0.1"


class AgentH3:
    def __init__(self, args):
        self.args = args
        self.p = M.load_params()
        self.W, self.N, self.L = self.p["W_H3_s"], self.p["N_H3"], self.p["lateness_s"]
        self.pre = "replay." if args.replay else ""
        self.inp = self.pre + "agent.H.audit.v0"
        self.bus = M.Bus(args.bootstrap, args.instance)
        self.run_ctx = M.Run(args.run_id, args.descriptor_sha256, self.p)
        self.loop = M.Loop(args.bootstrap, args.group, [self.inp, "source.completeness.v0"],
                           os.path.join(args.out, "agent.stop"), replay=args.replay)
        self.wm = M.Watermarks(self.loop.partitions())
        self.state = {}        # (key_hex, ws) -> {"key": bytes, "principal": EntityRef, "events": {eid: ne}}
        self.evaluated = set()
        self.audit_iv = []     # (start, end, status, [gap reasons])
        self.coverage = None
        self.contiguity_breaks = 0
        self.late = 0
        self.last_hb = None
        self.log = M.JsonLog(os.path.join(args.out, f"agent{'-replay' if args.replay else ''}.jsonl"))
        self.counts = {"FIRED": 0, "NOT_FIRED": 0, "ABSTAINED": 0}

    # ---------------------------------------------------------------- input
    def handle(self, topic, part, offset, env):
        if env.kind == M.RK("HEARTBEAT"):
            self.wm.update(topic, part, env.heartbeat.producer_instance, M.epoch(env.heartbeat.low_watermark))
            return
        if env.kind == M.RK("SOURCE_COMPLETENESS"):
            sc = env.source_completeness
            if sc.source != M.SRC("AUDIT"):
                return
            s, e = M.epoch(sc.interval_start), M.epoch(sc.interval_end)
            if self.coverage is not None and abs(s - self.coverage) > 1e-6:
                self.contiguity_breaks += 1
            self.audit_iv.append((s, e, M.stream_pb2.CompletenessStatus.Name(sc.status),
                                  [M.common_pb2.GapReason.Name(g.reason) for g in sc.gaps]))
            self.coverage = max(self.coverage or e, e)
            return
        ne = env.normalized_event
        a = ne.audit
        if not (a.object_ref.resource == "secrets" and a.object_ref.api_group == "" and not a.object_ref.subresource
                and a.stage == "ResponseComplete" and a.verb in ("get", "list", "watch")):
            return
        t = M.epoch(ne.time.event_time)
        ws = math.floor(t / self.W) * self.W
        key = M.key_for("agent.H.audit.v0", {
            "PRINCIPAL_KIND": M.common_pb2.EntityType.Name(ne.audit_derived.principal.type),
            "PRINCIPAL_ID": ne.audit_derived.principal.uid})
        kh = key.hex()
        if (kh, ws) in self.evaluated:
            self.late += 1
            return
        slot = self.state.setdefault((kh, ws), {"key": key, "principal": ne.audit_derived.principal, "events": {}})
        slot["events"][ne.event_id] = ne

    # ---------------------------------------------------------------- evaluation
    def tick(self):
        w = self.wm.topic(self.inp)
        if w is None:
            return
        for (kh, ws) in sorted(self.state):
            we = ws + self.W
            if w >= we + self.L and self.coverage is not None and self.coverage >= we:
                self.evaluate(kh, ws, we, self.state.pop((kh, ws)))
                self.evaluated.add((kh, ws))
        pending = [ws for (_, ws) in self.state]
        lw = min(pending + [math.floor((w - self.L) / self.W) * self.W])
        if lw != self.last_hb:
            self.bus.heartbeat(self.run_ctx, "agent-H", self.pre + "findings.v0", lw, "AUDIT")
            self.last_hb = lw

    def evaluate(self, kh, ws, we, slot):
        events = slot["events"]
        overl = [iv for iv in self.audit_iv if iv[0] < we and iv[1] > ws and iv[2] != "NO_KNOWN_GAP"]
        scopes, gets = set(), set()
        for ne in events.values():
            a = ne.audit
            if not 200 <= a.response_code < 300:
                continue
            if a.verb in ("list", "watch"):
                scopes.add(a.object_ref.namespace or "*")
            elif a.verb == "get" and a.object_ref.name:
                gets.add((a.object_ref.namespace, a.object_ref.name))
        score = len(scopes) + len(gets)
        ids = sorted(events)
        if overl:
            outcome = "ABSTAINED"
        elif score > self.N:
            outcome = "FIRED"
        else:
            outcome = "NOT_FIRED"
        self.counts[outcome] += 1
        ev_id = M.mtcodec.logical_id("evaluation", {"rule_id": RULE, "state_key_hex": kh,
                                                    "window_end": M.rfc3339(we), "detector_version": DETECTOR})
        rv = M.dataset_pb2.RuleEvaluation(evaluation_id=ev_id, rule_id=RULE, state_key_hex=kh,
                                          outcome=M.dataset_pb2.EvaluationOutcome.Value(outcome),
                                          detector_version=DETECTOR,
                                          parameter_set_version=self.p["parameter_set_version"])
        rv.window_start.CopyFrom(M.ts(ws))
        rv.window_end.CopyFrom(M.ts(we))
        rv.input_event_ids.extend(ids)
        for reasons in (iv[3] for iv in overl):
            for r in reasons:
                if M.common_pb2.GapReason.Value(r) not in rv.abstain_reasons:
                    rv.abstain_reasons.append(M.common_pb2.GapReason.Value(r))
        rv.features.update({"list_watch_scopes": str(len(scopes)), "distinct_secret_gets": str(len(gets)),
                            "score": str(score), "N_H3": str(self.N), "W_H3_s": str(self.W),
                            "input_events": str(len(ids))})
        fid = None
        if outcome == "FIRED":
            fid = self.publish_finding(slot, ids, scopes, gets, score, ws, we)
            rv.finding_id = fid
        self.bus.send(self.pre + "rule.evaluations.v0", M.key_for("rule.evaluations.v0", {"EVALUATION_ID": ev_id}),
                      M.envelope(self.run_ctx, "agent-H", "RULE_EVALUATION", "AUDIT", "rule_evaluation", rv,
                                 logical_id=ev_id))
        self.log.write({"evaluation_id": ev_id, "principal": slot["principal"].uid, "window_start": M.rfc3339(ws),
                        "window_end": M.rfc3339(we), "outcome": outcome, "score": score, "finding_id": fid,
                        "abstain": [r for iv in overl for r in iv[3]], "inputs": len(ids)})

    def publish_finding(self, slot, ids, scopes, gets, score, ws, we):
        events = slot["events"]
        fid = M.mtcodec.logical_id("finding", {"finding_type": RULE, "input_event_ids": ids,
                                               "detector_version": DETECTOR})
        times = sorted(M.epoch(ne.time.event_time) for ne in events.values())
        f = M.finding_pb2.Finding(finding_id=fid, finding_type=RULE, finding_name=NAME, agent_id="H",
                                  primary_tactic=M.finding_pb2.CREDENTIAL_ACCESS, detector_confidence=1.0,
                                  severity=M.finding_pb2.MEDIUM, detector_version=DETECTOR,
                                  parameter_set_version=self.p["parameter_set_version"])
        f.event_start.CopyFrom(M.ts(times[0]))
        f.event_end.CopyFrom(M.ts(times[-1]))
        f.publish_time.CopyFrom(M.ts(we + self.L))
        f.input_event_ids.extend(ids)
        f.entities.add().CopyFrom(slot["principal"])
        pods = {}
        for ne in events.values():
            for e in ne.entities:
                if e.type == M.common_pb2.POD:
                    pods[e.uid] = e
            for g in ne.completeness.gaps:
                if not any(x.reason == g.reason and x.scope == g.scope for x in f.completeness.gaps):
                    f.completeness.gaps.add().CopyFrom(g)
        for uid in sorted(pods):
            f.entities.add().CopyFrom(pods[uid])
        f.attributes.update({
            "principal": slot["principal"].uid, "list_requests": str(len(scopes)),
            "distinct_secret_gets": str(len(gets)), "namespaces": ",".join(sorted(scopes | {n for n, _ in gets})),
            "score": str(score), "window_start": M.rfc3339(ws), "window_end": M.rfc3339(we),
            "pod_relation": ("token-bound Pod: the Pod binding of the credential used, resolved in watched "
                             "history; not a proven caller Pod") if pods else "none resolved",
            "score_interpretation": self.p["h3_score"]})
        self.bus.send(self.pre + "findings.v0", M.key_for("findings.v0", {"FINDING_ID": fid}),
                      M.envelope(self.run_ctx, "agent-H", "FINDING", "AUDIT", "finding", f, logical_id=fid,
                                 completeness=f.completeness))
        return fid

    def idle(self):
        return True

    def run(self):
        self.loop.run(self.handle, tick=self.tick, idle=self.idle)
        self.tick()
        self.bus.flush()
        self.log.write({"final_counts": self.counts, "late_inputs": self.late, "coverage": self.coverage,
                        "contiguity_breaks": self.contiguity_breaks, "unevaluated_windows": len(self.state),
                        "input_wm": self.wm.topic(self.inp)})


def main():
    ap = argparse.ArgumentParser()
    for a in ("--bootstrap", "--instance", "--group", "--out", "--run-id", "--descriptor-sha256"):
        ap.add_argument(a, required=True)
    ap.add_argument("--replay", action="store_true")
    AgentH3(ap.parse_args()).run()


if __name__ == "__main__":
    main()
