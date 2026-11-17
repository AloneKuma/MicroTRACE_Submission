#!/usr/bin/env python3
"""Restreamer: norm.events.v0 -> agent.H.audit.v0 keyed (PRINCIPAL_KIND, PRINCIPAL_ID).

Only audit events with an authenticated principal are forwarded (H3's state
key). Heartbeats carry the input watermark, so downstream watermarks derive
from recorded heartbeats and replay identically.
"""

import argparse
import os

import mtslice as M

KIND_NAME = {M.common_pb2.SERVICE_ACCOUNT: "SERVICE_ACCOUNT", M.common_pb2.USER: "USER"}


class Restreamer:
    def __init__(self, args):
        self.args = args
        self.params = M.load_params()
        self.pre = "replay." if args.replay else ""
        self.inp = self.pre + "norm.events.v0"
        self.bus = M.Bus(args.bootstrap, args.instance)
        self.run_ctx = M.Run(args.run_id, args.descriptor_sha256, self.params)
        self.loop = M.Loop(args.bootstrap, args.group, [self.inp], os.path.join(args.out, "restreamer.stop"),
                           replay=args.replay)
        self.wm = M.Watermarks(self.loop.partitions())
        self.sent = 0
        self.last_hb = None

    def handle(self, topic, part, offset, env):
        if env.kind == M.RK("HEARTBEAT"):
            self.wm.update(topic, part, env.heartbeat.producer_instance, M.epoch(env.heartbeat.low_watermark))
            return
        ne = env.normalized_event
        if not ne.audit_derived.HasField("principal"):
            return
        p = ne.audit_derived.principal
        key = M.key_for("agent.H.audit.v0", {"PRINCIPAL_KIND": KIND_NAME.get(p.type, "OTHER"),
                                             "PRINCIPAL_ID": p.uid})
        self.bus.send(self.pre + "agent.H.audit.v0", key, env)
        self.sent += 1

    def tick(self):
        w = self.wm.topic(self.inp)
        if w is not None and w != self.last_hb:
            self.bus.heartbeat(self.run_ctx, "restreamer", self.pre + "agent.H.audit.v0", w, "AUDIT")
            self.last_hb = w

    def run(self):
        self.loop.run(self.handle, tick=self.tick)
        self.tick()
        self.bus.flush()
        M.JsonLog(os.path.join(self.args.out, f"restreamer{'-replay' if self.args.replay else ''}.jsonl")).write(
            {"forwarded": self.sent, "final_wm": self.wm.topic(self.inp)})


def main():
    ap = argparse.ArgumentParser()
    for a in ("--bootstrap", "--instance", "--group", "--out", "--run-id", "--descriptor-sha256"):
        ap.add_argument(a, required=True)
    ap.add_argument("--replay", action="store_true")
    Restreamer(ap.parse_args()).run()


if __name__ == "__main__":
    main()
