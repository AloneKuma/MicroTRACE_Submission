"""The scripted approver (Exp. 5 part B): it stands in for the analyst and
issues signed requests from real TGS snapshots. It decides nothing; the test
runner says what to approve. Approval time is scripted and excluded from the
latency measurements.
"""
import time

from microtrace.v0 import envelope_pb2

from mtcore.gre import request as R


class ScriptedApprover:
    def __init__(self, key_id, private_key, tgs_store, cluster, clock=time.time):
        self.key_id, self.key, self.tgs, self.cluster, self.clock = key_id, private_key, tgs_store, cluster, clock

    def issue(self, incident_id, act, ns, uid, rv, params, ttl_s=300, sid=None, rid=None, nonce=None, evid=None):
        """A signed R_resp for the incident's latest applied record, bound to
        its latest snapshot (or to sid). evid defaults to the incident's
        findings and link witnesses."""
        latest = self.tgs.latest_incident_record(incident_id)
        if latest is None:
            raise LookupError(f"no record of incident {incident_id}")
        if sid is None:
            snaps = self.tgs.select("snapshots", equals={"incident_id": incident_id,
                                                         "record_sha256": latest["record_sha256"]},
                                    order_by=["-seq"], limit=1)
            if not snaps:
                raise LookupError(f"no snapshot of incident {incident_id}'s latest record")
            sid = snaps[0]["sid"]
        if evid is None:
            env = envelope_pb2.Envelope()
            env.ParseFromString(bytes(latest["envelope"]))
            evid = sorted(set(env.incident.finding_ids) | set(env.incident.link_witness_ids))
        nonce = nonce or R.new_nonce()
        req = {"version": R.VERSION, "rid": rid or f"rq-{nonce[:12]}", "gid": incident_id, "sid": sid,
               "v_c": {"incident_id": incident_id, "version": latest["version"],
                       "record_sha256": latest["record_sha256"]},
               "cluster": self.cluster, "ns": ns, "uid": uid, "rv": rv, "act": act, "params": dict(params),
               "exp": int(self.clock()) + ttl_s, "nonce": nonce, "evid": list(evid)}
        return R.sign(req, self.key_id, self.key)
