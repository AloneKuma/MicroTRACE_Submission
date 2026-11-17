"""Build spec/examples/trace-v0.json, the synthetic Gap 1 trace.

Every UID, digest, and time below is an invented identifier for a schema
example, not observed data. No parameter value is chosen: applied limits
name their symbol with parameter_set_version UNFROZEN-EXAMPLE and no value.
Logical IDs and keys are filled with mtcodec; check_gap1.py re-derives them
from the record fields.

Usage (from the repository root): python spec/tools/build_example_trace.py
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mtcodec as C  # noqa: E402

OUT = os.path.join(os.path.dirname(HERE), "examples", "trace-v0.json")
UNFROZEN = "UNFROZEN-EXAMPLE"
NODE, BOOT = "node-1", "5f2a9c1e-0000-4000-8000-00000000b001"
POD = "3c9e1d2a-7a61-4f0e-9d11-00000000a007"
POD_NAME = "checkout-7d9f-abcde"
LROOT = {"nodeId": NODE, "bootId": BOOT, "tgid": 4100, "startTimeNs": "912345678901"}
PROC = {"nodeId": NODE, "bootId": BOOT, "tgid": 4217, "startTimeNs": "912399000000"}
SENSOR = {"nodeId": NODE, "bootId": BOOT, "tgid": 812, "startTimeNs": "1200000000"}
LINEAGE = C.logical_id("lineage", {"node_id": NODE, "boot_id": BOOT, "tgid": "4100",
                                   "start_time_ns": "912345678901"})
CONT = {"containerId": "containerd://7f3b0c", "cgroupId": "91234", "containerName": "checkout"}
VOL, VDIR = "kube-api-access-x7k2p", "..2026_09_26_09_40_00.3141592653"
PV = {"ownerPodUid": POD, "volumeName": VOL, "versionDir": VDIR, "fileName": "token"}
DIGEST = "sha256:0d5e7c1a9b3f4e2d8c6a0b1e2f3d4c5b6a7980e1d2c3b4a5968778695a4b3c2d"
ADM = "a1d7c3e9-2b4f-4c6d-8e0a-000000000091"
AID = "9c1f0e2d-3b4a-4c5d-9e6f-000000000042"
JTI = "4f0c2a7e-5d6b-4e8f-9a1b-000000000007"
PRODUCER = {"RAW_EBPF": "node-sensor", "RAW_AUDIT": "audit-collector", "RAW_GATEWAY": "gateway-observer",
            "RAW_KYVERNO": "kyverno-exporter", "CONTEXT_OBSERVATION": "context-collector",
            "NORMALIZED_EVENT": "normalizer", "FINDING": "agents", "WITNESS": "orchestrator",
            "INCIDENT": "orchestrator", "HEARTBEAT": "node-sensor", "SOURCE_COMPLETENESS": "audit-collector",
            "GROUND_TRUTH_ACTION": "scenario-harness", "RULE_EVALUATION": "agents"}
RUN = {"runId": "example-run-0", "split": "SYNTHETIC_EXAMPLE", "captureProfile": "research-superset-v0",
       "parameterSetVersion": UNFROZEN, "descriptorSetSha256": "NOT-COMPUTED-FOR-EXAMPLE"}
POD_E = {"type": "POD", "uid": POD, "namespace": "shop", "name": POD_NAME, "strengthClass": "STRENGTH_HIGH"}
LIN_E = {"type": "PROCESS_LINEAGE", "uid": LINEAGE, "strengthClass": "STRENGTH_HIGH"}
IMG_E = {"type": "IMAGE", "uid": DIGEST, "strengthClass": "STRENGTH_MEDIUM"}

records = []


def ev(source, native, stage, payload_version):
    return C.logical_id("event", {"source": source, "source_native_id": native,
                                  "source_stage": stage, "payload_version": payload_version})


def envelope(kind, source, logical_id, payload_name, payload):
    env = {"schemaMajor": 0, "schemaMinor": 1, "producerId": PRODUCER[kind],
           "producerVersion": "0.0.0-design", "kind": kind, "source": source, "run": RUN,
           payload_name: payload}
    if logical_id:
        env["logicalId"] = logical_id
    return env


def add(label, topic, env, **extra):
    rec = {"label": label, "topic": topic, "key_hex": None, "envelope": env}
    rec.update(extra)
    records.append(rec)


def raw_ebpf(label, seq, mono, family, body, **ids):
    rec = {"nodeId": NODE, "bootId": BOOT, "nodeSeq": str(seq), "monotonicNs": str(mono),
           "captureManifestVersion": "capture-manifest.v0", "eventFamily": family,
           "result": "SUCCESS", **ids, **body}
    rid = ev("EBPF", f"{NODE}/{BOOT}/{seq}", family, "raw.v0")
    add(label, "raw.ebpf.v0", envelope("RAW_EBPF", "EBPF", rid, "rawEbpf", rec))
    return rec


# ---------------------------------------------------------------- raw sources
raw_ebpf("R1 token.file_index census entry", 70, 912398000000, "token.file_index",
         {"projectedIndex": {"version": PV, "dev": "2049", "ino": "1573005", "current": True}},
         process=SENSOR, readerClass="READER_HOST_PROCESS")
r2 = raw_ebpf("R2 token read (file.read)", 71, 912400000000, "file.read",
              {"returnValue": "1043",
               "fileAccess": {"op": "FILE_READ", "fd": 7, "bytes": "1043", "file": {
                   "dev": "2049", "ino": "1573005", "mntNsInum": "4026532801", "mntId": 1422,
                   "resolvedPath": f"/var/run/secrets/kubernetes.io/serviceaccount/{VDIR}/token",
                   "pathAsOpened": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                   "projected": PV}}},
              process=PROC, parent=LROOT, lineageRoot=LROOT, container=CONT,
              readerClass="READER_POD_PROCESS")
r3 = raw_ebpf("R3 executable-mode change on a mounted volume (file.mutation)", 72, 912410000000,
              "file.mutation",
              {"returnValue": "0",
               "fileMutation": {"op": "CHMOD", "newMode": 493, "executableAfter": True, "file": {
                   "dev": "2050", "ino": "88113", "mntNsInum": "4026532801", "mntId": 1430,
                   "resolvedPath": "/work/cache/helper", "pathAsOpened": "/work/cache/helper"}}},
              process=PROC, parent=LROOT, lineageRoot=LROOT, container=CONT,
              readerClass="READER_POD_PROCESS")

r4 = {"admissionRequestUid": ADM, "resourceUid": POD, "resourceKind": "Pod", "namespace": "shop",
      "resourceName": POD_NAME, "policy": "require-signed-images", "rule": "verify-signature",
      "verdict": "FAIL", "enforcementAuditMode": True, "imageDigests": [DIGEST], "dryRun": False,
      "admissionTime": "2026-09-26T09:39:58Z", "reportUid": "b2c4e6f8-0000-4000-8000-0000000000a1",
      "reportObservedTime": "2026-09-26T09:40:03Z", "kyvernoVersion": "UNPINNED"}
add("R4 Kyverno audit-mode FAIL", "raw.kyverno.v0",
    envelope("RAW_KYVERNO", "KYVERNO", ev("KYVERNO", f"{ADM}/require-signed-images/verify-signature",
                                          "decision", "raw.v0"), "rawKyverno", r4))

r5 = {"auditId": AID, "stage": "ResponseComplete", "level": "Metadata",
      "requestUri": "/api/v1/namespaces/shop/serviceaccounts/checkout-sa/token", "verb": "create",
      "user": {"username": f"system:node:{NODE}", "groups": ["system:nodes", "system:authenticated"]},
      "sourceIps": ["10.0.0.11"], "userAgent": "kubelet/UNPINNED",
      "objectRef": {"resource": "serviceaccounts", "subresource": "token", "namespace": "shop",
                    "name": "checkout-sa", "apiVersion": "v1"},
      "responseCode": 201,
      "annotations": {"authentication.kubernetes.io/issued-credential-id": f"JTI={JTI}"},
      "requestReceivedTimestamp": "2026-09-26T09:39:59.100Z",
      "stageTimestamp": "2026-09-26T09:39:59.130Z", "policyVersion": "audit-policy.v0",
      "position": {"route": "LOG_FILE_TAIL", "fileDev": "2051", "fileIno": "5521", "fileOffset": "88213"}}
add("R5 TokenRequest audit event (issued-credential-id annotation)", "raw.audit.v0",
    envelope("RAW_AUDIT", "AUDIT", ev("AUDIT", AID, "ResponseComplete", "raw.v0"), "rawAudit", r5))

r6 = {"requestId": "req-17", "route": "/checkout", "method": "POST", "authority": "shop.example",
      "path": "/checkout", "peerIp": "198.51.100.23", "responseStatus": 400, "responseBodyBytes": "512",
      "matches": [{"patternId": "sqli-union", "patternSetVersion": f"P_A:{UNFROZEN}",
                   "location": "REQUEST_BODY", "chunkIndex": 0}],
      "bodyTruncated": False, "observerLoss": False, "gatewayBuild": "UNPINNED"}
add("R6 gateway observation", "raw.gateway.v0",
    envelope("RAW_GATEWAY", "GATEWAY", ev("GATEWAY", "req-17", "request", "raw.v0"), "rawGateway", r6))

c1 = {"apiGroup": "", "kind": "Pod", "namespace": "shop", "name": POD_NAME, "uid": POD,
      "resourceVersion": "48210", "changeType": "MODIFIED", "observedTime": "2026-09-26T09:40:02Z",
      "watchStreamId": "pods-watch-1", "watchStreamSeq": "311",
      "pod": {"nodeName": NODE, "podIps": ["10.244.1.17"], "serviceAccount": "checkout-sa",
              "containers": [{"name": "checkout", "containerId": "containerd://7f3b0c", "restartCount": 0,
                              "startedAt": "2026-09-26T09:40:01Z", "imageId": DIGEST}]}}
C1 = ev("CLUSTER_CONTEXT", f"{POD}/48210/MODIFIED", "watch", "raw.v0")
add("C1 Pod watch observation (context)", "context.cluster.v0",
    envelope("CONTEXT_OBSERVATION", "CLUSTER_CONTEXT", C1, "contextObservation", c1))

# ---------------------------------------------------------------- normalized
T_EBPF = {"eventTimeBasis": "EBPF_MONOTONIC_CORRECTED", "clockModelVersion": f"clock-model:{UNFROZEN}",
          "eventTimeUncertain": True}


def norm(label, topic, source, native, stage, rec_name, rec, times, entities, derived=None, action=None):
    eid = ev(source, native, stage, "norm.v0")
    n = {"eventId": eid, "source": source, "sourceNativeId": native, "sourceStage": stage, "time": times,
         "entities": entities, rec_name: rec, "normalizerVersion": "norm-0",
         "contextVersion": f"ctx-hist:{UNFROZEN}"}
    if action:
        n["actionId"] = action
    if derived:
        n.update(derived)
    if source == "EBPF":
        n["captureManifestVersion"] = "capture-manifest.v0"
    add(label, topic, envelope("NORMALIZED_EVENT", source, eid, "normalizedEvent", n))
    return eid


N2 = norm("N2 normalized token read", "agent.D.read.v0", "EBPF", f"{NODE}/{BOOT}/71", "file.read", "ebpf", r2,
          dict(T_EBPF, eventTime="2026-09-26T10:00:01Z", ingestTime="2026-09-26T10:00:01.400Z"),
          [POD_E, LIN_E],
          {"ebpfDerived": {"podUid": POD, "containerName": "checkout", "lineageId": LINEAGE, "tokenFile": PV}},
          action=f"{NODE}/{BOOT}/71")
N3 = norm("N3 normalized executable-mode change", "agent.E.v0", "EBPF", f"{NODE}/{BOOT}/72", "file.mutation",
          "ebpf", r3, dict(T_EBPF, eventTime="2026-09-26T10:00:11Z", ingestTime="2026-09-26T10:00:11.300Z"),
          [POD_E, LIN_E, IMG_E],
          {"ebpfDerived": {"podUid": POD, "containerName": "checkout", "lineageId": LINEAGE}},
          action=f"{NODE}/{BOOT}/72")
N4 = norm("N4 normalized admission decision", "agent.E.v0", "KYVERNO",
          f"{ADM}/require-signed-images/verify-signature", "decision", "kyverno", r4,
          {"sourceTime": "2026-09-26T09:39:58Z", "eventTime": "2026-09-26T09:39:58Z",
           "ingestTime": "2026-09-26T09:40:03.200Z", "eventTimeBasis": "KYVERNO_ADMISSION"},
          [POD_E, IMG_E],
          {"admissionDerived": {"podUid": POD, "containerName": "checkout"},
           "completeness": {"gaps": [{"reason": "CONDITIONAL_JOIN_UNVALIDATED", "scope": "join=admission-pod-uid",
                                      "detail": "KYV-POD-UID-DRYRUN and KYV-ADMISSION-TIME not run"}]}},
          action=ADM)
N5 = norm("N5 normalized TokenRequest (issuance side of the JTI join)", "agent.D.use.v0", "AUDIT", AID,
          "ResponseComplete", "audit", r5,
          {"sourceTime": "2026-09-26T09:39:59.130Z", "eventTime": "2026-09-26T09:39:59.130Z",
           "ingestTime": "2026-09-26T09:39:59.600Z", "eventTimeBasis": "AUDIT_STAGE"},
          [{"type": "AUDIT_ACTION", "uid": AID, "strengthClass": "STRENGTH_HIGH"},
           {"type": "SERVICE_ACCOUNT", "namespace": "shop", "name": "checkout-sa", "strengthClass": "STRENGTH_CONTEXT"}],
          {"auditDerived": {"issuedCredentialId": JTI, "observedSource": "10.0.0.11",
                            "principal": {"type": "NODE", "name": NODE, "strengthClass": "STRENGTH_CONTEXT"}}},
          action=AID)
norm("N6 normalized gateway observation", "agent.A.v0", "GATEWAY", "req-17", "request", "gateway", r6,
     {"sourceTime": "2026-09-26T09:59:40Z", "eventTime": "2026-09-26T09:59:40Z",
      "ingestTime": "2026-09-26T09:59:40.200Z", "eventTimeBasis": "GATEWAY_OBSERVATION"},
     [{"type": "HTTP_REQUEST", "uid": "req-17", "strengthClass": "STRENGTH_HIGH"}], action="req-17")


# ---------------------------------------------------------------- findings
def finding(label, ftype, name, agent, tactic, inputs, start, entities, artifacts, attrs, action,
            completeness=None):
    fid = C.logical_id("finding", {"finding_type": ftype, "input_event_ids": inputs,
                                   "detector_version": f"{agent}-0"})
    f = {"findingId": fid, "findingType": ftype, "findingName": name, "agentId": agent, "actionId": action,
         "eventStart": start, "eventEnd": start, "publishTime": start.replace("Z", ".900Z"),
         "entities": entities, "inputEventIds": inputs, "detectorVersion": f"{agent}-0",
         "artifactVersions": artifacts, "attributes": attrs, "parameterSetVersion": UNFROZEN,
         "severity": "MEDIUM"}
    if tactic:
        f["primaryTactic"] = tactic
    if completeness:
        f["completeness"] = completeness
    add(label, "findings.v0", envelope("FINDING", "SOURCE_UNSPECIFIED", fid, "finding", f))
    return fid


FD1 = finding("F1 D1 token-read-anomaly (mapped)", "D1", "token-read-anomaly", "D", "CREDENTIAL_ACCESS",
              [N2], "2026-09-26T10:00:01Z", [POD_E, LIN_E], [f"E_D1:{UNFROZEN}"],
              {"token_owner_pod_uid": POD, "token_version_dir": VDIR, "reader_class": "READER_POD_PROCESS",
               "reader_pod_uid": POD}, f"{NODE}/{BOOT}/71")
FE1 = finding("F2 E1 unsigned-image-admitted (unmapped)", "E1", "unsigned-image-admitted", "E", None,
              [N4], "2026-09-26T09:39:58Z", [POD_E, IMG_E], [],
              {"policy": "require-signed-images", "rule": "verify-signature", "image_digest": DIGEST,
               "pod_uid_join_status": "conditional"}, ADM,
              {"gaps": [{"reason": "CONDITIONAL_JOIN_UNVALIDATED", "scope": "join=admission-pod-uid",
                         "detail": "admission-instance witness unavailable until KYV-POD-UID-DRYRUN passes"}]})
FE2 = finding("F3 E2 post-start-binary-write (unmapped)", "E2", "post-start-binary-write", "E", None,
              [N3], "2026-09-26T10:00:11Z", [POD_E, LIN_E], [f"E_E2:{UNFROZEN}"],
              {"file_identity": "dev=2050,ino=88113", "mutation_op": "CHMOD",
               "writer_process": "tgid=4217,start=912399000000"}, f"{NODE}/{BOOT}/72")


# ---------------------------------------------------------------- witnesses
def witness(label, rtype, cls, src, tgt, jkt, jk, basis, st, tt, evid, status, limits, key_origin, coverage):
    wid = C.logical_id("witness", {"relationship_type": rtype, "source_finding_id": src,
                                   "target_finding_id": tgt, "evidence_event_ids": evid})
    w = {"witnessId": wid, "sourceFindingId": src, "targetFindingId": tgt, "relationshipType": rtype,
         "strengthClass": cls, "joinKeyType": jkt, "joinKey": jk, "directionBasis": basis,
         "sourceEventTime": st, "targetEventTime": tt, "appliedLimits": limits,
         "evidenceEventIds": evid, "status": status, "decisionVersion": "orch-0",
         "keyOrigin": key_origin, "contradictionCoverage": coverage}
    add(label, "witness.decisions.v0", envelope("WITNESS", "SOURCE_UNSPECIFIED", wid, "witness", w))
    return wid


# D1 is mapped and E2 is unmapped, so no tactic-pair window applies (design-spec 1).
W1 = witness("W1 process-ancestry (direct, confirmed)", "PROCESS_ANCESTRY", "DIRECT", FD1, FE2,
             "lineage_id", LINEAGE, "EVIDENCE_ORDER", "2026-09-26T10:00:01Z", "2026-09-26T10:00:11Z",
             [N2, N3], "CONFIRMED",
             [{"parameter": "W_w[process-ancestry]", "parameterSetVersion": UNFROZEN},
              {"parameter": "T", "parameterSetVersion": UNFROZEN}],
             # lineage_id is kernel-derived (sensor) and N's evidence predates any compromise epoch.
             [{"component": "lineage_id", "origin": "SENSOR", "evidenceEventIds": [N2, N3]}],
             # The node sensor is the only source able to contradict process ancestry; no overlap.
             [{"source": "EBPF"}])
W2 = witness("W2 image-class (enabling only)", "IMAGE_CLASS", "ENABLING", FE1, FE2, "image_digest", DIGEST,
             "EVIDENCE_ORDER", "2026-09-26T09:39:58Z", "2026-09-26T10:00:11Z", [N4, C1],
             "ENABLING_ONLY", [],
             [{"component": "image_digest", "origin": "SENSOR", "evidenceEventIds": [N4, C1]}], [])

# ---------------------------------------------------------------- incident
IID = C.logical_id("incident", {"anchor_finding_id": FD1})
inc = {"incidentId": IID, "anchorFindingId": FD1, "anchorEntity": POD_E, "version": 1,
       "findingIds": [FD1, FE2], "linkWitnessIds": [W1],
       "rankedPaths": [{"pathId": C.logical_id("path", {"finding_ids": [FD1, FE2]}),
                        "findingIds": [FD1, FE2], "witnessIds": [W1]}],
       "speculativePaths": [{"pathId": C.logical_id("path", {"finding_ids": [FE1, FE2]}),
                             "findingIds": [FE1, FE2], "witnessIds": [W2]}],
       "eventStart": "2026-09-26T10:00:01Z", "eventEnd": "2026-09-26T10:00:11Z",
       "status": "INCIDENT_SEALED", "watermarkTime": "2026-09-26T11:00:00Z", "sourceCompleteness": {},
       "sealedPredictionVersion": "snapshot-1", "decisionVersion": "orch-0"}
add("I1 incident version 1 (sealed)", "incidents.v0",
    envelope("INCIDENT", "SOURCE_UNSPECIFIED", IID, "incident", inc))
inc2 = copy.deepcopy(inc)
inc2.update({"version": 2, "status": "INCIDENT_AMENDED",
             "sourceCompleteness": {"currentExcludedSources": ["AUDIT"]},
             "amendments": [{"version": 2, "amendedAt": "2026-09-26T11:20:00Z",
                             "reason": "audit source excluded by max-idle after seal; analyst view only"}]})
add("I2 incident version 2 (amended; sealed snapshot unchanged)", "incidents.v0",
    envelope("INCIDENT", "SOURCE_UNSPECIFIED", IID, "incident", inc2))

# ---------------------------------------------------------------- dataset records
GT = {"runId": RUN["runId"], "actionSeq": "3", "scenarioId": "chain-1", "variantId": "stay-in-X",
      "stepLabel": "read projected token from inside the workload", "isAttack": True,
      "expectedFindingTypes": ["D1"], "intendedTactic": "CREDENTIAL_ACCESS",
      "actors": [POD_E], "targets": [POD_E], "startedAt": "2026-09-26T10:00:00.800Z",
      "endedAt": "2026-09-26T10:00:01.200Z", "harnessVersion": "harness-0", "harnessOutcome": "exit=0"}
add("GT ground-truth action (harness, access-separated)", "ground.truth.v0",
    envelope("GROUND_TRUTH_ACTION", "SOURCE_UNSPECIFIED",
             C.logical_id("ground_truth", {"run_id": GT["runId"], "action_seq": GT["actionSeq"]}),
             "groundTruthAction", GT))


def evaluation(label, rule, key_hex, wstart, wend, outcome, inputs, finding_id=None, features=None):
    eid = C.logical_id("evaluation", {"rule_id": rule, "state_key_hex": key_hex, "window_end": wend,
                                      "detector_version": f"{rule[0]}-0"})
    e = {"evaluationId": eid, "ruleId": rule, "stateKeyHex": key_hex, "windowStart": wstart,
         "windowEnd": wend, "outcome": outcome, "inputEventIds": inputs, "features": features or {},
         "detectorVersion": f"{rule[0]}-0", "parameterSetVersion": UNFROZEN}
    if finding_id:
        e["findingId"] = finding_id
    add(label, "rule.evaluations.v0", envelope("RULE_EVALUATION", "SOURCE_UNSPECIFIED", eid,
                                                "ruleEvaluation", e))


# State keys are the agent-topic key bytes (KEY_TOKEN_FILE_OWNER=10 for D1,
# KEY_POD_LINEAGE=13 for H4; components POD_UID=12, VOLUME_NAME=13, LINEAGE_ID=11).
D1_KEY_HEX = C.encode_key(10, [(12, POD), (13, VOL)]).hex()
H4_KEY_HEX = C.encode_key(13, [(12, POD), (11, LINEAGE)]).hex()
evaluation("RV1 D1 evaluation that fired", "D1", D1_KEY_HEX, "2026-09-26T10:00:01Z", "2026-09-26T10:00:01Z",
           "FIRED", [N2], FD1, {"reader_in_E_D1": "false", "token_version_dir": VDIR})
evaluation("RV2 H4 evaluation that did not fire (negative example)", "H4", H4_KEY_HEX, "2026-09-26T10:00:01Z",
           "2026-09-26T10:00:11Z", "NOT_FIRED", [N2, N3], None,
           {"sensitive_read_in_C_H4": "false", "external_transfer": "false"})

# ---------------------------------------------------------------- stream control
add("HB heartbeat to an explicit partition", "raw.ebpf.v0",
    envelope("HEARTBEAT", "EBPF", None, "heartbeat",
             {"producerId": "node-sensor", "producerInstance": "node-sensor@node-1", "topic": "raw.ebpf.v0",
              "partition": 0, "lowWatermark": "2026-09-26T10:00:10Z", "emittedAt": "2026-09-26T10:00:12Z",
              "producerSeq": "901"}),
    explicit_partition=0)
add("SC source completeness (audit idle interval)", "source.completeness.v0",
    envelope("SOURCE_COMPLETENESS", "AUDIT", None, "sourceCompleteness",
             {"source": "AUDIT", "scope": "audit-collector=ac-1", "intervalStart": "2026-09-26T10:40:00Z",
              "intervalEnd": "2026-09-26T11:10:00Z", "status": "INCOMPLETE",
              "gaps": [{"reason": "SOURCE_IDLE", "scope": "partition=raw.audit.v0/*",
                        "detail": "max-idle exceeded; excluded from watermark"}]}))

sys.path.insert(0, HERE)
from check_gap1 import fill_keys  # noqa: E402

fill_keys(records)
with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    json.dump({"trace_version": "trace-v0",
               "note": ("Synthetic schema example, not observed data. UIDs, digests, and times are invented "
                        "identifiers; no parameter value is chosen (UNFROZEN-EXAMPLE)."),
               "records": records}, fh, indent=1)
    fh.write("\n")
print(f"wrote {len(records)} records to {os.path.relpath(OUT)}")
