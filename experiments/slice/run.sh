#!/usr/bin/env bash
# MicroTRACE audit-to-incident slice runner (disposable kind cluster + one KRaft broker).
#
#   bash experiments/slice/run.sh                 # offline gate, then the live slice
#   bash experiments/slice/run.sh --offline-only  # fixture pipeline against a throwaway broker, no cluster
#   bash experiments/slice/run.sh --purge RUN_ID  # delete that run's private directory
#
# Deletes only: kind cluster microtrace-slice, containers labelled
# microtrace.slice.run=<run>, and a run-created empty kind network. Never prunes.
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

readonly CLUSTER=microtrace-slice
readonly TOOLS="${HOME}/microtrace-cluster"
readonly KIND="${TOOLS}/bin/kind" KUBECTL="${TOOLS}/bin/kubectl"
readonly DOCKER=/usr/bin/docker PY=/usr/bin/python3
readonly KIND_VERSION=v0.33.0 K8S_VERSION=v1.35.8
readonly NODE_IMAGE='kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
readonly WORKLOAD_IMAGE='docker.io/library/busybox@sha256:c230832bd3b0be59a6c47ed64294f9ce71e91b327957920b6929a0caa8353140'
readonly RUNTIME_IMAGE='microtrace-slice-runtime:0.1'
readonly BOOT=127.0.0.1:19092
readonly SLICE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO="$(cd "${SLICE}/../.." && pwd)"
readonly POLICY="${REPO}/spec/audit/audit-policy.v0.yaml"

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf -- "${TOOLS}/slice-runs/${2:?run id}/private"; echo "PURGED ${2}"; exit 0
fi
OFFLINE_ONLY=0; [[ "${1:-}" == "--offline-only" ]] && OFFLINE_ONLY=1

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"; readonly RUN_ID
readonly LBL="${RUN_ID,,}"
readonly WORK="${TOOLS}/slice-runs/${RUN_ID}"
readonly PRIV="${WORK}/private" PUB="${WORK}/public" GEN="${WORK}/gen"
mkdir -p "${PRIV}"/{out,collector,context,kube,dumps} "${PUB}" "${GEN}"
chmod 0700 "${WORK}" "${PRIV}"
exec > >(tee -a "${WORK}/run.log") 2>&1
FACTS="${PUB}/facts.tsv"
fact() { printf '%s\t%s\n' "$1" "$2" >> "${FACTS}"; echo "FACT $1=$2"; }
phase() { CURRENT_PHASE="$1"; echo "=== PHASE $1 $(date -u +%FT%TZ)"; fact "phase.$1" "$(date -u +%FT%TZ)"; }
CURRENT_PHASE=init
created=0
prior_kind_network="$(${DOCKER} network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
UIDGID="$(id -u):$(id -g)"
run_containers() { ${DOCKER} ps -aq --filter "label=microtrace.slice.run=${LBL}"; }
foreign_hash() {
  ${DOCKER} ps -a --format '{{.ID}} {{.Label "io.x-k8s.kind.cluster"}} {{.Label "microtrace.slice.run"}}' \
    | awk -v c="${CLUSTER}" -v r="${LBL}" -v o="offline-${LBL}" '$2 != c && $3 != r && $3 != o {print $1}' \
    | sort | sha256sum | cut -c1-64
}

teardown() {
  local rc=0 ids
  ids="$(run_containers)"; [[ -z "${ids}" ]] || ${DOCKER} rm -f ${ids} >/dev/null || rc=1
  ids="$(${DOCKER} ps -aq --filter "label=microtrace.slice.run=offline-${LBL}")"
  [[ -z "${ids}" ]] || ${DOCKER} rm -f ${ids} >/dev/null || rc=1
  if [[ "${created}" == 1 ]]; then
    timeout 300 "${KIND}" delete cluster --name "${CLUSTER}" --kubeconfig "${PRIV}/kube/kubeconfig" || rc=1
    created=0
  fi
  rm -f -- "${PRIV}/kube/"*
  if [[ -z "${prior_kind_network}" ]]; then
    local net; net="$(${DOCKER} network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
    if [[ -n "${net}" && "$(${DOCKER} network inspect kind --format '{{len .Containers}}')" == 0 ]]; then
      ${DOCKER} network rm "${net}" >/dev/null || rc=1
    fi
  fi
  fact teardown.node_containers "$(${DOCKER} ps -aq --filter "label=io.x-k8s.kind.cluster=${CLUSTER}" | wc -l)"
  fact teardown.run_containers "$(run_containers | wc -l)"
  fact teardown.kind_networks "$(${DOCKER} network ls -q --filter name=^kind$ | wc -l)"
  fact teardown.kube_material_files "$(ls -A "${PRIV}/kube" | wc -l)"
  fact teardown.rc "${rc}"
  return "${rc}"
}
on_exit() {
  local result=$?
  trap - EXIT; set +e
  teardown || result=1
  fact post.active_containers "$(${DOCKER} ps -q | wc -l)"
  fact post.total_containers "$(${DOCKER} ps -aq | wc -l)"
  fact post.foreign_container_set_sha256 "$(foreign_hash)"
  [[ "${result}" == 0 ]] || { fact failure.phase "${CURRENT_PHASE}"; fact failure.exit_code "${result}"; }
  fact end_utc "$(date -u +%FT%TZ)"
  echo "FINAL_EXIT_CODE=${result}"; exit "${result}"
}
trap on_exit EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM

# ------------------------------------------------------------------ preflight
phase preflight
fact run_id "${RUN_ID}"; fact start_utc "$(date -u +%FT%TZ)"
fact kernel "$(uname -srm)"; fact docker_server "$(${DOCKER} version --format '{{.Server.Version}}')"
fact pre.active_containers "$(${DOCKER} ps -q | wc -l)"; fact pre.total_containers "$(${DOCKER} ps -aq | wc -l)"
fact pre.foreign_container_set_sha256 "$(foreign_hash)"
[[ "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -ge 6291456 ]] || { echo 'ABORT: <6 GiB memory'; exit 1; }
[[ "$(df --output=avail -BG / | tail -1 | tr -dc '0-9')" -ge 20 ]] || { echo 'ABORT: <20 GiB disk'; exit 1; }
[[ -z "$(${DOCKER} ps -aq --filter "label=io.x-k8s.kind.cluster=${CLUSTER}")" ]] || { echo 'ABORT: cluster exists'; exit 1; }
! ss -ltn | grep -qE ':1909[23] ' || { echo 'ABORT: broker ports in use'; exit 1; }
tmpd="$(mktemp -d "${PRIV}/cksum.XXXX")"
curl -fsSL --retry 3 -o "${tmpd}/kind.sha256sum" "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64.sha256sum"
curl -fsSL --retry 3 -o "${tmpd}/kubectl.sha256" "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl.sha256"
echo "$(awk '{print $1}' "${tmpd}/kind.sha256sum")  ${KIND}" | sha256sum -c -
echo "$(cat "${tmpd}/kubectl.sha256")  ${KUBECTL}" | sha256sum -c -
rm -rf -- "${tmpd}"
for f in "${SLICE}"/*.py "${SLICE}"/*.sh "${SLICE}"/*.yaml "${SLICE}"/Dockerfile "${SLICE}"/tests/*.py \
         "${REPO}"/experiments/cluster/audit-context/collector.py "${REPO}"/experiments/cluster/audit-context/mtk8s.py \
         "${REPO}"/spec/tools/mtcodec.py "${REPO}"/spec/kafka/topics.yaml "${POLICY}"; do
  fact "sha256.${f#"${REPO}/"}" "$(sha256sum "$f" | cut -c1-64)"
done
${DOCKER} build -q -t "${RUNTIME_IMAGE}" "${SLICE}" >/dev/null
fact runtime_image_id "$(${DOCKER} image inspect "${RUNTIME_IMAGE}" --format '{{.Id}}')"
fact runtime_pip_freeze "$(${DOCKER} run --rm "${RUNTIME_IMAGE}" cat /pip-freeze.txt | tr '\n' ' ')"
${DOCKER} run --rm --user "${UIDGID}" -v "${REPO}:/repo:ro" -v "${GEN}:/gen" "${RUNTIME_IMAGE}" \
  sh -c 'cd /repo/spec/proto && python -m grpc_tools.protoc -I . --python_out=/gen --descriptor_set_out=/gen/descriptor.pb --include_imports microtrace/v0/*.proto'
DESC="$(sha256sum "${GEN}/descriptor.pb" | cut -c1-64)"; fact descriptor_set_sha256 "${DESC}"
POLICY_SHA="$(sha256sum "${POLICY}" | cut -c1-64)"; fact policy_sha256 "${POLICY_SHA}"
fact kafka_image "$(grep -o "apache/kafka:[^']*" "${SLICE}/kafka.sh")"

comp() {  # comp NAME [docker args...] -- python args...
  local name="$1"; shift
  local dargs=() ; while [[ "$1" != "--" ]]; do dargs+=("$1"); shift; done; shift
  ${DOCKER} run -d --name "mt-slice-${name}-${LBL}" --label "microtrace.slice.run=${LBL}" --network host \
    -e MT_REPO=/repo -e MT_PB_DIR=/gen -v "${REPO}:/repo:ro" -v "${GEN}:/gen:ro" -w /repo/experiments/slice "${dargs[@]}" \
    "${RUNTIME_IMAGE}" python "$@" >/dev/null
}
COMMON=(--bootstrap "${BOOT}" --run-id "${RUN_ID}" --descriptor-sha256 "${DESC}")

# ------------------------------------------------------------------ offline gate
phase offline_gate
bash "${SLICE}/kafka.sh" start "offline-${LBL}"
bash "${SLICE}/kafka.sh" topics "offline-${LBL}"
timeout 900 ${DOCKER} run --rm --name "mt-slice-fixture-${LBL}" --label "microtrace.slice.run=offline-${LBL}" \
  --network host -e MT_REPO=/repo -e MT_PB_DIR=/gen -v "${REPO}:/repo:ro" -v "${GEN}:/gen:ro" -w /repo/experiments/slice \
  "${RUNTIME_IMAGE}" python tests/fixture_pipeline.py > "${PRIV}/fixture.log" 2>&1 || { tail -40 "${PRIV}/fixture.log"; exit 1; }
grep -q '^FIXTURE_PIPELINE PASS' "${PRIV}/fixture.log" || { tail -40 "${PRIV}/fixture.log"; exit 1; }
sed -n '/^{/,/^}/p' "${PRIV}/fixture.log" > "${PUB}/fixture-report.json"
fact offline_fixture_pipeline pass
bash "${SLICE}/kafka.sh" stop "offline-${LBL}"
[[ "${OFFLINE_ONLY}" == 0 ]] || { echo 'OFFLINE ONLY: done'; exit 0; }

# ------------------------------------------------------------------ cluster and broker
phase create
stage="${WORK}/stage"; mkdir -p "${stage}"
install -m 0644 "${SLICE}/kind-config.yaml" "${stage}/kind-config.yaml"
install -m 0644 "${POLICY}" "${stage}/audit-policy.v0.yaml"
fact kind_config_sha256 "$(sha256sum "${stage}/kind-config.yaml" | cut -c1-64)"
created=1
( cd "${stage}" && timeout 600 "${KIND}" create cluster --name "${CLUSTER}" --config kind-config.yaml \
    --image "${NODE_IMAGE}" --kubeconfig "${PRIV}/kube/kubeconfig" --wait 5m )
KC=(timeout 120 "${KUBECTL}" --kubeconfig "${PRIV}/kube/kubeconfig")
"${KC[@]}" wait --for=condition=Ready nodes --all --timeout=180s
"${KC[@]}" config view --raw -o json > "${PRIV}/kube/kubeconfig.json"
chmod 0644 "${PRIV}/kube/kubeconfig.json"   # read by the non-root context container; directory is 0700
fact server_version "$("${KC[@]}" version -o json | ${PY} -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
CP="${CLUSTER}-control-plane"
[[ "$(${DOCKER} exec "${CP}" sha256sum /etc/kubernetes/policies/audit-policy.v0.yaml | cut -c1-64)" == "${POLICY_SHA}" ]] \
  || { echo 'ABORT: policy mismatch in node'; exit 1; }
fact audit_flags "$(${DOCKER} exec "${CP}" sh -c 'for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = kube-apiserver ]; then tr "\0" "\n" < $p/cmdline; fi; done; true' | grep -- '^--audit-' | sort | tr '\n' ' ' || true)"
timeout 60 bash -c "until ${DOCKER} exec ${CP} test -s /var/log/kubernetes/audit/audit.log; do sleep 1; done"
bash "${SLICE}/kafka.sh" start "${LBL}"
bash "${SLICE}/kafka.sh" topics "${LBL}"
head -c 32 /dev/urandom > "${PRIV}/pseudonym.key"; chmod 0444 "${PRIV}/pseudonym.key"
chmod 0777 "${PRIV}/collector" "${PRIV}/context" "${PRIV}/out"   # container writers; parent dir stays 0700

# ------------------------------------------------------------------ live pipeline
phase start_pipeline
start_collector() {  # $1 = container suffix, $2 = extra
  comp "$1" --volumes-from "${CP}:ro" -v "${PRIV}/collector:/out" -v "${PRIV}/pseudonym.key:/key:ro" -- \
    audit_collector.py --dir /var/log/kubernetes/audit --out /out --key /key --instance audit-collector-1 \
    --policy-sha256 "${POLICY_SHA}" --chown "${UIDGID}" "${COMMON[@]}" ${2:-}
}
start_context() {
  comp "$1" --user "${UIDGID}" -v "${PRIV}/context:/out" -v "${PRIV}/kube:/kube" -- \
    context_collector.py --kubeconfig-json /kube/kubeconfig.json --private /kube --out /out \
    --instance context-collector-1 "${COMMON[@]}" ${2:-}
}
start_collector collector
start_context context
for s in normalizer restreamer agent_h3 orchestrator; do
  comp "${s}" --user "${UIDGID}" -v "${PRIV}/out:/out" -- "${s}.py" --instance "${s}-1" --group "${LBL}-${s}" \
    --out /out "${COMMON[@]}"
done
sleep 15
for c in collector context normalizer restreamer agent_h3 orchestrator; do
  [[ "$(${DOCKER} inspect -f '{{.State.Running}}' "mt-slice-${c}-${LBL}")" == true ]] \
    || { ${DOCKER} logs --tail 30 "mt-slice-${c}-${LBL}"; echo "ABORT: ${c} not running"; exit 1; }
done
DRV=(${PY} "${SLICE}/driver.py" --kubeconfig-json "${PRIV}/kube/kubeconfig.json" --private "${PRIV}/kube"
     --state "${PRIV}/driver-state.json" --image "${WORKLOAD_IMAGE}")
phase setup;     "${DRV[@]}" setup
sleep 10
phase positive;  "${DRV[@]}" positive --stop-context "mt-slice-context-${LBL}"
phase wait_seal; "${DRV[@]}" wait --log "${PRIV}/out/orchestrator.jsonl" --cond status=INCIDENT_SEALED --timeout 300
phase churn;     "${DRV[@]}" churn --pods 60 --wait 80
phase resume_context
start_context context2 --resume
if "${DRV[@]}" wait --log "${PRIV}/context/slice-context.jsonl" --cond watch_gap="watch ERROR event code 410" --timeout 90 \
   || "${DRV[@]}" wait --log "${PRIV}/context/slice-context.jsonl" --cond watch_gap="HTTP 410 on watch request" --timeout 5; then
  fact context_resume_410 observed
  phase wait_amend
  "${DRV[@]}" wait --log "${PRIV}/out/orchestrator.jsonl" --cond status=INCIDENT_AMENDED --timeout 240 \
    && fact amendment observed || fact amendment not_observed
else
  fact context_resume_410 not_observed_within_bound
fi
phase gap
"${DRV[@]}" gap --stop-collector "mt-slice-collector-${LBL}" --filler 3500
start_collector collector2 --resume
G_UID="$(${PY} -c 'import json,sys;print(json.load(open(sys.argv[1]))["sa_uid"]["G"])' "${PRIV}/driver-state.json")"
"${DRV[@]}" wait --log "${PRIV}/out/agent.jsonl" --cond principal="${G_UID}" --cond outcome=ABSTAINED --timeout 300 \
  && fact abstention observed || fact abstention not_observed
phase settle; sleep 40

# ------------------------------------------------------------------ stop, replay, dump
phase stop_live
touch "${PRIV}/collector/collector.stop"
for s in normalizer restreamer agent orchestrator; do touch "${PRIV}/out/${s}.stop"; done
for c in collector2 normalizer restreamer agent_h3 orchestrator; do
  fact "exit.${c}" "$(timeout 120 ${DOCKER} wait "mt-slice-${c}-${LBL}")"
done
${DOCKER} stop -t 60 "mt-slice-context2-${LBL}" >/dev/null
rm -f "${PRIV}/out/"*.stop
phase replay
for s in normalizer restreamer agent_h3 orchestrator; do
  timeout 600 ${DOCKER} run --rm --name "mt-slice-replay-${s}-${LBL}" --label "microtrace.slice.run=${LBL}" \
    --network host --user "${UIDGID}" -e MT_REPO=/repo -e MT_PB_DIR=/gen -v "${REPO}:/repo:ro" -v "${GEN}:/gen:ro" \
    -v "${PRIV}/out:/out" -w /repo/experiments/slice "${RUNTIME_IMAGE}" python "${s}.py" --replay --instance "${s}-replay" \
    --group "${LBL}-${s}-replay" --out /out "${COMMON[@]}"
done
phase dump
${DOCKER} run --rm --label "microtrace.slice.run=${LBL}" --network host --user "${UIDGID}" -e MT_REPO=/repo \
  -e MT_PB_DIR=/gen -v "${REPO}:/repo:ro" -v "${GEN}:/gen:ro" -v "${PRIV}/dumps:/dumps" -w /repo/experiments/slice \
  "${RUNTIME_IMAGE}" python dump.py --bootstrap "${BOOT}" --out /dumps raw.audit.v0 context.cluster.v0 \
  norm.events.v0 agent.H.audit.v0 findings.v0 incidents.v0 source.completeness.v0 rule.evaluations.v0 \
  replay.norm.events.v0 replay.agent.H.audit.v0 replay.findings.v0 replay.incidents.v0 replay.rule.evaluations.v0
phase summarize
${PY} "${SLICE}/summarize_slice.py" --dumps "${PRIV}/dumps" --state "${PRIV}/driver-state.json" --facts "${FACTS}" \
  --logs "${PRIV}/out" --run-id "${RUN_ID}" --out-json "${PUB}/slice-${RUN_ID}.json" --out-md "${PUB}/slice-${RUN_ID}.summary.md"
fact retention "raw topics lived only in the run's broker container and were deleted with it; raw audit lines only in the node volume; kubeconfig and client material removed at teardown; decoded dumps and driver state stay in ${PRIV} (0700) until reviewed, then --purge ${RUN_ID}"
echo "RUN COMPLETE ${RUN_ID}"
