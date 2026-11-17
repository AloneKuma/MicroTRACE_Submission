#!/usr/bin/env bash
# MicroTRACE Gap 2 audit/context experiment runner (disposable kind cluster).
#
# Runs three sequential, separately hashed cluster generations with the same
# name and deletes each one before the next is created:
#   main      kind-config.yaml         candidate policy; probes, context controls, audited latency
#   fault     kind-config-fault.yaml   truncation + 1 MiB rotation faults
#   baseline  kind-config-noaudit.yaml no-audit latency comparison
#
# Usage (on the test host, from a copy of the repository subset):
#   bash experiments/cluster/audit-context/run.sh              # preflight + all generations
#   GENS="main" bash experiments/cluster/audit-context/run.sh  # subset
#   bash experiments/cluster/audit-context/run.sh --preflight-only
#   bash experiments/cluster/audit-context/run.sh --purge RUN_ID   # delete that run's private dir
#
# Only the cluster named below and the collector containers labelled with this
# run ID are ever deleted. Docker prune is never used.
set -Eeuo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

readonly CLUSTER=microtrace-gap2-audit
readonly TOOLS="${HOME}/microtrace-cluster"
readonly KIND="${TOOLS}/bin/kind"
readonly KUBECTL="${TOOLS}/bin/kubectl"
readonly DOCKER=/usr/bin/docker
readonly PY=/usr/bin/python3
readonly KIND_VERSION=v0.33.0
readonly K8S_VERSION=v1.35.8
readonly NODE_IMAGE='kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
readonly WORKLOAD_IMAGE='docker.io/library/busybox@sha256:c230832bd3b0be59a6c47ed64294f9ce71e91b327957920b6929a0caa8353140'
readonly COLLECTOR_IMAGE='docker.io/library/python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f'
readonly HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO="$(cd "${HARNESS}/../../.." && pwd)"
readonly POLICY="${REPO}/spec/audit/audit-policy.v0.yaml"
readonly RULEBOOK="${REPO}/spec/rules/rulebook.v0.yaml"

if [[ "${1:-}" == "--purge" ]]; then
  target="${TOOLS}/gap2-audit/${2:?run id}/private"
  [[ -d "${target}" ]] || { echo "no such private dir"; exit 1; }
  rm -rf -- "${target}"
  echo "PURGED ${target}"
  exit 0
fi
PREFLIGHT_ONLY=0
[[ "${1:-}" == "--preflight-only" ]] && PREFLIGHT_ONLY=1

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
readonly RUN_ID
readonly WORK="${TOOLS}/gap2-audit/${RUN_ID}"
readonly PRIV="${WORK}/private"   # identity-bearing or credential material: never leaves the host
readonly PUB="${WORK}/public"     # redacted outputs only
GENS="${GENS:-main fault baseline}"

mkdir -p "${PRIV}" "${PUB}"
chmod 0700 "${WORK}" "${PRIV}" "${PUB}"
exec > >(tee -a "${WORK}/run.log") 2>&1

FACTS="${PUB}/facts.tsv"
fact() { printf '%s\t%s\n' "$1" "$2" >> "${FACTS}"; echo "FACT $1=$2"; }
phase() { CURRENT_PHASE="$1"; echo "=== PHASE $1 $(date -u +%FT%TZ)"; fact "phase.$1.start" "$(date -u +%FT%TZ)"; }
CURRENT_PHASE=init
created=0
current_gen=''
prior_kind_network="$(${DOCKER} network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
WATCH_PID=''

node_cp() { echo "${CLUSTER}-control-plane"; }

cluster_containers() { ${DOCKER} ps -aq --filter "label=io.x-k8s.kind.cluster=${CLUSTER}"; }
collector_containers() { ${DOCKER} ps -aq --filter "label=microtrace.gap2.run=${RUN_ID}"; }

teardown_gen() {
  local gen="$1" rc=0
  if [[ -n "${WATCH_PID}" ]] && kill -0 "${WATCH_PID}" 2>/dev/null; then
    kill -TERM "${WATCH_PID}" 2>/dev/null || true
    wait "${WATCH_PID}" 2>/dev/null || true
  fi
  WATCH_PID=''
  local cc
  cc="$(collector_containers)"
  if [[ -n "${cc}" ]]; then
    # Give a running collector a chance to checkpoint and chown its output.
    ${DOCKER} stop -t 20 ${cc} >/dev/null 2>&1 || true
    ${DOCKER} rm -f ${cc} >/dev/null 2>&1 || rc=1
  fi
  if [[ "${created}" == 1 ]]; then
    echo "TEARDOWN(${gen}): deleting only ${CLUSTER}"
    timeout 300 "${KIND}" delete cluster --name "${CLUSTER}" --kubeconfig "${PRIV}/${gen}/kubeconfig" || rc=1
    created=0
  fi
  rm -f -- "${PRIV}/${gen}/kubeconfig" "${PRIV}/${gen}/kubeconfig.json" "${PRIV}/${gen}/ca.pem" \
           "${PRIV}/${gen}/client.pem" "${PRIV}/${gen}/client-key.pem"
  if [[ -n "$(cluster_containers)" ]]; then
    echo "TEARDOWN ERROR(${gen}): ${CLUSTER} node containers remain"; rc=1
  fi
  if [[ -n "$(collector_containers)" ]]; then
    echo "TEARDOWN ERROR(${gen}): collector containers remain"; rc=1
  fi
  if [[ -z "${prior_kind_network}" ]]; then
    local net members
    net="$(${DOCKER} network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
    if [[ -n "${net}" ]]; then
      members="$(${DOCKER} network inspect kind --format '{{len .Containers}}')"
      if [[ "${members}" == 0 ]]; then
        ${DOCKER} network rm "${net}" >/dev/null || rc=1
      else
        echo "TEARDOWN NOTE: kind network has ${members} containers; left in place"; rc=1
      fi
    fi
  fi
  fact "teardown.${gen}.node_containers_remaining" "$(cluster_containers | wc -l)"
  fact "teardown.${gen}.collector_containers_remaining" "$(collector_containers | wc -l)"
  fact "teardown.${gen}.kind_networks" "$(${DOCKER} network ls -q --filter name=^kind$ | wc -l)"
  fact "teardown.${gen}.kubeconfig_removed" "$([[ -e "${PRIV}/${gen}/kubeconfig" ]] && echo no || echo yes)"
  fact "teardown.${gen}.rc" "${rc}"
  return "${rc}"
}

on_exit() {
  local result=$?
  trap - EXIT
  set +e
  if [[ -n "${current_gen}" ]]; then
    teardown_gen "${current_gen}" || result=1
  fi
  fact "post.active_containers" "$(${DOCKER} ps -q | wc -l)"
  fact "post.total_containers" "$(${DOCKER} ps -aq | wc -l)"
  fact "post.foreign_container_set_sha256" "$(foreign_set_hash)"
  fact "post.target_label_containers" "$(cluster_containers | wc -l)"
  if [[ "${result}" != 0 ]]; then
    fact "failure.phase" "${CURRENT_PHASE}"
    fact "failure.exit_code" "${result}"
  fi
  fact "end_utc" "$(date -u +%FT%TZ)"
  echo "FINAL_EXIT_CODE=${result}"
  exit "${result}"
}

foreign_set_hash() {
  # IDs of every container not created by this run: must be identical before and after.
  ${DOCKER} ps -a --format '{{.ID}} {{.Label "io.x-k8s.kind.cluster"}} {{.Label "microtrace.gap2.run"}}' \
    | awk -v c="${CLUSTER}" -v r="${RUN_ID}" '$2 != c && $3 != r {print $1}' | sort | sha256sum | cut -c1-64
}

trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ------------------------------------------------------------------ preflight
phase preflight
fact run_id "${RUN_ID}"
fact start_utc "$(date -u +%FT%TZ)"
fact host "$(hostname)"
fact kernel "$(uname -srm)"
fact os "$(. /etc/os-release && echo "${PRETTY_NAME}")"
fact cpus "$(nproc)"
fact mem_available_kib "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
fact disk_available_gib "$(df --output=avail -BG / | tail -1 | tr -dc '0-9')"
fact docker_server "$(${DOCKER} version --format '{{.Server.Version}}')"
fact pre.active_containers "$(${DOCKER} ps -q | wc -l)"
fact pre.total_containers "$(${DOCKER} ps -aq | wc -l)"
fact pre.foreign_container_set_sha256 "$(foreign_set_hash)"
fact pre.kind_clusters "$("${KIND}" get clusters 2>/dev/null | tr '\n' ' ')"
fact pre.kind_network "${prior_kind_network:-none}"

[[ "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -ge 6291456 ]] || { echo 'ABORT: <6 GiB memory available'; exit 1; }
[[ "$(df --output=avail -BG / | tail -1 | tr -dc '0-9')" -ge 20 ]] || { echo 'ABORT: <20 GiB disk available'; exit 1; }
[[ -z "$(cluster_containers)" ]] || { echo "ABORT: ${CLUSTER} containers already exist"; exit 1; }
if "${KIND}" get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then echo "ABORT: cluster name in use"; exit 1; fi
if compgen -G "${TOOLS}/gap2-audit/*/private/*/kubeconfig" >/dev/null; then
  echo 'ABORT: a kubeconfig from an earlier run still exists'; exit 1
fi

# Tool checksums: fetch the official checksum files fresh and verify the local binaries.
tmpd="$(mktemp -d "${PRIV}/cksum.XXXX")"
curl -fsSL --retry 3 -o "${tmpd}/kind.sha256sum" \
  "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64.sha256sum"
curl -fsSL --retry 3 -o "${tmpd}/kubectl.sha256" "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl.sha256"
echo "$(awk '{print $1}' "${tmpd}/kind.sha256sum")  ${KIND}" | sha256sum -c -
echo "$(cat "${tmpd}/kubectl.sha256")  ${KUBECTL}" | sha256sum -c -
rm -rf -- "${tmpd}"
fact kind_sha256 "$(sha256sum "${KIND}" | cut -c1-64)"
fact kubectl_sha256 "$(sha256sum "${KUBECTL}" | cut -c1-64)"
fact kind_version "$("${KIND}" version)"
fact kubectl_client "$("${KUBECTL}" version --client -o json | ${PY} -c 'import json,sys;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])')"
fact node_image "${NODE_IMAGE}"
fact workload_image "${WORKLOAD_IMAGE}"
fact collector_image "${COLLECTOR_IMAGE}"
fact python_host "$(${PY} --version 2>&1)"
for f in "${POLICY}" "${RULEBOOK}" "${HARNESS}"/*.py "${HARNESS}"/*.yaml "${HARNESS}"/run.sh "${HARNESS}"/tests/*.py; do
  fact "sha256.${f#"${REPO}/"}" "$(sha256sum "$f" | cut -c1-64)"
done

# Offline gate: harness fixture tests (no cluster).
( cd "${HARNESS}" && timeout 300 ${PY} -m unittest -q tests.test_harness )
fact offline_fixture_tests pass

head -c 32 /dev/urandom > "${PRIV}/pseudonym.key"
chmod 0400 "${PRIV}/pseudonym.key"
${DOCKER} pull -q "${COLLECTOR_IMAGE}" >/dev/null
fact collector_image_pulled yes
if [[ "${PREFLIGHT_ONLY}" == 1 ]]; then
  echo 'PREFLIGHT ONLY: stopping before cluster creation'
  exit 0
fi

# ------------------------------------------------------------------ helpers
kc() { timeout 120 "${KUBECTL}" --kubeconfig "${PRIV}/${current_gen}/kubeconfig" "$@"; }
probe() {  # PROBE_TIMEOUT=<seconds> bounds each invocation (default 600)
  local cmd="$1"; shift
  ( cd "${HARNESS}" && timeout "${PROBE_TIMEOUT:-600}" ${PY} probe.py "${cmd}" --kubeconfig-json "${PRIV}/${current_gen}/kubeconfig.json" \
      --private "${PRIV}/${current_gen}" --key "${PRIV}/pseudonym.key" --run-id "${RUN_ID}" \
      --image "${WORKLOAD_IMAGE}" --kubectl "${KUBECTL}" --kubeconfig "${PRIV}/${current_gen}/kubeconfig" "$@" )
}

create_gen() {
  local gen="$1" cfg="$2"
  current_gen="${gen}"
  local stage="${WORK}/stage-${gen}"
  mkdir -p "${stage}" "${PRIV}/${gen}/collector"
  install -m 0644 "${HARNESS}/${cfg}" "${stage}/${cfg}"
  install -m 0644 "${POLICY}" "${stage}/audit-policy.v0.yaml"
  cmp "${POLICY}" "${stage}/audit-policy.v0.yaml"
  fact "${gen}.config" "${cfg}"
  fact "${gen}.config_sha256" "$(sha256sum "${stage}/${cfg}" | cut -c1-64)"
  fact "${gen}.policy_sha256_repo" "$(sha256sum "${POLICY}" | cut -c1-64)"
  phase "${gen}.create"
  created=1
  ( cd "${stage}" && timeout 600 "${KIND}" create cluster --name "${CLUSTER}" --config "${cfg}" \
      --image "${NODE_IMAGE}" --kubeconfig "${PRIV}/${gen}/kubeconfig" --wait 5m )
  chmod 0600 "${PRIV}/${gen}/kubeconfig"
  kc wait --for=condition=Ready nodes --all --timeout=180s
  kc config view --raw -o json > "${PRIV}/${gen}/kubeconfig.json"
  fact "${gen}.created_utc" "$(date -u +%FT%TZ)"
  fact "${gen}.server_version" "$(kc version -o json | ${PY} -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')"
  kc get nodes -o json | ${PY} -c '
import json,sys
for n in json.load(sys.stdin)["items"]:
    i=n["status"]["nodeInfo"]; c=n["status"]["capacity"]
    print("NODE", n["metadata"]["name"], i["kubeletVersion"], i["containerRuntimeVersion"], i["kernelVersion"], i["osImage"].replace(" ","_"), c["cpu"], c["memory"])' \
    | while read -r _ name kubelet rt kern os cpu mem; do
        fact "${gen}.node.${name}" "kubelet=${kubelet} runtime=${rt} kernel=${kern} os=${os} cpu=${cpu} mem=${mem}"
      done
}

verify_audit_active() {
  local gen="$1" cp
  cp="$(node_cp)"
  phase "${gen}.verify"
  local in_node
  in_node="$(${DOCKER} exec "${cp}" sha256sum /etc/kubernetes/policies/audit-policy.v0.yaml | cut -c1-64)"
  fact "${gen}.policy_sha256_in_node" "${in_node}"
  [[ "${in_node}" == "$(sha256sum "${POLICY}" | cut -c1-64)" ]] || { echo 'ABORT: mounted policy differs'; exit 1; }
  # Flags of the running kube-apiserver process, not only the manifest.
  local flags
  flags="$(${DOCKER} exec "${cp}" sh -c 'for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = kube-apiserver ]; then tr "\0" "\n" < $p/cmdline; fi; done; true' | grep -- '^--audit-' | sort || true)"
  echo "${flags}"
  fact "${gen}.audit_flags_running_process" "$(echo "${flags}" | tr '\n' ' ')"
  echo "${flags}" | grep -qx -- '--audit-policy-file=/etc/kubernetes/policies/audit-policy.v0.yaml' \
    || { echo 'ABORT: running apiserver lacks the candidate policy flag'; exit 1; }
  fact "${gen}.manifest_audit_flags" "$(${DOCKER} exec "${cp}" grep -c -- '--audit-' /etc/kubernetes/manifests/kube-apiserver.yaml)"
  timeout 60 bash -c "until ${DOCKER} exec ${cp} test -s /var/log/kubernetes/audit/audit.log; do sleep 1; done"
  fact "${gen}.audit_log_present" yes
  ${PY} - "${gen}" "${PRIV}/${gen}/gen-info.json" "${FACTS}" <<'PYEOF'
import json, sys
gen, out, facts = sys.argv[1:]
f = {}
for line in open(facts, encoding="utf-8"):
    k, _, v = line.rstrip("\n").partition("\t")
    if k.startswith(gen + "."):
        f[k[len(gen) + 1:]] = v
f["audit_flags"] = f.get("audit_flags_running_process", "").split()
json.dump(f, open(out, "w"), indent=1, sort_keys=True)
PYEOF
}

start_collector() {
  local gen="$1" name="$2" extra="${3:-}"
  ${DOCKER} run -d --name "${name}" --label "microtrace.gap2.run=${RUN_ID}" --network none \
    --volumes-from "$(node_cp):ro" \
    -v "${HARNESS}:/h:ro" -v "${PRIV}/${gen}/collector:/out" -v "${PRIV}/pseudonym.key:/key:ro" \
    "${COLLECTOR_IMAGE}" python /h/collector.py --dir /var/log/kubernetes/audit --base audit.log \
    --out /out --key /key --chown "$(id -u):$(id -g)" ${extra} >/dev/null
  local i
  for i in $(seq 1 120); do
    [[ -s "${PRIV}/${gen}/collector/checkpoint.json" ]] && break
    if [[ "$(${DOCKER} inspect -f '{{.State.Running}}' "${name}")" != true ]]; then
      echo "COLLECTOR ERROR: ${name} exited: $(${DOCKER} inspect -f '{{.State.ExitCode}} {{.State.Error}}' "${name}")"
      ${DOCKER} logs --tail 40 "${name}" 2>&1 | sed 's/^/COLLECTOR LOG: /'
      exit 1
    fi
    sleep 0.5
  done
  if [[ ! -s "${PRIV}/${gen}/collector/checkpoint.json" ]]; then
    echo "COLLECTOR ERROR: ${name} wrote no checkpoint within 60 s"
    ${DOCKER} logs --tail 40 "${name}" 2>&1 | sed 's/^/COLLECTOR LOG: /'
    ls -la "${PRIV}/${gen}/collector" | sed 's/^/COLLECTOR DIR: /'
    exit 1
  fi
  fact "${gen}.collector.${name}.started" "$(date -u +%FT%TZ)"
}

stop_collector_drain() {
  local gen="$1" name="$2"
  : > "${PRIV}/${gen}/collector/collector.stop" 2>/dev/null || \
    ${DOCKER} exec "${name}" touch /out/collector.stop
  local code
  code="$(timeout 180 ${DOCKER} wait "${name}")"
  fact "${gen}.collector.${name}.exit" "${code}"
  ${DOCKER} rm "${name}" >/dev/null
  [[ "${code}" == 0 ]] || { echo "collector ${name} exit ${code}"; exit 1; }
}

stop_collector_signal() {
  local gen="$1" name="$2"
  ${DOCKER} stop -t 20 "${name}" >/dev/null
  fact "${gen}.collector.${name}.stopped_by_signal" "$(date -u +%FT%TZ)"
  ${DOCKER} rm "${name}" >/dev/null
}

# ------------------------------------------------------------------ generations
run_main() {
  create_gen main kind-config.yaml
  verify_audit_active main
  start_collector main "mt-gap2-collector-main-${RUN_ID,,}"
  ( cd "${HARNESS}" && exec ${PY} context-watch.py --kubeconfig-json "${PRIV}/main/kubeconfig.json" \
      --private "${PRIV}/main" --out "${PRIV}/main/context.jsonl" --stream-name main ) &
  WATCH_PID=$!
  sleep 3
  cp "${PRIV}/main/collector/checkpoint.json" "${PRIV}/main/collector/pre-probe-checkpoint.json"
  fact main.pre_probe_checkpoint "$(${PY} -c 'import json,sys;c=json.load(open(sys.argv[1]));print(c["ino"],c["offset"],c["stats"]["records"])' "${PRIV}/main/collector/pre-probe-checkpoint.json")"
  probe metrics --tag pre-probe
  phase main.setup;          PROBE_TIMEOUT=300 probe setup
  phase main.matrix;         probe matrix
  phase main.exec;           probe exec
  phase main.rbac_recreate;  probe rbac-recreate
  phase main.watch410;       PROBE_TIMEOUT=900 probe watch410 --count 150 --wait 80 --attempts 2 || fact main.watch410_rc "$?"
  phase main.ip_reuse;       PROBE_TIMEOUT=1500 probe ip-reuse --batches 8 --batch-size 40 || fact main.ip_reuse_rc "$?"
  probe metrics --tag post-probe
  kill -TERM "${WATCH_PID}"; wait "${WATCH_PID}" || fact main.context_watch_exit "$?"
  WATCH_PID=''
  phase main.latency;        probe latency --label audit --count 200 --warmup 20
  probe metrics --tag main-end
  phase main.drain;          stop_collector_drain main "mt-gap2-collector-main-${RUN_ID,,}"
  phase main.teardown;       teardown_gen main; current_gen=''
}

run_fault() {
  create_gen fault kind-config-fault.yaml
  verify_audit_active fault
  local c1="mt-gap2-collector-fault1-${RUN_ID,,}" c2="mt-gap2-collector-fault2-${RUN_ID,,}"
  start_collector fault "${c1}"
  probe metrics --tag fault-start
  phase fault.truncation;    probe load-setup; probe truncation
  phase fault.rotation_tail; probe load --tag r1 --count 2500
  sleep 3
  phase fault.stopped_reader
  stop_collector_signal fault "${c1}"
  probe load --tag r2 --count 3500
  sleep 3
  start_collector fault "${c2}" --resume
  probe load --tag r3 --count 200
  probe metrics --tag fault-end
  phase fault.drain;         stop_collector_drain fault "${c2}"
  phase fault.teardown;      teardown_gen fault; current_gen=''
}

run_baseline() {
  create_gen baseline kind-config-noaudit.yaml
  ${PY} -c 'import json,sys;json.dump({"config":"kind-config-noaudit.yaml","audit":"disabled"},open(sys.argv[1],"w"))' \
    "${PRIV}/baseline/gen-info.json"
  phase baseline.latency;    probe latency --label noaudit --count 200 --warmup 20
  phase baseline.teardown;   teardown_gen baseline; current_gen=''
}

for g in ${GENS}; do
  case "${g}" in
    main) run_main ;;
    fault) run_fault ;;
    baseline) run_baseline ;;
    *) echo "unknown generation ${g}"; exit 1 ;;
  esac
done

# ------------------------------------------------------------------ summary
phase summarize
fact post_run.active_containers "$(${DOCKER} ps -q | wc -l)"
${PY} - "${FACTS}" "${PUB}/run-info.json" <<'PYEOF'
import json, sys
facts = {}
for line in open(sys.argv[1], encoding="utf-8"):
    k, _, v = line.rstrip("\n").partition("\t")
    facts[k] = v
json.dump(facts, open(sys.argv[2], "w"), indent=1, sort_keys=True)
PYEOF
( cd "${HARNESS}" && ${PY} summarize.py --rulebook "${RULEBOOK}" --key "${PRIV}/pseudonym.key" \
    --gen "main=${PRIV}/main" --gen "fault=${PRIV}/fault" --gen "baseline=${PRIV}/baseline" \
    --run-info "${PUB}/run-info.json" --run-id "${RUN_ID}" \
    --out-json "${PUB}/audit-context-${RUN_ID}.json" --out-md "${PUB}/audit-context-${RUN_ID}.summary.md" )
fact retention "raw audit lines lived only in the node container's /var volume and were deleted with each cluster; kubeconfig and client credentials removed at each teardown; redacted-private records and the pseudonym key remain in ${PRIV} (mode 0700) until reviewed, then removed with --purge ${RUN_ID}"
echo "RUN COMPLETE ${RUN_ID}"
