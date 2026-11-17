#!/usr/bin/env bash
# Disposable kind probe: can a Pod forge sensor-made identity fields (audit user,
# Pod UID, TCP peer) and workload-made fields (trace/request headers, UA, XFF)?
# Same pins, abort rules and teardown discipline as run-smoke.sh. Never prunes.
set -Eeuo pipefail

cluster=microtrace-forgery
ns=mt-forgery
here="$(cd "$(dirname "$0")" && pwd)"
base="${HOME}/microtrace-forgery"
tools="${HOME}/microtrace-cluster/bin"
kind_version=v0.33.0
k8s_version=v1.35.8
image='kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
py_image='python:3.12-alpine'
created=0
prior_kind_network="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
run_kind_network=''

mkdir -p "${base}" "${tools}"
umask 077
exec > >(tee "${base}/run.log") 2>&1
export KUBECONFIG="${base}/kubeconfig"
pre_active="$(docker ps -q | wc -l)"

cleanup() {
  result=$?
  trap - EXIT
  if [[ "${created}" == 1 ]]; then
    echo "TEARDOWN: deleting only ${cluster}"
    "${tools}/kind" delete cluster --name "${cluster}" || { echo 'TEARDOWN ERROR: kind delete failed'; result=1; }
    rm -f -- "${KUBECONFIG}"
  fi
  if [[ -n "$(docker ps -aq --filter "label=io.x-k8s.kind.cluster=${cluster}")" ]]; then
    echo 'TEARDOWN ERROR: cluster node containers remain'; result=1
  else
    echo "TEARDOWN: no ${cluster} node containers remain"
  fi
  if [[ -z "${prior_kind_network}" && -n "${run_kind_network}" ]]; then
    cur="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
    if [[ "${cur}" == "${run_kind_network}" ]]; then
      docker network rm "${run_kind_network}" || { echo 'TEARDOWN ERROR: run-created kind network remains'; result=1; }
    fi
  fi
  echo "PRE_ACTIVE_CONTAINERS=${pre_active} POST_ACTIVE_CONTAINERS=$(docker ps -q | wc -l)"
  echo "FINAL_EXIT_CODE=${result}"
  exit "${result}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "HOST=$(hostname)"
uname -srmo
docker version --format 'DOCKER_SERVER={{.Server.Version}}'
echo "PRE_ACTIVE_CONTAINERS=${pre_active}"
if [[ "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -lt 6291456 ]]; then echo 'ABORT: less than 6 GiB memory available'; exit 1; fi
if [[ "$(df --output=avail -BG / | tail -1 | tr -dc '0-9')" -lt 20 ]]; then echo 'ABORT: less than 20 GiB disk available'; exit 1; fi
if [[ -n "$(docker ps -aq --filter "label=io.x-k8s.kind.cluster=${cluster}")" ]]; then echo 'ABORT: target cluster containers already exist'; exit 1; fi

cd "${base}"
# Pinned tools: verify the existing binaries against the published checksums; download if absent.
curl -fsSL --retry 3 -o kind.sha256sum "https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-linux-amd64.sha256sum"
curl -fsSL --retry 3 -o kubectl.sha256 "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl.sha256"
if ! echo "$(cut -d' ' -f1 kind.sha256sum)  ${tools}/kind" | sha256sum -c -; then
  curl -fL --retry 3 -o kind-linux-amd64 "https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-linux-amd64"
  echo "$(cut -d' ' -f1 kind.sha256sum)  kind-linux-amd64" | sha256sum -c -
  install -m 0700 kind-linux-amd64 "${tools}/kind"
fi
if ! echo "$(cat kubectl.sha256)  ${tools}/kubectl" | sha256sum -c -; then
  curl -fL --retry 3 -o kubectl "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl"
  echo "$(cat kubectl.sha256)  kubectl" | sha256sum -c -
  install -m 0700 kubectl "${tools}/kubectl"
fi
k() { "${tools}/kubectl" "$@"; }
"${tools}/kind" version
k version --client
cp "${here}/kind-forgery.yaml" "${here}/forgery-audit-policy.yaml" .
sha256sum kind-forgery.yaml forgery-audit-policy.yaml "${here}/forgery/probe.py" "${here}/forgery/echo.py" "${here}/forgery-summary.py"
echo "PINNED_IMAGE=${image}"

docker pull -q "${py_image}"
echo "PY_IMAGE_DIGEST=$(docker image inspect "${py_image}" --format '{{index .RepoDigests 0}}')"

created=1
"${tools}/kind" create cluster --name "${cluster}" --config kind-forgery.yaml --image "${image}" --kubeconfig "${KUBECONFIG}" --wait 5m
run_kind_network="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
"${tools}/kind" load docker-image "${py_image}" --name "${cluster}"
k wait --for=condition=Ready nodes --all --timeout=120s
k version -o json | python3 -c 'import json,sys; v=json.load(sys.stdin); print("SERVER_VERSION="+v["serverVersion"]["gitVersion"])'

k create namespace "${ns}"
k -n "${ns}" create serviceaccount probe-sa            # no RoleBinding: RBAC-less
k -n "${ns}" create configmap probe-code --from-file="${here}/forgery/probe.py" --from-file="${here}/forgery/echo.py"
k -n "${ns}" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: {name: echo, labels: {app: echo}}
spec:
  automountServiceAccountToken: false
  containers:
  - {name: echo, image: ${py_image}, imagePullPolicy: Never, command: [python, /app/echo.py],
     ports: [{containerPort: 8080}], volumeMounts: [{name: code, mountPath: /app}]}
  volumes: [{name: code, configMap: {name: probe-code}}]
---
apiVersion: v1
kind: Service
metadata: {name: echo}
spec: {selector: {app: echo}, ports: [{port: 8080, targetPort: 8080}]}
---
apiVersion: v1
kind: Pod
metadata: {name: prober}
spec:
  serviceAccountName: probe-sa
  restartPolicy: Never
  containers:
  - {name: prober, image: ${py_image}, imagePullPolicy: Never, command: [sh, -c, "sleep 5; python /app/probe.py"],
     volumeMounts: [{name: code, mountPath: /app}]}
  volumes: [{name: code, configMap: {name: probe-code}}]
EOF
k -n "${ns}" wait --for=condition=Ready pod/echo --timeout=120s
k -n "${ns}" wait --for=jsonpath='{.status.phase}'=Succeeded pod/prober --timeout=180s
k -n "${ns}" logs prober | grep '^RESULT ' > result.txt
k -n "${ns}" get pod prober -o json | python3 -c 'import json,sys; p=json.load(sys.stdin); print(json.dumps({"pod_uid": p["metadata"]["uid"], "pod_ip": p["status"]["podIP"], "sa": p["spec"]["serviceAccountName"]}))' > pod.json
k get nodes -o json | python3 -c 'import json,sys; f=json.load(open("pod.json")); f["node_ips"]=[a["address"] for n in json.load(sys.stdin)["items"] for a in n["status"]["addresses"] if a["type"]=="InternalIP"]; print(json.dumps(f))' > facts.json
sleep 3   # let the audit backend flush
docker exec "${cluster}-control-plane" cat /var/log/kubernetes/kube-apiserver-audit.log \
  | python3 "${here}/forgery-summary.py" result.txt facts.json > summary.json
cat summary.json
rm -f result.txt facts.json pod.json   # summary.json holds only redacted verdicts
echo "END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
