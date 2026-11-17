#!/usr/bin/env bash
set -Eeuo pipefail

cluster=microtrace-smoke
probe=microtrace-smoke-probe
base="${HOME}/microtrace-cluster"
kind_version=v0.33.0
k8s_version=v1.35.8
image='kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
created=0
prior_kind_network="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
run_kind_network=''

mkdir -p "${base}/bin"
umask 077
exec > >(tee "${base}/run.log") 2>&1
export KUBECONFIG="${base}/kubeconfig"

cleanup() {
  result=$?
  trap - EXIT
  if [[ "${created}" == 1 ]]; then
    echo 'TEARDOWN: deleting only microtrace-smoke'
    if ! "${base}/bin/kind" delete cluster --name "${cluster}"; then
      echo 'TEARDOWN ERROR: kind delete failed'
      result=1
    fi
    rm -f -- "${KUBECONFIG}"
  fi
  leftover="$(docker ps -aq --filter "label=io.x-k8s.kind.cluster=${cluster}")"
  if [[ -n "${leftover}" ]]; then
    echo 'TEARDOWN ERROR: cluster node containers remain'
    result=1
  else
    echo 'TEARDOWN: no microtrace-smoke node containers remain'
  fi
  if [[ -z "${prior_kind_network}" && -n "${run_kind_network}" ]]; then
    current_kind_network="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
    if [[ "${current_kind_network}" == "${run_kind_network}" ]]; then
      if ! docker network rm "${run_kind_network}"; then
        echo 'TEARDOWN ERROR: run-created kind network remains'
        result=1
      fi
    fi
  fi
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
echo "PRE_ACTIVE_CONTAINERS=$(docker ps -q | wc -l)"
free -h
df -h /
if [[ "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)" -lt 6291456 ]]; then
  echo 'ABORT: less than 6 GiB memory available'
  exit 1
fi
if [[ "$(df --output=avail -BG / | tail -1 | tr -dc '0-9')" -lt 20 ]]; then
  echo 'ABORT: less than 20 GiB disk available'
  exit 1
fi
if [[ -n "$(docker ps -aq --filter "label=io.x-k8s.kind.cluster=${cluster}")" ]]; then
  echo 'ABORT: target cluster containers already exist'
  exit 1
fi

cd "${base}"
curl -fL --retry 3 -o kind-linux-amd64 "https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-linux-amd64"
curl -fL --retry 3 -o kind-linux-amd64.sha256sum "https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}/kind-linux-amd64.sha256sum"
sha256sum -c kind-linux-amd64.sha256sum
install -m 0700 kind-linux-amd64 bin/kind
bin/kind version

curl -fL --retry 3 -o kubectl "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl"
curl -fL --retry 3 -o kubectl.sha256 "https://dl.k8s.io/release/${k8s_version}/bin/linux/amd64/kubectl.sha256"
echo "$(cat kubectl.sha256)  kubectl" | sha256sum -c -
install -m 0700 kubectl bin/kubectl
bin/kubectl version --client
sha256sum kind-smoke.yaml smoke-audit-policy.yaml
echo "PINNED_IMAGE=${image}"

created=1
bin/kind create cluster --name "${cluster}" --config kind-smoke.yaml --image "${image}" --kubeconfig "${KUBECONFIG}" --wait 5m
run_kind_network="$(docker network inspect kind --format '{{.Id}}' 2>/dev/null || true)"
bin/kubectl wait --for=condition=Ready nodes --all --timeout=120s
bin/kubectl get nodes -o wide
bin/kubectl version -o json | python3 -c 'import json,sys; v=json.load(sys.stdin); print("CLIENT_VERSION="+v["clientVersion"]["gitVersion"]); print("SERVER_VERSION="+v["serverVersion"]["gitVersion"])'
docker exec "${cluster}-control-plane" test -s /etc/kubernetes/policies/audit-policy.yaml
docker exec "${cluster}-control-plane" grep -- '--audit-' /etc/kubernetes/manifests/kube-apiserver.yaml

bin/kubectl create namespace "${probe}"
bin/kubectl get namespace "${probe}" -o name
bin/kubectl delete namespace "${probe}" --wait=true
docker exec "${cluster}-control-plane" cat /var/log/kubernetes/kube-apiserver-audit.log | python3 audit-summary.py "${probe}"

echo "END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
