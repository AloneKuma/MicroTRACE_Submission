#!/usr/bin/env bash
# Delete the GRE test cluster microtrace-gre and nothing else
# (experiments/cluster/TEST-PLAN.md): no prune, no other cluster, the docker
# network "kind" only if gre-kind-up.sh created it and no other kind cluster
# uses it. Keeps $MT_DEV/gre-kind/up.log; removes the kubeconfigs and token.
set -uo pipefail

: "${MT_DEV:?source env.sh first}"
BASE="$MT_DEV/gre-kind"
CLUSTER=microtrace-gre
PATH="$HOME/microtrace-cluster/bin:$PATH"
fail=0

echo "PRE_ACTIVE_CONTAINERS=$(docker ps -q | wc -l)"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind delete cluster --name "$CLUSTER" || fail=1
fi
left="$(docker ps -aq --filter "label=io.x-k8s.kind.cluster=$CLUSTER")"
if [ -n "$left" ]; then
  echo "TEARDOWN ERROR: $CLUSTER node containers remain"
  fail=1
else
  echo "no $CLUSTER node containers remain"
fi
if [ "$(cat "$BASE/kind-network" 2>/dev/null)" = created ] && [ -z "$(kind get clusters 2>/dev/null)" ]; then
  docker network rm kind > /dev/null 2>&1 && echo "removed the kind network this script created"
fi
rm -f "$BASE/admin.kubeconfig" "$BASE/executor.kubeconfig" "$BASE/gre.env" "$BASE/kind-network"
echo "POST_ACTIVE_CONTAINERS=$(docker ps -q | wc -l)"
exit "$fail"
