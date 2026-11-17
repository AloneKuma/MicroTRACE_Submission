#!/usr/bin/env bash
# Exp. 5 part B (graph consistency and GRE) on the kind node. Settings: experiments/exp5/SETTINGS.md
# (user 2026-11-16). Run after bootstrap.sh, as ubuntu:
#
#   . ~/mt-env.sh; BUCKET=<work> SESSION=exp5 nohup bash code/experiments/exp5/run_exp5_kind.sh > exp5b.out 2>&1 &
#
# 1 toolchain: setup-dev-host.sh; kind v0.33.0 and kubectl v1.35.8 (published checksums) into
#   ~/microtrace-cluster/bin; gre-kind-up.sh (kind + Calico + audit policy + GRE identities, RBAC,
#   admission policies, test workloads from src/k8s/gre/).
# 2 suite: every GRE test (unit and kube: mutations, compromised executor, interrupted submissions
#   by failpoint, postconditions incl. the accepted-but-ineffective case, guard ablation), and the
#   TGS tests (tgs-contract.md section 8). The toxiproxy API-fault cases were never built and are
#   not run (disclosed; user 2026-11-16).
# 3 sequences: 1,000 randomised sequences from seed 1 (40 steps), then each guard ablated alone
#   (200 sequences from seed 1, the runner's default count): the full GRE must violate nothing,
#   each ablation must violate its named property.
# Output: s3://$BUCKET/results/$SESSION/partB/. The machine shuts down at the end.
set -uo pipefail
: "${BUCKET:?}" "${SESSION:?}"
CODE=${CODE:-$HOME/code}; OUT=${OUT:-$HOME/exp5b}; AUTO_SHUTDOWN=${AUTO_SHUTDOWN:-1}
export MT_DEV=${MT_DEV:-$HOME/microtrace-dev}
R="s3://$BUCKET/results/$SESSION/partB"
KIND_VERSION=v0.33.0; KUBECTL_VERSION=v1.35.8
mkdir -p "$OUT"; S=$OUT/STATUS
st() { echo "$(date -u +%FT%TZ) $*" | tee -a "$S"; aws s3 cp --only-show-errors "$S" "$R/STATUS" < /dev/null; }
ARMED=0   # shut down only once the cluster is up; a setup failure leaves the machine running
finish() { aws s3 sync --only-show-errors "$OUT" "$R" < /dev/null; if [ "$AUTO_SHUTDOWN" = 1 ] && [ "$ARMED" = 1 ]; then st "SHUTDOWN"; sudo shutdown -h now; else st "STOPPED (machine left running)"; fi; }
stop() { st "FAILED $*"; exit 1; }
trap finish EXIT
[ -z "$(git -C "$CODE" status --porcelain --untracked-files=no)" ] || stop "code tree has local changes"
st "START part B, code $(git -C "$CODE" rev-parse --short HEAD)"

# 1. Toolchain and cluster.
# Postgres 17 configure needs bison and flex even from a release tarball (found 2026-11-16).
sudo apt-get install -y -q bison flex > "$OUT/apt.log" 2>&1 || stop "apt-get bison flex"
bash "$CODE/src/scripts/setup-dev-host.sh" > "$OUT/toolchain.log" 2>&1     || { cp -r "$MT_DEV/logs" "$OUT/toolchain-logs" 2>/dev/null; stop "setup-dev-host.sh (toolchain.log, toolchain-logs/; machine left running)"; }
. "$MT_DEV/env.sh"
export PATH="$CODE/.venv/bin:$PATH" VIRTUAL_ENV="$CODE/.venv" PYTHONPATH=$CODE/src/python PYTHONHASHSEED=1
PY=$CODE/.venv/bin/python
B=$HOME/microtrace-cluster/bin; mkdir -p "$B"
if [ ! -x "$B/kind" ]; then
  curl -fsSL --retry 3 -o /tmp/kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" \
    && curl -fsSL --retry 3 -o /tmp/kind.sha "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64.sha256sum" \
    && [ "$(sha256sum /tmp/kind | cut -d' ' -f1)" = "$(cut -d' ' -f1 /tmp/kind.sha)" ] \
    && install -m 755 /tmp/kind "$B/kind" || stop "kind $KIND_VERSION download or checksum"
fi
if [ ! -x "$B/kubectl" ]; then
  curl -fsSL --retry 3 -o /tmp/kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" \
    && curl -fsSL --retry 3 -o /tmp/kubectl.sha "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl.sha256" \
    && [ "$(sha256sum /tmp/kubectl | cut -d' ' -f1)" = "$(tr -d ' \n' < /tmp/kubectl.sha)" ] \
    && install -m 755 /tmp/kubectl "$B/kubectl" || stop "kubectl $KUBECTL_VERSION download or checksum"
fi
export PATH="$B:$PATH"
bash "$CODE/src/scripts/gre-kind-up.sh" > "$OUT/kind-up.log" 2>&1 || stop "gre-kind-up.sh (kind-up.log)"
. "$MT_DEV/gre-kind/gre.env"
ARMED=1
st "CLUSTER up ($(kind version | head -1); $(kubectl version --client | head -1))"

# 2. Test suite (pytest junit XML kept for the paper's table). The TGS and GRE store tests need
# the dev Kafka and Postgres (their DSNs come from $MT_DEV/pg.env).
bash "$CODE/src/scripts/kafka-up.sh" > "$OUT/kafka-up.log" 2>&1 || stop "kafka-up.sh"
bash "$CODE/src/scripts/pg-up.sh" > "$OUT/pg-up.log" 2>&1 || stop "pg-up.sh"
. "$MT_DEV/pg.env"
# A fresh machine lacks what a long-lived dev host already has (part B run 2026-11-16): the Kafka
# topics (auto-create is off) and the TGS tables, which TGS ingest creates on first start.
"$PY" -m mtcore.kafka_topics --bootstrap 127.0.0.1:9092 > "$OUT/topics.log" 2>&1 || stop "kafka topics (topics.log)"
"$PY" -c "import os, psycopg; from mtcore.tgs.store import PgStore; PgStore(psycopg.connect(os.environ['MT_TGS_DSN'])).apply_schema()" \
  > "$OUT/tgs-schema.log" 2>&1 || stop "TGS schema (tgs-schema.log)"
(cd "$CODE/src/python" && "$PY" -m pytest -q -rs --junitxml="$OUT/gre-suite.xml" tests/test_gre_*.py tests/test_tgs*.py) \
  > "$OUT/gre-suite.log" 2>&1
rc=$?
st "SUITE exit $rc: $(tail -1 "$OUT/gre-suite.log")"
grep -q "skipped" "$OUT/gre-suite.log" && st "SUITE note: skips listed in gre-suite.log (-rs)"

# 3. Randomised sequences: the full GRE, then each guard ablated alone.
(cd "$CODE/src/python" && "$PY" -m mtcore.harness.gre_sequences --seeds 1000 --first-seed 1 --steps 40) \
  > "$OUT/sequences-full.json" 2> "$OUT/sequences-full.err"
st "SEQUENCES full exit $? (0 = no property violated)"
for g in $("$PY" -c "from mtcore.gre.validate import GUARDS;print(' '.join(GUARDS))"); do
  (cd "$CODE/src/python" && "$PY" -m mtcore.harness.gre_sequences --seeds 200 --first-seed 1 --steps 40 --ablate "$g") \
    > "$OUT/sequences-no-$g.json" 2> "$OUT/sequences-no-$g.err"
  st "SEQUENCES no-$g exit $? (1 = a property violated, as the ablation must)"
done
bash "$CODE/src/scripts/gre-kind-down.sh" > "$OUT/kind-down.log" 2>&1
st "ALL_DONE"
