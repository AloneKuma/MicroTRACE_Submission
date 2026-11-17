#!/usr/bin/env bash
# Single pinned KRaft broker for the slice, on the host network bound to loopback only.
# Usage: kafka.sh start RUN_LABEL | topics RUN_LABEL | stop RUN_LABEL
set -Eeuo pipefail
readonly KAFKA_IMAGE='apache/kafka:4.2.0@sha256:9516fb7634bad307d17c33b589fde9023003b0cb761374f500002b980a3149b9'
readonly BOOT=127.0.0.1:19092
cmd="${1:?start|topics|stop}"
label="${2:?run label}"
name="mt-slice-kafka-${label,,}"
topics=(raw.audit.v0 context.cluster.v0 norm.events.v0 agent.H.audit.v0 findings.v0 incidents.v0
        source.completeness.v0 rule.evaluations.v0 replay.norm.events.v0 replay.agent.H.audit.v0
        replay.findings.v0 replay.incidents.v0 replay.rule.evaluations.v0)
kt() { docker exec "${name}" /opt/kafka/bin/kafka-topics.sh --bootstrap-server "${BOOT}" "$@"; }

case "${cmd}" in
  start)
    if ss -ltn | grep -qE '127\.0\.0\.1:1909[23] |\*:1909[23] |0\.0\.0\.0:1909[23] '; then
      echo 'ABORT: port 19092/19093 already in use'; exit 1
    fi
    docker run -d --name "${name}" --label "microtrace.slice.run=${label}" --network host \
      -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
      -e KAFKA_LISTENERS=PLAINTEXT://127.0.0.1:19092,CONTROLLER://127.0.0.1:19093 \
      -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:19092 \
      -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
      -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
      -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@127.0.0.1:19093 \
      -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
      -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
      -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=false "${KAFKA_IMAGE}" >/dev/null
    for _ in $(seq 90); do kt --list >/dev/null 2>&1 && break; sleep 1; done
    kt --list >/dev/null
    echo "KAFKA_VERSION=$(docker exec "${name}" /opt/kafka/bin/kafka-topics.sh --version 2>/dev/null | head -1)"
    ;;
  topics)
    for t in "${topics[@]}"; do
      kt --create --topic "${t}" --partitions 3 --replication-factor 1 \
        --config retention.ms=86400000 --config retention.bytes=1073741824 >/dev/null
    done
    echo "TOPICS=$(kt --list | grep -c .)"
    ;;
  stop)
    ids="$(docker ps -aq --filter "label=microtrace.slice.run=${label}" --filter "name=^${name}$")"
    [[ -z "${ids}" ]] || docker rm -f ${ids} >/dev/null
    echo "KAFKA_REMOVED=${name}"
    ;;
esac
