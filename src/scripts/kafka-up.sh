#!/usr/bin/env bash
# Start a single-node Kafka (KRaft) for development, bound to 127.0.0.1 only.
# Data, config, log and pid live under $MT_DEV. Needs: source $MT_DEV/env.sh
set -euo pipefail

: "${MT_DEV:?source env.sh first}"
CONF="$MT_DEV/kafka-server.properties"
DATA="$MT_DEV/kafka-data"
PID="$MT_DEV/kafka.pid"
PORT="${MT_KAFKA_PORT:-9092}"
CPORT="${MT_KAFKA_CONTROLLER_PORT:-9093}"

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  echo "kafka already running (pid $(cat "$PID"))"
  exit 0
fi

cat > "$CONF" <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=127.0.0.1:$CPORT
listeners=PLAINTEXT://127.0.0.1:$PORT,CONTROLLER://127.0.0.1:$CPORT
advertised.listeners=PLAINTEXT://127.0.0.1:$PORT,CONTROLLER://127.0.0.1:$CPORT
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
log.dirs=$DATA
auto.create.topics.enable=false
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
share.coordinator.state.topic.replication.factor=1
share.coordinator.state.topic.min.isr=1
group.initial.rebalance.delay.ms=0
EOF

if [ ! -f "$DATA/meta.properties" ]; then
  kafka-storage.sh format --standalone -t "$(kafka-storage.sh random-uuid)" -c "$CONF"
fi

KAFKA_HEAP_OPTS="${KAFKA_HEAP_OPTS:--Xms512m -Xmx1g}" \
  nohup kafka-server-start.sh "$CONF" > "$MT_DEV/logs/kafka.log" 2>&1 &
echo $! > "$PID"

for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    echo "kafka up on 127.0.0.1:$PORT (pid $(cat "$PID"))"
    exit 0
  fi
  sleep 1
done
echo "kafka did not start; see $MT_DEV/logs/kafka.log" >&2
exit 1
