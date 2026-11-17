#!/usr/bin/env bash
# Stop only the Kafka started by kafka-up.sh (by its pid file). Never uses
# kafka-server-stop.sh, which would stop every Kafka on a shared host.
# Pass --wipe to also delete the data folder.
set -euo pipefail

: "${MT_DEV:?source env.sh first}"
PID="$MT_DEV/kafka.pid"

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  kill "$(cat "$PID")"
  for _ in $(seq 1 30); do
    kill -0 "$(cat "$PID")" 2>/dev/null || break
    sleep 1
  done
  echo "kafka stopped"
else
  echo "kafka not running"
fi
rm -f "$PID"

if [ "${1:-}" = "--wipe" ]; then
  rm -rf "$MT_DEV/kafka-data"
  echo "kafka data deleted"
fi
