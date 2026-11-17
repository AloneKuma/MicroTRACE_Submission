#!/usr/bin/env bash
# Stop only the Postgres started by pg-up.sh (its own data folder).
# Pass --wipe to also delete the data folder and the generated credentials.
set -euo pipefail

: "${MT_DEV:?source env.sh first}"
DATA="$MT_DEV/pg-data"

if pg_ctl -D "$DATA" status > /dev/null 2>&1; then
  pg_ctl -D "$DATA" -m fast -w stop > /dev/null
  echo "postgres stopped"
else
  echo "postgres not running"
fi

if [ "${1:-}" = "--wipe" ]; then
  rm -rf "$DATA" "$MT_DEV/pg.env"
  echo "postgres data and credentials deleted"
fi
