#!/usr/bin/env bash
set -euo pipefail

: "${INFLUX_URL:?set INFLUX_URL, e.g. https://influx.example.com}"
: "${INFLUX_ORG:?set INFLUX_ORG}"
: "${INFLUX_BUCKET:?set INFLUX_BUCKET}"
: "${INFLUX_TOKEN:?set INFLUX_TOKEN}"

export SERVER_TAG="${SERVER_TAG:-$(hostname -s)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/ookla_tail_to_influx.py" | \
curl -sS --fail \
  -X POST "${INFLUX_URL}/api/v2/write?org=${INFLUX_ORG}&bucket=${INFLUX_BUCKET}&precision=s" \
  -H "Authorization: Token ${INFLUX_TOKEN}" \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary @-
