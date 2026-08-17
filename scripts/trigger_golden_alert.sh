#!/usr/bin/env bash
set -euo pipefail
curl -sS -X POST http://localhost:8000/api/v1/incidents/trigger \
  -H 'Content-Type: application/json' \
  -d '{"ticket_id":"INC-1001","description":"Web_App cannot reach DB_Primary:443","severity":"high"}'
echo
echo "Open http://localhost:3000/incidents/INC-1001"
