#!/usr/bin/env bash
# Triggers the golden cross-zone incident. Authenticates the way a real caller
# would: either a service token, or an operator login.
#
# Logins now return a session cookie rather than a token, so the cookie jar is
# carried through the call and the CSRF value is echoed back in a header.
set -euo pipefail

API="${API_URL:-http://localhost:8000}"
TICKET="${TICKET_ID:-INC-1001}"
BODY="{\"ticket_id\":\"$TICKET\",\"description\":\"Web_App cannot reach DB_Primary:443\",\"severity\":\"high\"}"

if [[ -n "${SERVICE_TOKEN:-}" ]]; then
  curl -sS -X POST "$API/api/v1/incidents/trigger" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $SERVICE_TOKEN" \
    -d "$BODY"
else
  EMAIL="${ZERONODE_EMAIL:-${BOOTSTRAP_ADMIN_EMAIL:-admin@example.com}}"
  PASSWORD="${ZERONODE_PASSWORD:-${BOOTSTRAP_ADMIN_PASSWORD:-}}"
  TOTP="${ZERONODE_TOTP:-}"
  if [[ -z "$PASSWORD" ]]; then
    echo "Set SERVICE_TOKEN, or ZERONODE_PASSWORD for $EMAIL, to authenticate." >&2
    exit 1
  fi

  JAR=$(mktemp)
  trap 'rm -f "$JAR"' EXIT

  CSRF=$(curl -sS -X POST "$API/api/v1/auth/login" -c "$JAR" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"totp_code\":\"$TOTP\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')

  curl -sS -X POST "$API/api/v1/incidents/trigger" -b "$JAR" \
    -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $CSRF" \
    -d "$BODY"
fi

echo
echo "Open http://localhost:3000/incidents/$TICKET"
