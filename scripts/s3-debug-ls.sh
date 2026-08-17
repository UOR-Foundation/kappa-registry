#!/usr/bin/env bash
set -euo pipefail

# Minimal reproduction: start server, create bucket, put file, aws s3 ls with --debug
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/debug/kappa-server"

TMP=$(mktemp -d)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

KAPPA_LISTEN_ADDR="127.0.0.1:$PORT" \
KAPPA_STORE_ROOT="$TMP/store" \
KAPPA_RATELIMIT_READ_PERIOD_MS=0 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=0 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=0 \
RUST_LOG=warn \
  "$BINARY" 2>"$TMP/server.log" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; rm -rf $TMP" EXIT

for i in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/_status" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

ENDPOINT="http://127.0.0.1:$PORT"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_PAGER=""
AWS="aws --endpoint-url $ENDPOINT --no-sign-request"

$AWS s3 mb s3://testbucket 2>&1
echo "hello" > "$TMP/hello.txt"
$AWS s3 cp "$TMP/hello.txt" s3://testbucket/dir/hello.txt --quiet 2>&1

echo ""
echo "=== aws s3 ls with --debug ==="
$AWS s3 ls s3://testbucket/dir/ --debug 2>&1 | tail -60
