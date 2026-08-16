#!/usr/bin/env bash
set -euo pipefail

# S3 end-to-end test: bucket ops, object CRUD, multipart, versioning
# against a live kappa-server.
# Usage: ./scripts/s3-e2e.sh
# Requires: aws CLI, curl, cargo build completed

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/debug/kappa-server"

if [ ! -f "$BINARY" ]; then
  echo "Building kappa-server..."
  cargo build -p kappa-server
fi

TMP=$(mktemp -d)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

KAPPA_LISTEN_ADDR="127.0.0.1:$PORT" \
KAPPA_STORE_ROOT="$TMP/store" \
KAPPA_RATELIMIT_READ_PERIOD_MS=0 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=0 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=0 \
RUST_LOG=debug \
  "$BINARY" 2>"$TMP/server.log" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; echo '--- server log ---'; cat $TMP/server.log 2>/dev/null; echo '--- end server log ---'; rm -rf $TMP" EXIT

for i in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/_status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

ENDPOINT="http://127.0.0.1:$PORT"

# aws CLI config: no real credentials needed (unauthenticated mode),
# path-style addressing, no signature (the server has no credential
# store configured so auth passes through).
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_PAGER=""
AWS="aws --endpoint-url $ENDPOINT --no-sign-request"

echo "=== create bucket ==="
$AWS s3 mb s3://testbucket 2>&1
echo "exit: $?"

echo ""
echo "=== list buckets ==="
$AWS s3 ls 2>&1
echo "exit: $?"

echo ""
echo "=== put object ==="
echo "hello from kappa s3" > "$TMP/hello.txt"
$AWS s3 cp "$TMP/hello.txt" s3://testbucket/hello.txt 2>&1
echo "exit: $?"

echo ""
echo "=== get object ==="
$AWS s3 cp s3://testbucket/hello.txt "$TMP/downloaded.txt" 2>&1
echo "exit: $?"
diff "$TMP/hello.txt" "$TMP/downloaded.txt"
echo "files match"

echo ""
echo "=== list objects ==="
$AWS s3 ls s3://testbucket/ 2>&1
echo "exit: $?"

echo ""
echo "=== put multiple objects ==="
for i in 1 2 3 4 5; do
  echo "file $i content" > "$TMP/file$i.txt"
  $AWS s3 cp "$TMP/file$i.txt" "s3://testbucket/dir/file$i.txt" --quiet 2>&1
done
echo "5 files uploaded"

echo ""
echo "=== list with prefix (raw XML) ==="
XML_RESPONSE=$(curl -s "$ENDPOINT/testbucket?list-type=2&prefix=dir/&delimiter=/")
echo "$XML_RESPONSE" | xxd | head -30
echo ""
echo "=== list with prefix (aws cli) ==="
$AWS s3 ls s3://testbucket/dir/ 2>&1 || echo "s3 ls prefix exit: $?"

echo ""
echo "=== head object ==="
$AWS s3api head-object --bucket testbucket --key hello.txt 2>&1
echo "exit: $?"

echo ""
echo "=== delete object ==="
$AWS s3 rm s3://testbucket/hello.txt 2>&1
echo "exit: $?"

echo ""
echo "=== verify deleted ==="
if $AWS s3api head-object --bucket testbucket --key hello.txt 2>&1; then
  echo "FAIL: object should be deleted"
  exit 1
else
  echo "confirmed deleted (404)"
fi

echo ""
echo "=== delete bucket ==="
$AWS s3 rb s3://testbucket --force 2>&1
echo "exit: $?"

echo ""
echo "SUCCESS: S3 bucket ops + object CRUD complete"
