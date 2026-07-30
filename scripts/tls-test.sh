#!/usr/bin/env bash
set -euo pipefail

# Generate self-signed cert, start server with TLS, probe readiness,
# print diagnostics on failure.

CERTDIR=$(mktemp -d)
STOREDIR=$(mktemp -d)
PORT=9876

trap 'kill $PID 2>/dev/null; rm -rf "$CERTDIR" "$STOREDIR"' EXIT

echo "=== Generating self-signed cert ==="
openssl req -x509 -newkey rsa:2048 \
  -keyout "$CERTDIR/test.key" \
  -out "$CERTDIR/test.crt" \
  -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
echo "cert: $CERTDIR/test.crt"
echo "key:  $CERTDIR/test.key"
ls -la "$CERTDIR/"

echo ""
echo "=== Starting kappa-server with TLS ==="
KAPPA_LISTEN_ADDR="127.0.0.1:$PORT" \
KAPPA_STORE_ROOT="$STOREDIR" \
KAPPA_TLS_CERT="$CERTDIR/test.crt" \
KAPPA_TLS_KEY="$CERTDIR/test.key" \
KAPPA_RATELIMIT_READ_PERIOD_MS=0 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=0 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=0 \
RUST_LOG=debug \
  ./target/debug/kappa-server &
PID=$!

echo "server pid: $PID"
echo ""

echo "=== Waiting for readiness ==="
for i in $(seq 1 50); do
  sleep 0.1
  if ! kill -0 $PID 2>/dev/null; then
    echo "FAIL: server process exited early (after ${i}00ms)"
    wait $PID 2>/dev/null || true
    exit 1
  fi
  if curl -sk "https://127.0.0.1:$PORT/_status" 2>/dev/null; then
    echo ""
    echo "PASS: server ready on HTTPS after ${i}00ms"
    echo ""
    echo "=== Testing blob PUT/GET ==="
    DIGEST=$(echo -n "tls-test" | sha256sum | cut -d' ' -f1)
    curl -sk -X PUT -d "tls-test" "https://127.0.0.1:$PORT/v2/test/blobs/sha256:$DIGEST" -w "\nPUT status: %{http_code}\n"
    curl -sk "https://127.0.0.1:$PORT/v2/test/blobs/sha256:$DIGEST" -w "\nGET status: %{http_code}\n"
    exit 0
  fi
done

echo "FAIL: server did not become ready within 5 seconds"
echo ""
echo "=== server stderr (if captured) ==="
echo "(stderr was sent to terminal above)"
exit 1
