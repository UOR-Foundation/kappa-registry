#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for the Nix binary cache protocol.
# Builds nixpkgs#hello, pushes to kappa-registry, and fetches it back.
# Requires: nix, curl, and a built kappa-server binary.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/release/kappa-server"

if [ ! -f "$BINARY" ]; then
    BINARY="$PROJECT_ROOT/target/debug/kappa-server"
fi
if [ ! -f "$BINARY" ]; then
    echo "kappa-server binary not found. Run: cargo build -p kappa-server"
    exit 1
fi

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
trap 'kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true; if [ "${FAILED:-0}" = "1" ]; then echo "--- server log ---"; tail -100 "$TMP/server.log" 2>/dev/null; echo "--- end server log ---"; fi; rm -rf "$TMP"' EXIT

echo "Waiting for server on port $PORT..."
for i in $(seq 1 50); do
    if curl -sf "http://127.0.0.1:$PORT/_status" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

ENDPOINT="http://127.0.0.1:$PORT"

echo ""
echo "=== nix-cache-info ==="
CACHE_INFO=$(curl -sf "$ENDPOINT/nix/nix-cache-info")
echo "$CACHE_INFO"
echo "$CACHE_INFO" | grep -q "StoreDir: /nix/store" || { echo "FAIL: missing StoreDir"; FAILED=1; exit 1; }
echo "$CACHE_INFO" | grep -q "WantMassQuery: 1" || { echo "FAIL: missing WantMassQuery"; FAILED=1; exit 1; }
echo "PASS"

echo ""
echo "=== build hello ==="
HELLO_PATH=$(nix build nixpkgs#hello --print-out-paths --no-link 2>/dev/null)
echo "built: $HELLO_PATH"

echo ""
echo "=== push to cache ==="
if nix copy --to "http://127.0.0.1:$PORT/nix" "$HELLO_PATH" 2>&1; then
    echo "push: PASS"
else
    echo "nix copy failed with exit $?"
    FAILED=1
    exit 1
fi

echo ""
echo "=== verify narinfo exists ==="
HASH=$(echo "$HELLO_PATH" | sed 's|/nix/store/||' | cut -c1-32)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT/nix/$HASH.narinfo")
echo "GET narinfo: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then
    echo "FAIL: expected 200, got $HTTP_CODE"
    FAILED=1
    exit 1
fi
echo "PASS"

echo ""
echo "=== fetch narinfo ==="
curl -sf "$ENDPOINT/nix/$HASH.narinfo"
echo ""

echo ""
echo "=== verify fetch from cache ==="
# Verify the NAR is fetchable via the URL in the narinfo
NAR_URL=$(curl -sf "$ENDPOINT/nix/$HASH.narinfo" | grep '^URL: ' | cut -c6-)
echo "NAR URL: $NAR_URL"
NAR_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT/nix/$NAR_URL")
echo "GET NAR: $NAR_CODE"
if [ "$NAR_CODE" != "200" ]; then
    echo "FAIL: expected 200, got $NAR_CODE"
    FAILED=1
    exit 1
fi
echo "PASS"

echo ""
echo "=== ALL PASSED ==="
