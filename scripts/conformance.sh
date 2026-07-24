#!/usr/bin/env bash
set -euo pipefail

# Run the kappa-conformance binary against a locally started kappa-registry.
# Usage: ./scripts/conformance.sh
#
# Prerequisites:
#   - kappa-registry built:  cargo build --release
#   - kappa-conformance built in ../kappa-distribution: cargo build --release

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFORMANCE_ROOT="$(cd "${REPO_ROOT}/../kappa-distribution" && pwd)"

REGISTRY_BIN="${REPO_ROOT}/target/release/kappa-registry"
CONFORMANCE_BIN="${CONFORMANCE_ROOT}/target/release/kappa-conformance"

if [[ ! -x "${REGISTRY_BIN}" ]]; then
    echo "error: registry binary not found at ${REGISTRY_BIN}"
    echo "run: cargo build --release"
    exit 1
fi

if [[ ! -x "${CONFORMANCE_BIN}" ]]; then
    echo "error: conformance binary not found at ${CONFORMANCE_BIN}"
    echo "run: cd ../kappa-distribution && cargo build --release"
    exit 1
fi

STORE_DIR="$(mktemp -d)"
PORT=9877
ADDR="127.0.0.1:${PORT}"
REPORT_DIR="${REPO_ROOT}/tmp/conformance-report"

cleanup() {
    if [[ -n "${REGISTRY_PID:-}" ]]; then
        kill "${REGISTRY_PID}" 2>/dev/null || true
        wait "${REGISTRY_PID}" 2>/dev/null || true
    fi
    # Preserve store for post-mortem. Cleaned up by the next run.
}
trap cleanup EXIT

echo "starting registry on ${ADDR} with store at ${STORE_DIR}"
KAPPA_STORE_ROOT="${STORE_DIR}" \
KAPPA_LISTEN_ADDR="${ADDR}" \
KAPPA_RATELIMIT_READ_PERIOD_MS=1000 \
KAPPA_RATELIMIT_READ_BURST=400 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=1000 \
KAPPA_RATELIMIT_WRITE_BURST=400 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=1000 \
KAPPA_RATELIMIT_ADMIN_BURST=400 \
RUST_LOG="${RUST_LOG:-kappa_registry=info}" \
    "${REGISTRY_BIN}" &
REGISTRY_PID=$!

# Wait for the registry to accept connections.
for i in $(seq 1 30); do
    if curl -s -o /dev/null "http://${ADDR}/v2/" 2>/dev/null; then
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "error: registry did not start within 3 seconds"
        exit 1
    fi
    sleep 0.1
done

echo "registry running (pid ${REGISTRY_PID})"
echo "running conformance suite..."
echo ""

mkdir -p "${REPORT_DIR}"

KAPPA_REGISTRY_URL="http://${ADDR}" \
KAPPA_NAMESPACE="_conformance/test/v1:conformance" \
KAPPA_TEST_LEVELS=1,2,3,4,5 \
KAPPA_TEARDOWN_ENABLED=true \
KAPPA_TEARDOWN_ORDER=tags-first \
KAPPA_REPORT_DIR="${REPORT_DIR}" \
    "${CONFORMANCE_BIN}"

EXIT_CODE=$?

echo ""
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo "conformance: PASS"
else
    echo "conformance: FAIL (exit ${EXIT_CODE})"
fi

echo "reports: ${REPORT_DIR}"
echo "store:   ${STORE_DIR}"
exit ${EXIT_CODE}
