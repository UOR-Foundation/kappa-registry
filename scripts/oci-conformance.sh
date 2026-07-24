#!/usr/bin/env bash
set -euo pipefail

# Run the OCI distribution-spec conformance binary against a locally started kappa-registry.
# Usage: ./scripts/oci-conformance.sh
#
# Prerequisites:
#   - kappa-registry built:  cargo build --release
#   - OCI conformance binary built:
#       cd ../distribution-spec/conformance && go build -o /tmp/oci-conformance .

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OCI_SPEC_ROOT="${REPO_ROOT}/../../opencontainers/distribution-spec/conformance"

REGISTRY_BIN="${REPO_ROOT}/target/release/kappa-registry"
OCI_BIN="${OCI_BIN:-/tmp/oci-conformance}"

if [[ ! -x "${REGISTRY_BIN}" ]]; then
    echo "error: registry binary not found at ${REGISTRY_BIN}"
    echo "run: cargo build --release"
    exit 1
fi

if [[ ! -x "${OCI_BIN}" ]]; then
    echo "OCI conformance binary not found at ${OCI_BIN}"
    if [[ -d "${OCI_SPEC_ROOT}" ]]; then
        echo "building from ${OCI_SPEC_ROOT}..."
        (cd "${OCI_SPEC_ROOT}" && go build -o "${OCI_BIN}" .)
    else
        echo "error: cannot find distribution-spec source at ${OCI_SPEC_ROOT}"
        echo "clone: git clone https://github.com/opencontainers/distribution-spec.git"
        exit 1
    fi
fi

STORE_DIR="$(mktemp -d)"
PORT=9878
ADDR="127.0.0.1:${PORT}"
REPORT_DIR="${REPO_ROOT}/tmp/oci-conformance-report"

cleanup() {
    if [[ -n "${REGISTRY_PID:-}" ]]; then
        kill "${REGISTRY_PID}" 2>/dev/null || true
        wait "${REGISTRY_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "starting registry on ${ADDR} with store at ${STORE_DIR}"
REG_LOG="${REPORT_DIR}/registry.log"
KAPPA_STORE_ROOT="${STORE_DIR}" \
KAPPA_LISTEN_ADDR="${ADDR}" \
KAPPA_RATELIMIT_READ_PERIOD_MS=0 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=0 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=0 \
RUST_LOG="${RUST_LOG:-kappa_registry=warn}" \
    "${REGISTRY_BIN}" 2>"${REG_LOG}" &
REGISTRY_PID=$!

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
echo "running OCI distribution-spec conformance suite..."
echo ""

mkdir -p "${REPORT_DIR}"

OCI_REGISTRY="${ADDR}" \
OCI_TLS=disabled \
OCI_REPO1=conformance/repo1 \
OCI_REPO2=conformance/repo2 \
OCI_API_PULL=true \
OCI_API_PUSH=true \
OCI_API_TAG_LIST=true \
OCI_API_TAG_DELETE=true \
OCI_API_MANIFEST_DELETE=true \
OCI_API_BLOB_DELETE=true \
OCI_API_REFERRER=true \
OCI_RESULTS_DIR="${REPORT_DIR}" \
OCI_LOG=warn \
    "${OCI_BIN}"

EXIT_CODE=$?

echo ""
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo "OCI conformance: PASS"
else
    echo "OCI conformance: FAIL (exit ${EXIT_CODE})"
fi

echo "reports: ${REPORT_DIR}"
echo "store:   ${STORE_DIR}"
exit ${EXIT_CODE}
