#!/usr/bin/env bash
set -euo pipefail

# Manage a local kappa-registry instance for development and testing.
#
# Usage:
#   ./scripts/service.sh --start              Start registry on localhost:5000
#   ./scripts/service.sh --stop               Stop the running registry
#   ./scripts/service.sh --status             Show registry status
#   ./scripts/service.sh --logs               Tail the registry log
#   ./scripts/service.sh --clean              Remove log and pid files
#   ./scripts/service.sh --clean --force      Also remove the store directory
#
# Prerequisites:
#   cargo build --release

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REGISTRY_BIN="${REPO_ROOT}/target/release/kappa-registry"
RUN_DIR="${REPO_ROOT}/tmp"
PID_FILE="${RUN_DIR}/registry.pid"
LOG_FILE="${RUN_DIR}/registry.log"
STORE_FILE="${RUN_DIR}/registry.store"
ADDR="${KAPPA_LISTEN_ADDR:-127.0.0.1:5000}"

usage() {
    sed -n '3,12p' "$0" | sed 's/^# \?//'
    exit 1
}

require_binary() {
    if [[ ! -x "${REGISTRY_BIN}" ]]; then
        echo "error: registry binary not found at ${REGISTRY_BIN}"
        echo "run: cargo build --release"
        exit 1
    fi
}

read_pid() {
    if [[ -f "${PID_FILE}" ]]; then
        cat "${PID_FILE}"
    else
        echo ""
    fi
}

is_running() {
    local pid
    pid="$(read_pid)"
    [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

do_start() {
    require_binary
    if is_running; then
        echo "registry already running (pid $(read_pid))"
        exit 1
    fi

    mkdir -p "${RUN_DIR}"

    local store_dir
    if [[ -f "${STORE_FILE}" ]]; then
        store_dir="$(cat "${STORE_FILE}")"
        if [[ ! -d "${store_dir}" ]]; then
            store_dir="$(mktemp -d)"
            echo "${store_dir}" > "${STORE_FILE}"
        fi
    else
        store_dir="$(mktemp -d)"
        echo "${store_dir}" > "${STORE_FILE}"
    fi

    KAPPA_STORE_ROOT="${store_dir}" \
    KAPPA_LISTEN_ADDR="${ADDR}" \
    KAPPA_RATELIMIT_READ_PERIOD_MS="${KAPPA_RATELIMIT_READ_PERIOD_MS:-0}" \
    KAPPA_RATELIMIT_WRITE_PERIOD_MS="${KAPPA_RATELIMIT_WRITE_PERIOD_MS:-0}" \
    KAPPA_RATELIMIT_ADMIN_PERIOD_MS="${KAPPA_RATELIMIT_ADMIN_PERIOD_MS:-0}" \
    RUST_LOG="${RUST_LOG:-kappa_registry=info}" \
        "${REGISTRY_BIN}" >"${LOG_FILE}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PID_FILE}"

    for i in $(seq 1 30); do
        if curl -s -o /dev/null "http://${ADDR}/v2/" 2>/dev/null; then
            break
        fi
        if [[ $i -eq 30 ]]; then
            echo "error: registry did not start within 3 seconds"
            kill "${pid}" 2>/dev/null || true
            rm -f "${PID_FILE}"
            exit 1
        fi
        sleep 0.1
    done

    echo "registry running"
    echo "  pid:    ${pid}"
    echo "  listen: ${ADDR}"
    echo "  store:  ${store_dir}"
    echo "  log:    ${LOG_FILE}"
}

do_stop() {
    local pid
    pid="$(read_pid)"
    if [[ -z "${pid}" ]]; then
        echo "registry not running (no pid file)"
        return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
        echo "registry not running (stale pid ${pid})"
        rm -f "${PID_FILE}"
        return 0
    fi
    kill "${pid}"
    local waited=0
    while kill -0 "${pid}" 2>/dev/null && [[ ${waited} -lt 50 ]]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    if kill -0 "${pid}" 2>/dev/null; then
        echo "registry did not exit within 5 seconds, sending SIGKILL"
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
    echo "registry stopped (pid ${pid})"
}

do_status() {
    local pid
    pid="$(read_pid)"
    if [[ -z "${pid}" ]]; then
        echo "registry not running (no pid file)"
        return 1
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        echo "registry running (pid ${pid})"
        if [[ -f "${STORE_FILE}" ]]; then
            echo "  store: $(cat "${STORE_FILE}")"
        fi
        echo "  log:   ${LOG_FILE}"
        return 0
    else
        echo "registry not running (stale pid ${pid})"
        return 1
    fi
}

do_logs() {
    if [[ ! -f "${LOG_FILE}" ]]; then
        echo "no log file at ${LOG_FILE}"
        exit 1
    fi
    cat "${LOG_FILE}"
}

do_clean() {
    local force="${1:-}"
    if is_running; then
        echo "error: registry is running, stop it first"
        exit 1
    fi
    rm -f "${PID_FILE}" "${LOG_FILE}"
    echo "removed pid and log files"
    if [[ "${force}" == "--force" ]]; then
        if [[ -f "${STORE_FILE}" ]]; then
            local store_dir
            store_dir="$(cat "${STORE_FILE}")"
            if [[ -d "${store_dir}" ]]; then
                rm -rf "${store_dir}"
                echo "removed store: ${store_dir}"
            fi
            rm -f "${STORE_FILE}"
        fi
    fi
}

if [[ $# -eq 0 ]]; then
    usage
fi

case "${1}" in
    --start)  do_start ;;
    --stop)   do_stop ;;
    --status) do_status ;;
    --logs)   do_logs ;;
    --clean)  do_clean "${2:-}" ;;
    --help)   usage ;;
    *)        echo "unknown option: ${1}"; usage ;;
esac
