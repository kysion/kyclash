#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TART_VERSION="2.32.1"
readonly BASE_VM="kyclash-macos-lab-base"
readonly WORK_VM="kyclash-macos-lab-work"
readonly DEFAULT_TART="${REPO_ROOT}/target/tools/tart-${TART_VERSION}/tart.app/Contents/MacOS/tart"
readonly TART_BIN="${KYCLASH_TART_BIN:-${DEFAULT_TART}}"

usage() {
  echo "usage: $0 {preflight|create|clone|run|ip|list}" >&2
}

require_tart() {
  if [[ ! -x "${TART_BIN}" ]]; then
    echo "Tart ${TART_VERSION} is required at ${TART_BIN}" >&2
    echo "See docs/testing/kyclash-macos-virtualization-lab.md" >&2
    exit 69
  fi
}

require_apple_silicon() {
  if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "Apple Silicon macOS is required" >&2
    exit 69
  fi
  if [[ "$(sysctl -n kern.hv_support 2>/dev/null || true)" != "1" ]]; then
    echo "Apple Hypervisor support is unavailable" >&2
    exit 69
  fi
}

require_tart
require_apple_silicon

case "${1:-}" in
  preflight)
    "${TART_BIN}" --version
    sw_vers
    sysctl -n hw.model
    sysctl -n kern.hv_support
    df -h /
    ;;
  create)
    "${TART_BIN}" create --from-ipsw=latest "${BASE_VM}"
    ;;
  clone)
    if "${TART_BIN}" list | awk '{print $1}' | grep -Fxq "${WORK_VM}"; then
      echo "refusing to overwrite existing VM ${WORK_VM}" >&2
      exit 73
    fi
    "${TART_BIN}" clone "${BASE_VM}" "${WORK_VM}"
    ;;
  run)
    "${TART_BIN}" run --dir=kyclash:"${REPO_ROOT}":ro "${WORK_VM}"
    ;;
  ip)
    "${TART_BIN}" ip "${WORK_VM}"
    ;;
  list)
    "${TART_BIN}" list
    ;;
  *)
    usage
    exit 64
    ;;
esac
