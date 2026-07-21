#!/usr/bin/env bash
set -euo pipefail

readonly LAB_OUTPUT="${KYCLASH_MACOS_LAB_OUTPUT:-target/macos-system-lab}"
readonly LAB_BUILD="${KYCLASH_MACOS_LAB_BUILD:-target/macos-system-build}"
readonly ROUTE_CONFIRM="authorized-disposable-macos-host"
readonly KEYCHAIN_CONFIRM="authorized-disposable-macos-account"
readonly ROUTE_LAB="${LAB_BUILD}/debug/kyclash-route-lab"
readonly KEYCHAIN_LAB="${LAB_BUILD}/debug/kyclash-keychain-lab"
readonly JOURNAL_DIR="/var/tmp/net.kysion.kyclash-route-lab"
readonly TEST_SERVICE="net.kysion.kyclash.test"
readonly TEST_ACCOUNT="kyclash.test.synthetic.v1"
readonly LOCAL_VM_CONFIRM="authorized-kyclash-virtualization-framework-vm"
readonly USE_PREBUILT="${KYCLASH_MACOS_LAB_USE_PREBUILT:-0}"

route_lines() {
  netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2/24" || $1 == "192.0.2.0/24"'
}

rust_version() {
  if command -v rustc >/dev/null 2>&1; then
    rustc --version
  else
    echo "rustc=not-installed-prebuilt-mode"
  fi
}

cleanup() {
  KYCLASH_KEYCHAIN_LAB_CONFIRM="${KEYCHAIN_CONFIRM}" "${KEYCHAIN_LAB}" cleanup >/dev/null 2>&1 || true
  sudo env KYCLASH_ROUTE_LAB_CONFIRM="${ROUTE_CONFIRM}" "${ROUTE_LAB}" recover >/dev/null 2>&1 || true
  sudo rm -f "${JOURNAL_DIR}/route-journal.json" "${JOURNAL_DIR}/lab.lock"
  sudo rmdir "${JOURNAL_DIR}" 2>/dev/null || true
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "refusing to run: this lab is macOS-only" >&2
  exit 69
fi
case "${KYCLASH_RUNNER_ENVIRONMENT:-}" in
  github-hosted)
    if [[ "${CI:-}" != "true" ]]; then
      echo "refusing GitHub-hosted mode without CI=true" >&2
      exit 77
    fi
    ;;
  local-virtualization-framework)
    if [[ "${KYCLASH_VM_LAB_CONFIRM:-}" != "${LOCAL_VM_CONFIRM}" ]]; then
      echo "refusing local VM mode without the exact VM confirmation" >&2
      exit 77
    fi
    if [[ "$(sysctl -n hw.model 2>/dev/null || true)" != VirtualMac* ]]; then
      echo "refusing local VM mode outside an Apple Virtualization.framework macOS guest" >&2
      exit 77
    fi
    ;;
  *)
    echo "refusing to run outside a GitHub-hosted runner or confirmed Apple Virtualization.framework VM" >&2
    exit 77
    ;;
esac
if [[ "${KYCLASH_RUNNER_ENVIRONMENT:-}" == "github-hosted" ]]; then
  if ! sudo -n true; then
    echo "passwordless sudo is required on the disposable runner" >&2
    exit 77
  fi
else
  if ! sudo -v; then
    echo "interactive sudo authorization is required in the disposable local VM" >&2
    exit 77
  fi
fi

mkdir -p "${LAB_OUTPUT}"
{
  sw_vers
  uname -m
  rust_version
  df -h .
} >"${LAB_OUTPUT}/environment-before-build.txt"

if [[ "${USE_PREBUILT}" == "1" ]]; then
  if [[ "${KYCLASH_RUNNER_ENVIRONMENT:-}" != "local-virtualization-framework" ]]; then
    echo "refusing prebuilt binaries outside the confirmed local VM mode" >&2
    exit 77
  fi
  mkdir -p "${LAB_BUILD}/debug"
  cp target/debug/kyclash-route-lab "${ROUTE_LAB}"
  cp target/debug/kyclash-keychain-lab "${KEYCHAIN_LAB}"
  chmod 755 "${ROUTE_LAB}" "${KEYCHAIN_LAB}"
  echo "build_source=host-built-arm64-read-only-share" >"${LAB_OUTPUT}/cargo-build.log"
else
  set +e
  CARGO_TARGET_DIR="${LAB_BUILD}" \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=0 \
    cargo build -p clash-verge \
    --features networking-route-lab,networking-keychain-lab,networking-system-lab \
    --bin kyclash-route-lab \
    --bin kyclash-keychain-lab \
    >"${LAB_OUTPUT}/cargo-build.log" 2>&1
  build_status=$?
  set -e
  if [[ "${build_status}" -ne 0 ]]; then
    tail -n 80 "${LAB_OUTPUT}/cargo-build.log" >&2
    summary=$(tail -n 12 "${LAB_OUTPUT}/cargo-build.log" | tr '\n' ' ' | sed 's/%/%25/g; s/\r/%0D/g; s/\n/%0A/g')
    echo "::error title=macOS system lab Cargo build failed::${summary}"
    exit "${build_status}"
  fi
fi
test -x "${ROUTE_LAB}"
test -x "${KEYCHAIN_LAB}"
trap cleanup EXIT INT TERM

{
  sw_vers
  uname -m
  rust_version
  df -h .
} >"${LAB_OUTPUT}/environment.txt"

KYCLASH_KEYCHAIN_LAB_CONFIRM="${KEYCHAIN_CONFIRM}" "${KEYCHAIN_LAB}" cleanup
KYCLASH_KEYCHAIN_LAB_CONFIRM="${KEYCHAIN_CONFIRM}" "${KEYCHAIN_LAB}" cycle
if security find-generic-password -s "${TEST_SERVICE}" -a "${TEST_ACCOUNT}" >/dev/null 2>&1; then
  echo "fixed synthetic Keychain item remained after cycle" >&2
  exit 1
fi
echo "keychain_cycle=passed" >"${LAB_OUTPUT}/keychain.txt"

if [[ -n "$(route_lines)" ]]; then
  echo "fixed TEST-NET route existed before the lab" >&2
  exit 1
fi
sudo env KYCLASH_ROUTE_LAB_CONFIRM="${ROUTE_CONFIRM}" "${ROUTE_LAB}" cycle
if [[ -n "$(route_lines)" ]]; then
  echo "fixed TEST-NET route remained after normal cycle" >&2
  exit 1
fi

set +e
sudo env KYCLASH_ROUTE_LAB_CONFIRM="${ROUTE_CONFIRM}" "${ROUTE_LAB}" abort-after-apply
abort_status=$?
set -e
if [[ "${abort_status}" -eq 0 ]]; then
  echo "abort-after-apply unexpectedly returned success" >&2
  exit 1
fi
route_lines >"${LAB_OUTPUT}/route-after-abort.txt"
test -s "${LAB_OUTPUT}/route-after-abort.txt"
sudo cp "${JOURNAL_DIR}/route-journal.json" "${LAB_OUTPUT}/route-journal-after-abort.json"
sudo chown "$(id -u):$(id -g)" "${LAB_OUTPUT}/route-journal-after-abort.json"

sudo env KYCLASH_ROUTE_LAB_CONFIRM="${ROUTE_CONFIRM}" "${ROUTE_LAB}" recover
if [[ -n "$(route_lines)" ]]; then
  echo "fixed TEST-NET route remained after crash recovery" >&2
  exit 1
fi
{
  echo "normal_cycle=passed"
  echo "abort_exit_status=${abort_status}"
  echo "crash_recovery=passed"
} >"${LAB_OUTPUT}/route.txt"

echo "KyClash macOS system lab passed (${KYCLASH_RUNNER_ENVIRONMENT})"
