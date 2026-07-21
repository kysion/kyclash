#!/usr/bin/env bash
set -euo pipefail

readonly LAB_OUTPUT="${KYCLASH_MACOS_LAB_OUTPUT:-target/macos-system-lab}"
readonly ROUTE_CONFIRM="authorized-disposable-macos-host"
readonly KEYCHAIN_CONFIRM="authorized-disposable-macos-account"
readonly ROUTE_LAB="target/debug/kyclash-route-lab"
readonly KEYCHAIN_LAB="target/debug/kyclash-keychain-lab"
readonly JOURNAL_DIR="/var/tmp/net.kysion.kyclash-route-lab"
readonly TEST_SERVICE="net.kysion.kyclash.test"
readonly TEST_ACCOUNT="kyclash.test.synthetic.v1"

route_lines() {
  netstat -rn -f inet | awk '$1 == "192.0.2" || $1 == "192.0.2/24" || $1 == "192.0.2.0/24"'
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
if [[ "${CI:-}" != "true" || "${KYCLASH_RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
  echo "refusing to run outside a GitHub-hosted disposable runner" >&2
  exit 77
fi
if ! sudo -n true; then
  echo "passwordless sudo is required on the disposable runner" >&2
  exit 77
fi

mkdir -p "${LAB_OUTPUT}"
cargo build -p clash-verge \
  --features networking-route-lab,networking-keychain-lab \
  --bin kyclash-route-lab \
  --bin kyclash-keychain-lab
test -x "${ROUTE_LAB}"
test -x "${KEYCHAIN_LAB}"
trap cleanup EXIT INT TERM

{
  sw_vers
  uname -m
  rustc --version
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

echo "KyClash GitHub-hosted macOS system lab passed"
