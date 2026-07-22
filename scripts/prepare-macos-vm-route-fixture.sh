#!/usr/bin/env bash
set -euo pipefail

# This script is intentionally limited to the disposable Apple Virtualization
# Framework guest. It stages the privileged route helper and real-utun hold
# fixture outside the user-writable home directory before launchd starts them.

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly STAGE_ROOT="/Library/Application Support/KyClash/route-lab"
readonly STAGE_BIN="${STAGE_ROOT}/bin"
readonly HELPER_LABEL="net.kysion.kyclash.route-helper"
readonly UTUN_LABEL="net.kysion.kyclash.utun-route-fixture"
readonly HELPER_PLIST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
readonly UTUN_PLIST="/Library/LaunchDaemons/${UTUN_LABEL}.plist"
readonly VM_CONFIRM="authorized-kyclash-virtualization-framework-vm"

readonly HELPER_SOURCE_NAME="kyclash-route-helper-fixed"
readonly UTUN_SOURCE_NAME="kyclash-utun-lab.test"
readonly HOLD_CLIENT_SOURCE_NAME="kyclash-route-helper-lab-client-hold.scp"
readonly EXPECTED_TEAM_ID="RQUQ8Y3S9H"

usage() {
  echo "usage: $0 stage <guest-writable-source-dir>" >&2
  echo "       $0 bootstrap" >&2
  echo "       $0 remove" >&2
}

require_guest() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "refusing: macOS guest required" >&2
    exit 69
  fi
  if [[ "$(sysctl -n hw.model 2>/dev/null || true)" != VirtualMac* ]]; then
    echo "refusing: VirtualMac guest required" >&2
    exit 69
  fi
  if [[ "${KYCLASH_VM_LAB_CONFIRM:-}" != "${VM_CONFIRM}" ]]; then
    echo "refusing: set KYCLASH_VM_LAB_CONFIRM to the documented VM marker" >&2
    exit 77
  fi
}

require_sudo() {
  if ! sudo -v; then
    echo "interactive sudo authorization is required" >&2
    exit 77
  fi
}

source_file() {
  local source_dir="$1"
  local name="$2"
  local path="${source_dir}/${name}"
  if [[ ! -f "${path}" || -L "${path}" ]]; then
    echo "refusing missing or symlinked fixture: ${path}" >&2
    exit 66
  fi
  printf '%s\n' "${path}"
}

verify_signed_arm64_binary() {
  local path="$1"
  local team_id
  if ! codesign --verify --strict "${path}" >/dev/null 2>&1; then
    echo "refusing unsigned or invalidly signed fixture: ${path}" >&2
    exit 70
  fi
  team_id="$(codesign -dv --verbose=4 "${path}" 2>&1 |
    awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  if [[ "${team_id}" != "${EXPECTED_TEAM_ID}" ]]; then
    echo "refusing fixture with unexpected Team ID: ${path}" >&2
    exit 70
  fi
  if ! file "${path}" | grep -Fq 'Mach-O 64-bit executable arm64'; then
    echo "refusing non-arm64 fixture: ${path}" >&2
    exit 70
  fi
}

assert_root_owned() {
  local path="$1"
  local owner_group mode
  owner_group="$(stat -f '%Su:%Sg' "${path}")"
  mode="$(stat -f '%Lp' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "755" ]]; then
    echo "unsafe staged ownership/mode for ${path}: ${owner_group} ${mode}" >&2
    exit 70
  fi
}

stage() {
  local source_dir="$1"
  source_dir="$(cd "${source_dir}" && pwd -P)"
  local helper_source utun_source hold_source
  helper_source="$(source_file "${source_dir}" "${HELPER_SOURCE_NAME}")"
  utun_source="$(source_file "${source_dir}" "${UTUN_SOURCE_NAME}")"
  hold_source="${source_dir}/${HOLD_CLIENT_SOURCE_NAME}"
  verify_signed_arm64_binary "${helper_source}"
  verify_signed_arm64_binary "${utun_source}"
  if [[ -f "${hold_source}" && ! -L "${hold_source}" ]]; then
    verify_signed_arm64_binary "${hold_source}"
  fi

  sudo install -d -o root -g wheel -m 755 \
    "/Library/Application Support/KyClash" "${STAGE_ROOT}" "${STAGE_BIN}"
  sudo install -o root -g wheel -m 755 "${helper_source}" \
    "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  sudo install -o root -g wheel -m 755 "${utun_source}" \
    "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  if [[ -f "${hold_source}" && ! -L "${hold_source}" ]]; then
    sudo install -o root -g wheel -m 755 "${hold_source}" \
      "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  fi

  sudo install -o root -g wheel -m 644 \
    "${REPO_ROOT}/macos/route-helper/route-helper-lab.launchd.plist" \
    "${HELPER_PLIST}"
  sudo install -o root -g wheel -m 644 \
    "${REPO_ROOT}/macos/route-helper/utun-hold-lab.launchd.plist" \
    "${UTUN_PLIST}"
  sudo plutil -lint "${HELPER_PLIST}" "${UTUN_PLIST}"

  assert_root_owned "${STAGE_ROOT}"
  assert_root_owned "${STAGE_BIN}"
  assert_root_owned "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  assert_root_owned "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  if [[ -f "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" ]]; then
    assert_root_owned "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  fi
  printf 'staged_root=%s\n' "${STAGE_ROOT}"
  shasum -a 256 "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  shasum -a 256 "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  if [[ -f "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" ]]; then
    shasum -a 256 "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  fi
}

bootstrap() {
  [[ -x "${STAGE_BIN}/${HELPER_SOURCE_NAME}" ]] || {
    echo "staged helper is missing; run stage first" >&2
    exit 66
  }
  [[ -x "${STAGE_BIN}/${UTUN_SOURCE_NAME}" ]] || {
    echo "staged utun fixture is missing; run stage first" >&2
    exit 66
  }
  assert_root_owned "${STAGE_ROOT}"
  assert_root_owned "${STAGE_BIN}"
  assert_root_owned "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  assert_root_owned "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  sudo launchctl bootout "system/${HELPER_LABEL}" 2>/dev/null || true
  sudo launchctl bootout "system/${UTUN_LABEL}" 2>/dev/null || true
  sudo launchctl bootstrap system "${HELPER_PLIST}"
  sudo launchctl bootstrap system "${UTUN_PLIST}"
  sudo launchctl print "system/${HELPER_LABEL}" >/dev/null
  sudo launchctl print "system/${UTUN_LABEL}" >/dev/null
  echo "bootstrapped=${HELPER_LABEL},${UTUN_LABEL}"
}

remove() {
  sudo launchctl bootout "system/${HELPER_LABEL}" 2>/dev/null || true
  sudo launchctl bootout "system/${UTUN_LABEL}" 2>/dev/null || true
  sudo rm -f "${HELPER_PLIST}" "${UTUN_PLIST}" \
    "${STAGE_BIN}/${HELPER_SOURCE_NAME}" \
    "${STAGE_BIN}/${UTUN_SOURCE_NAME}" \
    "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  sudo rmdir "${STAGE_BIN}" "${STAGE_ROOT}" 2>/dev/null || true
  echo "removed=${STAGE_ROOT}"
}

require_guest
require_sudo
case "${1:-}" in
  stage)
    [[ "$#" -eq 2 ]] || { usage; exit 64; }
    stage "$2"
    ;;
  bootstrap)
    [[ "$#" -eq 1 ]] || { usage; exit 64; }
    bootstrap
    ;;
  remove)
    [[ "$#" -eq 1 ]] || { usage; exit 64; }
    remove
    ;;
  *)
    usage
    exit 64
    ;;
esac
