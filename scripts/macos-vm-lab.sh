#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TART_VERSION="2.32.1"
readonly BASE_VM="kyclash-macos-lab-base"
readonly WORK_VM="kyclash-macos-lab-work"
readonly DEFAULT_TART="${REPO_ROOT}/target/tools/tart-${TART_VERSION}/tart.app/Contents/MacOS/tart"
readonly TART_BIN="${KYCLASH_TART_BIN:-${DEFAULT_TART}}"
readonly LAB_ROOT="${REPO_ROOT}/target/macos-vm-lab"
readonly GUEST_INPUT_ROOT="${LAB_ROOT}/guest-share"
readonly CLIENT_REVIEW_ROOT="${LAB_ROOT}/guest-client-output"
readonly HOST_UID="$(/usr/bin/id -u)"
readonly HOST_GID="$(/usr/bin/id -g)"
readonly SHARE_ROOT_MODE="700"
readonly SHARE_SCAN_MAX_BYTES=1048576
readonly CREDENTIAL_MARKER_PATTERN='-----BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----|TAURI_SIGNING_PRIVATE_KEY|APPLE_PASSWORD|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|(^|/)id_(rsa|ed25519)(\.|$)|target/macos-vm-lab/private'

usage() {
  echo "usage: $0 {preflight|share-preflight|create|clone|run|ip|list}" >&2
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

share_refused() {
  echo "required safe VM share failed closed" >&2
  exit 66
}

require_safe_share_root() {
  local share_path="$1"
  local share_kind="$2"
  local root_metadata
  local root_uid
  local root_gid
  local root_mode
  local root_device
  local resolved_root
  local entry
  local entry_name
  local entry_metadata
  local entry_uid
  local entry_mode
  local entry_device
  local entry_links
  local entry_size
  local entry_mode_value
  local marker_status

  if [[ ! -d "${share_path}" || -L "${share_path}" ]]; then
    share_refused
  fi
  resolved_root="$(cd "${share_path}" && /bin/pwd -P)" || share_refused
  if [[ "${resolved_root}" != "${share_path}" ]]; then
    share_refused
  fi
  root_metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%d' "${share_path}")" ||
    share_refused
  IFS=: read -r root_uid root_gid root_mode root_device <<<"${root_metadata}"
  if [[ "${root_uid}" != "${HOST_UID}" ||
    "${root_gid}" != "${HOST_GID}" ||
    "${root_mode}" != "${SHARE_ROOT_MODE}" ||
    ! "${root_device}" =~ ^[0-9]+$ ]]; then
    share_refused
  fi

  while IFS= read -r -d '' entry; do
    entry_name="${entry##*/}"
    case "${share_kind}:${entry_name}" in
      input:layer-a-inputs|input:layer-b-prepare-inputs|input:layer-b-pin-inputs)
        [[ -d "${entry}" && ! -L "${entry}" ]] || share_refused
        ;;
      review:listener-inventory-v1.json|\
        review:listener-baseline-candidate-v1.json|\
        review:layer-b-review-witness-v1.json|\
        review:management-ssh-bootstrap-witness-v1.json|\
        review:management-ssh-host-ed25519-public.bin|\
        review:management-ssh-host-ed25519-fingerprint.txt|\
        review:vm-identity-layer-a-v1.json)
        [[ -f "${entry}" && ! -L "${entry}" ]] || share_refused
        ;;
      *)
        share_refused
        ;;
    esac
  done < <(/usr/bin/find "${share_path}" -mindepth 1 -maxdepth 1 -print0)

  while IFS= read -r -d '' entry; do
    if [[ -L "${entry}" || (! -d "${entry}" && ! -f "${entry}") ]]; then
      share_refused
    fi
    entry_metadata="$(/usr/bin/stat -f '%u:%Lp:%d:%l:%z' "${entry}")" ||
      share_refused
    IFS=: read -r entry_uid entry_mode entry_device entry_links entry_size \
      <<<"${entry_metadata}"
    if [[ "${entry_uid}" != "${HOST_UID}" ||
      ! "${entry_mode}" =~ ^[0-7]{3,4}$ ||
      "${entry_device}" != "${root_device}" ||
      ! "${entry_links}" =~ ^[0-9]+$ ||
      ! "${entry_size}" =~ ^[0-9]+$ ]]; then
      share_refused
    fi
    entry_mode_value=$((8#${entry_mode}))
    if ((entry_mode_value & 0022)); then
      share_refused
    fi
    if [[ -d "${entry}" ]] && (( (entry_mode_value & 0500) != 0500 )); then
      share_refused
    fi
    if [[ -f "${entry}" ]] && (( (entry_mode_value & 0400) != 0400 )); then
      share_refused
    fi
    if [[ -f "${entry}" && "${entry_links}" != "1" ]]; then
      share_refused
    fi
    entry_name="${entry##*/}"
    if [[ "${entry_name}" =~ [Pp][Rr][Ii][Vv][Aa][Tt][Ee] ||
      "${entry_name}" =~ [Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd] ||
      "${entry_name}" =~ [Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll] ||
      "${entry_name}" =~ [Tt][Oo][Kk][Ee][Nn] ||
      "${entry_name}" =~ \.[Kk][Ee][Yy]$ ||
      "${entry_name}" =~ \.[Pp][Ee][Mm]$ ||
      "${entry_name}" =~ ^id_(rsa|ed25519) ]]; then
      share_refused
    fi
    if [[ -f "${entry}" ]] && ((entry_size <= SHARE_SCAN_MAX_BYTES)); then
      if LC_ALL=C /usr/bin/grep -aEiq -e \
        "${CREDENTIAL_MARKER_PATTERN}" "${entry}" 2>/dev/null; then
        share_refused
      else
        marker_status=$?
        [[ "${marker_status}" == "1" ]] || share_refused
      fi
    fi
  done < <(/usr/bin/find "${share_path}" -print0)

  root_metadata="$(/usr/bin/stat -f '%u:%g:%Lp:%d' "${share_path}")" ||
    share_refused
  if [[ "${root_metadata}" != "${HOST_UID}:${HOST_GID}:${SHARE_ROOT_MODE}:${root_device}" ]]; then
    share_refused
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
  share-preflight)
    require_safe_share_root "${GUEST_INPUT_ROOT}" input
    require_safe_share_root "${CLIENT_REVIEW_ROOT}" review
    echo "vm_share_preflight=safe"
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
    require_safe_share_root "${GUEST_INPUT_ROOT}" input
    require_safe_share_root "${CLIENT_REVIEW_ROOT}" review
    "${TART_BIN}" run \
      --dir=kyclash-staging:"${GUEST_INPUT_ROOT}":ro \
      --dir=kyclash-review-client:"${CLIENT_REVIEW_ROOT}" \
      "${WORK_VM}"
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
