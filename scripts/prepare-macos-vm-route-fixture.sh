#!/bin/bash
set -euo pipefail
if [[ -n "${BASH_ENV:-}" || -n "${ENV:-}" ]]; then
  echo "refusing inherited Bash startup hooks; invoke with env -u BASH_ENV -u ENV" >&2
  exit 77
fi
umask 077
unset BASH_ENV ENV CDPATH
readonly SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="${SAFE_PATH}"

# This script is intentionally limited to the disposable Apple Virtualization
# Framework guest. It stages the privileged route helper and real-utun hold
# fixture outside the user-writable home directory before launchd starts them.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPO_ROOT
readonly STAGE_ROOT="/Library/Application Support/KyClash/route-lab"
readonly STAGE_BIN="${STAGE_ROOT}/bin"
readonly HELPER_LABEL="net.kysion.kyclash.route-helper"
readonly UTUN_LABEL="net.kysion.kyclash.utun-route-fixture"
readonly HELPER_PLIST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
readonly UTUN_PLIST="/Library/LaunchDaemons/${UTUN_LABEL}.plist"
readonly VM_CONFIRM="authorized-kyclash-virtualization-framework-vm"
readonly COMBINED_OWNER_FILE="/var/tmp/kyclash-utun-lab-combined-hold.evidence"
readonly COMBINED_LOG_FILE="${STAGE_ROOT}/combined-hold.log"

readonly HELPER_SOURCE_NAME="kyclash-route-helper-fixed"
readonly UTUN_SOURCE_NAME="kyclash-utun-lab.test"
readonly SYNTHETIC_UTUN_SOURCE_NAME="kyclash-utun-mihomo-lab.test"
readonly HOLD_CLIENT_SOURCE_NAME="kyclash-route-helper-lab-client-hold.scp"
readonly PUBLIC_CLIENT_PATH="/var/tmp/kyclash-route-helper-lab-client-v2.scp"
readonly EXPECTED_TEAM_ID="RQUQ8Y3S9H"
readonly HELPER_IDENTIFIER="net.kysion.kyclash.route-helper"
readonly PRIMARY_UTUN_IDENTIFIER="net.kysion.kyclash.network-sidecar-utun-lab"
readonly SYNTHETIC_UTUN_IDENTIFIER="net.kysion.kyclash.utun-mihomo-lab"
readonly CLIENT_IDENTIFIER="net.kysion.kyclash"
readonly SYNTHETIC_FIXTURE_PATH="${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}"
readonly SYNTHETIC_OWNER_FILE="/var/tmp/kyclash-utun-lab-mihomo-v2-owner"

# launchd's error text is not a stable API.  These are the only absence
# phrases accepted by the bounded bootout helper; every other error remains a
# hard failure instead of being swallowed.
readonly LAUNCHD_ABSENT_PATTERN='could not find service|no such process|not found'

usage() {
  echo "usage: $0 stage <guest-writable-source-dir>" >&2
  echo "       $0 bootstrap" >&2
  echo "       $0 remove" >&2
}

require_guest() {
  if [[ "$(/usr/bin/uname -s)" != "Darwin" ]]; then
    echo "refusing: macOS guest required" >&2
    exit 69
  fi
  if [[ "$(/usr/sbin/sysctl -n hw.model 2>/dev/null || true)" != VirtualMac* ]]; then
    echo "refusing: VirtualMac guest required" >&2
    exit 69
  fi
  if [[ "${KYCLASH_VM_LAB_CONFIRM:-}" != "${VM_CONFIRM}" ]]; then
    echo "refusing: set KYCLASH_VM_LAB_CONFIRM to the documented VM marker" >&2
    exit 77
  fi
}

require_sudo() {
  if ! /usr/bin/sudo -v; then
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
  local expected_identifier="$2"
  local metadata team_id identifier
  if ! sudo codesign --verify --strict "${path}" >/dev/null 2>&1; then
    echo "refusing unsigned or invalidly signed fixture: ${path}" >&2
    exit 70
  fi
  metadata="$(sudo codesign -dv --verbose=4 "${path}" 2>&1)"
  team_id="$(printf '%s\n' "${metadata}" | awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  identifier="$(printf '%s\n' "${metadata}" | awk -F= '/^Identifier=/{print $2; exit}')"
  if [[ "${team_id}" != "${EXPECTED_TEAM_ID}" ]]; then
    echo "refusing fixture with unexpected Team ID: ${path}" >&2
    exit 70
  fi
  if [[ "${identifier}" != "${expected_identifier}" ]]; then
    echo "refusing fixture with unexpected identifier: ${path}" >&2
    exit 70
  fi
  if ! sudo file "${path}" | grep -Fq 'Mach-O 64-bit executable arm64'; then
    echo "refusing non-arm64 fixture: ${path}" >&2
    exit 70
  fi
}

assert_root_owned() {
  local path="$1"
  local owner_group mode
  if /usr/bin/sudo /bin/test -L "${path}" ||
    ! /usr/bin/sudo /bin/test -d "${path}"; then
    echo "refusing missing, symlinked, or non-directory staged path: ${path}" >&2
    exit 70
  fi
  owner_group="$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg' "${path}")"
  mode="$(/usr/bin/sudo /usr/bin/stat -f '%Lp' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "755" ]]; then
    echo "unsafe staged ownership/mode for ${path}: ${owner_group} ${mode}" >&2
    exit 70
  fi
}

assert_root_owned_file() {
  local path="$1"
  local expected_mode="${2:-755}"
  local owner_group mode links
  if /usr/bin/sudo /bin/test -L "${path}" ||
    ! /usr/bin/sudo /bin/test -f "${path}"; then
    echo "refusing missing, symlinked, or non-regular staged file: ${path}" >&2
    exit 70
  fi
  owner_group="$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg' "${path}")"
  mode="$(/usr/bin/sudo /usr/bin/stat -f '%Lp' "${path}")"
  links="$(/usr/bin/sudo /usr/bin/stat -f '%l' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "${expected_mode}" ||
    "${links}" != "1" ]]; then
    echo "unsafe staged file ownership/mode/link count for ${path}: ${owner_group}:${mode}:${links}" >&2
    exit 70
  fi
}

assert_private_root_directory() {
  local path="$1"
  local owner_group mode
  if /usr/bin/sudo /bin/test -L "${path}" ||
    ! /usr/bin/sudo /bin/test -d "${path}"; then
    echo "refusing missing or symlinked private root directory: ${path}" >&2
    exit 70
  fi
  owner_group="$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg' "${path}")"
  mode="$(/usr/bin/sudo /usr/bin/stat -f '%Lp' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "700" ]]; then
    echo "unsafe private ownership/mode for ${path}: ${owner_group} ${mode}" >&2
    exit 70
  fi
}

assert_private_directory_path() {
  local path="$1"
  local expected_mode="$2"
  local owner_group mode
  if /usr/bin/sudo /bin/test -L "${path}" || ! /usr/bin/sudo /bin/test -d "${path}"; then
    echo "refusing missing or symlinked private directory: ${path}" >&2
    exit 70
  fi
  owner_group="$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg' "${path}")"
  mode="$(/usr/bin/sudo /usr/bin/stat -f '%Lp' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "${expected_mode}" ]]; then
    echo "unsafe private directory: ${path} ${owner_group} ${mode}" >&2
    exit 70
  fi
}

ensure_private_log_file() {
  if /usr/bin/sudo /bin/test -e "${COMBINED_LOG_FILE}" ||
    /usr/bin/sudo /bin/test -L "${COMBINED_LOG_FILE}"; then
    if /usr/bin/sudo /bin/test -L "${COMBINED_LOG_FILE}" ||
      ! /usr/bin/sudo /bin/test -f "${COMBINED_LOG_FILE}" || \
      [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' "${COMBINED_LOG_FILE}" \
        2>/dev/null || true)" != \
        "root:wheel:600:1" ]]; then
      echo "refusing unsafe combined launchd log path: ${COMBINED_LOG_FILE}" >&2
      exit 70
    fi
  else
    /usr/bin/sudo /usr/bin/install -o root -g wheel -m 600 /dev/null "${COMBINED_LOG_FILE}"
  fi
}

remove_private_log_file() {
  if ! /usr/bin/sudo /bin/test -e "${COMBINED_LOG_FILE}" &&
    ! /usr/bin/sudo /bin/test -L "${COMBINED_LOG_FILE}"; then
    return 0
  fi
  if /usr/bin/sudo /bin/test -L "${COMBINED_LOG_FILE}" ||
    ! /usr/bin/sudo /bin/test -f "${COMBINED_LOG_FILE}" || \
    [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' "${COMBINED_LOG_FILE}" \
      2>/dev/null || true)" != "root:wheel:600:1" ]]; then
    echo "refusing unsafe combined launchd log cleanup: ${COMBINED_LOG_FILE}" >&2
    exit 70
  fi
  /usr/bin/sudo /bin/rm -f "${COMBINED_LOG_FILE}"
}

assert_plist_value() {
  local plist="$1"
  local key_path="$2"
  local expected="$3"
  local actual
  actual="$(/usr/bin/plutil -extract "${key_path}" raw -o - "${plist}" 2>/dev/null || true)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "refusing unexpected launchd plist value: ${plist} ${key_path}=${actual}" >&2
    exit 70
  fi
}

assert_plist_array_value() {
  local plist="$1"
  local index="$2"
  local expected="$3"
  assert_plist_value "${plist}" "ProgramArguments.${index}" "${expected}"
}

assert_plist_array_length() {
  local plist="$1"
  local expected_length="$2"
  local index="${expected_length}"
  if /usr/bin/plutil -extract "ProgramArguments.${index}" raw -o - "${plist}" \
    >/dev/null 2>&1; then
    echo "refusing launchd plist with unexpected extra ProgramArguments: ${plist}" >&2
    exit 70
  fi
}

assert_plist_environment_count() {
  local plist="$1"
  local expected_count="$2"
  local xml count
  xml="$(/usr/bin/plutil -extract EnvironmentVariables xml1 -o - "${plist}" \
    2>/dev/null || true)"
  count="$(printf '%s\n' "${xml}" | /usr/bin/awk '/<key>/{value += 1} END {print value + 0}')"
  if [[ "${count}" != "${expected_count}" ]]; then
    echo "refusing launchd plist with unexpected EnvironmentVariables count: ${plist}" >&2
    exit 70
  fi
}

assert_plist_no_environment() {
  local plist="$1"
  if /usr/bin/plutil -extract EnvironmentVariables xml1 -o - "${plist}" \
    >/dev/null 2>&1; then
    echo "refusing helper plist with unexpected EnvironmentVariables" >&2
    exit 70
  fi
}

assert_lab_plists() {
  local helper_plist="${1:-${HELPER_PLIST}}"
  local utun_plist="${2:-${UTUN_PLIST}}"
  /usr/bin/plutil -lint "${helper_plist}" "${utun_plist}" >/dev/null
  assert_plist_value "${helper_plist}" Label "${HELPER_LABEL}"
  assert_plist_array_value "${helper_plist}" 0 \
    "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  assert_plist_array_length "${helper_plist}" 1
  assert_plist_no_environment "${helper_plist}"
  if ! /usr/bin/plutil -p "${helper_plist}" |
    /usr/bin/grep -F '"net.kysion.kyclash.route-helper" => true' >/dev/null; then
    echo "refusing helper plist without its exact MachServices entry" >&2
    exit 70
  fi

  assert_plist_value "${utun_plist}" Label "${UTUN_LABEL}"
  assert_plist_array_value "${utun_plist}" 0 \
    "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  assert_plist_array_value "${utun_plist}" 1 \
    '-test.run=^TestRealUTUNProductionSidecarControllerHoldForForcedTermination$'
  assert_plist_array_value "${utun_plist}" 2 '-test.count=1'
  assert_plist_array_value "${utun_plist}" 3 '-test.v=true'
  assert_plist_array_length "${utun_plist}" 4
  assert_plist_environment_count "${utun_plist}" 3
  assert_plist_value "${utun_plist}" \
    EnvironmentVariables.KYCLASH_VM_LAB_CONFIRM "${VM_CONFIRM}"
  assert_plist_value "${utun_plist}" \
    EnvironmentVariables.KYCLASH_UTUN_LAB_COMBINED_HOLD 1
  assert_plist_value "${utun_plist}" \
    EnvironmentVariables.KYCLASH_UTUN_LAB_COMBINED_EVIDENCE_FILE "${COMBINED_OWNER_FILE}"
  assert_plist_value "${utun_plist}" RunAtLoad true
  assert_plist_value "${utun_plist}" StandardOutPath "${COMBINED_LOG_FILE}"
  assert_plist_value "${utun_plist}" StandardErrorPath "${COMBINED_LOG_FILE}"
}

verify_public_client_slot() {
  local hold_source="$1"
  local source_hash existing_hash staged_hash
  if sudo test -L "${PUBLIC_CLIENT_PATH}"; then
    echo "refusing symlinked public v2 lab client path: ${PUBLIC_CLIENT_PATH}" >&2
    exit 70
  fi
  if ! sudo test -e "${PUBLIC_CLIENT_PATH}"; then
    return 0
  fi
  if ! sudo test -f "${PUBLIC_CLIENT_PATH}"; then
    echo "refusing non-regular public v2 lab client path: ${PUBLIC_CLIENT_PATH}" >&2
    exit 70
  fi
  assert_root_owned_file "${PUBLIC_CLIENT_PATH}"
  source_hash="$(sudo shasum -a 256 "${hold_source}" | awk '{print $1}')"
  existing_hash="$(sudo shasum -a 256 "${PUBLIC_CLIENT_PATH}" | awk '{print $1}')"
  if [[ -z "${source_hash}" || -z "${existing_hash}" ]]; then
    echo "refusing public v2 lab client with an unreadable hash" >&2
    exit 70
  fi
  if [[ "${source_hash}" != "${existing_hash}" ]]; then
    # Permit a managed upgrade only when the public copy is byte-identical to
    # the previous private staged source. An unrelated root-owned file is not
    # enough authority to overwrite this fixed public path.
    if sudo test -L "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" || \
      ! sudo test -f "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"; then
      echo "refusing to overwrite an unproven public v2 lab client" >&2
      exit 70
    fi
    assert_root_owned_file "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
    verify_signed_arm64_binary "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" \
      "${CLIENT_IDENTIFIER}"
    staged_hash="$(sudo shasum -a 256 "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" | \
      awk '{print $1}')"
    if [[ -z "${staged_hash}" || "${staged_hash}" != "${existing_hash}" ]]; then
      echo "refusing to overwrite a different public v2 lab client: ${PUBLIC_CLIENT_PATH}" >&2
      exit 70
    fi
  fi
}

remove_combined_owner_file() {
  if ! sudo test -e "${COMBINED_OWNER_FILE}" &&
    ! sudo test -L "${COMBINED_OWNER_FILE}"; then
    return 0
  fi
  if sudo test -L "${COMBINED_OWNER_FILE}" ||
    ! sudo test -f "${COMBINED_OWNER_FILE}" ||
    [[ "$(sudo stat -f '%Su:%Sg:%Lp:%l' "${COMBINED_OWNER_FILE}" 2>/dev/null || true)" != \
      "root:wheel:600:1" ]]; then
    echo "refusing unsafe combined utun evidence cleanup: ${COMBINED_OWNER_FILE}" >&2
    exit 70
  fi
  if ! sudo awk 'END { exit NR == 2 ? 0 : 1 }' "${COMBINED_OWNER_FILE}"; then
    echo "refusing combined utun evidence with unexpected line count" >&2
    exit 70
  fi
  local owner_utun owner_pid child_command
  owner_utun="$(sudo head -n 1 "${COMBINED_OWNER_FILE}")"
  if [[ ! "${owner_utun}" =~ ^utun([1-9][0-9]*|0)$ || "${#owner_utun}" -gt 15 ]]; then
    echo "refusing combined utun evidence with invalid interface name" >&2
    exit 70
  fi
  owner_pid="$(/usr/bin/sudo /usr/bin/sed -n '2p' "${COMBINED_OWNER_FILE}")"
  if [[ ! "${owner_pid}" =~ ^[1-9][0-9]*$ || "${owner_pid}" -le 1 ]]; then
    echo "refusing combined utun evidence with invalid child PID" >&2
    exit 70
  fi
  if /usr/bin/sudo /bin/kill -0 "${owner_pid}" 2>/dev/null; then
    child_command="$(/usr/bin/sudo /bin/ps -p "${owner_pid}" -o command= 2>/dev/null || true)"
    echo "refusing to remove live or reused combined child PID: ${owner_pid} ${child_command}" >&2
    exit 70
  fi
  if /sbin/ifconfig "${owner_utun}" >/dev/null 2>&1; then
    echo "refusing to remove live combined utun evidence: ${owner_utun}" >&2
    exit 70
  fi
  /usr/bin/sudo /bin/rm -f "${COMBINED_OWNER_FILE}"
}

launchd_job_pid() {
  local label="$1"
  /usr/bin/sudo /bin/launchctl print "system/${label}" 2>/dev/null |
    /usr/bin/awk '$1 == "pid" && $2 == "=" {value = $3} END {print value}'
}

launchd_job_state() {
  local label="$1"
  local output
  if output="$(/usr/bin/sudo /bin/launchctl print "system/${label}" 2>&1)"; then
    printf 'loaded\n%s\n' "${output}"
    return 0
  fi
  if printf '%s\n' "${output}" | /usr/bin/grep -Eiq "${LAUNCHD_ABSENT_PATTERN}"; then
    printf 'absent\n'
    return 0
  fi
  printf 'launchd print failed for system/%s: %s\n' "${label}" "${output}" >&2
  return 1
}

wait_for_launchd_job_absent() {
  local label="$1"
  local attempt state
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    state="$(launchd_job_state "${label}" | /usr/bin/awk 'NR == 1 {print; exit}')"
    if [[ "${state}" == "absent" ]]; then
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'launchd job remained loaded after bootout: system/%s\n' "${label}" >&2
  return 1
}

wait_for_pid_absent() {
  local pid="$1"
  local expected_path="$2"
  local attempt command_line
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  if [[ ! "${pid}" =~ ^[1-9][0-9]*$ || "${pid}" -le 1 ]]; then
    printf 'refusing invalid launchd PID evidence: %s\n' "${pid}" >&2
    return 1
  fi
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    if ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
    case "${command_line}" in
      "${expected_path}"|"${expected_path} "*) ;;
      *)
        printf 'launchd PID identity changed while waiting for exit: %s %s\n' \
          "${pid}" "${command_line}" >&2
        return 1
        ;;
    esac
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'launchd fixture process remained after bootout: pid=%s path=%s\n' \
    "${pid}" "${expected_path}" >&2
  return 1
}

bootout_job_if_loaded() {
  local label="$1"
  local expected_path="$2"
  local state pid
  state="$(launchd_job_state "${label}" | /usr/bin/awk 'NR == 1 {print; exit}')"
  if [[ "${state}" == "absent" ]]; then
    return 0
  fi
  pid="$(launchd_job_pid "${label}")"
  if [[ -n "${pid}" && (! "${pid}" =~ ^[1-9][0-9]*$ || "${pid}" -le 1) ]]; then
    printf 'refusing invalid launchd PID before bootout: system/%s pid=%s\n' \
      "${label}" "${pid}" >&2
    return 1
  fi
  if ! /usr/bin/sudo /bin/launchctl bootout "system/${label}"; then
    printf 'launchd bootout failed: system/%s\n' "${label}" >&2
    return 1
  fi
  wait_for_launchd_job_absent "${label}"
  wait_for_pid_absent "${pid}" "${expected_path}"
}

assert_no_stale_synthetic_fixture() {
  local owner_pid command_line
  if /usr/bin/sudo /bin/test -e "${SYNTHETIC_OWNER_FILE}" ||
    /usr/bin/sudo /bin/test -L "${SYNTHETIC_OWNER_FILE}"; then
    echo "refusing to remove while synthetic Mihomo owner evidence exists: ${SYNTHETIC_OWNER_FILE}" >&2
    echo "run the v2 matrix cleanup and re-audit the disposable guest before remove" >&2
    return 1
  fi
  owner_pid="$(/usr/bin/sudo /bin/ps -axo pid=,command= |
    /usr/bin/awk -v executable="${SYNTHETIC_FIXTURE_PATH}" \
      'index($0, executable) && index($0, "TestRealUTUNHoldForForcedTermination") && $0 !~ /\/usr\/bin\/sudo/ {print $1; exit}')"
  if [[ -n "${owner_pid}" ]]; then
    command_line="$(/usr/bin/sudo /bin/ps -p "${owner_pid}" -o command= 2>/dev/null || true)"
    printf 'refusing to remove while synthetic Mihomo fixture is running: pid=%s %s\n' \
      "${owner_pid}" "${command_line}" >&2
    return 1
  fi
}

remove_staged_file() {
  local path="$1"
  local expected_mode="${2:-755}"
  if ! /usr/bin/sudo /bin/test -e "${path}" &&
    ! /usr/bin/sudo /bin/test -L "${path}"; then
    return 0
  fi
  assert_root_owned_file "${path}" "${expected_mode}"
  /usr/bin/sudo /bin/rm -f "${path}"
}

verify_staged_fixtures() {
  verify_signed_arm64_binary "${STAGE_BIN}/${HELPER_SOURCE_NAME}" "${HELPER_IDENTIFIER}"
  verify_signed_arm64_binary "${STAGE_BIN}/${UTUN_SOURCE_NAME}" "${PRIMARY_UTUN_IDENTIFIER}"
  verify_signed_arm64_binary "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}" \
    "${SYNTHETIC_UTUN_IDENTIFIER}"
  verify_signed_arm64_binary "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" \
    "${CLIENT_IDENTIFIER}"
  verify_signed_arm64_binary "${PUBLIC_CLIENT_PATH}" "${CLIENT_IDENTIFIER}"
}

install_verified_binary() {
  local source="$1"
  local destination="$2"
  local expected_identifier="$3"
  local incoming="${destination}.incoming"
  if /usr/bin/sudo /bin/test -e "${destination}" ||
    /usr/bin/sudo /bin/test -L "${destination}"; then
    assert_root_owned_file "${destination}"
  fi
  remove_staged_file "${incoming}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 755 \
    "${source}" "${incoming}"
  if ! (assert_root_owned_file "${incoming}" &&
    verify_signed_arm64_binary "${incoming}" "${expected_identifier}"); then
    remove_staged_file "${incoming}"
    echo "refusing fixture that changed before its privileged snapshot: ${source}" >&2
    exit 70
  fi
  /usr/bin/sudo /bin/mv -f "${incoming}" "${destination}"
  assert_root_owned_file "${destination}"
  verify_signed_arm64_binary "${destination}" "${expected_identifier}"
}

install_verified_plists() {
  local helper_incoming="${HELPER_PLIST}.incoming"
  local utun_incoming="${UTUN_PLIST}.incoming"
  if /usr/bin/sudo /bin/test -e "${HELPER_PLIST}" ||
    /usr/bin/sudo /bin/test -L "${HELPER_PLIST}"; then
    assert_root_owned_file "${HELPER_PLIST}" 644
  fi
  if /usr/bin/sudo /bin/test -e "${UTUN_PLIST}" ||
    /usr/bin/sudo /bin/test -L "${UTUN_PLIST}"; then
    assert_root_owned_file "${UTUN_PLIST}" 644
  fi
  remove_staged_file "${helper_incoming}" 644
  remove_staged_file "${utun_incoming}" 644
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 \
    "${REPO_ROOT}/macos/route-helper/route-helper-lab.launchd.plist" \
    "${helper_incoming}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 \
    "${REPO_ROOT}/macos/route-helper/utun-hold-lab.launchd.plist" \
    "${utun_incoming}"
  if ! (assert_root_owned_file "${helper_incoming}" 644 &&
    assert_root_owned_file "${utun_incoming}" 644 &&
    assert_lab_plists "${helper_incoming}" "${utun_incoming}"); then
    remove_staged_file "${helper_incoming}" 644
    remove_staged_file "${utun_incoming}" 644
    echo "refusing launchd plist that changed before its privileged snapshot" >&2
    exit 70
  fi
  /usr/bin/sudo /bin/mv -f "${helper_incoming}" "${HELPER_PLIST}"
  /usr/bin/sudo /bin/mv -f "${utun_incoming}" "${UTUN_PLIST}"
  assert_root_owned_file "${HELPER_PLIST}" 644
  assert_root_owned_file "${UTUN_PLIST}" 644
  assert_lab_plists
}

stage() {
  local source_dir="$1"
  source_dir="$(cd "${source_dir}" && pwd -P)"
  local helper_source utun_source synthetic_utun_source hold_source
  helper_source="$(source_file "${source_dir}" "${HELPER_SOURCE_NAME}")"
  utun_source="$(source_file "${source_dir}" "${UTUN_SOURCE_NAME}")"
  synthetic_utun_source="$(source_file "${source_dir}" "${SYNTHETIC_UTUN_SOURCE_NAME}")"
  hold_source="${source_dir}/${HOLD_CLIENT_SOURCE_NAME}"
  verify_signed_arm64_binary "${helper_source}" "${HELPER_IDENTIFIER}"
  verify_signed_arm64_binary "${utun_source}" "${PRIMARY_UTUN_IDENTIFIER}"
  verify_signed_arm64_binary "${synthetic_utun_source}" "${SYNTHETIC_UTUN_IDENTIFIER}"
  if [[ -f "${hold_source}" && ! -L "${hold_source}" ]]; then
    verify_signed_arm64_binary "${hold_source}" "${CLIENT_IDENTIFIER}"
  else
    echo "refusing missing typed v2 lab client fixture: ${hold_source}" >&2
    exit 66
  fi
  verify_public_client_slot "${hold_source}"

  # The production journal validator requires its parent to be private. Keep
  # only the nested executable fixture directories traversable by launchd.
  if /usr/bin/sudo /bin/test -L "/Library/Application Support/KyClash" || \
    /usr/bin/sudo /bin/test -L "${STAGE_ROOT}" || /usr/bin/sudo /bin/test -L "${STAGE_BIN}"; then
    echo "refusing symlinked KyClash staging directory" >&2
    exit 70
  fi
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 700 "/Library/Application Support/KyClash"
  /usr/bin/sudo /bin/chmod 700 "/Library/Application Support/KyClash"
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 755 "${STAGE_ROOT}" "${STAGE_BIN}"
  assert_private_directory_path "/Library/Application Support/KyClash" 700
  assert_private_directory_path "${STAGE_ROOT}" 755
  assert_private_directory_path "${STAGE_BIN}" 755
  ensure_private_log_file
  # Never replace a launchd-referenced executable while its job or owned utun
  # is alive. Snapshot each user-writable source into a root-owned incoming
  # file, validate that immutable copy, and only then move it into the fixed
  # executable slot.
  bootout_job_if_loaded "${HELPER_LABEL}" "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  bootout_job_if_loaded "${UTUN_LABEL}" "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  assert_no_stale_synthetic_fixture
  remove_combined_owner_file
  install_verified_binary "${helper_source}" \
    "${STAGE_BIN}/${HELPER_SOURCE_NAME}" "${HELPER_IDENTIFIER}"
  install_verified_binary "${utun_source}" \
    "${STAGE_BIN}/${UTUN_SOURCE_NAME}" "${PRIMARY_UTUN_IDENTIFIER}"
  install_verified_binary "${synthetic_utun_source}" \
    "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}" "${SYNTHETIC_UTUN_IDENTIFIER}"
  install_verified_binary "${hold_source}" \
    "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" "${CLIENT_IDENTIFIER}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 755 \
    "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}" "${PUBLIC_CLIENT_PATH}"
  install_verified_plists

  assert_private_root_directory "/Library/Application Support/KyClash"
  ensure_private_log_file
  assert_root_owned "${STAGE_ROOT}"
  assert_root_owned "${STAGE_BIN}"
  assert_root_owned_file "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  assert_root_owned_file "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  assert_root_owned_file "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}"
  assert_root_owned_file "${PUBLIC_CLIENT_PATH}"
  verify_staged_fixtures
  assert_root_owned_file "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  printf 'staged_root=%s\n' "${STAGE_ROOT}"
  /usr/bin/sudo /usr/bin/shasum -a 256 "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  /usr/bin/sudo /usr/bin/shasum -a 256 "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  /usr/bin/sudo /usr/bin/shasum -a 256 "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}"
  if /usr/bin/sudo /bin/test -f "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"; then
    /usr/bin/sudo /usr/bin/shasum -a 256 "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  fi
}

bootstrap() {
  /usr/bin/sudo /bin/test -x "${STAGE_BIN}/${HELPER_SOURCE_NAME}" || {
    echo "staged helper is missing; run stage first" >&2
    exit 66
  }
  /usr/bin/sudo /bin/test -x "${STAGE_BIN}/${UTUN_SOURCE_NAME}" || {
    echo "staged utun fixture is missing; run stage first" >&2
    exit 66
  }
  /usr/bin/sudo /bin/test -x "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}" || {
    echo "staged synthetic Mihomo utun fixture is missing; run stage first" >&2
    exit 66
  }
  /usr/bin/sudo /bin/test -x "${PUBLIC_CLIENT_PATH}" || {
    echo "staged public v2 lab client is missing; run stage first" >&2
    exit 66
  }
  assert_private_root_directory "/Library/Application Support/KyClash"
  assert_private_directory_path "${STAGE_ROOT}" 755
  assert_private_directory_path "${STAGE_BIN}" 755
  assert_root_owned "${STAGE_ROOT}"
  assert_root_owned "${STAGE_BIN}"
  assert_root_owned_file "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  assert_root_owned_file "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  assert_root_owned_file "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}"
  assert_root_owned_file "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  assert_root_owned_file "${PUBLIC_CLIENT_PATH}"
  assert_root_owned_file "${HELPER_PLIST}" 644
  assert_root_owned_file "${UTUN_PLIST}" 644
  ensure_private_log_file
  assert_lab_plists
  verify_staged_fixtures
  bootout_job_if_loaded "${HELPER_LABEL}" "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  bootout_job_if_loaded "${UTUN_LABEL}" "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  remove_combined_owner_file
  /usr/bin/sudo /bin/launchctl bootstrap system "${HELPER_PLIST}"
  /usr/bin/sudo /bin/launchctl bootstrap system "${UTUN_PLIST}"
  /usr/bin/sudo /bin/launchctl print "system/${HELPER_LABEL}" >/dev/null
  /usr/bin/sudo /bin/launchctl print "system/${UTUN_LABEL}" >/dev/null
  echo "bootstrapped=${HELPER_LABEL},${UTUN_LABEL}"
}

remove() {
  local hold_source="${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  # Validate the complete private path before resolving any fixed child. This
  # prevents a root-created symlink from redirecting cleanup to another tree.
  assert_private_root_directory "/Library/Application Support/KyClash"
  assert_private_directory_path "${STAGE_ROOT}" 755
  assert_private_directory_path "${STAGE_BIN}" 755
  if /usr/bin/sudo /bin/test -e "${PUBLIC_CLIENT_PATH}" ||
    /usr/bin/sudo /bin/test -L "${PUBLIC_CLIENT_PATH}"; then
    if /usr/bin/sudo /bin/test -L "${PUBLIC_CLIENT_PATH}" ||
      ! /usr/bin/sudo /bin/test -f "${PUBLIC_CLIENT_PATH}"; then
      echo "refusing unsafe public v2 lab client removal: ${PUBLIC_CLIENT_PATH}" >&2
      exit 70
    fi
    if ! /usr/bin/sudo /bin/test -f "${hold_source}"; then
      echo "refusing public v2 lab client removal without its staged source" >&2
      exit 70
    fi
    verify_public_client_slot "${hold_source}"
  fi
  bootout_job_if_loaded "${HELPER_LABEL}" "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  bootout_job_if_loaded "${UTUN_LABEL}" "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  assert_no_stale_synthetic_fixture
  remove_combined_owner_file
  remove_staged_file "${HELPER_PLIST}.incoming" 644
  remove_staged_file "${UTUN_PLIST}.incoming" 644
  remove_staged_file "${STAGE_BIN}/${HELPER_SOURCE_NAME}.incoming"
  remove_staged_file "${STAGE_BIN}/${UTUN_SOURCE_NAME}.incoming"
  remove_staged_file "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}.incoming"
  remove_staged_file "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}.incoming"
  remove_staged_file "${HELPER_PLIST}" 644
  remove_staged_file "${UTUN_PLIST}" 644
  remove_staged_file "${STAGE_BIN}/${HELPER_SOURCE_NAME}"
  remove_staged_file "${STAGE_BIN}/${UTUN_SOURCE_NAME}"
  remove_staged_file "${STAGE_BIN}/${SYNTHETIC_UTUN_SOURCE_NAME}"
  remove_staged_file "${STAGE_BIN}/${HOLD_CLIENT_SOURCE_NAME}"
  remove_private_log_file
  remove_staged_file "${PUBLIC_CLIENT_PATH}"
  if ! /usr/bin/sudo /bin/rmdir "${STAGE_BIN}"; then
    echo "refusing to remove non-empty or changed staging bin: ${STAGE_BIN}" >&2
    exit 70
  fi
  if ! /usr/bin/sudo /bin/rmdir "${STAGE_ROOT}"; then
    echo "refusing to remove non-empty or changed staging root: ${STAGE_ROOT}" >&2
    exit 70
  fi
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
