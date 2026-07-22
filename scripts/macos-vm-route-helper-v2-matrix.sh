#!/bin/bash
set -euo pipefail
if [[ -n "${BASH_ENV:-}" || -n "${ENV:-}" ]]; then
  printf 'refusing inherited Bash startup hooks; invoke with env -u BASH_ENV -u ENV\n' >&2
  exit 77
fi
IFS=$'\n\t'
umask 077
readonly SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="${SAFE_PATH}"

# This matrix is deliberately unable to accept a CIDR, interface, command,
# path, or launchd label from its caller.  The mutating mode is restricted to
# the confirmed disposable Apple Virtualization.framework guest.

readonly VM_CONFIRM="authorized-kyclash-virtualization-framework-vm"
readonly RUNNER_ENVIRONMENT="local-virtualization-framework"
readonly EXPECTED_TEAM_ID="RQUQ8Y3S9H"
readonly APP_IDENTIFIER="net.kysion.kyclash"
readonly HELPER_IDENTIFIER="net.kysion.kyclash.route-helper"
readonly PRIMARY_UTUN_IDENTIFIER="net.kysion.kyclash.network-sidecar-utun-lab"
readonly SYNTHETIC_UTUN_IDENTIFIER="net.kysion.kyclash.utun-mihomo-lab"

readonly STAGE_ROOT="/Library/Application Support/KyClash/route-lab"
readonly STAGE_BIN="${STAGE_ROOT}/bin"
readonly HELPER="${STAGE_BIN}/kyclash-route-helper-fixed"
readonly CLIENT_SOURCE="${STAGE_BIN}/kyclash-route-helper-lab-client-hold.scp"
readonly CLIENT="/var/tmp/kyclash-route-helper-lab-client-v2.scp"
readonly UTUN_FIXTURE="${STAGE_BIN}/kyclash-utun-lab.test"
readonly SYNTHETIC_UTUN_FIXTURE="${STAGE_BIN}/kyclash-utun-mihomo-lab.test"
readonly HELPER_LABEL="net.kysion.kyclash.route-helper"
readonly UTUN_LABEL="net.kysion.kyclash.utun-route-fixture"
readonly HELPER_PLIST="/Library/LaunchDaemons/${HELPER_LABEL}.plist"
readonly UTUN_PLIST="/Library/LaunchDaemons/${UTUN_LABEL}.plist"

readonly OWNER_FILE="/var/tmp/kyclash-utun-lab-combined-hold.evidence"
readonly COMBINED_LOG_FILE="${STAGE_ROOT}/combined-hold.log"
readonly SYNTHETIC_MIHOMO_OWNER_FILE="/var/tmp/kyclash-utun-lab-mihomo-v2-owner"
readonly JOURNAL="/Library/Application Support/KyClash/route-lease-v1.plist"
readonly EVIDENCE_ROOT="${STAGE_ROOT}/evidence-v2"
readonly WRONG_MIHOMO_UTUN="utun65535"
readonly CORRUPT_JOURNAL_TEXT="kyclash-route-helper-v2-fixed-corrupt-journal"

# Keep this fixed pair synchronized with macos/route-helper/lab-client.m. The
# current VirtualMac guest already routes both TEST-NET blocks through en0.
readonly EXACT_V4="10.200.0.0/16"
readonly EXACT_V6="fd00:200::/48"
readonly MORE_SPECIFIC_V4="10.200.128.0/24"
readonly MORE_SPECIFIC_V6="fd00:200:0:1::/64"
readonly COVERING_V4="10.200.0.0/15"
readonly COVERING_V6="fd00:200::/47"

TMP_ROOT=""
LOG_FILE=""
OWNER_UTUN=""
SYNTHETIC_MIHOMO_UTUN=""
SYNTHETIC_MIHOMO_PID=""
SYNTHETIC_LAUNCH_PID=""
SYNTHETIC_OWNER_EVIDENCE_SAFE=0
HOLD_CLIENT_PID=""
HOLD_CLIENT_LOG=""
PREEXISTING_UTUNS=""
HELPER_IS_BOOTSTRAPPED=1
CORRUPT_JOURNAL_INSTALLED=0
CLEANUP_ACTIVE=0
CLEANUP_FAILURE=0
KEEP_TMP_ROOT=0
ADDED_ROUTES=()
ROUTE_FINGERPRINTS=()

usage() {
  printf 'usage: %s dry-run|preflight|run\n' "$0" >&2
}

dry_run() {
  /bin/cat <<'EOF'
KyClash route-helper v2 disposable-VM matrix (static dry-run)
mutation_guard=VirtualMac + local-virtualization-framework + exact KYCLASH_VM_LAB_CONFIRM
root_owned_stage=/Library/Application Support/KyClash/route-lab
primary_utun_fixture=kyclash-utun-lab.test
synthetic_mihomo_utun_fixture=kyclash-utun-mihomo-lab.test
desired_routes=10.200.0.0/16,fd00:200::/48
conflict_routes=10.200.128.0/24,fd00:200:0:1::/64
covering_routes=10.200.0.0/15,fd00:200::/47
preflight_overlap_guard=reject-fixed-prefix-and-selected-less-specific-overlap
scenarios=discover,dual-stack-normal,exact-conflict,more-specific-conflict,unknown-interface-conflict,explicit-mihomo-covering,helper-kill-restart,journal-corrupt-fail-closed,final-absence
forbidden=default-route,DNS,caller-supplied-route,caller-supplied-command,production-network
dry_run_mutations=none
EOF
}

require_disposable_guest() {
  if [[ "$(/usr/bin/uname -s)" != "Darwin" ]]; then
    printf 'refusing: macOS is required\n' >&2
    exit 69
  fi
  if [[ "$(/usr/bin/uname -m)" != "arm64" ]]; then
    printf 'refusing: Apple Silicon guest is required\n' >&2
    exit 69
  fi
  if [[ "$(/usr/sbin/sysctl -n hw.model 2>/dev/null || true)" != VirtualMac* ]]; then
    printf 'refusing: hw.model must identify a disposable VirtualMac guest\n' >&2
    exit 77
  fi
  if [[ "${KYCLASH_RUNNER_ENVIRONMENT:-}" != "${RUNNER_ENVIRONMENT}" ]]; then
    printf 'refusing: KYCLASH_RUNNER_ENVIRONMENT must be %s\n' \
      "${RUNNER_ENVIRONMENT}" >&2
    exit 77
  fi
  if [[ "${KYCLASH_VM_LAB_CONFIRM:-}" != "${VM_CONFIRM}" ]]; then
    printf 'refusing: set KYCLASH_VM_LAB_CONFIRM to the documented VM marker\n' >&2
    exit 77
  fi
  if [[ "$(/usr/bin/id -u)" -eq 0 ]]; then
    printf 'refusing: run as the disposable non-root login user; sudo is scoped internally\n' >&2
    exit 77
  fi
}

require_sudo() {
  if ! /usr/bin/sudo -v; then
    printf 'refusing: interactive sudo authorization is required in the disposable VM\n' >&2
    exit 77
  fi
}

assert_root_path() {
  local path="$1"
  local expected_mode="$2"
  local kind="$3"
  local owner_group mode links
  if /usr/bin/sudo /bin/test -L "${path}"; then
    printf 'refusing symlinked staged path: %s\n' "${path}" >&2
    exit 70
  fi
  case "${kind}" in
    directory)
      /usr/bin/sudo /bin/test -d "${path}" || {
        printf 'missing staged directory: %s\n' "${path}" >&2
        exit 66
      }
      ;;
    file)
      /usr/bin/sudo /bin/test -f "${path}" || {
        printf 'missing staged file: %s\n' "${path}" >&2
        exit 66
      }
      ;;
    *)
      printf 'internal error: unsupported staged-path kind\n' >&2
      exit 70
      ;;
  esac
  owner_group="$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg' "${path}")"
  mode="$(/usr/bin/sudo /usr/bin/stat -f '%Lp' "${path}")"
  links="$(/usr/bin/sudo /usr/bin/stat -f '%l' "${path}")"
  if [[ "${owner_group}" != "root:wheel" || "${mode}" != "${expected_mode}" || \
    ("${kind}" == "file" && "${links}" != "1") ]]; then
    printf 'unsafe staged ownership/mode for %s: %s %s\n' \
      "${path}" "${owner_group}" "${mode}" >&2
    exit 70
  fi
}

verify_signed_binary() {
  local path="$1"
  local expected_identifier="$2"
  local metadata team_id identifier
  if ! /usr/bin/sudo /usr/bin/codesign --verify --strict "${path}" >/dev/null 2>&1; then
    printf 'refusing unsigned or invalidly signed fixture: %s\n' "${path}" >&2
    exit 70
  fi
  metadata="$(/usr/bin/sudo /usr/bin/codesign -dv --verbose=4 "${path}" 2>&1)"
  team_id="$(printf '%s\n' "${metadata}" | /usr/bin/awk -F= \
    '/^TeamIdentifier=/{value=$2} END{print value}')"
  identifier="$(printf '%s\n' "${metadata}" | /usr/bin/awk -F= \
    '/^Identifier=/{value=$2} END{print value}')"
  if [[ "${team_id}" != "${EXPECTED_TEAM_ID}" ]]; then
    printf 'refusing fixture with unexpected Team ID: %s\n' "${path}" >&2
    exit 70
  fi
  if [[ -n "${expected_identifier}" && "${identifier}" != "${expected_identifier}" ]]; then
    printf 'refusing fixture with unexpected identifier: %s\n' "${path}" >&2
    exit 70
  fi
  if ! /usr/bin/sudo /usr/bin/file "${path}" | /usr/bin/grep -F 'Mach-O 64-bit executable arm64' >/dev/null; then
    printf 'refusing non-arm64 fixture: %s\n' "${path}" >&2
    exit 70
  fi
}

valid_utun() {
  local value="$1"
  [[ "${value}" =~ ^utun([1-9][0-9]*|0)$ && "${#value}" -le 15 ]]
}

read_owner_utun() {
  local value fixture_pid child_pid controller_ppid
  assert_root_path "${OWNER_FILE}" 600 file
  if ! /usr/bin/sudo /usr/bin/awk 'END { exit NR == 2 ? 0 : 1 }' \
    "${OWNER_FILE}"; then
    printf 'refusing combined utun evidence with unexpected line count: %s\n' \
      "${OWNER_FILE}" >&2
    return 1
  fi
  value="$(/usr/bin/sudo /usr/bin/head -n 1 "${OWNER_FILE}")"
  if ! valid_utun "${value}" || ! /sbin/ifconfig "${value}" >/dev/null 2>&1; then
    printf 'invalid or absent fixed owner utun: %s\n' "${value}" >&2
    return 1
  fi
  child_pid="$(/usr/bin/sudo /usr/bin/sed -n '2p' "${OWNER_FILE}")"
  if [[ ! "${child_pid}" =~ ^[1-9][0-9]*$ || "${child_pid}" -le 1 ]]; then
    printf 'invalid combined utun child PID evidence\n' >&2
    return 1
  fi
  fixture_pid="$(utun_fixture_pid)"
  if [[ -z "${fixture_pid}" ]] || ! /usr/bin/sudo /bin/kill -0 "${fixture_pid}" 2>/dev/null || \
    ! assert_process_identity_contains "${fixture_pid}" "${UTUN_FIXTURE}" \
      "TestRealUTUNProductionSidecarControllerHoldForForcedTermination" || \
    [[ "${child_pid}" == "${fixture_pid}" ]] || \
    ! /usr/bin/sudo /bin/kill -0 "${child_pid}" 2>/dev/null || \
    ! assert_process_identity_contains "${child_pid}" "${UTUN_FIXTURE}" \
      "TestRealUTUNProductionSidecarChild"; then
    printf 'fixed utun owner is not backed by the staged combined launchd fixture\n' >&2
    return 1
  fi
  controller_ppid="$(/usr/bin/sudo /bin/ps -p "${child_pid}" -o ppid= 2>/dev/null | \
    /usr/bin/awk '{print $1}')"
  if [[ ! "${controller_ppid}" =~ ^[1-9][0-9]*$ ]] || \
    [[ "${controller_ppid}" -le 1 || "${controller_ppid}" != "${fixture_pid}" ]]; then
    printf 'fixed utun child is not directly owned by the staged controller: child=%s ppid=%s controller=%s\n' \
      "${child_pid}" "${controller_ppid}" "${fixture_pid}" >&2
    return 1
  fi
  printf '%s\n' "${value}"
}

utun_fixture_pid() {
  /usr/bin/sudo /bin/launchctl print "system/${UTUN_LABEL}" 2>/dev/null | \
    /usr/bin/awk '$1 == "pid" && $2 == "=" { value = $3 } END { print value }'
}

utun_names() {
  /sbin/ifconfig -l | /usr/bin/tr ' ' '\n' | /usr/bin/grep '^utun' || true
}

find_synthetic_mihomo_pid() {
  local matches count
  matches="$(/usr/bin/sudo /bin/ps -axo pid=,command= | /usr/bin/awk \
    -v executable="${SYNTHETIC_UTUN_FIXTURE}" \
    'index($0, executable) && index($0, "TestRealUTUNHoldForForcedTermination") && $0 !~ /\/usr\/bin\/sudo/ { print $1 }')"
  count="$(/usr/bin/printf '%s\n' "${matches}" | /usr/bin/awk 'NF {value += 1} END {print value + 0}')"
  if [[ "${count}" -gt 1 ]]; then
    printf 'refusing multiple synthetic Mihomo fixture processes: %s\n' "${matches}" >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "${matches}"
}

assert_process_identity() {
  local pid="$1"
  local expected_path="$2"
  local command_line
  [[ "${pid}" =~ ^[1-9][0-9]*$ && "${pid}" -gt 1 ]] || return 1
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  case "${command_line}" in
    "${expected_path}"|"${expected_path} "*) return 0 ;;
    *) return 1 ;;
  esac
}

assert_process_identity_contains() {
  local pid="$1"
  local expected_path="$2"
  local expected_marker="$3"
  local command_line
  assert_process_identity "${pid}" "${expected_path}" || return 1
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command_line}" == *"${expected_marker}"* ]]
}

assert_plist_value() {
  local plist="$1"
  local key_path="$2"
  local expected="$3"
  local actual
  actual="$(/usr/bin/plutil -extract "${key_path}" raw -o - "${plist}" 2>/dev/null || true)"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'refusing unexpected fixed launchd plist value: %s %s=%s\n' \
      "${plist}" "${key_path}" "${actual}" >&2
    return 1
  fi
}

assert_plist_contains() {
  local plist="$1"
  local literal="$2"
  if ! /usr/bin/plutil -p "${plist}" | /usr/bin/grep -F "${literal}" >/dev/null; then
    printf 'refusing launchd plist without fixed literal: %s %s\n' \
      "${plist}" "${literal}" >&2
    return 1
  fi
}

assert_plist_array_length() {
  local plist="$1"
  local expected_length="$2"
  if /usr/bin/plutil -extract "ProgramArguments.${expected_length}" raw -o - \
    "${plist}" >/dev/null 2>&1; then
    printf 'refusing launchd plist with unexpected extra ProgramArguments: %s\n' \
      "${plist}" >&2
    return 1
  fi
}

assert_plist_environment_count() {
  local plist="$1"
  local expected_count="$2"
  local xml count
  xml="$(/usr/bin/plutil -extract EnvironmentVariables xml1 -o - "${plist}" \
    2>/dev/null || true)"
  count="$(/usr/bin/printf '%s\n' "${xml}" | /usr/bin/awk \
    '/<key>/{value += 1} END {print value + 0}')"
  [[ "${count}" == "${expected_count}" ]]
}

assert_fixed_plists() {
  assert_plist_value "${HELPER_PLIST}" Label "${HELPER_LABEL}"
  assert_plist_value "${HELPER_PLIST}" ProgramArguments.0 "${HELPER}"
  assert_plist_array_length "${HELPER_PLIST}" 1
  if /usr/bin/plutil -extract EnvironmentVariables xml1 -o - "${HELPER_PLIST}" \
    >/dev/null 2>&1; then
    printf 'refusing helper plist with unexpected environment variables\n' >&2
    return 1
  fi
  if ! /usr/bin/plutil -p "${HELPER_PLIST}" |
    /usr/bin/grep -F '"net.kysion.kyclash.route-helper" => true' >/dev/null; then
    printf 'refusing helper plist without its exact MachServices entry\n' >&2
    return 1
  fi
  assert_plist_value "${UTUN_PLIST}" Label "${UTUN_LABEL}"
  assert_plist_value "${UTUN_PLIST}" ProgramArguments.0 "${UTUN_FIXTURE}"
  assert_plist_value "${UTUN_PLIST}" \
    ProgramArguments.1 '-test.run=^TestRealUTUNProductionSidecarControllerHoldForForcedTermination$'
  assert_plist_value "${UTUN_PLIST}" ProgramArguments.2 '-test.count=1'
  assert_plist_value "${UTUN_PLIST}" ProgramArguments.3 '-test.v=true'
  assert_plist_array_length "${UTUN_PLIST}" 4
  assert_plist_environment_count "${UTUN_PLIST}" 3
  assert_plist_value "${UTUN_PLIST}" \
    EnvironmentVariables.KYCLASH_VM_LAB_CONFIRM "${VM_CONFIRM}"
  assert_plist_value "${UTUN_PLIST}" \
    EnvironmentVariables.KYCLASH_UTUN_LAB_COMBINED_HOLD 1
  assert_plist_value "${UTUN_PLIST}" \
    EnvironmentVariables.KYCLASH_UTUN_LAB_COMBINED_EVIDENCE_FILE "${OWNER_FILE}"
  assert_plist_value "${UTUN_PLIST}" RunAtLoad true
  assert_plist_value "${UTUN_PLIST}" StandardOutPath "${COMBINED_LOG_FILE}"
  assert_plist_value "${UTUN_PLIST}" StandardErrorPath "${COMBINED_LOG_FILE}"
}

route_spec() {
  local key="$1"
  case "${key}" in
    exact4)
      ROUTE_FAMILY="inet"
      ROUTE_CIDR="${EXACT_V4}"
      ROUTE_DESTINATION_REGEX='^(10\.200|10\.200/16|10\.200\.0\.0/16)$'
      ;;
    exact6)
      ROUTE_FAMILY="inet6"
      ROUTE_CIDR="${EXACT_V6}"
      ROUTE_DESTINATION_REGEX='^fd00:200::/48$'
      ;;
    more4)
      ROUTE_FAMILY="inet"
      ROUTE_CIDR="${MORE_SPECIFIC_V4}"
      ROUTE_DESTINATION_REGEX='^(10\.200\.128|10\.200\.128/24|10\.200\.128\.0/24)$'
      ;;
    more6)
      ROUTE_FAMILY="inet6"
      ROUTE_CIDR="${MORE_SPECIFIC_V6}"
      ROUTE_DESTINATION_REGEX='^fd00:200:0:1::/64$'
      ;;
    covering4)
      ROUTE_FAMILY="inet"
      ROUTE_CIDR="${COVERING_V4}"
      ROUTE_DESTINATION_REGEX='^(10\.200/15|10\.200\.0\.0/15)$'
      ;;
    covering6)
      ROUTE_FAMILY="inet6"
      ROUTE_CIDR="${COVERING_V6}"
      ROUTE_DESTINATION_REGEX='^fd00:200::/47$'
      ;;
    *)
      printf 'internal error: unsupported fixed route key\n' >&2
      return 70
      ;;
  esac
}

route_count() {
  local key="$1"
  local interface_name="${2:-}"
  local count
  route_spec "${key}"
  if ! count="$(/usr/sbin/netstat -rn -f "${ROUTE_FAMILY}" | /usr/bin/awk \
    -v destination="${ROUTE_DESTINATION_REGEX}" -v interface_name="${interface_name}" '
      tolower($1) ~ destination && (interface_name == "" || $4 == interface_name) { count += 1 }
      END { print count + 0 }
    ')" || [[ ! "${count}" =~ ^[0-9]+$ ]]; then
    printf 'unable to inspect the fixed route table\n' >&2
    return 1
  fi
  printf '%s\n' "${count}"
}

route_fingerprint() {
  local key="$1"
  local interface_name="$2"
  route_spec "${key}"
  /usr/sbin/netstat -rn -f "${ROUTE_FAMILY}" | /usr/bin/awk \
    -v destination="${ROUTE_DESTINATION_REGEX}" -v interface_name="${interface_name}" '
      tolower($1) ~ destination && $4 == interface_name {
        print $1 "|" $2 "|" $3 "|" $4
      }
    '
}

remember_route_fingerprint() {
  local key="$1"
  local interface_name="$2"
  local fingerprint="$3"
  local index entry prefix
  prefix="${key}|${interface_name}|"
  for index in "${!ROUTE_FINGERPRINTS[@]}"; do
    entry="${ROUTE_FINGERPRINTS[${index}]}"
    if [[ "${entry}" == "${prefix}"* ]]; then
      ROUTE_FINGERPRINTS[index]="${key}|${interface_name}|${fingerprint}"
      return 0
    fi
  done
  ROUTE_FINGERPRINTS+=("${key}|${interface_name}|${fingerprint}")
}

remembered_route_fingerprint() {
  local key="$1"
  local interface_name="$2"
  local index entry prefix
  prefix="${key}|${interface_name}|"
  for index in "${!ROUTE_FINGERPRINTS[@]}"; do
    entry="${ROUTE_FINGERPRINTS[${index}]}"
    if [[ "${entry}" == "${prefix}"* ]]; then
      printf '%s\n' "${entry#"${prefix}"}"
      return 0
    fi
  done
  return 1
}

forget_route_fingerprint() {
  local key="$1"
  local interface_name="$2"
  local index entry prefix
  local -a retained=()
  prefix="${key}|${interface_name}|"
  for index in "${!ROUTE_FINGERPRINTS[@]}"; do
    entry="${ROUTE_FINGERPRINTS[${index}]}"
    if [[ "${entry}" != "${prefix}"* ]]; then
      retained+=("${entry}")
    fi
  done
  ROUTE_FINGERPRINTS=()
  for index in "${!retained[@]}"; do
    ROUTE_FINGERPRINTS+=("${retained[${index}]}")
  done
}

assert_route_absent() {
  local key="$1"
  local interface_name="${2:-}"
  local count
  count="$(route_count "${key}" "${interface_name}")"
  if [[ "${count}" -ne 0 ]]; then
    printf 'unexpected fixed route remains: key=%s interface=%s count=%s\n' \
      "${key}" "${interface_name:-any}" "${count}" >&2
    return 1
  fi
}

assert_route_present_once() {
  local key="$1"
  local interface_name="$2"
  local count
  count="$(route_count "${key}" "${interface_name}")"
  if [[ "${count}" -ne 1 ]]; then
    printf 'expected one fixed route: key=%s interface=%s count=%s\n' \
      "${key}" "${interface_name}" "${count}" >&2
    return 1
  fi
}

add_fixed_route() {
  local key="$1"
  local interface_name="$2"
  assert_route_absent "${key}"
  route_spec "${key}"
  if [[ "${ROUTE_FAMILY}" == "inet6" ]]; then
    /usr/bin/sudo /sbin/route -n add -inet6 -net "${ROUTE_CIDR}" \
      -interface "${interface_name}"
  else
    /usr/bin/sudo /sbin/route -n add -net "${ROUTE_CIDR}" \
      -interface "${interface_name}"
  fi
  ADDED_ROUTES+=("${key}|${interface_name}")
  assert_route_present_once "${key}" "${interface_name}"
  local fingerprint
  fingerprint="$(route_fingerprint "${key}" "${interface_name}")"
  if [[ "$(printf '%s\n' "${fingerprint}" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')" -ne 1 ]]; then
    printf 'refusing route with ambiguous post-add identity: key=%s interface=%s\n' \
      "${key}" "${interface_name}" >&2
    return 1
  fi
  remember_route_fingerprint "${key}" "${interface_name}" "${fingerprint}"
}

delete_fixed_route() {
  local key="$1"
  local interface_name="$2"
  local matching_count total_count
  matching_count="$(route_count "${key}" "${interface_name}")"
  total_count="$(route_count "${key}")"
  if [[ "${matching_count}" -eq 0 && "${total_count}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${matching_count}" -ne 1 || "${total_count}" -ne 1 ]]; then
    printf 'refusing ambiguous fixed-route cleanup: key=%s interface=%s matching=%s total=%s\n' \
      "${key}" "${interface_name}" "${matching_count}" "${total_count}" >&2
    return 1
  fi
  local expected_fingerprint current_fingerprint
  expected_fingerprint="$(remembered_route_fingerprint "${key}" "${interface_name}" || true)"
  current_fingerprint="$(route_fingerprint "${key}" "${interface_name}")"
  if [[ -z "${expected_fingerprint}" || "${current_fingerprint}" != "${expected_fingerprint}" ]]; then
    printf 'refusing changed fixed-route identity: key=%s interface=%s\n' \
      "${key}" "${interface_name}" >&2
    return 1
  fi
  route_spec "${key}"
  if [[ "${ROUTE_FAMILY}" == "inet6" ]]; then
    /usr/bin/sudo /sbin/route -n delete -inet6 -net "${ROUTE_CIDR}" \
      -interface "${interface_name}"
  else
    /usr/bin/sudo /sbin/route -n delete -net "${ROUTE_CIDR}" \
      -interface "${interface_name}"
  fi
  assert_route_absent "${key}"
  forget_route_fingerprint "${key}" "${interface_name}"
}

assert_matrix_routes_absent() {
  local key
  for key in exact4 exact6 more4 more6 covering4 covering6; do
    assert_route_absent "${key}"
  done
}

assert_no_preexisting_private_overlap() {
  local ipv4_table ipv6_table ipv4_overlap ipv6_overlap
  if ! ipv4_table="$(/usr/sbin/netstat -rn -f inet)"; then
    printf 'unable to inspect the IPv4 underlay route table\n' >&2
    return 1
  fi
  if ! ipv6_table="$(/usr/sbin/netstat -rn -f inet6)"; then
    printf 'unable to inspect the IPv6 underlay route table\n' >&2
    return 1
  fi
  # Only the fixed matrix prefixes are protected here.  The guest may have
  # unrelated RFC1918/ULA routes (for example the combined fixture's own
  # 10.90.0.1 host route, or the pre-existing 10.127 underlay); rejecting all
  # 10/8 or fd00::/8 routes would make a safe fixture impossible to run.
  # Never exempt a route inside the matrix prefix, even when it points at the
  # owner utun: that would hide stale state from a prior run.
  ipv4_overlap="$(/usr/bin/printf '%s\n' "${ipv4_table}" | /usr/bin/awk \
    -v owner_interface="${OWNER_UTUN}" '
      $1 == "Destination" { header = 1; next }
      header && $1 != "default" && $1 ~ /^10\.(200|201)([.]|\/|$)/ {
        print; found = 1
      }
      END { exit found ? 0 : 1 }
    ' || true)"
  ipv6_overlap="$(/usr/bin/printf '%s\n' "${ipv6_table}" | /usr/bin/awk \
    -v owner_interface="${OWNER_UTUN}" '
      $1 == "Destination" { header = 1; next }
      header && $1 != "default" && tolower($1) ~ /^fd00:200(:|\/|$)/ {
        print; found = 1
      }
      END { exit found ? 0 : 1 }
    ' || true)"
  if [[ -n "${ipv4_overlap}" || -n "${ipv6_overlap}" ]]; then
    printf 'refusing pre-existing fixed-matrix route overlap; underlay snapshot follows\n' >&2
    [[ -n "${ipv4_overlap}" ]] && printf '%s\n' "${ipv4_overlap}" >&2
    [[ -n "${ipv6_overlap}" ]] && printf '%s\n' "${ipv6_overlap}" >&2
    return 1
  fi
  assert_no_selected_route_overlap inet 10.200.0.1
  assert_no_selected_route_overlap inet 10.200.128.1
  assert_no_selected_route_overlap inet 10.201.0.1
  assert_no_selected_route_overlap inet 10.201.255.254
  assert_no_selected_route_overlap inet6 fd00:200::1
  assert_no_selected_route_overlap inet6 fd00:200:0:1::1
}

assert_no_selected_route_overlap() {
  local family="$1"
  local address="$2"
  local snapshot destination mask interface_name
  # A route-get probe catches less-specific routes which do not begin with the
  # fixed prefix (10/8, 10.128/9, 0/1, fd00::/8, and similar). A genuinely
  # unrouted IPv6 address is allowed to return "not in table"; netstat above
  # remains the authoritative read-only table check in that case.
  set +e
  snapshot="$(/sbin/route -n get -"${family}" "${address}" 2>&1)"
  local route_status=$?
  set -e
  if /usr/bin/printf '%s\n' "${snapshot}" | /usr/bin/grep -Fq 'not in table'; then
    return 0
  fi
  if [[ "${route_status}" -ne 0 ]]; then
    printf 'unable to inspect selected %s route for %s\n%s\n' \
      "${family}" "${address}" "${snapshot}" >&2
    return 1
  fi
  destination="$(/usr/bin/printf '%s\n' "${snapshot}" | /usr/bin/awk \
    '$1 == "destination:" { value = $2 } END { print value }')"
  mask="$(/usr/bin/printf '%s\n' "${snapshot}" | /usr/bin/awk \
    '$1 == "mask:" { value = $2 } END { print value }')"
  interface_name="$(/usr/bin/printf '%s\n' "${snapshot}" | /usr/bin/awk \
    '$1 == "interface:" { value = $2 } END { print value }')"
  if [[ -z "${destination}" || -z "${mask}" || -z "${interface_name}" ]]; then
    printf 'unable to parse selected %s route for %s\n' "${family}" "${address}" >&2
    return 1
  fi
  case "${mask}" in
    default|0.0.0.0|::|::0|0:0:0:0:0:0:0:0)
      case "${interface_name}" in
        utun*|tun*|ppp*)
          printf 'refusing selected default route through a tunnel interface for %s: %s\n' \
            "${address}" "${interface_name}" >&2
          return 1
          ;;
        *)
          return 0
          ;;
      esac
      ;;
  esac
  printf 'refusing selected pre-existing route overlapping matrix address %s: %s mask=%s interface=%s\n' \
    "${address}" "${destination}" "${mask}" "${interface_name}" >&2
  return 1
}

helper_pid() {
  /usr/bin/sudo /bin/launchctl print "system/${HELPER_LABEL}" 2>/dev/null | \
    /usr/bin/awk '$1 == "pid" && $2 == "=" { value=$3 } END { print value }'
}

wait_for_helper_pid_change() {
  local previous_pid="$1"
  local attempt current_pid
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    current_pid="$(helper_pid || true)"
    if [[ -n "${current_pid}" && "${current_pid}" != "${previous_pid}" ]]; then
      printf '%s\n' "${current_pid}"
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'helper did not restart with a new PID\n' >&2
  return 1
}

client_integrity_status() {
  local source_hash client_hash
  /usr/bin/sudo /bin/test -f "${CLIENT_SOURCE}" || return 1
  /usr/bin/sudo /bin/test -f "${CLIENT}" || return 1
  ! /usr/bin/sudo /bin/test -L "${CLIENT_SOURCE}" || return 1
  ! /usr/bin/sudo /bin/test -L "${CLIENT}" || return 1
  [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' "${CLIENT_SOURCE}" \
    2>/dev/null || true)" == "root:wheel:755:1" ]] || return 1
  [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' "${CLIENT}" \
    2>/dev/null || true)" == "root:wheel:755:1" ]] || return 1
  /usr/bin/sudo /usr/bin/codesign --verify --strict "${CLIENT}" >/dev/null 2>&1 || return 1
  source_hash="$(/usr/bin/sudo /usr/bin/shasum -a 256 "${CLIENT_SOURCE}" | /usr/bin/awk '{print $1}')"
  client_hash="$(/usr/bin/sudo /usr/bin/shasum -a 256 "${CLIENT}" | /usr/bin/awk '{print $1}')"
  [[ -n "${source_hash}" && "${source_hash}" == "${client_hash}" ]]
}

assert_client_integrity() {
  if ! client_integrity_status; then
    printf 'refusing client copy whose signature, ownership, mode, or bytes changed\n' >&2
    return 1
  fi
}

run_client() {
  assert_client_integrity
  "${CLIENT}" "$@" 2>&1 | /usr/bin/tee -a "${LOG_FILE}"
}

run_discover_retry() {
  local attempt rc
  attempt=0
  while [[ "${attempt}" -lt 30 ]]; do
    if ! assert_client_integrity; then
      return 1
    fi
    set +e
    "${CLIENT}" >"${TMP_ROOT}/discover-retry.log" 2>&1
    rc=$?
    set -e
    /bin/cat "${TMP_ROOT}/discover-retry.log" | /usr/bin/tee -a "${LOG_FILE}"
    if [[ "${rc}" -eq 0 ]]; then
      return 0
    fi
    /bin/sleep 0.2
    attempt=$((attempt + 1))
  done
  printf 'v2 discover did not become ready within the bounded retry window\n' >&2
  return 1
}

start_synthetic_mihomo_utun() {
  local attempt existing_pid candidate synthetic_ready
  synthetic_ready=0
  if /usr/bin/sudo /bin/test -e "${SYNTHETIC_MIHOMO_OWNER_FILE}" || \
    /usr/bin/sudo /bin/test -L "${SYNTHETIC_MIHOMO_OWNER_FILE}"; then
    printf 'refusing pre-existing synthetic Mihomo owner file\n' >&2
    return 1
  fi
  existing_pid="$(find_synthetic_mihomo_pid)"
  if [[ -n "${existing_pid}" ]] && /usr/bin/sudo /bin/kill -0 "${existing_pid}" 2>/dev/null; then
    printf 'refusing pre-existing synthetic Mihomo fixture process: %s\n' \
      "${existing_pid}" >&2
    return 1
  fi
  PREEXISTING_UTUNS="$(utun_names)"
  # The log is deliberately user-owned temporary evidence; sudo applies only
  # to the fixture process, not to this shell redirection.
  # shellcheck disable=SC2024
  /usr/bin/sudo /usr/bin/env \
    KYCLASH_VM_LAB_CONFIRM="${VM_CONFIRM}" \
    KYCLASH_UTUN_LAB_HOLD=1 \
    KYCLASH_UTUN_LAB_OWNER_FILE="${SYNTHETIC_MIHOMO_OWNER_FILE}" \
    "${SYNTHETIC_UTUN_FIXTURE}" \
    '-test.run=^TestRealUTUNHoldForForcedTermination$' \
    '-test.count=1' '-test.v=true' \
    >"${TMP_ROOT}/synthetic-mihomo-utun.log" 2>&1 &
  SYNTHETIC_LAUNCH_PID=$!
  SYNTHETIC_MIHOMO_PID=""
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    if [[ -z "${SYNTHETIC_MIHOMO_PID}" ]]; then
      SYNTHETIC_MIHOMO_PID="$(find_synthetic_mihomo_pid)"
    fi
    if [[ -z "${SYNTHETIC_MIHOMO_PID}" ]] || \
      ! /usr/bin/sudo /bin/kill -0 "${SYNTHETIC_MIHOMO_PID}" 2>/dev/null; then
      if [[ -n "${SYNTHETIC_LAUNCH_PID}" ]] && \
        ! /usr/bin/sudo /bin/kill -0 "${SYNTHETIC_LAUNCH_PID}" 2>/dev/null; then
        /bin/cat "${TMP_ROOT}/synthetic-mihomo-utun.log" >&2
        printf 'synthetic Mihomo utun fixture exited early\n' >&2
        return 1
      fi
    fi
    if [[ -z "${SYNTHETIC_MIHOMO_PID}" ]]; then
      /bin/sleep 0.1
      attempt=$((attempt + 1))
      continue
    fi
    if ! /usr/bin/sudo /bin/kill -0 "${SYNTHETIC_MIHOMO_PID}" 2>/dev/null; then
      /bin/cat "${TMP_ROOT}/synthetic-mihomo-utun.log" >&2
      printf 'synthetic Mihomo utun fixture exited early\n' >&2
      return 1
    fi
    if /usr/bin/sudo /bin/test -f "${SYNTHETIC_MIHOMO_OWNER_FILE}" && \
      ! /usr/bin/sudo /bin/test -L "${SYNTHETIC_MIHOMO_OWNER_FILE}"; then
      candidate="$(/usr/bin/sudo /usr/bin/head -n 1 "${SYNTHETIC_MIHOMO_OWNER_FILE}")"
      if valid_utun "${candidate}" && \
        /sbin/ifconfig "${candidate}" >/dev/null 2>&1 && \
        ! /usr/bin/printf '%s\n' "${PREEXISTING_UTUNS}" | \
          /usr/bin/grep -Fqx "${candidate}" && \
        /usr/bin/sudo /usr/bin/awk 'END { exit NR == 1 ? 0 : 1 }' \
          "${SYNTHETIC_MIHOMO_OWNER_FILE}" && \
        [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' \
          "${SYNTHETIC_MIHOMO_OWNER_FILE}")" == "root:wheel:600:1" ]] && \
        assert_process_identity "${SYNTHETIC_MIHOMO_PID}" "${SYNTHETIC_UTUN_FIXTURE}"; then
        SYNTHETIC_MIHOMO_UTUN="${candidate}"
        SYNTHETIC_OWNER_EVIDENCE_SAFE=1
        synthetic_ready=1
        break
      fi
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  if [[ "${synthetic_ready}" -ne 1 || -z "${SYNTHETIC_MIHOMO_UTUN}" || \
    "${SYNTHETIC_MIHOMO_UTUN}" == "${OWNER_UTUN}" ]]; then
    SYNTHETIC_MIHOMO_UTUN=""
    printf 'synthetic Mihomo utun was not created or collided with the owned utun\n' >&2
    return 1
  fi
  printf 'synthetic_mihomo_utun=%s\n' "${SYNTHETIC_MIHOMO_UTUN}" | \
    /usr/bin/tee -a "${LOG_FILE}"
}

stop_exact_process() {
  local pid="$1"
  local expected_path="$2"
  local command_line start_token attempt
  if [[ -z "${pid}" ]] || ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  case "${command_line}" in
    "${expected_path}"|"${expected_path} "*) ;;
    *)
      printf 'refusing to signal unexpected PID %s: %s\n' \
        "${pid}" "${command_line}" >&2
      return 1
      ;;
  esac
  start_token="$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)"
  [[ -n "${start_token}" ]] || return 1
  if ! assert_process_identity "${pid}" "${expected_path}" || \
    [[ "$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)" != "${start_token}" ]]; then
    printf 'refusing to signal PID whose identity changed: %s\n' "${pid}" >&2
    return 1
  fi
  /usr/bin/sudo /bin/kill -TERM "${pid}"
  attempt=0
  while [[ "${attempt}" -lt 30 ]]; do
    if ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  case "${command_line}" in
    "${expected_path}"|"${expected_path} "*)
      if [[ "$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)" != "${start_token}" ]]; then
        printf 'refusing SIGKILL after process start time changed: %s\n' "${pid}" >&2
        return 1
      fi
      /usr/bin/sudo /bin/kill -KILL "${pid}"
      ;;
    *)
      printf 'refusing SIGKILL after PID identity changed: %s\n' "${pid}" >&2
      return 1
      ;;
  esac
}

stop_synthetic_launcher() {
  local pid="$1"
  local command_line start_token attempt
  if [[ -z "${pid}" ]] || ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  # The shell-owned PID is the exact sudo/env wrapper started by this script.
  # Require both immutable fixture markers before signaling it; never treat a
  # caller-provided PID or an unrelated sudo process as ours.
  if [[ "${command_line}" != /usr/bin/sudo\ /usr/bin/env\ *"${SYNTHETIC_UTUN_FIXTURE}"*"TestRealUTUNHoldForForcedTermination"* ]]; then
    printf 'refusing to signal unexpected synthetic launcher PID %s: %s\n' \
      "${pid}" "${command_line}" >&2
    return 1
  fi
  start_token="$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)"
  [[ -n "${start_token}" ]] || return 1
  if ! assert_process_identity_contains "${pid}" "${SYNTHETIC_UTUN_FIXTURE}" \
    "TestRealUTUNHoldForForcedTermination" ||
    [[ "$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)" != \
      "${start_token}" ]]; then
    printf 'refusing to signal synthetic launcher whose identity changed: %s\n' "${pid}" >&2
    return 1
  fi
  /usr/bin/sudo /bin/kill -TERM "${pid}"
  attempt=0
  while [[ "${attempt}" -lt 30 ]]; do
    if ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  command_line="$(/usr/bin/sudo /bin/ps -p "${pid}" -o command= 2>/dev/null || true)"
  if [[ "${command_line}" != /usr/bin/sudo\ /usr/bin/env\ *"${SYNTHETIC_UTUN_FIXTURE}"*"TestRealUTUNHoldForForcedTermination"* ]] || \
    [[ "$(/usr/bin/sudo /bin/ps -p "${pid}" -o lstart= 2>/dev/null || true)" != "${start_token}" ]]; then
    printf 'refusing SIGKILL after synthetic launcher identity changed: %s\n' "${pid}" >&2
    return 1
  fi
  /usr/bin/sudo /bin/kill -KILL "${pid}"
  attempt=0
  while [[ "${attempt}" -lt 30 ]]; do
    if ! /usr/bin/sudo /bin/kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'synthetic launcher did not terminate: %s\n' "${pid}" >&2
  return 1
}

stop_synthetic_mihomo_utun() {
  local attempt cleanup_failed
  cleanup_failed=0
  if [[ -z "${SYNTHETIC_MIHOMO_UTUN}" ]] && \
    /usr/bin/sudo /bin/test -f "${SYNTHETIC_MIHOMO_OWNER_FILE}" && \
    ! /usr/bin/sudo /bin/test -L "${SYNTHETIC_MIHOMO_OWNER_FILE}"; then
    local recovered_utun
    recovered_utun="$(/usr/bin/sudo /usr/bin/head -n 1 \
      "${SYNTHETIC_MIHOMO_OWNER_FILE}")"
    if valid_utun "${recovered_utun}" && \
      /sbin/ifconfig "${recovered_utun}" >/dev/null 2>&1 && \
      ! /usr/bin/printf '%s\n' "${PREEXISTING_UTUNS}" | \
        /usr/bin/grep -Fqx "${recovered_utun}" && \
      /usr/bin/sudo /usr/bin/awk 'END { exit NR == 1 ? 0 : 1 }' \
        "${SYNTHETIC_MIHOMO_OWNER_FILE}" && \
      [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' \
        "${SYNTHETIC_MIHOMO_OWNER_FILE}" 2>/dev/null || true)" == \
        "root:wheel:600:1" ]]; then
      SYNTHETIC_MIHOMO_UTUN="${recovered_utun}"
      SYNTHETIC_OWNER_EVIDENCE_SAFE=1
    else
      printf 'refusing to trust unverifiable synthetic owner evidence\n' >&2
      cleanup_failed=1
      SYNTHETIC_OWNER_EVIDENCE_SAFE=0
    fi
  fi
  if [[ -n "${SYNTHETIC_MIHOMO_PID}" ]]; then
    if ! stop_exact_process "${SYNTHETIC_MIHOMO_PID}" "${SYNTHETIC_UTUN_FIXTURE}"; then
      cleanup_failed=1
    fi
    wait "${SYNTHETIC_MIHOMO_PID}" 2>/dev/null || true
    SYNTHETIC_MIHOMO_PID=""
  fi
  if [[ -n "${SYNTHETIC_LAUNCH_PID}" ]]; then
    if ! stop_synthetic_launcher "${SYNTHETIC_LAUNCH_PID}"; then
      cleanup_failed=1
    fi
    wait "${SYNTHETIC_LAUNCH_PID}" 2>/dev/null || true
    SYNTHETIC_LAUNCH_PID=""
  fi
  if [[ -n "${SYNTHETIC_MIHOMO_UTUN}" ]]; then
    attempt=0
    while [[ "${attempt}" -lt 50 ]]; do
      if ! /sbin/ifconfig "${SYNTHETIC_MIHOMO_UTUN}" >/dev/null 2>&1; then
        break
      fi
      /bin/sleep 0.1
      attempt=$((attempt + 1))
    done
    if /sbin/ifconfig "${SYNTHETIC_MIHOMO_UTUN}" >/dev/null 2>&1; then
      printf 'synthetic Mihomo utun remained after fixture termination: %s\n' \
        "${SYNTHETIC_MIHOMO_UTUN}" >&2
      cleanup_failed=1
    else
      SYNTHETIC_MIHOMO_UTUN=""
    fi
  fi
  if /usr/bin/sudo /bin/test -e "${SYNTHETIC_MIHOMO_OWNER_FILE}" || \
    /usr/bin/sudo /bin/test -L "${SYNTHETIC_MIHOMO_OWNER_FILE}"; then
    if [[ "${SYNTHETIC_OWNER_EVIDENCE_SAFE}" -ne 1 || \
      -n "${SYNTHETIC_MIHOMO_UTUN}" ]] || \
      /usr/bin/sudo /bin/test -L "${SYNTHETIC_MIHOMO_OWNER_FILE}" || \
      [[ "$(/usr/bin/sudo /usr/bin/stat -f '%Su:%Sg:%Lp:%l' \
        "${SYNTHETIC_MIHOMO_OWNER_FILE}" 2>/dev/null || true)" != "root:wheel:600:1" ]]; then
      printf 'refusing unsafe synthetic owner-file cleanup\n' >&2
      cleanup_failed=1
    else
      if ! /usr/bin/sudo /bin/rm -f "${SYNTHETIC_MIHOMO_OWNER_FILE}"; then
        cleanup_failed=1
      else
        SYNTHETIC_OWNER_EVIDENCE_SAFE=0
      fi
    fi
  fi
  if [[ -n "${PREEXISTING_UTUNS}" ]]; then
    local current_utun
    while IFS= read -r current_utun; do
      [[ -z "${current_utun}" ]] && continue
      if ! /usr/bin/printf '%s\n' "${PREEXISTING_UTUNS}" | \
        /usr/bin/grep -Fqx "${current_utun}"; then
        printf 'unexpected new utun remained after synthetic fixture cleanup: %s\n' \
          "${current_utun}" >&2
        cleanup_failed=1
      fi
    done <<<"$(utun_names)"
  fi
  return "${cleanup_failed}"
}

start_hold_client() {
  HOLD_CLIENT_LOG="${TMP_ROOT}/helper-kill-client.log"
  assert_client_integrity
  "${CLIENT}" --hold-after-apply --dual-stack "${OWNER_UTUN}" \
    >"${HOLD_CLIENT_LOG}" 2>&1 &
  HOLD_CLIENT_PID=$!
  local attempt
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    if ! /bin/kill -0 "${HOLD_CLIENT_PID}" 2>/dev/null; then
      /bin/cat "${HOLD_CLIENT_LOG}" >&2
      printf 'hold client exited before apply\n' >&2
      return 1
    fi
    if /usr/bin/grep -Fq 'KYCLASH_ROUTE_HELPER_LAB_READY state=applied' \
      "${HOLD_CLIENT_LOG}"; then
      return 0
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'hold client did not reach applied state\n' >&2
  return 1
}

stop_hold_client() {
  if [[ -n "${HOLD_CLIENT_PID}" ]]; then
    if ! stop_exact_process "${HOLD_CLIENT_PID}" "${CLIENT}"; then
      return 1
    fi
    wait "${HOLD_CLIENT_PID}" 2>/dev/null || true
    HOLD_CLIENT_PID=""
  fi
}

bootout_helper() {
  local previous_pid current_pid attempt command_line
  previous_pid="$(helper_pid || true)"
  if ! /usr/bin/sudo /bin/launchctl bootout "system/${HELPER_LABEL}" >/dev/null; then
    printf 'helper launchd bootout failed\n' >&2
    return 1
  fi
  HELPER_IS_BOOTSTRAPPED=0
  attempt=0
  while [[ "${attempt}" -lt 100 ]]; do
    current_pid="$(helper_pid || true)"
    if [[ -z "${current_pid}" ]]; then
      if [[ -z "${previous_pid}" ]] ||
        ! /usr/bin/sudo /bin/kill -0 "${previous_pid}" 2>/dev/null; then
        return 0
      fi
      command_line="$(/usr/bin/sudo /bin/ps -p "${previous_pid}" -o command= \
        2>/dev/null || true)"
      case "${command_line}" in
        "${HELPER}"|"${HELPER} "*) ;;
        *)
          printf 'refusing helper PID identity change during bootout: %s %s\n' \
            "${previous_pid}" "${command_line}" >&2
          return 1
          ;;
      esac
    fi
    /bin/sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'helper launchd job or process remained after bootout\n' >&2
  return 1
}

bootstrap_helper() {
  if [[ "${HELPER_IS_BOOTSTRAPPED}" -eq 0 ]]; then
    assert_root_path "${HELPER_PLIST}" 644 file
    assert_fixed_plists
    /usr/bin/sudo /bin/launchctl bootstrap system "${HELPER_PLIST}"
    HELPER_IS_BOOTSTRAPPED=1
  fi
}

install_corrupt_journal() {
  local source_file="${TMP_ROOT}/fixed-corrupt-journal"
  if /usr/bin/sudo /bin/test -e "${JOURNAL}" || \
    /usr/bin/sudo /bin/test -L "${JOURNAL}"; then
    printf 'refusing to overwrite a pre-existing route-helper journal\n' >&2
    return 1
  fi
  printf '%s\n' "${CORRUPT_JOURNAL_TEXT}" >"${source_file}"
  /bin/chmod 600 "${source_file}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 600 \
    "${source_file}" "${JOURNAL}"
  CORRUPT_JOURNAL_INSTALLED=1
}

remove_our_corrupt_journal() {
  local source_file="${TMP_ROOT}/fixed-corrupt-journal"
  local expected_sha actual_sha
  if [[ "${CORRUPT_JOURNAL_INSTALLED}" -eq 0 ]]; then
    return 0
  fi
  if ! /usr/bin/sudo /bin/test -f "${JOURNAL}" || \
    /usr/bin/sudo /bin/test -L "${JOURNAL}"; then
    printf 'refusing corrupt-journal cleanup: expected regular file is absent\n' >&2
    return 1
  fi
  expected_sha="$(/usr/bin/shasum -a 256 "${source_file}" | /usr/bin/awk '{print $1}')"
  actual_sha="$(/usr/bin/sudo /usr/bin/shasum -a 256 "${JOURNAL}" | \
    /usr/bin/awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    printf 'refusing corrupt-journal cleanup because content changed\n' >&2
    return 1
  fi
  /usr/bin/sudo /bin/rm -f "${JOURNAL}"
  CORRUPT_JOURNAL_INSTALLED=0
}

journal_absent() {
  ! /usr/bin/sudo /bin/test -e "${JOURNAL}" &&
    ! /usr/bin/sudo /bin/test -L "${JOURNAL}"
}

assert_journal_absent() {
  if ! journal_absent; then
    printf 'unexpected route-helper journal remains: %s\n' "${JOURNAL}" >&2
    return 1
  fi
}

preflight() {
  assert_root_path "/Library/Application Support/KyClash" 700 directory
  assert_root_path "${STAGE_ROOT}" 755 directory
  assert_root_path "${STAGE_BIN}" 755 directory
  assert_root_path "${HELPER}" 755 file
  assert_root_path "${CLIENT_SOURCE}" 755 file
  assert_root_path "${CLIENT}" 755 file
  assert_root_path "${UTUN_FIXTURE}" 755 file
  assert_root_path "${SYNTHETIC_UTUN_FIXTURE}" 755 file
  assert_root_path "${COMBINED_LOG_FILE}" 600 file
  assert_root_path "${HELPER_PLIST}" 644 file
  assert_root_path "${UTUN_PLIST}" 644 file
  /usr/bin/plutil -lint "${HELPER_PLIST}" "${UTUN_PLIST}" >/dev/null
  assert_fixed_plists
  verify_signed_binary "${HELPER}" "${HELPER_IDENTIFIER}"
  verify_signed_binary "${CLIENT_SOURCE}" "${APP_IDENTIFIER}"
  verify_signed_binary "${CLIENT}" "${APP_IDENTIFIER}"
  verify_signed_binary "${UTUN_FIXTURE}" "${PRIMARY_UTUN_IDENTIFIER}"
  verify_signed_binary "${SYNTHETIC_UTUN_FIXTURE}" "${SYNTHETIC_UTUN_IDENTIFIER}"
  local source_hash client_hash
  source_hash="$(/usr/bin/sudo /usr/bin/shasum -a 256 "${CLIENT_SOURCE}" | /usr/bin/awk '{print $1}')"
  client_hash="$(/usr/bin/sudo /usr/bin/shasum -a 256 "${CLIENT}" | /usr/bin/awk '{print $1}')"
  if [[ -z "${source_hash}" || "${source_hash}" != "${client_hash}" ]]; then
    printf 'refusing client copy whose bytes differ from the root-staged source\n' >&2
    return 1
  fi
  /usr/bin/sudo /bin/launchctl print "system/${HELPER_LABEL}" >/dev/null
  /usr/bin/sudo /bin/launchctl print "system/${UTUN_LABEL}" >/dev/null
  OWNER_UTUN="$(read_owner_utun)"
  if /sbin/ifconfig "${WRONG_MIHOMO_UTUN}" >/dev/null 2>&1; then
    printf 'refusing: fixed wrong-interface sentinel unexpectedly exists\n' >&2
    return 1
  fi
  if ! journal_absent; then
    printf 'refusing: route-helper journal must be absent before the matrix\n' >&2
    return 1
  fi
  if [[ -e "${SYNTHETIC_MIHOMO_OWNER_FILE}" || -L "${SYNTHETIC_MIHOMO_OWNER_FILE}" ]]; then
    printf 'refusing: synthetic Mihomo owner file must be absent before the matrix\n' >&2
    return 1
  fi
  assert_no_preexisting_private_overlap
  assert_matrix_routes_absent
  assert_client_integrity
  "${CLIENT}"
  printf 'preflight=passed owner_utun=%s\n' "${OWNER_UTUN}"
}

run_matrix() {
  TMP_ROOT="$(/usr/bin/mktemp -d /var/tmp/kyclash-route-helper-v2-matrix.XXXXXX)"
  LOG_FILE="${TMP_ROOT}/route-helper-v2-matrix.log"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if /usr/bin/sudo /bin/test -L "${EVIDENCE_ROOT}"; then
    printf 'refusing symlinked evidence directory: %s\n' "${EVIDENCE_ROOT}" >&2
    return 70
  fi
  /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 755 "${EVIDENCE_ROOT}"
  assert_root_path "${EVIDENCE_ROOT}" 755 directory

  {
    printf 'matrix=kyclash-route-helper-v2\n'
    /usr/bin/sw_vers
    printf 'architecture=%s\n' "$(/usr/bin/uname -m)"
    printf 'hardware_model=%s\n' "$(/usr/sbin/sysctl -n hw.model)"
    printf 'owner_utun=%s\n' "${OWNER_UTUN}"
    printf 'desired_routes=%s,%s\n' "${EXACT_V4}" "${EXACT_V6}"
  } | /usr/bin/tee "${LOG_FILE}"

  printf 'scenario=discover\n' | /usr/bin/tee -a "${LOG_FILE}"
  run_discover_retry

  printf 'scenario=dual-stack-normal\n' | /usr/bin/tee -a "${LOG_FILE}"
  run_client --dual-stack "${OWNER_UTUN}"
  assert_route_absent exact4
  assert_route_absent exact6
  assert_journal_absent

  start_synthetic_mihomo_utun

  printf 'scenario=exact-conflict-even-when-trusted\n' | /usr/bin/tee -a "${LOG_FILE}"
  add_fixed_route exact4 "${SYNTHETIC_MIHOMO_UTUN}"
  add_fixed_route exact6 "${SYNTHETIC_MIHOMO_UTUN}"
  run_client --expect-conflict --dual-stack "${OWNER_UTUN}" \
    --mihomo-utun "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route exact6 "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route exact4 "${SYNTHETIC_MIHOMO_UTUN}"
  assert_journal_absent

  printf 'scenario=more-specific-conflict-even-when-trusted\n' | \
    /usr/bin/tee -a "${LOG_FILE}"
  add_fixed_route more4 "${SYNTHETIC_MIHOMO_UTUN}"
  add_fixed_route more6 "${SYNTHETIC_MIHOMO_UTUN}"
  run_client --expect-conflict --dual-stack "${OWNER_UTUN}" \
    --mihomo-utun "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route more6 "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route more4 "${SYNTHETIC_MIHOMO_UTUN}"
  assert_journal_absent

  printf 'scenario=unknown-interface-covering-conflict\n' | \
    /usr/bin/tee -a "${LOG_FILE}"
  add_fixed_route covering4 lo0
  add_fixed_route covering6 lo0
  run_client --expect-conflict --dual-stack "${OWNER_UTUN}" \
    --mihomo-utun "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route covering6 lo0
  delete_fixed_route covering4 lo0
  assert_journal_absent

  printf 'scenario=covering-requires-explicit-matching-mihomo-utun\n' | \
    /usr/bin/tee -a "${LOG_FILE}"
  add_fixed_route covering4 "${SYNTHETIC_MIHOMO_UTUN}"
  add_fixed_route covering6 "${SYNTHETIC_MIHOMO_UTUN}"
  run_client --expect-conflict --dual-stack "${OWNER_UTUN}"
  run_client --expect-conflict --dual-stack "${OWNER_UTUN}" \
    --mihomo-utun "${WRONG_MIHOMO_UTUN}"
  run_client --dual-stack "${OWNER_UTUN}" \
    --mihomo-utun "${SYNTHETIC_MIHOMO_UTUN}"
  assert_route_present_once covering4 "${SYNTHETIC_MIHOMO_UTUN}"
  assert_route_present_once covering6 "${SYNTHETIC_MIHOMO_UTUN}"
  assert_route_absent exact4
  assert_route_absent exact6
  delete_fixed_route covering6 "${SYNTHETIC_MIHOMO_UTUN}"
  delete_fixed_route covering4 "${SYNTHETIC_MIHOMO_UTUN}"
  assert_journal_absent
  stop_synthetic_mihomo_utun

  printf 'scenario=helper-kill-restart-recovery\n' | /usr/bin/tee -a "${LOG_FILE}"
  start_hold_client
  /bin/cat "${HOLD_CLIENT_LOG}" | /usr/bin/tee -a "${LOG_FILE}"
  assert_route_present_once exact4 "${OWNER_UTUN}"
  assert_route_present_once exact6 "${OWNER_UTUN}"
  if ! /usr/bin/sudo /bin/test -f "${JOURNAL}" || \
    /usr/bin/sudo /bin/test -L "${JOURNAL}"; then
    printf 'route-helper journal is not a regular non-symlink file\n' >&2
    return 1
  fi
  assert_root_path "${JOURNAL}" 600 file
  local previous_helper_pid restarted_helper_pid
  previous_helper_pid="$(helper_pid)"
  [[ -n "${previous_helper_pid}" ]]
  printf 'helper_pid_before_kill=%s\n' "${previous_helper_pid}" | \
    /usr/bin/tee -a "${LOG_FILE}"
  /usr/bin/sudo /bin/launchctl kill SIGKILL "system/${HELPER_LABEL}"
  stop_hold_client
  run_discover_retry
  restarted_helper_pid="$(wait_for_helper_pid_change "${previous_helper_pid}")"
  printf 'helper_pid_after_restart=%s\n' "${restarted_helper_pid}" | \
    /usr/bin/tee -a "${LOG_FILE}"
  assert_route_absent exact4
  assert_route_absent exact6
  assert_journal_absent

  printf 'scenario=journal-corruption-fail-closed\n' | /usr/bin/tee -a "${LOG_FILE}"
  bootout_helper
  install_corrupt_journal
  assert_root_path "${JOURNAL}" 600 file
  bootstrap_helper
  local corrupt_status
  set +e
  assert_client_integrity
  "${CLIENT}" >"${TMP_ROOT}/journal-corrupt-client.log" 2>&1
  corrupt_status=$?
  set -e
  /bin/cat "${TMP_ROOT}/journal-corrupt-client.log" | /usr/bin/tee -a "${LOG_FILE}"
  if [[ "${corrupt_status}" -eq 0 ]] || ! /usr/bin/grep -Fqx \
    'discover transport_status=0 protocol_version=2 state=4 error_code=8' \
    "${TMP_ROOT}/journal-corrupt-client.log"; then
    printf 'journal corruption did not fail closed with the v2 typed error\n' >&2
    return 1
  fi
  assert_route_absent exact4
  assert_route_absent exact6
  bootout_helper
  remove_our_corrupt_journal
  bootstrap_helper
  run_discover_retry

  printf 'scenario=final-absence\n' | /usr/bin/tee -a "${LOG_FILE}"
  assert_matrix_routes_absent
  assert_journal_absent
  run_discover_retry
  printf 'final_routes=absent\nfinal_journal=absent\nfinal_lease=idle\n' | \
    /usr/bin/tee -a "${LOG_FILE}"
  /usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 \
    "${LOG_FILE}" "${EVIDENCE_ROOT}/route-helper-v2-matrix.log"
  if [[ -f "${TMP_ROOT}/synthetic-mihomo-utun.log" ]]; then
    /usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 \
      "${TMP_ROOT}/synthetic-mihomo-utun.log" \
      "${EVIDENCE_ROOT}/synthetic-mihomo-utun.log"
  fi
  printf 'matrix=passed evidence=%s\n' "${EVIDENCE_ROOT}"
}

cleanup() {
  local status=$?
  local index entry key interface_name restore_helper journal_recovery_safe
  if [[ "${CLEANUP_ACTIVE}" -eq 1 ]]; then
    exit "${status}"
  fi
  CLEANUP_ACTIVE=1
  trap - EXIT INT TERM
  set +e

  if ! stop_hold_client; then CLEANUP_FAILURE=1; fi
  for ((index = ${#ADDED_ROUTES[@]} - 1; index >= 0; index--)); do
    entry="${ADDED_ROUTES[${index}]}"
    key="${entry%%|*}"
    interface_name="${entry#*|}"
    if ! delete_fixed_route "${key}" "${interface_name}"; then CLEANUP_FAILURE=1; fi
  done
  if ! stop_synthetic_mihomo_utun; then CLEANUP_FAILURE=1; fi

  restore_helper=1
  if [[ "${CORRUPT_JOURNAL_INSTALLED}" -eq 1 ]]; then
    # A journal is untrusted until its bytes are re-hashed and the exact file
    # is removed.  If either proof step fails, leave launchd booted out and do
    # not issue a discover/apply request that could consume the corrupt state.
    restore_helper=0
    journal_recovery_safe=1
    if [[ "${HELPER_IS_BOOTSTRAPPED}" -eq 1 ]]; then
      if ! bootout_helper; then
        CLEANUP_FAILURE=1
        journal_recovery_safe=0
      fi
    fi
    if ! remove_our_corrupt_journal; then
      CLEANUP_FAILURE=1
      journal_recovery_safe=0
    fi
    if [[ "${journal_recovery_safe}" -eq 1 ]]; then
      restore_helper=1
    fi
  fi
  if [[ "${restore_helper}" -eq 1 ]]; then
    if ! bootstrap_helper; then CLEANUP_FAILURE=1; fi
    if [[ -x "${CLIENT}" && "${HELPER_IS_BOOTSTRAPPED}" -eq 1 ]]; then
      if ! assert_client_integrity || ! "${CLIENT}" >/dev/null 2>&1; then
        CLEANUP_FAILURE=1
      fi
    fi
  else
    printf 'cleanup kept route helper booted out because corrupt journal recovery was not proven safe\n' >&2
  fi

  if ! assert_matrix_routes_absent; then CLEANUP_FAILURE=1; fi
  if ! journal_absent; then
    printf 'cleanup left a route-helper journal in place: %s\n' "${JOURNAL}" >&2
    CLEANUP_FAILURE=1
  fi
  if [[ "${CLEANUP_FAILURE}" -ne 0 ]]; then
    KEEP_TMP_ROOT=1
  fi

  if [[ -n "${TMP_ROOT}" && -d "${TMP_ROOT}" && ! -L "${TMP_ROOT}" ]]; then
    if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
      if ! /usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 \
        "${LOG_FILE}" "${EVIDENCE_ROOT}/route-helper-v2-matrix.log" \
        >/dev/null 2>&1; then
        printf 'unable to persist matrix evidence; retaining temporary log at %s\n' \
          "${TMP_ROOT}" >&2
        CLEANUP_FAILURE=1
        KEEP_TMP_ROOT=1
      fi
    fi
    if [[ "${KEEP_TMP_ROOT}" -eq 0 ]]; then
      /bin/rm -rf "${TMP_ROOT}"
    fi
  fi
  if [[ "${CLEANUP_FAILURE}" -ne 0 ]]; then
    printf 'cleanup=failed; inspect root-owned evidence under %s\n' \
      "${EVIDENCE_ROOT}" >&2
    status=1
  fi
  exit "${status}"
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 64
fi

case "$1" in
  dry-run)
    dry_run
    ;;
  preflight)
    require_disposable_guest
    require_sudo
    preflight
    ;;
  run)
    require_disposable_guest
    require_sudo
    preflight
    run_matrix
    ;;
  *)
    usage
    exit 64
    ;;
esac
