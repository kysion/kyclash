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

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly SCRIPT_ROOT

# The caller can select only a fixed mode. No path, process, interface, CIDR,
# route, command, endpoint, or credential is accepted from argv or env.
readonly VM_CONFIRM="authorized-kyclash-virtualization-framework-vm"
readonly RUNNER_ENVIRONMENT="local-virtualization-framework"
readonly EXPECTED_TEAM_ID="RQUQ8Y3S9H"
readonly APP_IDENTIFIER="net.kysion.kyclash"
readonly PACKAGE_RECEIPT="net.kysion.kyclash"
readonly INSTALLED_APP="/Applications/KyClash.app"
readonly APP_EXECUTABLE="${INSTALLED_APP}/Contents/MacOS/clash-verge"
readonly PACKAGED_MIHOMO="${INSTALLED_APP}/Contents/MacOS/verge-mihomo"
readonly SERVICE_SOCKET="/tmp/verge/clash-verge-service.sock"
readonly MANAGED_MIHOMO_SOCKET="/tmp/verge/verge-mihomo.sock"
readonly FIXED_UTUN="utun4093"
readonly LAB_MARKER_NAME=".kyclash-app-tun-lab-no-dns"
readonly LAB_MARKER_TEXT="kyclash-app-tun-lab-no-system-dns-v1"
readonly SYNTHETIC_API_TOKEN="kyclash-app-tun-lab-fixed-synthetic-token-not-a-secret"

readonly FIXTURE_ROOT="${SCRIPT_ROOT}/macos/app-tun-lab"
readonly CONFIG_FIXTURE="${FIXTURE_ROOT}/config.json"
readonly VERGE_FIXTURE="${FIXTURE_ROOT}/verge.json"
readonly PROFILES_FIXTURE="${FIXTURE_ROOT}/profiles.json"
readonly NO_DNS_MARKER_FIXTURE="${FIXTURE_ROOT}/no-dns-mutation.marker"
readonly CONFIG_FIXTURE_SHA256="f68642b670fb0309b1d89f4cad3228bb7a2e153d30eb4637c7ef7e66e10c521c"
readonly VERGE_FIXTURE_SHA256="d32591e7a2914f09475bb03366d727683e12ceee23f0cdf1b3a51c7da7349d4f"
readonly PROFILES_FIXTURE_SHA256="0343639fac1511a32a4c9a92c7655a6e9f9ad3a600fc6f30b5bdad6806160a97"
readonly NO_DNS_MARKER_SHA256="440951e09c32cbb782f5f1204918cb324e5fcfcf0e19b9128fcc8aa8dffea76e"

CURRENT_UID=""
CURRENT_GID=""
CURRENT_USER=""
CURRENT_HOME=""
DATA_ROOT=""
APP_HOME=""
BACKUP_ROOT=""
ACTIVE_RECORD=""
BACKUP_DIR=""
BACKUP_STATE=""
APP_PID=""
MIHOMO_PID=""
MONITOR_PID=""
TRAP_ACTIVE=0
RESTORE_FAILURE=0

usage() {
  printf 'usage: %s dry-run|static-check|preflight|run|restore\n' "$0" >&2
}

die() {
  printf 'refusing: %s\n' "$1" >&2
  exit "${2:-70}"
}

sha256_file() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

assert_source_file() {
  local path="$1"
  local expected="$2"
  local mode actual

  [[ -f "${path}" && ! -L "${path}" ]] || die "missing or symlinked fixed source: ${path}" 66
  mode="$(/usr/bin/stat -f '%Lp' "${path}")"
  [[ "${mode}" == "644" ]] || die "unsafe fixed-source mode for ${path}: ${mode}"
  actual="$(sha256_file "${path}")"
  [[ "${actual}" == "${expected}" ]] || die "fixed-source digest mismatch: ${path}"
}

assert_json_value() {
  local path="$1"
  local key="$2"
  local expected="$3"
  local actual

  actual="$(/usr/bin/plutil -extract "${key}" raw -o - "${path}" 2>/dev/null || true)"
  [[ "${actual}" == "${expected}" ]] || \
    die "unexpected fixed JSON value at ${key} in ${path}"
}

assert_json_array_length() {
  local path="$1"
  local key="$2"
  local expected="$3"

  if /usr/bin/plutil -extract "${key}.${expected}" raw -o - "${path}" >/dev/null 2>&1; then
    die "unexpected extra fixed JSON array member at ${key} in ${path}"
  fi
  if [[ "${expected}" -gt 0 ]] && \
    ! /usr/bin/plutil -extract "${key}.$((expected - 1))" raw -o - "${path}" >/dev/null 2>&1; then
    die "missing fixed JSON array member at ${key} in ${path}"
  fi
  if [[ "${expected}" -eq 0 ]]; then
    local value
    value="$(/usr/bin/plutil -extract "${key}" json -o - "${path}" 2>/dev/null || true)"
    [[ "${value}" == "[]" ]] || die "fixed JSON array is not empty at ${key} in ${path}"
  fi
}

assert_json_key_absent() {
  local path="$1"
  local key="$2"
  if /usr/bin/plutil -extract "${key}" raw -o - "${path}" >/dev/null 2>&1 || \
    /usr/bin/plutil -extract "${key}" json -o - "${path}" >/dev/null 2>&1; then
    die "forbidden fixed JSON key ${key} in ${path}"
  fi
}

static_check() {
  local key

  assert_source_file "${CONFIG_FIXTURE}" "${CONFIG_FIXTURE_SHA256}"
  assert_source_file "${VERGE_FIXTURE}" "${VERGE_FIXTURE_SHA256}"
  assert_source_file "${PROFILES_FIXTURE}" "${PROFILES_FIXTURE_SHA256}"
  assert_source_file "${NO_DNS_MARKER_FIXTURE}" "${NO_DNS_MARKER_SHA256}"

  /usr/bin/plutil -convert xml1 -o /dev/null "${CONFIG_FIXTURE}"
  /usr/bin/plutil -convert xml1 -o /dev/null "${VERGE_FIXTURE}"
  /usr/bin/plutil -convert xml1 -o /dev/null "${PROFILES_FIXTURE}"

  assert_json_value "${CONFIG_FIXTURE}" allow-lan false
  assert_json_value "${CONFIG_FIXTURE}" bind-address 127.0.0.1
  assert_json_value "${CONFIG_FIXTURE}" mode direct
  assert_json_value "${CONFIG_FIXTURE}" secret "${SYNTHETIC_API_TOKEN}"
  assert_json_value "${CONFIG_FIXTURE}" dns.enable false
  assert_json_value "${CONFIG_FIXTURE}" dns.ipv6 false
  assert_json_value "${CONFIG_FIXTURE}" dns.enhanced-mode redir-host
  assert_json_array_length "${CONFIG_FIXTURE}" dns.nameserver 0
  assert_json_value "${CONFIG_FIXTURE}" tun.enable false
  assert_json_value "${CONFIG_FIXTURE}" tun.device "${FIXED_UTUN}"
  assert_json_value "${CONFIG_FIXTURE}" tun.stack system
  assert_json_value "${CONFIG_FIXTURE}" tun.auto-route false
  assert_json_value "${CONFIG_FIXTURE}" tun.auto-detect-interface false
  assert_json_value "${CONFIG_FIXTURE}" tun.strict-route false
  assert_json_value "${CONFIG_FIXTURE}" tun.mtu 1420
  assert_json_array_length "${CONFIG_FIXTURE}" tun.dns-hijack 0
  assert_json_value "${CONFIG_FIXTURE}" tun.inet4-address.0 198.18.0.1/30
  assert_json_array_length "${CONFIG_FIXTURE}" tun.inet4-address 1
  assert_json_value "${CONFIG_FIXTURE}" tun.inet6-address.0 2001:db8:4093::1/126
  assert_json_array_length "${CONFIG_FIXTURE}" tun.inet6-address 1
  assert_json_array_length "${CONFIG_FIXTURE}" proxies 0
  assert_json_array_length "${CONFIG_FIXTURE}" proxy-groups 0
  assert_json_value "${CONFIG_FIXTURE}" rules.0 MATCH,DIRECT
  assert_json_array_length "${CONFIG_FIXTURE}" rules 1

  for key in route-address route-exclude-address auto-redirect include-interface \
    exclude-interface; do
    assert_json_key_absent "${CONFIG_FIXTURE}" "tun.${key}"
  done
  for key in external-controller external-controller-unix external-controller-tls \
    hosts listeners proxy-providers rule-providers tunnels sniffer; do
    assert_json_key_absent "${CONFIG_FIXTURE}" "${key}"
  done

  assert_json_value "${VERGE_FIXTURE}" enable_tun_mode true
  assert_json_value "${VERGE_FIXTURE}" enable_system_proxy false
  assert_json_value "${VERGE_FIXTURE}" proxy_auto_config false
  assert_json_value "${VERGE_FIXTURE}" enable_proxy_guard false
  assert_json_value "${VERGE_FIXTURE}" enable_dns_settings false
  assert_json_value "${VERGE_FIXTURE}" enable_builtin_enhanced false
  assert_json_value "${VERGE_FIXTURE}" enable_auto_launch false
  assert_json_value "${VERGE_FIXTURE}" enable_silent_start false
  assert_json_value "${VERGE_FIXTURE}" enable_external_controller false
  assert_json_value "${VERGE_FIXTURE}" verge_redir_enabled false
  assert_json_value "${VERGE_FIXTURE}" verge_socks_enabled false
  assert_json_value "${VERGE_FIXTURE}" verge_http_enabled false
  assert_json_value "${VERGE_FIXTURE}" clash_core verge-mihomo
  assert_json_array_length "${PROFILES_FIXTURE}" items 0
  assert_json_key_absent "${PROFILES_FIXTURE}" current

  [[ "$(/bin/cat "${NO_DNS_MARKER_FIXTURE}")" == "${LAB_MARKER_TEXT}" ]] || \
    die "unexpected no-DNS marker text"

  printf 'static_check=passed\n'
  printf 'static_mutations=none\n'
}

dry_run() {
  /bin/cat <<'EOF'
KyClash app-managed Mihomo TUN disposable-VM matrix (static dry-run)
execution_target=kyclash-macos-lab-work
mutation_guard=VirtualMac-prefix + console-user + local-virtualization-framework + exact confirmation
installed_app=/Applications/KyClash.app
service_socket=/tmp/verge/clash-verge-service.sock
managed_socket=/tmp/verge/verge-mihomo.sock
fixed_tun=utun4093
app_data_isolation=atomic whole-directory move to unique mode-0700 sibling backup
network_invariants=system-DNS,system-proxy,default-routes,RFC1918-and-ULA-routes
forbidden=host-run,caller-path,caller-command,caller-interface,caller-CIDR,auto-route,DNS-mutation,system-proxy,production-network
production_rust_live_source=separate-S1.13-gate
dry_run_mutations=none
EOF
}

initialize_guest_paths() {
  local user_record

  CURRENT_UID="$(/usr/bin/id -u)"
  CURRENT_GID="$(/usr/bin/id -g)"
  CURRENT_USER="$(/usr/bin/id -un)"
  case "${CURRENT_USER}" in
    ''|*[!A-Za-z0-9._-]*) die "unsafe current user name" ;;
  esac

  user_record="$(/usr/bin/dscacheutil -q user -a uid "${CURRENT_UID}" 2>/dev/null || true)"
  CURRENT_HOME="$(printf '%s\n' "${user_record}" | /usr/bin/awk -F': ' '$1 == "dir" {print $2; exit}')"
  case "${CURRENT_HOME}" in
    /Users/*) ;;
    *) die "current console account must have a fixed /Users home" ;;
  esac
  [[ -d "${CURRENT_HOME}" && ! -L "${CURRENT_HOME}" ]] || die "unsafe current home directory"

  DATA_ROOT="${CURRENT_HOME}/Library/Application Support"
  APP_HOME="${DATA_ROOT}/${APP_IDENTIFIER}"
  BACKUP_ROOT="${DATA_ROOT}/${APP_IDENTIFIER}.app-tun-lab-backups"
  ACTIVE_RECORD="${BACKUP_ROOT}/active"
}

require_disposable_guest() {
  local model console_user

  [[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "macOS is required" 69
  [[ "$(/usr/bin/uname -m)" == "arm64" ]] || die "Apple Silicon guest is required" 69
  model="$(/usr/sbin/sysctl -n hw.model 2>/dev/null || true)"
  [[ "${model}" == VirtualMac* ]] || die "hw.model must begin with VirtualMac" 77
  [[ "${KYCLASH_RUNNER_ENVIRONMENT:-}" == "${RUNNER_ENVIRONMENT}" ]] || \
    die "KYCLASH_RUNNER_ENVIRONMENT must be ${RUNNER_ENVIRONMENT}" 77
  [[ "${KYCLASH_VM_LAB_CONFIRM:-}" == "${VM_CONFIRM}" ]] || \
    die "KYCLASH_VM_LAB_CONFIRM must be the documented VM marker" 77
  [[ "$(/usr/bin/id -u)" -ne 0 ]] || die "run as the disposable non-root console user" 77

  initialize_guest_paths
  console_user="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"
  [[ "${console_user}" == "${CURRENT_USER}" ]] || \
    die "current user must own the guest console session" 77
}

require_sudo() {
  /usr/bin/sudo -v || die "interactive sudo authorization is required inside the disposable VM" 77
}

assert_regular_file() {
  local path="$1"
  [[ -f "${path}" && ! -L "${path}" ]] || die "unsafe or missing regular file: ${path}"
  [[ "$(/usr/bin/stat -f '%l' "${path}")" == "1" ]] || die "unexpected hard link: ${path}"
}

verify_installed_app() {
  local metadata team_id identifier bundle_identifier receipt version

  [[ -d "${INSTALLED_APP}" && ! -L "${INSTALLED_APP}" ]] || die "installed KyClash bundle is missing or linked" 66
  assert_regular_file "${INSTALLED_APP}/Contents/Info.plist"
  assert_regular_file "${APP_EXECUTABLE}"
  assert_regular_file "${PACKAGED_MIHOMO}"

  bundle_identifier="$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - \
    "${INSTALLED_APP}/Contents/Info.plist" 2>/dev/null || true)"
  [[ "${bundle_identifier}" == "${APP_IDENTIFIER}" ]] || die "unexpected installed bundle identifier"
  /usr/bin/codesign --verify --deep --strict "${INSTALLED_APP}" >/dev/null 2>&1 || \
    die "installed KyClash deep signature is invalid"
  metadata="$(/usr/bin/codesign -dv --verbose=4 "${INSTALLED_APP}" 2>&1)"
  team_id="$(printf '%s\n' "${metadata}" | /usr/bin/awk -F= '/^TeamIdentifier=/{value=$2} END{print value}')"
  identifier="$(printf '%s\n' "${metadata}" | /usr/bin/awk -F= '/^Identifier=/{value=$2} END{print value}')"
  [[ "${team_id}" == "${EXPECTED_TEAM_ID}" ]] || die "unexpected installed App Team ID"
  [[ "${identifier}" == "${APP_IDENTIFIER}" ]] || die "unexpected installed App signature identifier"
  /usr/bin/file "${APP_EXECUTABLE}" | /usr/bin/grep -F 'Mach-O 64-bit executable arm64' >/dev/null || \
    die "installed App executable is not arm64"
  /usr/bin/file "${PACKAGED_MIHOMO}" | /usr/bin/grep -F 'Mach-O 64-bit executable arm64' >/dev/null || \
    die "packaged Mihomo is not arm64"

  receipt="$(/usr/sbin/pkgutil --pkg-info "${PACKAGE_RECEIPT}" 2>/dev/null || true)"
  printf '%s\n' "${receipt}" | /usr/bin/grep -Fqx 'volume: /' || die "package receipt volume is not /"
  printf '%s\n' "${receipt}" | /usr/bin/grep -Fqx 'location: Applications' || \
    die "package receipt is not pinned to /Applications"
  version="$(printf '%s\n' "${receipt}" | /usr/bin/awk -F': ' '$1 == "version" {print $2; exit}')"
  [[ -n "${version}" ]] || die "package receipt version is missing"
}

verify_service_socket() {
  local owner group mode links parent_owner parent_group parent_mode parent_symbolic

  [[ -d /tmp/verge && ! -L /tmp/verge ]] || die "service socket parent is missing or linked"
  [[ -S "${SERVICE_SOCKET}" && ! -L "${SERVICE_SOCKET}" ]] || die "fixed service socket is missing or not a socket"
  parent_owner="$(/usr/bin/stat -f '%Su' /tmp/verge)"
  parent_group="$(/usr/bin/stat -f '%Sg' /tmp/verge)"
  parent_mode="$(/usr/bin/stat -f '%Lp' /tmp/verge)"
  parent_symbolic="$(/usr/bin/stat -f '%Sp' /tmp/verge)"
  [[ "${parent_owner}" == "root" && "${parent_group}" == "staff" && \
    "${parent_mode}" == "770" && "${parent_symbolic}" == "drwxrws---" ]] || \
    die "unsafe service socket parent ownership or mode"
  /usr/bin/id -Gn | /usr/bin/tr ' ' '\n' | /usr/bin/grep -Fqx staff || \
    die "console user is not a member of the service socket group"
  owner="$(/usr/bin/stat -f '%Su' "${SERVICE_SOCKET}")"
  group="$(/usr/bin/stat -f '%Sg' "${SERVICE_SOCKET}")"
  mode="$(/usr/bin/stat -f '%Lp' "${SERVICE_SOCKET}")"
  links="$(/usr/bin/stat -f '%l' "${SERVICE_SOCKET}")"
  [[ "${owner}" == "root" && "${group}" == "staff" && "${links}" == "1" ]] || \
    die "unsafe service socket ownership or links"
  # clash-verge-service creates this socket as 0777, but its fixed root:staff
  # 02770 parent is the access-control boundary and is not traversable by
  # users outside that group. Accept a future group-only socket as well.
  case "${mode}" in
    770|777) ;;
    *) die "unexpected service socket mode: ${mode}" ;;
  esac
}

assert_app_home() {
  local owner mode
  [[ -d "${DATA_ROOT}" && ! -L "${DATA_ROOT}" ]] || die "unsafe Application Support root"
  [[ -d "${APP_HOME}" && ! -L "${APP_HOME}" ]] || die "existing App data directory is required"
  owner="$(/usr/bin/stat -f '%u' "${APP_HOME}")"
  mode="$(/usr/bin/stat -f '%Lp' "${APP_HOME}")"
  [[ "${owner}" == "${CURRENT_UID}" ]] || die "App data directory is not owned by the console user"
  case "${mode}" in
    700|750|755) ;;
    *) die "unsafe App data directory mode: ${mode}" ;;
  esac
  [[ ! -e "${APP_HOME}/${LAB_MARKER_NAME}" && ! -L "${APP_HOME}/${LAB_MARKER_NAME}" ]] || \
    die "lab marker is already present; run restore"
}

process_has_text_path() {
  local pid="$1"
  local expected="$2"
  local privilege="$3"
  local output

  case "${pid}" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [[ "${privilege}" == "root" ]]; then
    output="$(/usr/bin/sudo -n /usr/sbin/lsof -a -p "${pid}" -d txt -Fn 2>/dev/null || true)"
  else
    output="$(/usr/sbin/lsof -a -p "${pid}" -d txt -Fn 2>/dev/null || true)"
  fi
  printf '%s\n' "${output}" | /usr/bin/grep -Fqx "n${expected}"
}

app_pids() {
  local pid uid
  for pid in $(/usr/bin/pgrep -f "${APP_EXECUTABLE}" 2>/dev/null || true); do
    uid="$(/bin/ps -p "${pid}" -o uid= 2>/dev/null | /usr/bin/awk '{print $1}')"
    if [[ "${uid}" == "${CURRENT_UID}" ]] && process_has_text_path "${pid}" "${APP_EXECUTABLE}" user; then
      printf '%s\n' "${pid}"
    fi
  done
}

mihomo_pids() {
  local pid uid
  for pid in $(/usr/bin/pgrep -f "${PACKAGED_MIHOMO}" 2>/dev/null || true); do
    uid="$(/bin/ps -p "${pid}" -o uid= 2>/dev/null | /usr/bin/awk '{print $1}')"
    if [[ "${uid}" == "0" ]] && process_has_text_path "${pid}" "${PACKAGED_MIHOMO}" root; then
      printf '%s\n' "${pid}"
    fi
  done
}

line_count() {
  /usr/bin/awk 'NF {count += 1} END {print count + 0}'
}

utun_exists() {
  /sbin/ifconfig "${FIXED_UTUN}" >/dev/null 2>&1
}

list_utuns() {
  /sbin/ifconfig -l | /usr/bin/tr ' ' '\n' | \
    /usr/bin/awk '/^utun[0-9]+$/ {print}' | LC_ALL=C /usr/bin/sort
}

assert_no_runtime_before_test() {
  local pids

  pids="$(app_pids)"
  [[ -z "${pids}" ]] || die "installed App is already running; quit it in the guest first"
  if /usr/bin/pgrep -x verge-mihomo >/dev/null 2>&1 || \
    /usr/bin/pgrep -x verge-mihomo-alpha >/dev/null 2>&1; then
    die "a Mihomo process is already running; do not adopt ambiguous state"
  fi
  [[ ! -e "${MANAGED_MIHOMO_SOCKET}" && ! -L "${MANAGED_MIHOMO_SOCKET}" ]] || \
    die "managed Mihomo socket already exists; quit the App or restore first"
  ! utun_exists || die "fixed ${FIXED_UTUN} already exists"
}

assert_no_active_backup() {
  [[ ! -e "${BACKUP_ROOT}" && ! -L "${BACKUP_ROOT}" ]] || \
    die "an App-TUN backup root already exists; run restore before a new test"
}

preflight_checks() {
  local model os_version package_version

  static_check >/dev/null
  require_disposable_guest
  verify_installed_app
  verify_service_socket
  assert_app_home
  assert_no_active_backup
  assert_no_runtime_before_test

  model="$(/usr/sbin/sysctl -n hw.model)"
  os_version="$(/usr/bin/sw_vers -productVersion)"
  package_version="$(/usr/sbin/pkgutil --pkg-info "${PACKAGE_RECEIPT}" | \
    /usr/bin/awk -F': ' '$1 == "version" {print $2; exit}')"
  printf 'preflight=passed\n'
  printf 'execution_target=kyclash-macos-lab-work\n'
  printf 'guest_model=%s\n' "${model}"
  printf 'guest_os=%s\n' "${os_version}"
  printf 'guest_arch=arm64\n'
  printf 'package_version=%s\n' "${package_version}"
  printf 'installed_app_sha256=%s\n' "$(sha256_file "${APP_EXECUTABLE}")"
  printf 'packaged_mihomo_sha256=%s\n' "$(sha256_file "${PACKAGED_MIHOMO}")"
  printf 'preflight_mutations=none\n'
}

write_private_file() {
  local target="$1"
  local content="$2"
  local incoming="${target}.incoming"
  printf '%s\n' "${content}" >"${incoming}"
  /bin/chmod 600 "${incoming}"
  /bin/mv -f "${incoming}" "${target}"
}

write_phase() {
  write_private_file "${BACKUP_DIR}/phase" "$1"
}

validate_backup_basename() {
  printf '%s\n' "$1" | /usr/bin/grep -Eq '^backup\.[A-Za-z0-9]{6}$'
}

assert_private_directory() {
  local path="$1"
  local owner mode
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  owner="$(/usr/bin/stat -f '%u' "${path}")"
  mode="$(/usr/bin/stat -f '%Lp' "${path}")"
  [[ "${owner}" == "${CURRENT_UID}" && "${mode}" == "700" ]]
}

create_backup_transaction() {
  local backup_basename original_identity

  /bin/mkdir -m 700 "${BACKUP_ROOT}"
  assert_private_directory "${BACKUP_ROOT}" || die "failed to create private backup root"
  BACKUP_DIR="$(/usr/bin/mktemp -d "${BACKUP_ROOT}/backup.XXXXXX")"
  assert_private_directory "${BACKUP_DIR}" || die "failed to create unique private backup"
  backup_basename="$(/usr/bin/basename "${BACKUP_DIR}")"
  validate_backup_basename "${backup_basename}" || die "unexpected generated backup basename"
  BACKUP_STATE="${BACKUP_DIR}/state"
  /bin/mkdir -m 700 "${BACKUP_STATE}"

  original_identity="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "${APP_HOME}")"
  write_private_file "${BACKUP_DIR}/original-identity" "${original_identity}"
  write_phase prepared
  # Publish the active record only after restore has every file it needs. The
  # original App directory is not moved until this atomic record is visible.
  write_private_file "${ACTIVE_RECORD}" "${backup_basename}"

  /bin/mv "${APP_HOME}" "${BACKUP_DIR}/original-app-home"
  [[ ! -e "${APP_HOME}" && ! -L "${APP_HOME}" ]] || die "original App data directory did not move atomically"
  [[ "$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "${BACKUP_DIR}/original-app-home")" == "${original_identity}" ]] || \
    die "original App data directory identity changed during backup"
  write_phase original_moved
}

install_fixture_file() {
  local source="$1"
  local target="$2"
  local expected="$3"
  local incoming="${target}.incoming"

  /bin/cp -p "${source}" "${incoming}"
  /bin/chmod 600 "${incoming}"
  [[ "$(sha256_file "${incoming}")" == "${expected}" ]] || die "fixture copy digest mismatch"
  /bin/mv -f "${incoming}" "${target}"
}

install_lab_app_home() {
  /bin/mkdir -m 700 "${APP_HOME}"
  assert_private_directory "${APP_HOME}" || die "failed to create isolated App data directory"
  # Install the ownership/no-DNS marker first so an interruption during the
  # remaining fixed copies still leaves a safely identifiable lab directory.
  install_fixture_file "${NO_DNS_MARKER_FIXTURE}" "${APP_HOME}/${LAB_MARKER_NAME}" "${NO_DNS_MARKER_SHA256}"
  install_fixture_file "${CONFIG_FIXTURE}" "${APP_HOME}/config.yaml" "${CONFIG_FIXTURE_SHA256}"
  install_fixture_file "${VERGE_FIXTURE}" "${APP_HOME}/verge.yaml" "${VERGE_FIXTURE_SHA256}"
  install_fixture_file "${PROFILES_FIXTURE}" "${APP_HOME}/profiles.yaml" "${PROFILES_FIXTURE_SHA256}"
  [[ "$(/bin/cat "${APP_HOME}/${LAB_MARKER_NAME}")" == "${LAB_MARKER_TEXT}" ]] || \
    die "installed no-DNS marker mismatch"
  write_phase lab_installed
}

capture_dns() {
  /usr/sbin/scutil --dns >"$1"
}

capture_proxy() {
  /usr/sbin/scutil --proxy >"$1"
}

capture_default_routes() {
  {
    /usr/sbin/netstat -rn -f inet
    /usr/sbin/netstat -rn -f inet6
  } | /usr/bin/awk '
    $1 == "default" || $1 == "0/1" || $1 == "128.0/1" ||
    $1 == "::/1" || $1 == "8000::/1" { print }
  ' | LC_ALL=C /usr/bin/sort >"$1"
}

capture_private_routes() {
  {
    /usr/sbin/netstat -rn -f inet
    /usr/sbin/netstat -rn -f inet6
  } | /usr/bin/awk '
    function private_destination(value, lower) {
      lower = tolower(value)
      return value ~ /^10([.\/]|$)/ ||
        value ~ /^192\.168([.\/]|$)/ ||
        value ~ /^172\.(1[6-9]|2[0-9]|3[01])([.\/]|$)/ ||
        lower ~ /^f[cd][0-9a-f]*:/
    }
    private_destination($1) { print }
  ' | LC_ALL=C /usr/bin/sort >"$1"
}

normalized_route_hash() {
  # macOS netstat appends a volatile ARP/ND expiry counter to some otherwise
  # identical routes. Compare only destination, gateway, flags, and interface;
  # these are the fields KyClash could materially alter.
  /usr/bin/awk 'NF >= 4 {printf "%s|%s|%s|%s\n", $1, $2, $3, $4}' "$1" | \
    LC_ALL=C /usr/bin/sort | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
}

capture_baseline() {
  capture_dns "${BACKUP_STATE}/dns.before"
  capture_proxy "${BACKUP_STATE}/proxy.before"
  capture_default_routes "${BACKUP_STATE}/default-routes.before"
  capture_private_routes "${BACKUP_STATE}/private-routes.before"
  list_utuns >"${BACKUP_STATE}/utuns.before"
  /bin/chmod 600 "${BACKUP_STATE}"/*.before
}

record_invariant_failure() {
  local label="$1"
  if [[ ! -e "${BACKUP_STATE}/monitor.failure" ]]; then
    write_private_file "${BACKUP_STATE}/monitor.failure" "${label}"
  fi
}

check_invariants_once() {
  local suffix="$1"
  local failed=0

  capture_dns "${BACKUP_STATE}/dns.${suffix}"
  capture_proxy "${BACKUP_STATE}/proxy.${suffix}"
  capture_default_routes "${BACKUP_STATE}/default-routes.${suffix}"
  capture_private_routes "${BACKUP_STATE}/private-routes.${suffix}"
  /bin/chmod 600 "${BACKUP_STATE}"/*."${suffix}"

  /usr/bin/cmp -s "${BACKUP_STATE}/dns.before" "${BACKUP_STATE}/dns.${suffix}" || {
    record_invariant_failure system-dns
    failed=1
  }
  /usr/bin/cmp -s "${BACKUP_STATE}/proxy.before" "${BACKUP_STATE}/proxy.${suffix}" || {
    record_invariant_failure system-proxy
    failed=1
  }
  [[ "$(normalized_route_hash "${BACKUP_STATE}/default-routes.before")" == \
    "$(normalized_route_hash "${BACKUP_STATE}/default-routes.${suffix}")" ]] || {
    record_invariant_failure default-routes
    failed=1
  }
  [[ "$(normalized_route_hash "${BACKUP_STATE}/private-routes.before")" == \
    "$(normalized_route_hash "${BACKUP_STATE}/private-routes.${suffix}")" ]] || {
    record_invariant_failure private-routes
    failed=1
  }
  return "${failed}"
}

assert_no_protected_route_on_fixed_utun() {
  local matches
  matches="$({
    /usr/sbin/netstat -rn -f inet
    /usr/sbin/netstat -rn -f inet6
  } | /usr/bin/awk -v iface="${FIXED_UTUN}" '
    function protected(value, lower) {
      lower = tolower(value)
      return value == "default" || value == "0/1" || value == "128.0/1" ||
        value == "::/1" || value == "8000::/1" ||
        value ~ /^10([.\/]|$)/ || value ~ /^192\.168([.\/]|$)/ ||
        value ~ /^172\.(1[6-9]|2[0-9]|3[01])([.\/]|$)/ || lower ~ /^f[cd][0-9a-f]*:/
    }
    protected($1) && $0 ~ ("(^|[[:space:]])" iface "([[:space:]]|$)") {print}
  ')"
  [[ -z "${matches}" ]] || die "fixed TUN acquired a default or private route"
}

invariant_monitor() {
  while [[ ! -e "${BACKUP_STATE}/monitor.stop" ]]; do
    if ! check_invariants_once monitor; then
      return 1
    fi
    /bin/sleep 1
  done
  return 0
}

start_invariant_monitor() {
  invariant_monitor &
  MONITOR_PID=$!
}

stop_invariant_monitor() {
  local status=0
  if [[ -n "${MONITOR_PID}" ]]; then
    : >"${BACKUP_STATE}/monitor.stop"
    /bin/chmod 600 "${BACKUP_STATE}/monitor.stop"
    wait "${MONITOR_PID}" || status=$?
    MONITOR_PID=""
  fi
  return "${status}"
}

assert_monitor_clean() {
  [[ ! -e "${BACKUP_STATE}/monitor.failure" ]] || {
    printf 'network invariant changed: %s\n' "$(/bin/cat "${BACKUP_STATE}/monitor.failure")" >&2
    return 1
  }
  if [[ -n "${MONITOR_PID}" ]]; then
    /bin/kill -0 "${MONITOR_PID}" 2>/dev/null
  else
    return 0
  fi
}

assert_managed_socket() {
  local owner links
  [[ -S "${MANAGED_MIHOMO_SOCKET}" && ! -L "${MANAGED_MIHOMO_SOCKET}" ]] || return 1
  owner="$(/usr/bin/stat -f '%Su' "${MANAGED_MIHOMO_SOCKET}")"
  links="$(/usr/bin/stat -f '%l' "${MANAGED_MIHOMO_SOCKET}")"
  [[ "${owner}" == "root" && "${links}" == "1" ]]
}

request_mihomo_api() {
  local endpoint="$1"
  local output="$2"

  case "${endpoint}" in
    /version|/configs) ;;
    *) return 1 ;;
  esac

  {
    printf 'header = "Authorization: Bearer %s"\n' "${SYNTHETIC_API_TOKEN}"
    printf 'url = "http://localhost%s"\n' "${endpoint}"
    printf 'noproxy = "*"\n'
    printf 'fail\n'
    printf 'silent\n'
    printf 'show-error\n'
    printf 'max-time = 2\n'
  } | /usr/bin/curl --config - --unix-socket "${MANAGED_MIHOMO_SOCKET}" \
    --output "${output}" 2>/dev/null
  /bin/chmod 600 "${output}"
  [[ "$(/usr/bin/stat -f '%z' "${output}")" -le 1048576 ]]
  ! /usr/bin/grep -F "${SYNTHETIC_API_TOKEN}" "${output}" >/dev/null 2>&1
}

assert_live_api() {
  local config_response="${BACKUP_STATE}/api-configs.json"
  local version_response="${BACKUP_STATE}/api-version.json"

  request_mihomo_api /configs "${config_response}" || return 1
  request_mihomo_api /version "${version_response}" || return 1
  # Mihomo's valid JSON includes null values that cannot be represented by a
  # property list, so plutil rejects the whole object. Parse locally with the
  # system JSON library and validate only the allowlisted fields; never print
  # or retain the full runtime configuration.
  /usr/bin/ruby --disable-gems -rjson -e '
    begin
      config = JSON.parse(File.binread(ARGV.fetch(0)))
      tun = config.fetch("tun")
      valid = tun.is_a?(Hash) &&
        tun["enable"] == true &&
        tun["device"] == ARGV.fetch(2) &&
        tun["auto-route"] == false &&
        tun["auto-detect-interface"] == false &&
        (tun["strict-route"] == false || tun["strict-route"].nil?) &&
        config["mode"] == "direct"
      version = JSON.parse(File.binread(ARGV.fetch(1))).fetch("version")
      valid &&= version.is_a?(String) && !version.empty?
      exit(valid ? 0 : 1)
    rescue JSON::ParserError, KeyError, TypeError
      exit 1
    end
  ' "${config_response}" "${version_response}" "${FIXED_UTUN}" || return 1

  /bin/rm -f "${config_response}" "${version_response}"
}

assert_only_fixed_new_utun() {
  local current added
  current="${BACKUP_STATE}/utuns.current"
  list_utuns >"${current}"
  added="$(/usr/bin/comm -13 "${BACKUP_STATE}/utuns.before" "${current}")"
  [[ "${added}" == "${FIXED_UTUN}" ]]
}

wait_for_lab_runtime() {
  local attempt app_values mihomo_values

  attempt=0
  while [[ "${attempt}" -lt 60 ]]; do
    assert_monitor_clean || return 1
    app_values="$(app_pids)"
    mihomo_values="$(mihomo_pids)"
    if [[ "$(printf '%s\n' "${app_values}" | line_count)" == "1" && \
      "$(printf '%s\n' "${mihomo_values}" | line_count)" == "1" ]] && \
      assert_managed_socket && utun_exists && assert_only_fixed_new_utun && assert_live_api; then
      APP_PID="${app_values}"
      MIHOMO_PID="${mihomo_values}"
      return 0
    fi
    attempt=$((attempt + 1))
    /bin/sleep 1
  done
  return 1
}

assert_guest_window_visible() {
  local result
  result="$(/usr/bin/osascript - "${APP_PID}" <<'APPLESCRIPT'
on run argv
  set targetPID to (item 1 of argv) as integer
  tell application "System Events"
    set matches to every application process whose unix id is targetPID
    if (count of matches) is not 1 then error "guest process is not unique"
    set targetProcess to item 1 of matches
    set frontmost of targetProcess to true
    delay 1
    return ((frontmost of targetProcess) as text) & "|" & ((count of windows of targetProcess) as text)
  end tell
end run
APPLESCRIPT
)"
  printf '%s\n' "${result}" | /usr/bin/awk -F'|' '$1 == "true" && $2 + 0 >= 1 {passed=1} END {exit passed ? 0 : 1}'
}

launch_lab_app() {
  /usr/bin/open -na "${INSTALLED_APP}"
  wait_for_lab_runtime || die "installed guest App did not reach the fixed managed-TUN state"
  assert_guest_window_visible || die "installed guest App did not expose a frontmost visible window"
  assert_no_protected_route_on_fixed_utun
  assert_monitor_clean || die "a protected network invariant changed while the App was running"
  write_phase app_running
}

wait_for_app_absence() {
  local attempt
  attempt=0
  while [[ "${attempt}" -lt 15 ]]; do
    [[ -z "$(app_pids)" ]] && return 0
    attempt=$((attempt + 1))
    /bin/sleep 1
  done
  return 1
}

wait_for_mihomo_absence() {
  local attempt
  attempt=0
  while [[ "${attempt}" -lt 15 ]]; do
    [[ -z "$(mihomo_pids)" ]] && return 0
    attempt=$((attempt + 1))
    /bin/sleep 1
  done
  return 1
}

terminate_validated_apps() {
  local signal="$1"
  local pid
  for pid in $(app_pids); do
    process_has_text_path "${pid}" "${APP_EXECUTABLE}" user || return 1
    /bin/kill "-${signal}" "${pid}" || return 1
  done
}

terminate_validated_mihomo() {
  local signal="$1"
  local pid
  for pid in $(mihomo_pids); do
    process_has_text_path "${pid}" "${PACKAGED_MIHOMO}" root || return 1
    /usr/bin/sudo /bin/kill "-${signal}" "${pid}" || return 1
  done
}

remove_stale_managed_socket() {
  local owner links holders
  if [[ ! -e "${MANAGED_MIHOMO_SOCKET}" && ! -L "${MANAGED_MIHOMO_SOCKET}" ]]; then
    return 0
  fi
  [[ -S "${MANAGED_MIHOMO_SOCKET}" && ! -L "${MANAGED_MIHOMO_SOCKET}" ]] || return 1
  owner="$(/usr/bin/stat -f '%Su' "${MANAGED_MIHOMO_SOCKET}")"
  links="$(/usr/bin/stat -f '%l' "${MANAGED_MIHOMO_SOCKET}")"
  [[ "${owner}" == "root" && "${links}" == "1" ]] || return 1
  holders="$(/usr/bin/sudo /usr/sbin/lsof -n -U "${MANAGED_MIHOMO_SOCKET}" 2>/dev/null || true)"
  [[ -z "${holders}" ]] || return 1
  /usr/bin/sudo /bin/rm -f "${MANAGED_MIHOMO_SOCKET}"
}

stop_lab_runtime() {
  local pid

  if [[ -n "$(app_pids)" ]]; then
    /usr/bin/osascript -e 'tell application id "net.kysion.kyclash" to quit' >/dev/null 2>&1 || true
  fi
  if ! wait_for_app_absence; then
    terminate_validated_apps TERM || return 1
    /bin/sleep 2
  fi
  if ! wait_for_app_absence; then
    terminate_validated_apps KILL || return 1
    /bin/sleep 1
  fi
  [[ -z "$(app_pids)" ]] || return 1

  if ! wait_for_mihomo_absence; then
    terminate_validated_mihomo TERM || return 1
    /bin/sleep 2
  fi
  if ! wait_for_mihomo_absence; then
    terminate_validated_mihomo KILL || return 1
    /bin/sleep 1
  fi
  [[ -z "$(mihomo_pids)" ]] || return 1

  remove_stale_managed_socket || return 1
  pid=0
  while utun_exists && [[ "${pid}" -lt 15 ]]; do
    pid=$((pid + 1))
    /bin/sleep 1
  done
  ! utun_exists
}

resolve_active_backup() {
  local basename owner mode links phase

  assert_private_directory "${BACKUP_ROOT}" || die "backup root is missing or unsafe"
  assert_regular_file "${ACTIVE_RECORD}"
  owner="$(/usr/bin/stat -f '%u' "${ACTIVE_RECORD}")"
  mode="$(/usr/bin/stat -f '%Lp' "${ACTIVE_RECORD}")"
  links="$(/usr/bin/stat -f '%l' "${ACTIVE_RECORD}")"
  [[ "${owner}" == "${CURRENT_UID}" && "${mode}" == "600" && "${links}" == "1" ]] || \
    die "active backup record is unsafe"
  basename="$(/bin/cat "${ACTIVE_RECORD}")"
  validate_backup_basename "${basename}" || die "active backup basename is invalid"
  BACKUP_DIR="${BACKUP_ROOT}/${basename}"
  assert_private_directory "${BACKUP_DIR}" || die "active unique backup is missing or unsafe"
  BACKUP_STATE="${BACKUP_DIR}/state"
  assert_private_directory "${BACKUP_STATE}" || die "active backup state directory is unsafe"
  assert_regular_file "${BACKUP_DIR}/phase"
  assert_regular_file "${BACKUP_DIR}/original-identity"
  phase="$(/bin/cat "${BACKUP_DIR}/phase")"
  case "${phase}" in
    prepared|original_moved|lab_installed|app_running|restoring) ;;
    *) die "unknown active backup phase" ;;
  esac
}

assert_lab_app_home() {
  local marker owner mode links parent_real

  [[ -d "${APP_HOME}" && ! -L "${APP_HOME}" ]] || return 1
  parent_real="$(cd "$(/usr/bin/dirname "${APP_HOME}")" && pwd -P)"
  [[ "${parent_real}" == "${DATA_ROOT}" ]] || return 1
  owner="$(/usr/bin/stat -f '%u' "${APP_HOME}")"
  mode="$(/usr/bin/stat -f '%Lp' "${APP_HOME}")"
  [[ "${owner}" == "${CURRENT_UID}" && "${mode}" == "700" ]] || return 1
  marker="${APP_HOME}/${LAB_MARKER_NAME}"
  [[ -f "${marker}" && ! -L "${marker}" ]] || return 1
  links="$(/usr/bin/stat -f '%l' "${marker}")"
  owner="$(/usr/bin/stat -f '%u' "${marker}")"
  mode="$(/usr/bin/stat -f '%Lp' "${marker}")"
  [[ "${links}" == "1" && "${owner}" == "${CURRENT_UID}" && "${mode}" == "600" ]] || return 1
  [[ "$(sha256_file "${marker}")" == "${NO_DNS_MARKER_SHA256}" ]]
}

assert_backup_cleanup_layout() {
  local entry name
  for entry in "${BACKUP_DIR}"/* "${BACKUP_DIR}"/.[!.]*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    name="$(/usr/bin/basename "${entry}")"
    case "${name}" in
      phase|phase.incoming|original-identity|state) ;;
      *) return 1 ;;
    esac
  done
  return 0
}

remove_backup_metadata() {
  assert_backup_cleanup_layout || return 1
  [[ ! -e "${BACKUP_DIR}/original-app-home" && ! -L "${BACKUP_DIR}/original-app-home" ]] || return 1
  /bin/rm -R "${BACKUP_STATE}"
  /bin/rm -f "${BACKUP_DIR}/phase" "${BACKUP_DIR}/phase.incoming" \
    "${BACKUP_DIR}/original-identity"
  /bin/rmdir "${BACKUP_DIR}"
  /bin/rm -f "${ACTIVE_RECORD}" "${ACTIVE_RECORD}.incoming"
  /bin/rmdir "${BACKUP_ROOT}"
}

cleanup_unactivated_backup() {
  local entry name candidate incoming_owner incoming_mode incoming_links parent_real
  candidate=""

  assert_private_directory "${BACKUP_ROOT}" || return 1
  [[ ! -e "${ACTIVE_RECORD}" && ! -L "${ACTIVE_RECORD}" ]] || return 1
  # Without an active record the original directory has not crossed the move
  # boundary. Prove it is still the ordinary, unmarked App directory before
  # deleting any transaction scaffolding.
  assert_app_home || return 1
  parent_real="$(cd "$(/usr/bin/dirname "${BACKUP_ROOT}")" && pwd -P)"
  [[ "${parent_real}" == "${DATA_ROOT}" ]] || return 1

  for entry in "${BACKUP_ROOT}"/* "${BACKUP_ROOT}"/.[!.]*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    name="$(/usr/bin/basename "${entry}")"
    case "${name}" in
      backup.*)
        [[ -z "${candidate}" ]] || return 1
        validate_backup_basename "${name}" || return 1
        assert_private_directory "${entry}" || return 1
        [[ ! -e "${entry}/original-app-home" && ! -L "${entry}/original-app-home" ]] || return 1
        candidate="${entry}"
        ;;
      active.incoming)
        [[ -f "${entry}" && ! -L "${entry}" ]] || return 1
        incoming_owner="$(/usr/bin/stat -f '%u' "${entry}")"
        incoming_mode="$(/usr/bin/stat -f '%Lp' "${entry}")"
        incoming_links="$(/usr/bin/stat -f '%l' "${entry}")"
        [[ "${incoming_owner}" == "${CURRENT_UID}" && "${incoming_mode}" == "600" && \
          "${incoming_links}" == "1" ]] || return 1
        ;;
      *)
        return 1
        ;;
    esac
  done

  if [[ -n "${candidate}" ]]; then
    /bin/rm -R "${candidate}"
  fi
  if [[ -e "${ACTIVE_RECORD}.incoming" ]]; then
    /bin/rm -f "${ACTIVE_RECORD}.incoming"
  fi
  /bin/rmdir "${BACKUP_ROOT}"
}

restore_transaction() {
  local expected_identity actual_identity prior_phase
  RESTORE_FAILURE=0

  resolve_active_backup
  prior_phase="$(/bin/cat "${BACKUP_DIR}/phase")"
  expected_identity="$(/bin/cat "${BACKUP_DIR}/original-identity")"
  write_phase restoring
  stop_invariant_monitor || RESTORE_FAILURE=1
  stop_lab_runtime || RESTORE_FAILURE=1

  if [[ -e "${BACKUP_STATE}/dns.before" ]]; then
    check_invariants_once restored || RESTORE_FAILURE=1
  fi
  verify_service_socket || RESTORE_FAILURE=1

  if [[ "${RESTORE_FAILURE}" -ne 0 ]]; then
    printf 'cleanup could not prove runtime and network absence; preserving active backup\n' >&2
    return 1
  fi

  if [[ -d "${BACKUP_DIR}/original-app-home" && ! -L "${BACKUP_DIR}/original-app-home" ]]; then
    if [[ -e "${APP_HOME}" || -L "${APP_HOME}" ]]; then
      assert_lab_app_home || {
        printf 'active App data directory lacks the fixed lab marker; preserving both states\n' >&2
        return 1
      }
      /bin/rm -R "${APP_HOME}"
    fi
    /bin/mv "${BACKUP_DIR}/original-app-home" "${APP_HOME}"
  else
    actual_identity="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "${APP_HOME}" 2>/dev/null || true)"
    if [[ "${actual_identity}" == "${expected_identity}" && \
      ! -e "${APP_HOME}/${LAB_MARKER_NAME}" && ! -L "${APP_HOME}/${LAB_MARKER_NAME}" ]]; then
      # Either the original was never moved (interrupted prepared phase), or a
      # prior restore already moved it back and was interrupted during metadata
      # cleanup. In both cases the recorded directory object is authoritative.
      :
    else
      printf 'original App data directory is missing from active phase %s\n' "${prior_phase}" >&2
      return 1
    fi
  fi

  actual_identity="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp' "${APP_HOME}")"
  [[ "${actual_identity}" == "${expected_identity}" ]] || {
    printf 'restored App data directory identity mismatch\n' >&2
    return 1
  }
  [[ -z "$(app_pids)" && -z "$(mihomo_pids)" ]] || return 1
  [[ ! -e "${MANAGED_MIHOMO_SOCKET}" && ! -L "${MANAGED_MIHOMO_SOCKET}" ]] || return 1
  ! utun_exists || return 1

  remove_backup_metadata || return 1
  BACKUP_DIR=""
  BACKUP_STATE=""
  printf 'original_app_data_identity_restored=true\n'
  printf 'final_app_process=absent\n'
  printf 'final_mihomo_process=absent\n'
  printf 'final_managed_socket=absent\n'
  printf 'final_%s=absent\n' "${FIXED_UTUN}"
  printf 'final_network_invariants=baseline\n'
  return 0
}

cleanup_on_exit() {
  local original_status=$?
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  if [[ "${TRAP_ACTIVE}" -eq 1 ]]; then
    if [[ -e "${ACTIVE_RECORD}" && ! -L "${ACTIVE_RECORD}" ]]; then
      restore_transaction || cleanup_status=$?
    elif [[ -e "${BACKUP_ROOT}" || -L "${BACKUP_ROOT}" ]]; then
      cleanup_unactivated_backup || cleanup_status=$?
    fi
  fi
  if [[ "${original_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    original_status="${cleanup_status}"
  fi
  exit "${original_status}"
}

run_matrix() {
  preflight_checks
  require_sudo
  TRAP_ACTIVE=1
  trap cleanup_on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  create_backup_transaction

  install_lab_app_home
  capture_baseline
  start_invariant_monitor
  launch_lab_app

  printf 'execution_target=kyclash-macos-lab-work\n'
  printf 'guest_app_pid=%s\n' "${APP_PID}"
  printf 'guest_app_executable=%s\n' "${APP_EXECUTABLE}"
  printf 'guest_mihomo_pid=%s\n' "${MIHOMO_PID}"
  printf 'guest_mihomo_executable=%s\n' "${PACKAGED_MIHOMO}"
  printf 'guest_window=frontmost-visible\n'
  printf 'managed_tun_enable=true\n'
  printf 'managed_tun_device=%s\n' "${FIXED_UTUN}"
  printf 'managed_tun_auto_route=false\n'
  printf 'system_dns=baseline\n'
  printf 'system_proxy=baseline\n'
  printf 'default_routes=baseline\n'
  printf 'private_routes=baseline\n'

  stop_lab_runtime || die "failed to stop the exact guest App/Mihomo/TUN runtime"
  stop_invariant_monitor || die "network invariant monitor reported a change"
  check_invariants_once final || die "final protected network state differs from baseline"
  assert_monitor_clean || die "a protected network invariant changed during the test"
  write_phase lab_installed

  restore_transaction
  TRAP_ACTIVE=0
  trap - EXIT INT TERM
  printf 'app_managed_tun_matrix=passed\n'
}

restore_mode() {
  static_check >/dev/null
  require_disposable_guest
  verify_installed_app
  verify_service_socket
  require_sudo
  if [[ ! -e "${BACKUP_ROOT}" && ! -L "${BACKUP_ROOT}" ]]; then
    printf 'restore=nothing-to-do\n'
    return 0
  fi
  restore_transaction
  printf 'restore=passed\n'
}

[[ "$#" -eq 1 ]] || {
  usage
  exit 64
}

case "$1" in
  dry-run)
    dry_run
    ;;
  static-check)
    static_check
    ;;
  preflight)
    preflight_checks
    ;;
  run)
    run_matrix
    ;;
  restore)
    restore_mode
    ;;
  *)
    usage
    exit 64
    ;;
esac
