#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "credential_v2_native=refused_non_linux"
  exit 1
fi
if [[ "$(id -u)" -eq 0 ]]; then
  echo "credential_v2_native=refused_root_test_identity"
  exit 1
fi
for command_name in \
  go setfacl getfacl setpriv mount umount \
  systemd-creds systemd-run systemctl journalctl \
  useradd userdel groupadd groupdel getent nsenter dd mountpoint; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "credential_v2_native=missing_tool"
    exit 1
  fi
done

peer_uid="$(id -u)"
peer_gid="$(id -g)"
unrelated_uid=65534
broker_uid=65533
if [[ "${peer_uid}" -eq "${unrelated_uid}" || "${peer_uid}" -eq "${broker_uid}" ]]; then
  echo "credential_v2_native=refused_reserved_test_uid"
  exit 1
fi

fixture_root=""
runtime_root=""
executable_root=""
owner_mount=""
mounted=false
native_unit=""
native_user="kyclash"
native_group="kyclash-ipc"
native_group_created=false
native_user_created=false
native_unit_owned=false
cleanup_completed=false

cleanup_best_effort() {
  if [[ "${cleanup_completed}" == true ]]; then
    return
  fi
  if [[ -n "${fixture_root}" &&
    "${fixture_root}" != /var/tmp/kyclash-credential-v2.* ]] ||
    [[ -n "${runtime_root}" &&
      "${runtime_root}" != /run/kyclash-credential-v2.* ]] ||
    [[ -n "${executable_root}" &&
      "${executable_root}" != /opt/kyclash-credential-v2.* ]]; then
    echo "credential_v2_native=refused_cleanup_target"
    return
  fi
  if [[ "${native_unit_owned}" == true ]]; then
    sudo systemctl stop "${native_unit}" >/dev/null 2>&1 || true
    sudo systemctl reset-failed "${native_unit}" >/dev/null 2>&1 || true
  fi
  if [[ "${mounted}" == true ]]; then
    sudo mount -o remount,rw,nodev,nosuid,noexec "${owner_mount}" >/dev/null 2>&1 || true
    sudo umount "${owner_mount}" >/dev/null 2>&1 || true
  fi
  if [[ "${native_user_created}" == true ]]; then
    sudo userdel "${native_user}" >/dev/null 2>&1 || true
  fi
  if [[ "${native_group_created}" == true ]]; then
    sudo groupdel "${native_group}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${executable_root}" ]]; then
    sudo rm -rf -- "${executable_root}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${runtime_root}" ]]; then
    sudo rm -rf -- "${runtime_root}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${fixture_root}" ]]; then
    sudo rm -rf -- "${fixture_root}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_best_effort EXIT

fixture_root="$(mktemp -d /var/tmp/kyclash-credential-v2.XXXXXX)"
runtime_root="$(sudo mktemp -d /run/kyclash-credential-v2.XXXXXX)"
executable_root="$(sudo mktemp -d /opt/kyclash-credential-v2.XXXXXX)"
sudo chown root:root "${runtime_root}"
sudo chmod 0711 "${runtime_root}"
sudo chown root:root "${executable_root}"
sudo chmod 0711 "${executable_root}"
owner_mount="${fixture_root}/peer-owned-read-only"
native_unit="kyclash-credential-v2-${runtime_root##*.}.service"

write_sources() {
  local source_directory="$1"
  install -d -m 0700 "${source_directory}"
  printf '%s' 'kyclash-native-v2-synthetic-certificate' \
    >"${source_directory}/tls-chain.pem"
  printf '%s' 'kyclash-native-v2-synthetic-tls-private-key' \
    >"${source_directory}/tls-private-key.pem"
  printf '%s' 'kyclash-native-v2-synthetic-wireguard-private-key' \
    >"${source_directory}/wireguard-private-key"
  chmod 0600 "${source_directory}/"*
}

assert_denied_for_identity() {
  local directory="$1"
  local uid="$2"
  local gid="$3"
  local groups="$4"
  local name
  for name in tls-chain.pem tls-private-key.pem wireguard-private-key; do
    if ! sudo /usr/bin/test -f "${directory}/${name}"; then
      echo "credential_v2_native=missing_denial_target"
      exit 1
    fi
    if sudo setpriv \
      --reuid "${uid}" \
      --regid "${gid}" \
      --groups "${groups}" \
      dd \
      if="${directory}/${name}" \
      of=/dev/null \
      bs=1 \
      count=1 \
      status=none; then
      echo "credential_v2_native=unauthorized_read"
      exit 1
    fi
  done
}

assert_denied_in_mount_namespace() {
  local main_pid="$1"
  local directory="$2"
  local uid="$3"
  local gid="$4"
  local groups="$5"
  local namespace="/proc/${main_pid}/ns/mnt"
  if [[ ! -e "${namespace}" ]]; then
    echo "credential_v2_native=missing_service_namespace"
    exit 1
  fi
  if ! sudo nsenter --mount="${namespace}" -- \
    setpriv \
    --reuid "${uid}" \
    --regid "${gid}" \
    --groups "${groups}" \
    /usr/bin/true; then
    echo "credential_v2_native=invalid_denial_identity"
    exit 1
  fi

  local name
  for name in tls-chain.pem tls-private-key.pem wireguard-private-key; do
    local path="${directory}/${name}"
    if ! sudo nsenter --mount="${namespace}" -- \
      /usr/bin/test -f "${path}"; then
      echo "credential_v2_native=missing_namespaced_credential"
      exit 1
    fi
    if ! sudo nsenter --mount="${namespace}" -- \
      dd if="${path}" of=/dev/null bs=1 count=1 status=none; then
      echo "credential_v2_native=root_namespaced_read_failed"
      exit 1
    fi
    if sudo nsenter --mount="${namespace}" -- \
      setpriv \
      --reuid "${uid}" \
      --regid "${gid}" \
      --groups "${groups}" \
      dd if="${path}" of=/dev/null bs=1 count=1 status=none; then
      echo "credential_v2_native=unauthorized_namespaced_read"
      exit 1
    fi
  done
}

run_reader_gate() {
  local profile="$1"
  local directory="$2"
  KYCLASH_CREDENTIAL_V2_NATIVE_PROFILE="${profile}" \
  KYCLASH_CREDENTIAL_V2_NATIVE_DIRECTORY="${directory}" \
  KYCLASH_CREDENTIAL_V2_NATIVE_PEER_UID="${peer_uid}" \
    go test -count=1 ./internal/productionpeer \
      -run '^TestNativeSystemdCredentialFilesystemV2Materialization$'
}

wait_for_path() {
  local path="$1"
  local attempts=300
  while [[ "${attempts}" -gt 0 ]]; do
    if sudo test -f "${path}"; then
      return
    fi
    attempts=$((attempts - 1))
    sleep 0.1
  done
  echo "credential_v2_native=systemd_ready_timeout"
  exit 1
}

wait_for_unit_exit() {
  local attempts=300
  while [[ "${attempts}" -gt 0 ]]; do
    local active_state
    local sub_state
    active_state="$(
      sudo systemctl show "${native_unit}" --property=ActiveState --value
    )"
    sub_state="$(
      sudo systemctl show "${native_unit}" --property=SubState --value
    )"
    if [[ "${active_state}" == active && "${sub_state}" == exited ]]; then
      return
    fi
    if [[ "${active_state}" == failed ]]; then
      return
    fi
    attempts=$((attempts - 1))
    sleep 0.1
  done
  echo "credential_v2_native=systemd_exit_timeout"
  exit 1
}

wait_for_unit_unload() {
  local attempts=300
  while [[ "${attempts}" -gt 0 ]]; do
    local load_state
    if ! load_state="$(
      sudo systemctl show "${native_unit}" --property=LoadState --value
    )"; then
      echo "credential_v2_native=systemd_unload_query_failed"
      exit 1
    fi
    if [[ "${load_state}" == not-found ]]; then
      return
    fi
    attempts=$((attempts - 1))
    sleep 0.1
  done
  echo "credential_v2_native=systemd_unload_timeout"
  exit 1
}

complete_success_cleanup() {
  sudo systemctl stop "${native_unit}"
  wait_for_unit_unload
  native_unit_owned=false
  if sudo test -e "${materialized_directory}"; then
    echo "credential_v2_native=credential_path_survived"
    exit 1
  fi

  sudo mount -o remount,rw,nodev,nosuid,noexec "${owner_mount}"
  sudo umount "${owner_mount}"
  mounted=false
  if mountpoint -q "${owner_mount}"; then
    echo "credential_v2_native=read_only_mount_survived"
    exit 1
  fi

  sudo userdel "${native_user}"
  native_user_created=false
  sudo groupdel "${native_group}"
  native_group_created=false
  if getent passwd "${native_user}" >/dev/null ||
    getent group "${native_group}" >/dev/null; then
    echo "credential_v2_native=test_identity_survived"
    exit 1
  fi

  sudo rm -rf -- "${executable_root}"
  sudo rm -rf -- "${runtime_root}"
  sudo rm -rf -- "${fixture_root}"
  if sudo test -e "${executable_root}" ||
    sudo test -e "${runtime_root}" ||
    sudo test -e "${fixture_root}"; then
    echo "credential_v2_native=temporary_root_survived"
    exit 1
  fi
  cleanup_completed=true
}

source_root="${fixture_root}/sources"
write_sources "${source_root}"
sudo chown root:root "${fixture_root}"
sudo chmod 0711 "${fixture_root}"

root_acl_directory="${fixture_root}/root-acl"
sudo install -d -o root -g root -m 0500 "${root_acl_directory}"
for name in tls-chain.pem tls-private-key.pem wireguard-private-key; do
  sudo install -o root -g root -m 0400 \
    "${source_root}/${name}" "${root_acl_directory}/${name}"
  sudo setfacl -b "${root_acl_directory}/${name}"
  sudo setfacl -m \
    "u::r--,u:${peer_uid}:r--,g::---,m::r--,o::---" \
    "${root_acl_directory}/${name}"
done
sudo setfacl -b "${root_acl_directory}"
sudo setfacl -m \
  "u::r-x,u:${peer_uid}:r-x,g::---,m::r-x,o::---" \
  "${root_acl_directory}"
sudo setfacl -k "${root_acl_directory}"

run_reader_gate root-acl "${root_acl_directory}"
assert_denied_for_identity "${root_acl_directory}" \
  "${unrelated_uid}" "${unrelated_uid}" "${unrelated_uid}"
assert_denied_for_identity "${root_acl_directory}" \
  "${broker_uid}" "${peer_gid}" "${peer_gid}"
echo "credential_v2_root_acl=passed"

sudo install -d -o root -g root -m 0755 "${owner_mount}"
sudo mount -t tmpfs \
  -o rw,nodev,nosuid,noexec,size=1m \
  kyclash-credential-v2 "${owner_mount}"
mounted=true
for name in tls-chain.pem tls-private-key.pem wireguard-private-key; do
  sudo install -o "${peer_uid}" -g "${peer_gid}" -m 0400 \
    "${source_root}/${name}" "${owner_mount}/${name}"
  sudo setfacl -b "${owner_mount}/${name}"
done
sudo chown "${peer_uid}:${peer_gid}" "${owner_mount}"
sudo chmod 0500 "${owner_mount}"
sudo setfacl -b -k "${owner_mount}"
sudo mount -o remount,ro,nodev,nosuid,noexec "${owner_mount}"

run_reader_gate peer-owned-read-only "${owner_mount}"
assert_denied_for_identity "${owner_mount}" \
  "${unrelated_uid}" "${unrelated_uid}" "${unrelated_uid}"
assert_denied_for_identity "${owner_mount}" \
  "${broker_uid}" "${peer_gid}" "${peer_gid}"
echo "credential_v2_peer_owned_read_only=passed"

if getent passwd "${native_user}" >/dev/null ||
  getent group "${native_group}" >/dev/null; then
  echo "credential_v2_native=refused_existing_identity"
  exit 1
fi
sudo groupadd --system "${native_group}"
native_group_created=true
sudo useradd \
  --system \
  --no-create-home \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  --gid "${native_group}" \
  "${native_user}"
native_user_created=true
native_uid="$(id -u "${native_user}")"
native_gid="$(id -g "${native_user}")"
if [[ "${native_uid}" -eq 0 || "${native_gid}" -eq 0 ]]; then
  echo "credential_v2_native=refused_root_systemd_identity"
  exit 1
fi

native_binary_source="${source_root}/productionpeer-native.test"
native_binary="${executable_root}/productionpeer-native.test"
go test -c -o "${native_binary_source}" ./internal/productionpeer
sudo install -o root -g root -m 0755 \
  "${native_binary_source}" "${native_binary}"

encrypted_directory="${fixture_root}/credentials.encrypted"
sudo install -d -o root -g root -m 0700 "${encrypted_directory}"
for name in tls-chain.pem tls-private-key.pem wireguard-private-key; do
  encrypted_path="${encrypted_directory}/${name}.cred"
  sudo systemd-creds encrypt \
    --with-key=host \
    --name="${name}" \
    "${source_root}/${name}" \
    "${encrypted_path}" >/dev/null
  sudo chown root:root "${encrypted_path}"
  sudo chmod 0600 "${encrypted_path}"
done

hold_directory="${runtime_root}/systemd-hold"
sudo install -d -o "${native_uid}" -g "${native_gid}" -m 0700 \
  "${hold_directory}"
ready_file="${hold_directory}/ready"
release_file="${hold_directory}/release"

native_load_state="$(
  sudo systemctl show "${native_unit}" --property=LoadState --value 2>/dev/null ||
    true
)"
if [[ -n "${native_load_state}" && "${native_load_state}" != not-found ]]; then
  echo "credential_v2_native=refused_existing_unit"
  exit 1
fi
native_unit_owned=true
sudo systemd-run \
  --unit="${native_unit}" \
  --no-block \
  --remain-after-exit \
  --service-type=exec \
  --uid="${native_user}" \
  --gid="${native_group}" \
  --property=NoNewPrivileges=yes \
  --property=LimitCORE=0 \
  --property=PrivateTmp=yes \
  --property=UMask=0077 \
  --property="LoadCredentialEncrypted=tls-chain.pem:${encrypted_directory}/tls-chain.pem.cred" \
  --property="LoadCredentialEncrypted=tls-private-key.pem:${encrypted_directory}/tls-private-key.pem.cred" \
  --property="LoadCredentialEncrypted=wireguard-private-key:${encrypted_directory}/wireguard-private-key.cred" \
  --setenv=KYCLASH_CREDENTIAL_V2_NATIVE_PROFILE=systemd-materialized \
  --setenv="KYCLASH_CREDENTIAL_V2_NATIVE_PEER_UID=${native_uid}" \
  --setenv="KYCLASH_CREDENTIAL_V2_NATIVE_READY_FILE=${ready_file}" \
  --setenv="KYCLASH_CREDENTIAL_V2_NATIVE_RELEASE_FILE=${release_file}" \
  "${native_binary}" \
  -test.v \
  -test.run '^TestNativeSystemdCredentialFilesystemV2Materialization$'

wait_for_path "${ready_file}"
native_main_pid="$(
  sudo systemctl show "${native_unit}" --property=MainPID --value
)"
if [[ ! "${native_main_pid}" =~ ^[1-9][0-9]*$ || "${native_main_pid}" -le 1 ]]; then
  echo "credential_v2_native=invalid_main_pid"
  exit 1
fi
materialized_directory="$(
  sudo cat "/proc/${native_main_pid}/environ" |
    tr '\0' '\n' |
    sed -n 's/^CREDENTIALS_DIRECTORY=//p'
)"
if [[ "${materialized_directory}" != "/run/credentials/${native_unit}" ]]; then
  echo "credential_v2_native=unexpected_credentials_directory"
  exit 1
fi
assert_denied_in_mount_namespace \
  "${native_main_pid}" \
  "${materialized_directory}" \
  "${unrelated_uid}" \
  "${unrelated_uid}" \
  "${unrelated_uid}"
assert_denied_in_mount_namespace \
  "${native_main_pid}" \
  "${materialized_directory}" \
  "${broker_uid}" \
  "${native_gid}" \
  "${native_gid}"
sudo touch "${release_file}"
wait_for_unit_exit
sudo journalctl --unit="${native_unit}" --no-pager --output=cat
native_active_state="$(
  sudo systemctl show "${native_unit}" --property=ActiveState --value
)"
native_sub_state="$(
  sudo systemctl show "${native_unit}" --property=SubState --value
)"
native_result="$(sudo systemctl show "${native_unit}" --property=Result --value)"
native_code="$(sudo systemctl show "${native_unit}" --property=ExecMainCode --value)"
native_status="$(sudo systemctl show "${native_unit}" --property=ExecMainStatus --value)"
if [[ "${native_active_state}" != active ||
  "${native_sub_state}" != exited ||
  "${native_result}" != success ||
  "${native_code}" != 1 ||
  "${native_status}" != 0 ]]; then
  echo "credential_v2_native=systemd_materialization_failed"
  exit 1
fi
echo "credential_v2_systemd_materialized=passed"
complete_success_cleanup
echo "credential_v2_native=passed"
