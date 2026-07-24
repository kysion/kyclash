#!/usr/bin/env bash

set -euo pipefail
umask 077
export LANG=C
export LC_ALL=C

if [[ "$#" -ne 0 ]]; then
  echo "binary_manifest_v1_native=refused_arguments"
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "binary_manifest_v1_native=refused_non_linux"
  exit 1
fi
if [[ "$(id -u)" -eq 0 ]]; then
  echo "binary_manifest_v1_native=refused_root_test_identity"
  exit 1
fi

for command_name in \
  go sudo chroot useradd userdel groupadd groupdel getent \
  setfacl getfacl setcap getcap getfattr setfattr \
  stat sha256sum file install cp pgrep findmnt grep \
  awk cut mktemp tee ln chmod chown rm; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "binary_manifest_v1_native=missing_tool"
    exit 1
  fi
done

script_directory="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1
  pwd -P
)"
module_root="$(
  cd "${script_directory}/../.." >/dev/null 2>&1
  pwd -P
)"
if [[ ! -f "${module_root}/go.mod" ||
  ! -d "${module_root}/internal/productionpeer" ]]; then
  echo "binary_manifest_v1_native=invalid_module_root"
  exit 1
fi
cd "${module_root}"

evidence_directory="${module_root}/build/binary-manifest-v1-native"
mkdir -p "${evidence_directory}"
filesystem_evidence="${evidence_directory}/filesystem.txt"
teardown_evidence="${evidence_directory}/teardown.txt"
: >"${filesystem_evidence}"
: >"${teardown_evidence}"

native_group="kyclash-ipc"
peer_user="kyclash"
broker_user="kyclash-broker"
native_group_created=false
peer_user_created=false
broker_user_created=false
native_group_id=""
peer_user_id=""
broker_user_id=""
fixture_root=""
chroot_root=""

valid_fixture_root() {
  [[ -n "${fixture_root}" &&
    "${fixture_root}" == /var/tmp/kyclash-binary-manifest-v1.* &&
    "${fixture_root}" != /var/tmp/kyclash-binary-manifest-v1. &&
    ! -L "${fixture_root}" ]]
}

cleanup_native_gate() {
  local initial_status="$?"
  local cleanup_ok=true
  trap - EXIT INT TERM
  set +e

  if [[ "${broker_user_created}" == true ]]; then
    if ! sudo userdel "${broker_user}" >/dev/null 2>&1; then
      cleanup_ok=false
    fi
    broker_user_created=false
  fi
  if [[ "${peer_user_created}" == true ]]; then
    if ! sudo userdel "${peer_user}" >/dev/null 2>&1; then
      cleanup_ok=false
    fi
    peer_user_created=false
  fi
  if [[ "${native_group_created}" == true ]]; then
    if ! sudo groupdel "${native_group}" >/dev/null 2>&1; then
      cleanup_ok=false
    fi
    native_group_created=false
  fi

  if [[ -n "${fixture_root}" ]]; then
    if valid_fixture_root; then
      if ! sudo rm -rf -- "${fixture_root}"; then
        cleanup_ok=false
      fi
    else
      cleanup_ok=false
    fi
  fi

  if getent passwd "${peer_user}" >/dev/null 2>&1 ||
    getent passwd "${broker_user}" >/dev/null 2>&1 ||
    getent group "${native_group}" >/dev/null 2>&1; then
    cleanup_ok=false
  fi
  if [[ -n "${fixture_root}" && -e "${fixture_root}" ]]; then
    cleanup_ok=false
  fi
  if [[ -n "${peer_user_id}" ]] &&
    pgrep -u "${peer_user_id}" >/dev/null 2>&1; then
    cleanup_ok=false
  fi
  if [[ -n "${broker_user_id}" ]] &&
    pgrep -u "${broker_user_id}" >/dev/null 2>&1; then
    cleanup_ok=false
  fi

  {
    echo "fixture_absent=$([[ -z "${fixture_root}" || ! -e "${fixture_root}" ]] && echo true || echo false)"
    echo "peer_identity_absent=$(! getent passwd "${peer_user}" >/dev/null 2>&1 && echo true || echo false)"
    echo "broker_identity_absent=$(! getent passwd "${broker_user}" >/dev/null 2>&1 && echo true || echo false)"
    echo "ipc_group_absent=$(! getent group "${native_group}" >/dev/null 2>&1 && echo true || echo false)"
    echo "network_endpoint=none"
    echo "production_activation=false"
    if [[ "${cleanup_ok}" == true ]]; then
      echo "teardown=passed"
    else
      echo "teardown=failed"
    fi
  } >"${teardown_evidence}"

  if [[ "${cleanup_ok}" != true ]]; then
    initial_status=1
  fi
  exit "${initial_status}"
}

trap cleanup_native_gate EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if getent passwd "${peer_user}" >/dev/null 2>&1 ||
  getent passwd "${broker_user}" >/dev/null 2>&1 ||
  getent group "${native_group}" >/dev/null 2>&1; then
  echo "binary_manifest_v1_native=refused_existing_identity"
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
  "${peer_user}"
peer_user_created=true
sudo useradd \
  --system \
  --no-create-home \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  --gid "${native_group}" \
  "${broker_user}"
broker_user_created=true

native_group_id="$(getent group "${native_group}" | cut -d: -f3)"
peer_user_id="$(getent passwd "${peer_user}" | cut -d: -f3)"
broker_user_id="$(getent passwd "${broker_user}" | cut -d: -f3)"
if [[ ! "${native_group_id}" =~ ^[1-9][0-9]*$ ||
  ! "${peer_user_id}" =~ ^[1-9][0-9]*$ ||
  ! "${broker_user_id}" =~ ^[1-9][0-9]*$ ||
  "${peer_user_id}" == "${broker_user_id}" ]]; then
  echo "binary_manifest_v1_native=invalid_test_identity"
  exit 1
fi
if pgrep -u "${peer_user_id}" >/dev/null 2>&1 ||
  pgrep -u "${broker_user_id}" >/dev/null 2>&1; then
  echo "binary_manifest_v1_native=refused_active_test_uid"
  exit 1
fi

fixture_root="$(mktemp -d /var/tmp/kyclash-binary-manifest-v1.XXXXXX)"
if ! valid_fixture_root; then
  echo "binary_manifest_v1_native=invalid_fixture_root"
  exit 1
fi
chroot_root="${fixture_root}/root"
source_directory="${fixture_root}/sources"
mkdir -p "${source_directory}"
chmod 0700 "${source_directory}"
sudo install -d -o root -g root -m 0755 "${chroot_root}"

native_test_source="${source_directory}/binary-manifest-native.test"
CGO_ENABLED=0 go test -c \
  -o "${native_test_source}" \
  ./internal/productionpeer
if ! file "${native_test_source}" |
  grep -F 'ELF 64-bit' >/dev/null ||
  ! file "${native_test_source}" |
    grep -F 'statically linked' >/dev/null; then
  echo "binary_manifest_v1_native=invalid_test_binary"
  exit 1
fi

peer_source="${source_directory}/kyclash-network-peer"
broker_source="${source_directory}/kyclash-network-peer-broker"
bootstrap_source="${source_directory}/kyclash-network-peer-host-bootstrap"
cp "${native_test_source}" "${peer_source}"
cp "${native_test_source}" "${broker_source}"
cp "${native_test_source}" "${bootstrap_source}"
printf '\nKYCLASH_SYNTHETIC_ROLE=peer\n' >>"${peer_source}"
printf '\nKYCLASH_SYNTHETIC_ROLE=broker\n' >>"${broker_source}"
printf '\nKYCLASH_SYNTHETIC_ROLE=host-bootstrap\n' >>"${bootstrap_source}"
chmod 0755 "${peer_source}" "${broker_source}" "${bootstrap_source}"

peer_digest="$(sha256sum "${peer_source}" | awk '{print $1}')"
broker_digest="$(sha256sum "${broker_source}" | awk '{print $1}')"
bootstrap_digest="$(sha256sum "${bootstrap_source}" | awk '{print $1}')"
if [[ "${peer_digest}" == "${broker_digest}" ||
  "${peer_digest}" == "${bootstrap_digest}" ||
  "${broker_digest}" == "${bootstrap_digest}" ]]; then
  echo "binary_manifest_v1_native=non_distinct_fixture_digests"
  exit 1
fi

host_manifest_directory="${chroot_root}/usr/lib/kyclash"
host_executable_directory="${chroot_root}/usr/libexec"
host_manifest="${host_manifest_directory}/network-peer-binaries-v1.json"
host_peer="${host_executable_directory}/kyclash-network-peer"
host_broker="${host_executable_directory}/kyclash-network-peer-broker"
host_bootstrap="${host_executable_directory}/kyclash-network-peer-host-bootstrap"
host_replacement="${host_executable_directory}/.kyclash-network-peer-replacement-v1"
host_hardlink="${host_manifest_directory}/.network-peer-binaries-v1.hardlink"
chroot_test_binary="${chroot_root}/binary-manifest-native.test"
manifest_source="${source_directory}/network-peer-binaries-v1.json"

clear_extended_metadata() {
  local path="$1"
  sudo setfacl -b -- "${path}"
  if [[ -d "${path}" ]]; then
    sudo setfacl -k -- "${path}"
  fi
  sudo setfattr -x security.capability -- "${path}" >/dev/null 2>&1 || true
}

reset_exact_fixture() {
  sudo install -d -o root -g root -m 0755 \
    "${chroot_root}/usr" \
    "${chroot_root}/usr/lib" \
    "${host_manifest_directory}" \
    "${host_executable_directory}"
  sudo rm -f -- \
    "${host_manifest}" \
    "${host_peer}" \
    "${host_broker}" \
    "${host_bootstrap}" \
    "${host_replacement}" \
    "${host_hardlink}"

  sudo install -o root -g root -m 0755 \
    "${native_test_source}" \
    "${chroot_test_binary}"
  sudo install -o root -g root -m 0755 "${peer_source}" "${host_peer}"
  sudo install -o root -g root -m 0755 "${broker_source}" "${host_broker}"
  sudo install -o root -g root -m 0755 "${bootstrap_source}" "${host_bootstrap}"
  printf \
    '{"schema_version":1,"peer_uid":%s,"broker_uid":%s,"ipc_gid":%s,"binaries":{"peer_sha256":"%s","broker_sha256":"%s","host_bootstrap_sha256":"%s"}}' \
    "${peer_user_id}" \
    "${broker_user_id}" \
    "${native_group_id}" \
    "${peer_digest}" \
    "${broker_digest}" \
    "${bootstrap_digest}" \
    >"${manifest_source}"
  sudo install -o root -g root -m 0644 "${manifest_source}" "${host_manifest}"

  local path
  for path in \
    "${chroot_root}" \
    "${chroot_root}/usr" \
    "${chroot_root}/usr/lib" \
    "${host_manifest_directory}" \
    "${host_executable_directory}" \
    "${chroot_test_binary}" \
    "${host_manifest}" \
    "${host_peer}" \
    "${host_broker}" \
    "${host_bootstrap}"; do
    clear_extended_metadata "${path}"
  done
}

assert_no_extended_acl_or_capability() {
  local path="$1"
  local acl
  acl="$(sudo getfacl -cp -- "${path}")"
  if grep -Eq '^(default:|mask:|user:[^:]|group:[^:])' <<<"${acl}"; then
    echo "binary_manifest_v1_native=unexpected_acl"
    exit 1
  fi
  if sudo getfattr \
    --only-values \
    -n security.capability \
    -- "${path}" >/dev/null 2>&1; then
    echo "binary_manifest_v1_native=unexpected_file_capability"
    exit 1
  fi
}

assert_exact_regular_file() {
  local path="$1"
  local expected_mode="$2"
  local facts
  facts="$(sudo stat -c '%u %g %a %h %F' -- "${path}")"
  if [[ "${facts}" != "0 0 ${expected_mode} 1 regular file" ||
    -L "${path}" ]]; then
    echo "binary_manifest_v1_native=invalid_file_facts"
    exit 1
  fi
  assert_no_extended_acl_or_capability "${path}"
}

assert_exact_directory() {
  local path="$1"
  local facts
  facts="$(sudo stat -c '%u %g %a %F' -- "${path}")"
  if [[ "${facts}" != "0 0 755 directory" ||
    -L "${path}" ]]; then
    echo "binary_manifest_v1_native=invalid_directory_facts"
    exit 1
  fi
  assert_no_extended_acl_or_capability "${path}"
}

assert_exact_fixture() {
  assert_exact_directory "${chroot_root}"
  assert_exact_directory "${chroot_root}/usr"
  assert_exact_directory "${chroot_root}/usr/lib"
  assert_exact_directory "${host_manifest_directory}"
  assert_exact_directory "${host_executable_directory}"
  assert_exact_regular_file "${host_manifest}" 644
  assert_exact_regular_file "${host_peer}" 755
  assert_exact_regular_file "${host_broker}" 755
  assert_exact_regular_file "${host_bootstrap}" 755

  if [[ "$(sha256sum "${host_peer}" | awk '{print $1}')" != "${peer_digest}" ||
    "$(sha256sum "${host_broker}" | awk '{print $1}')" != "${broker_digest}" ||
    "$(sha256sum "${host_bootstrap}" | awk '{print $1}')" != "${bootstrap_digest}" ]]; then
    echo "binary_manifest_v1_native=installed_digest_mismatch"
    exit 1
  fi
}

record_filesystem_evidence() {
  local mount_facts
  mount_facts="$(findmnt -n -o ID,FSTYPE -T "${chroot_root}")"
  {
    echo "fixture=synthetic_chroot"
    echo "production_activation=false"
    echo "runtime_manifest_generated=false"
    echo "network_endpoint=none"
    echo "peer_uid=${peer_user_id}"
    echo "broker_uid=${broker_user_id}"
    echo "ipc_gid=${native_group_id}"
    echo "mount=${mount_facts}"
    echo "path=/usr/lib/kyclash/network-peer-binaries-v1.json uid=0 gid=0 mode=644 nlink=1 acl=absent file_capability=absent sha256=$(sha256sum "${host_manifest}" | awk '{print $1}')"
    echo "path=/usr/libexec/kyclash-network-peer uid=0 gid=0 mode=755 nlink=1 acl=absent file_capability=absent sha256=${peer_digest}"
    echo "path=/usr/libexec/kyclash-network-peer-broker uid=0 gid=0 mode=755 nlink=1 acl=absent file_capability=absent sha256=${broker_digest}"
    echo "path=/usr/libexec/kyclash-network-peer-host-bootstrap uid=0 gid=0 mode=755 nlink=1 acl=absent file_capability=absent sha256=${bootstrap_digest}"
  } >"${filesystem_evidence}"
}

run_native_profile() {
  local profile="$1"
  local role="${2:-}"
  local selected_uid=""
  local -a identity_options=()
  case "${role}" in
  peer)
    selected_uid="${peer_user_id}"
    identity_options=(
      "--userspec=+${peer_user_id}:+${native_group_id}"
      "--groups=+${native_group_id}"
    )
    ;;
  broker)
    selected_uid="${broker_user_id}"
    identity_options=(
      "--userspec=+${broker_user_id}:+${native_group_id}"
      "--groups=+${native_group_id}"
    )
    ;;
  "")
    ;;
  *)
    echo "binary_manifest_v1_native=invalid_role"
    exit 1
    ;;
  esac

  sudo env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C \
    LC_ALL=C \
    KYCLASH_BINARY_MANIFEST_V1_NATIVE=1 \
    "KYCLASH_BINARY_MANIFEST_V1_NATIVE_PROFILE=${profile}" \
    "KYCLASH_BINARY_MANIFEST_V1_NATIVE_PEER_UID=${peer_user_id}" \
    "KYCLASH_BINARY_MANIFEST_V1_NATIVE_BROKER_UID=${broker_user_id}" \
    "KYCLASH_BINARY_MANIFEST_V1_NATIVE_IPC_GID=${native_group_id}" \
    "KYCLASH_BINARY_MANIFEST_V1_NATIVE_ROLE=${role}" \
    chroot \
    "${identity_options[@]}" \
    "${chroot_root}" \
    /binary-manifest-native.test \
    -test.v \
    -test.count=1 \
    -test.run '^TestNativeFixedBinaryIdentityFilesystemV1$'
  if [[ -n "${selected_uid}" ]] &&
    pgrep -u "${selected_uid}" >/dev/null 2>&1; then
    echo "binary_manifest_v1_native=identity_process_survived"
    exit 1
  fi
}

reset_exact_fixture
assert_exact_fixture
record_filesystem_evidence
run_native_profile accept-unwritable peer
echo "binary_manifest_v1_peer_read_not_write=passed"
run_native_profile accept-unwritable broker
echo "binary_manifest_v1_broker_read_not_write=passed"

reset_exact_fixture
sudo chown "+${peer_user_id}:+0" "${host_manifest}"
run_native_profile reject
echo "binary_manifest_v1_wrong_owner=passed"

reset_exact_fixture
sudo chown "+0:+${native_group_id}" "${host_peer}"
run_native_profile reject
echo "binary_manifest_v1_wrong_group=passed"

reset_exact_fixture
sudo chmod 0775 "${host_peer}"
run_native_profile reject
echo "binary_manifest_v1_wrong_mode=passed"

reset_exact_fixture
sudo ln "${host_manifest}" "${host_hardlink}"
run_native_profile reject
echo "binary_manifest_v1_hardlink=passed"

reset_exact_fixture
sudo setfacl -n \
  -m "u:${peer_user_id}:r-x,m::r-x" \
  "${host_peer}"
if [[ "$(sudo stat -c '%a' "${host_peer}")" != 755 ]]; then
  echo "binary_manifest_v1_native=acl_changed_mode"
  exit 1
fi
run_native_profile reject
echo "binary_manifest_v1_named_acl=passed"

reset_exact_fixture
sudo setcap cap_net_bind_service=ep "${host_broker}"
if [[ -z "$(sudo getcap -n "${host_broker}")" ]]; then
  echo "binary_manifest_v1_native=capability_injection_failed"
  exit 1
fi
run_native_profile reject
echo "binary_manifest_v1_file_capability=passed"

reset_exact_fixture
sudo rm -f -- "${host_broker}"
sudo ln -s kyclash-network-peer "${host_broker}"
run_native_profile reject
echo "binary_manifest_v1_symlink=passed"

reset_exact_fixture
printf 'digest-mismatch' | sudo tee -a "${host_peer}" >/dev/null
run_native_profile reject
echo "binary_manifest_v1_digest_mismatch=passed"

reset_exact_fixture
sudo install -o root -g root -m 0755 "${peer_source}" "${host_replacement}"
clear_extended_metadata "${host_replacement}"
replacement_inode="$(sudo stat -c '%i' "${host_replacement}")"
peer_inode="$(sudo stat -c '%i' "${host_peer}")"
replacement_digest="$(sha256sum "${host_replacement}" | awk '{print $1}')"
installed_peer_digest="$(sha256sum "${host_peer}" | awk '{print $1}')"
if [[ "${replacement_inode}" == "${peer_inode}" ||
  "${replacement_digest}" != "${installed_peer_digest}" ]]; then
  echo "binary_manifest_v1_native=invalid_replacement_fixture"
  exit 1
fi
run_native_profile replacement-race
echo "binary_manifest_v1_replacement_race=passed"

echo "binary_manifest_v1_native=passed"
