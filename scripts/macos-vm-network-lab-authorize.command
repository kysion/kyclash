#!/bin/zsh
set -euo pipefail

readonly EXPECTED_VM='kyclash-macos-lab-work'
readonly RESULT='/private/var/tmp/kyclash-vm-network-lab-authorization.log'

umask 077
model="$(/usr/sbin/sysctl -n hw.model)"
architecture="$(/usr/bin/uname -m)"
console_user="$(/usr/bin/stat -f '%Su' /dev/console)"
current_user="$(/usr/bin/id -un)"

if [[ "${model}" != VirtualMac* || "${architecture}" != arm64 || \
  "${console_user}" != "${current_user}" || "${current_user}" != supen ]]; then
  /usr/bin/printf 'authorization=refused\n' >| "${RESULT}"
  /usr/bin/printf 'KyClash VM network lab refused this machine.\n'
  /usr/bin/read -r '?Press Return to close. '
  exit 69
fi

/usr/bin/printf 'authorization=pending\nvm=%s\nmodel=%s\narchitecture=%s\n' \
  "${EXPECTED_VM}" "${model}" "${architecture}" >| "${RESULT}"

/usr/bin/printf '\nKyClash VM network lab needs one visible administrator authorization.\n'
/usr/bin/printf 'The password is read only by macOS sudo and is never sent to SSH or saved.\n\n'
if /usr/bin/sudo -v; then
  /usr/bin/printf 'authorization=granted\nvm=%s\nmodel=%s\narchitecture=%s\n' \
    "${EXPECTED_VM}" "${model}" "${architecture}" >| "${RESULT}"
  /usr/bin/printf '\nAuthorization granted. Keep this Terminal open while KyClash is tested.\n'
else
  /usr/bin/printf 'authorization=denied\nvm=%s\nmodel=%s\narchitecture=%s\n' \
    "${EXPECTED_VM}" "${model}" "${architecture}" >| "${RESULT}"
  /usr/bin/printf '\nAuthorization was not granted.\n'
  /usr/bin/read -r '?Press Return to close. '
  exit 77
fi

while true; do
  /bin/sleep 30
  /usr/bin/sudo -n -v >/dev/null 2>&1 || break
done

/usr/bin/printf '\nAuthorization cache expired. You may close this Terminal.\n'
/usr/bin/read -r '?Press Return to close. '
