#!/bin/zsh

set -euo pipefail
umask 077

readonly SCRIPT_DIR="${0:A:h}"
readonly SCREENSHOT_PATH="${SCRIPT_DIR}/kyclash-visible.png"
readonly STATUS_PATH="${SCRIPT_DIR}/capture-status.txt"
readonly APP_EXECUTABLE="/Applications/KyClash.app/Contents/MacOS/clash-verge"

fail() {
  if [[ -L "${STATUS_PATH}" ]]; then
    /usr/bin/printf 'capture=failed reason=status-path-is-a-symlink\n' >&2
    exit 1
  fi
  /usr/bin/printf 'capture=failed reason=%s\n' "$1" >"${STATUS_PATH}"
  exit 1
}

model="$(/usr/sbin/sysctl -n hw.model 2>/dev/null || true)"
case "${model}" in
  VirtualMac*) ;;
  *) fail 'runtime-target-is-not-VirtualMac' ;;
esac

[[ "${TERM_PROGRAM:-}" == 'Apple_Terminal' ]] || fail 'not-running-in-guest-GUI-Terminal'
[[ -f "$0" && ! -L "$0" ]] || fail 'capture-script-is-not-a-regular-file'
[[ "$(/usr/bin/stat -f '%Su' "${SCRIPT_DIR}")" == "$(/usr/bin/id -un)" ]] ||
  fail 'unexpected-evidence-directory-owner'
[[ "$(/usr/bin/stat -f '%Lp' "${SCRIPT_DIR}")" == '700' ]] ||
  fail 'unexpected-evidence-directory-mode'
[[ ! -e "${SCREENSHOT_PATH}" && ! -L "${SCREENSHOT_PATH}" ]] ||
  fail 'screenshot-path-already-exists'

typeset -a app_pids=()
while IFS= read -r candidate_pid; do
  [[ "${candidate_pid}" == <-> ]] || fail 'invalid-app-pid'
  app_pids+=("${candidate_pid}")
done < <(/usr/bin/pgrep -x clash-verge 2>/dev/null || true)
(( ${#app_pids[@]} == 1 )) || fail 'expected-exactly-one-app-process'
readonly app_pid="${app_pids[1]}"
readonly app_command="$(/bin/ps -p "${app_pid}" -o command=)"
case "${app_command}" in
  "${APP_EXECUTABLE}"*) ;;
  *) fail 'app-process-is-not-installed-bundle' ;;
esac

# This script is deliberately launched by the guest's Terminal.app.  Running
# screencapture from the SSH bootstrap cannot see the Aqua display or inherit
# Terminal's Screen Recording grant.  `open` activates the already-running App
# without requiring Automation permission for System Events.
/usr/bin/open -a "/Applications/KyClash.app" >/dev/null 2>&1 || fail 'unable-to-activate-app'
/bin/sleep 2
/usr/sbin/screencapture -x -D 1 -t png "${SCREENSHOT_PATH}" || fail 'screencapture-failed'
[[ -f "${SCREENSHOT_PATH}" && ! -L "${SCREENSHOT_PATH}" && -s "${SCREENSHOT_PATH}" ]] ||
  fail 'screenshot-is-not-a-nonempty-regular-file'

readonly screenshot_owner="$(/usr/bin/stat -f '%Su' "${SCREENSHOT_PATH}")"
readonly screenshot_mode="$(/usr/bin/stat -f '%Lp' "${SCREENSHOT_PATH}")"
[[ "${screenshot_owner}" == "$(/usr/bin/id -un)" ]] || fail 'unexpected-screenshot-owner'
[[ "${screenshot_mode}" == '600' ]] || fail 'unexpected-screenshot-mode'
/usr/bin/file -b "${SCREENSHOT_PATH}" | /usr/bin/grep -q '^PNG image data' ||
  fail 'screenshot-is-not-png'

readonly screenshot_width="$(/usr/bin/sips -g pixelWidth "${SCREENSHOT_PATH}" 2>/dev/null | /usr/bin/awk '/pixelWidth:/ {print $2}')"
readonly screenshot_height="$(/usr/bin/sips -g pixelHeight "${SCREENSHOT_PATH}" 2>/dev/null | /usr/bin/awk '/pixelHeight:/ {print $2}')"
[[ "${screenshot_width}" == <-> && "${screenshot_height}" == <-> ]] ||
  fail 'invalid-screenshot-dimensions'
(( screenshot_width > 0 && screenshot_height > 0 )) || fail 'empty-screenshot-dimensions'

readonly screenshot_hash="$(/usr/bin/shasum -a 256 "${SCREENSHOT_PATH}" | /usr/bin/awk '{print $1}')"
/usr/bin/printf '%s\n' \
  'capture=passed' \
  "model=${model}" \
  "app_pid=${app_pid}" \
  "app_path=${APP_EXECUTABLE}" \
  "screenshot_owner=${screenshot_owner}" \
  "screenshot_mode=${screenshot_mode}" \
  "screenshot_width=${screenshot_width}" \
  "screenshot_height=${screenshot_height}" \
  "screenshot_sha256=${screenshot_hash}" >"${STATUS_PATH}"

exit 0
