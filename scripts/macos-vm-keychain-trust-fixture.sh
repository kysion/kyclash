#!/usr/bin/env bash
set -euo pipefail

# Guest-runtime-only fixture for the production networking VM candidate. This
# script refuses a physical Mac and never accepts a password, certificate
# private key, or Keychain value through argv/environment.

readonly CONFIRMATION_VALUE="authorized-kyclash-virtualization-framework-vm"
readonly RUNNER_ENVIRONMENT="local-virtualization-framework"
readonly RUNTIME_TARGET="kyclash-macos-lab-work"
readonly BASE_DIR="/private/var/tmp/kyclash-networking-vm-lab"
readonly SERVICE="net.kysion.kyclash.test"
readonly SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"
readonly ROOT_CERT_NAME="loopback-trust-root.pem"
readonly ROOT_KEY_NAME="loopback-trust-root.key"
readonly LEAF_CERT_NAME="loopback-leaf.pem"
readonly LEAF_KEY_NAME="loopback-leaf.key"
readonly ROOT_CONFIG_NAME="loopback-root.cnf"
readonly LEAF_CONFIG_NAME="loopback-leaf.cnf"
readonly LEAF_CSR_NAME="loopback-leaf.csr"
readonly PUBLIC_KEY_NAME="client-public.key"
readonly PUBLIC_HELPER_NAME="kyclash-keychain-public-lab"
readonly PUBLIC_OUTPUT_NAME="client-public-output.txt"
readonly POLICY_PREFLIGHT_NAME="policy-revision-preflight.json"
readonly POLICY_PREFLIGHT_OUTPUT_NAME="policy-revision-preflight-output.txt"
readonly MANIFEST_NAME="manifest.txt"
readonly CERT_INTENT_NAME="certificate-importing"
readonly CERT_STATE_NAME="certificate-imported"
readonly CERT_REMOVED_STATE_NAME="certificate-removed"
readonly PROBE_BEFORE_STATE_NAME="probe-before-import-failed"
readonly PROBE_IMPORTED_STATE_NAME="probe-after-import-passed"
readonly PROBE_REMOVED_STATE_NAME="probe-after-remove-failed"
readonly CREATION_INTENT_NAME="credential-creating"
readonly CREDENTIAL_STATE_NAME="credential-created"
readonly PUBLIC_STATE_NAME="client-public-key-created"
readonly PROBE_NAME="kyclash-system-trust-probe"
readonly NETWORKING_PEER_NAME="kyclash-networking-system-lab"
readonly PEER_KEY_NAME="wg-private.key"
readonly PEER_MANIFEST_NAME="peer-manifest.json"
readonly PEER_DESCRIPTOR_NAME="guest-descriptor.json"

usage() {
  cat >&2 <<'EOF'
usage: macos-vm-keychain-trust-fixture.sh <command> --run-id <16-lowercase-hex>

commands:
  prepare                 create a fresh run root, root/leaf certs, and absent-state proof
  probe-absent            prove nil-RootCAs rejects before import/after removal
  import-cert             import only the generated root into System.keychain
  probe                   run the CGO-disabled carrier trust visibility probe
  prepare-client-key     run the guest-only test-service Keychain/public-key helper
  policy-revision-preflight  prove the exact production policy record is absent in a clean work VM
  mark-keychain-created   record that the fixture created the exact run-bound item
  remove-cert             remove only the recorded root by SHA-256
  cleanup                 prove scoped root/item absence; defer durable state to VM reset

The command must run inside kyclash-macos-lab-work with:
  KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework
  KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm
  KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work
EOF
  exit 64
}

die() {
  echo "kyclash_keychain_trust_fixture=refused" >&2
  exit "$1"
}

require_guest() {
  [ "$(uname -s)" = "Darwin" ] || die 69
  local model
  model="$(sysctl -n hw.model 2>/dev/null || true)"
  case "$model" in VirtualMac*) ;; *) die 69 ;; esac
  [ "$(printenv KYCLASH_RUNNER_ENVIRONMENT 2>/dev/null || true)" = "$RUNNER_ENVIRONMENT" ] || die 69
  [ "$(printenv KYCLASH_VM_LAB_CONFIRM 2>/dev/null || true)" = "$CONFIRMATION_VALUE" ] || die 69
  [ "$(printenv KYCLASH_RUNTIME_TARGET 2>/dev/null || true)" = "$RUNTIME_TARGET" ] || die 69
  [ "$(uname -m)" = "arm64" ] || die 69
  [ -x /usr/bin/security ] && [ -x /usr/bin/sudo ] && [ -x /usr/bin/openssl ] && [ -x /usr/bin/shasum ] || die 69
  # Never turn an SSH invocation into an interactive password transport.
  /usr/bin/sudo -n true >/dev/null 2>&1 || die 77
}

parse_args() {
  [ "$#" -gt 0 ] || usage
  COMMAND="$1"
  shift
  RUN_ID=""
  REVISION=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --run-id)
        [ "$#" -ge 2 ] || usage
        RUN_ID="$2"
        shift 2
        ;;
      --revision)
        [ "$#" -ge 2 ] && [ -z "$REVISION" ] || usage
        REVISION="$2"
        shift 2
        ;;
      *) usage ;;
    esac
  done
  echo "$RUN_ID" | /usr/bin/grep -Eq '^[0-9a-f]{16}$' || usage
  if [ "$COMMAND" = policy-revision-preflight ]; then
    echo "$REVISION" | /usr/bin/grep -Eq '^[1-9][0-9]*$' || usage
  else
    [ -z "$REVISION" ] || usage
  fi
  RUN_ROOT="$BASE_DIR/$RUN_ID"
  ROOT_CERT_PATH="$RUN_ROOT/$ROOT_CERT_NAME"
  ROOT_KEY_PATH="$RUN_ROOT/$ROOT_KEY_NAME"
  LEAF_CERT_PATH="$RUN_ROOT/$LEAF_CERT_NAME"
  LEAF_KEY_PATH="$RUN_ROOT/$LEAF_KEY_NAME"
  ROOT_CONFIG_PATH="$RUN_ROOT/$ROOT_CONFIG_NAME"
  LEAF_CONFIG_PATH="$RUN_ROOT/$LEAF_CONFIG_NAME"
  LEAF_CSR_PATH="$RUN_ROOT/$LEAF_CSR_NAME"
  MANIFEST_PATH="$RUN_ROOT/$MANIFEST_NAME"
  CERT_INTENT_PATH="$RUN_ROOT/$CERT_INTENT_NAME"
  CERT_STATE_PATH="$RUN_ROOT/$CERT_STATE_NAME"
  CERT_REMOVED_STATE_PATH="$RUN_ROOT/$CERT_REMOVED_STATE_NAME"
  PROBE_BEFORE_STATE_PATH="$RUN_ROOT/$PROBE_BEFORE_STATE_NAME"
  PROBE_IMPORTED_STATE_PATH="$RUN_ROOT/$PROBE_IMPORTED_STATE_NAME"
  PROBE_REMOVED_STATE_PATH="$RUN_ROOT/$PROBE_REMOVED_STATE_NAME"
  CREATION_INTENT_PATH="$RUN_ROOT/$CREATION_INTENT_NAME"
  CREDENTIAL_STATE_PATH="$RUN_ROOT/$CREDENTIAL_STATE_NAME"
  PUBLIC_KEY_PATH="$RUN_ROOT/$PUBLIC_KEY_NAME"
  PUBLIC_STATE_PATH="$RUN_ROOT/$PUBLIC_STATE_NAME"
  PUBLIC_HELPER_PATH="$RUN_ROOT/$PUBLIC_HELPER_NAME"
  PUBLIC_OUTPUT_PATH="$RUN_ROOT/$PUBLIC_OUTPUT_NAME"
  POLICY_PREFLIGHT_PATH="$RUN_ROOT/$POLICY_PREFLIGHT_NAME"
  POLICY_PREFLIGHT_OUTPUT_PATH="$RUN_ROOT/$POLICY_PREFLIGHT_OUTPUT_NAME"
  PROBE_PATH="$RUN_ROOT/$PROBE_NAME"
  ACCOUNT="kyclash.vm.lab.$RUN_ID"
}

require_safe_root() {
  [ "$RUN_ROOT" = "$BASE_DIR/$RUN_ID" ] || die 64
  [ -L /var ] && [ "$(/usr/bin/readlink /var)" = private/var ] || die 73
  # APFS firmlinks expose /var as private/var while maintaining distinct
  # directory inodes.  Bind the alias to the same device and exact symlink
  # target; requiring inode equality incorrectly rejects real macOS VMs.
  [ "$(stat -f '%d' /var)" = "$(stat -f '%d' /private/var)" ] || die 73
  for parent in /private /private/var /private/var/tmp; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || die 73
    [ "$(stat -f '%u' "$parent")" = 0 ] || die 73
  done
  if [ -e "$RUN_ROOT" ] && [ ! -d "$RUN_ROOT" ]; then die 73; fi
  if [ -d "$BASE_DIR" ]; then
    [ ! -L "$BASE_DIR" ] || die 73
    [ "$(stat -f '%Lp' "$BASE_DIR" 2>/dev/null || true)" = "700" ] || die 73
    [ "$(stat -f '%u' "$BASE_DIR")" = "$(id -u)" ] || die 73
  fi
}

file_shape() {
  local path="$1" mode="$2"
  [ -f "$path" ] && [ ! -L "$path" ] || die 73
  [ "$(stat -f '%Lp' "$path")" = "$mode" ] || die 73
  [ "$(stat -f '%l' "$path")" = "1" ] || die 73
  [ "$(stat -f '%u' "$path")" = "$(id -u)" ] || die 73
}

write_private_file() {
  local path="$1"
  [ ! -e "$path" ] && [ ! -L "$path" ] || die 73
  umask 077
  (
    set -o noclobber
    : >"$path"
  ) 2>/dev/null || die 73
  /bin/chmod 600 "$path"
  file_shape "$path" 600
}

write_new_record() {
  local path="$1" record="$2"
  [ ! -e "$path" ] && [ ! -L "$path" ] || die 73
  (
    umask 077
    set -o noclobber
    exec 9>"$path"
    printf '%s' "$record" >&9
  ) 2>/dev/null || die 73
  /bin/chmod 600 "$path"
  file_shape "$path" 600
}

root_fingerprint() {
  /usr/bin/openssl x509 -in "$ROOT_CERT_PATH" -outform DER 2>/dev/null |
    /usr/bin/shasum -a 256 | /usr/bin/awk '{print tolower($1)}'
}

leaf_fingerprint() {
  /usr/bin/openssl x509 -in "$LEAF_CERT_PATH" -outform DER 2>/dev/null |
    /usr/bin/shasum -a 256 | /usr/bin/awk '{print tolower($1)}'
}

certificate_count() {
  local fingerprint="$1"
  /usr/bin/sudo -n /usr/bin/security find-certificate -a -Z "$SYSTEM_KEYCHAIN" 2>/dev/null |
    /usr/bin/awk -v wanted="$fingerprint" '
      $1 == "SHA-256" && $2 == "hash:" {
        value = tolower($3)
        if (value == wanted) count++
      }
      END { print count + 0 }
    '
}

admin_trust_count() {
  local fingerprint="$1" dump exit_code
  exit_code=0
  dump="$(/usr/bin/sudo -n /usr/bin/security dump-trust-settings -d 2>&1)" || exit_code="$?"
  if [ "$exit_code" -ne 0 ]; then
    [ "$exit_code" -eq 1 ] && [ "$dump" = 'SecTrustSettingsCopyCertificates: No Trust Settings were found.' ] || die 69
    printf '0\n'
    return
  fi
  printf '%s\n' "$dump" | /usr/bin/awk -v wanted="$fingerprint" '
    $1 == "SHA-256" && $2 == "hash:" {
      value = tolower($3)
      if (value == wanted) count++
    }
    END { print count + 0 }
  '
}

credential_present() {
  /usr/bin/security find-generic-password -s "$SERVICE" -a "$ACCOUNT" >/dev/null 2>&1
}

write_manifest() {
  local root_digest="$1" leaf_digest="$2" root_not_after="$3" leaf_not_after="$4" policy_ceiling="$5"
  local record
  printf -v record '%s\n' \
    'schema_version=1' \
    "run_id=$RUN_ID" \
    "service=$SERVICE" \
    "account=$ACCOUNT" \
    "system_keychain=$SYSTEM_KEYCHAIN" \
    "root_certificate_sha256=$root_digest" \
    "leaf_certificate_sha256=$leaf_digest" \
    "root_not_after_epoch=$root_not_after" \
    "leaf_not_after_epoch=$leaf_not_after" \
    "policy_expiry_ceiling_epoch=$policy_ceiling" \
    "root_certificate_path=$ROOT_CERT_PATH" \
    "leaf_certificate_path=$LEAF_CERT_PATH" \
    "leaf_key_path=$LEAF_KEY_PATH" \
    "public_key_path=$PUBLIC_KEY_PATH" \
    'credential_preflight=absent'
  write_new_record "$MANIFEST_PATH" "$record"
}

manifest_value() {
  local key="$1"
  /usr/bin/awk -F= -v wanted="$key" '$1 == wanted { print substr($0, length(wanted) + 2); found++ } END { if (found != 1) exit 1 }' "$MANIFEST_PATH"
}

load_manifest() {
  file_shape "$MANIFEST_PATH" 600
  # The root signing key is retired immediately after leaf issuance. Any
  # later reappearance is foreign state: fail closed and preserve it for
  # forensic review instead of silently deleting it during cleanup.
  [ ! -e "$ROOT_KEY_PATH" ] && [ ! -L "$ROOT_KEY_PATH" ] || die 73
  [ "$(manifest_value schema_version)" = 1 ] || die 73
  [ "$(manifest_value run_id)" = "$RUN_ID" ] || die 73
  [ "$(manifest_value service)" = "$SERVICE" ] || die 73
  [ "$(manifest_value account)" = "$ACCOUNT" ] || die 73
  [ "$(manifest_value system_keychain)" = "$SYSTEM_KEYCHAIN" ] || die 73
  [ "$(manifest_value root_certificate_path)" = "$ROOT_CERT_PATH" ] || die 73
  [ "$(manifest_value leaf_certificate_path)" = "$LEAF_CERT_PATH" ] || die 73
  [ "$(manifest_value leaf_key_path)" = "$LEAF_KEY_PATH" ] || die 73
  [ "$(manifest_value public_key_path)" = "$PUBLIC_KEY_PATH" ] || die 73
  ROOT_FINGERPRINT="$(manifest_value root_certificate_sha256)"
  LEAF_FINGERPRINT="$(manifest_value leaf_certificate_sha256)"
  ROOT_NOT_AFTER_EPOCH="$(manifest_value root_not_after_epoch)"
  LEAF_NOT_AFTER_EPOCH="$(manifest_value leaf_not_after_epoch)"
  POLICY_EXPIRY_CEILING_EPOCH="$(manifest_value policy_expiry_ceiling_epoch)"
  echo "$ROOT_FINGERPRINT" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 73
  echo "$LEAF_FINGERPRINT" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 73
  echo "$ROOT_NOT_AFTER_EPOCH" | /usr/bin/grep -Eq '^[0-9]{10,}$' || die 73
  echo "$LEAF_NOT_AFTER_EPOCH" | /usr/bin/grep -Eq '^[0-9]{10,}$' || die 73
  echo "$POLICY_EXPIRY_CEILING_EPOCH" | /usr/bin/grep -Eq '^[0-9]{10,}$' || die 73
  [ "$LEAF_NOT_AFTER_EPOCH" -le "$ROOT_NOT_AFTER_EPOCH" ] || die 73
  [ "$POLICY_EXPIRY_CEILING_EPOCH" -lt "$LEAF_NOT_AFTER_EPOCH" ] || die 73
  file_shape "$ROOT_CERT_PATH" 600
  file_shape "$LEAF_CERT_PATH" 600
  [ "$(root_fingerprint)" = "$ROOT_FINGERPRINT" ] || die 73
  [ "$(leaf_fingerprint)" = "$LEAF_FINGERPRINT" ] || die 73
}

public_key_fingerprint() {
  /usr/bin/shasum -a 256 "$PUBLIC_KEY_PATH" | /usr/bin/awk '{print tolower($1)}'
}

intent_value() {
  local key="$1"
  /usr/bin/awk -F= -v wanted="$key" '$1 == wanted { print substr($0, length(wanted) + 2); found++ } END { if (found != 1) exit 1 }' "$CREATION_INTENT_PATH"
}

validate_creation_intent() {
  file_shape "$CREATION_INTENT_PATH" 600
  [ "$(intent_value schema_version)" = 1 ] || die 73
  [ "$(intent_value run_id)" = "$RUN_ID" ] || die 73
  [ "$(intent_value service)" = "$SERVICE" ] || die 73
  [ "$(intent_value account)" = "$ACCOUNT" ] || die 73
  case "$(intent_value created)" in 0|1) ;; *) die 73 ;; esac
}

cert_intent_value() {
  local key="$1"
  /usr/bin/awk -F= -v wanted="$key" '$1 == wanted { print substr($0, length(wanted) + 2); found++ } END { if (found != 1) exit 1 }' "$CERT_INTENT_PATH"
}

validate_certificate_intent() {
  file_shape "$CERT_INTENT_PATH" 600
  [ "$(cert_intent_value schema_version)" = 1 ] || die 73
  [ "$(cert_intent_value run_id)" = "$RUN_ID" ] || die 73
  [ "$(cert_intent_value root_certificate_sha256)" = "$ROOT_FINGERPRINT" ] || die 73
  [ "$(cert_intent_value importing)" = 1 ] || die 73
}

prepare_failure_cleanup() {
  # This trap is limited to the exact names this fresh run may have created;
  # an unexpected symlink or foreign file deliberately leaves the run root for
  # manual review instead of broad deletion.
  local path
  for path in "$ROOT_CONFIG_PATH" "$LEAF_CONFIG_PATH" "$LEAF_CSR_PATH" "$ROOT_CERT_PATH" \
    "$ROOT_KEY_PATH" "$LEAF_CERT_PATH" "$LEAF_KEY_PATH" "$MANIFEST_PATH"; do
    [ ! -e "$path" ] && continue
    [ ! -L "$path" ] && [ -f "$path" ] || return 0
    [ "$(stat -f '%l' "$path" 2>/dev/null || true)" = 1 ] || return 0
    [ "$(stat -f '%u' "$path" 2>/dev/null || true)" = "$(id -u)" ] || return 0
    /bin/rm -f "$path" || return 0
  done
  /bin/rmdir "$RUN_ROOT" 2>/dev/null || true
}

run_trust_probe() {
  local expectation="$1" phase="$2" output error
  output="$RUN_ROOT/probe-$phase-output.txt"
  error="$RUN_ROOT/probe-$phase-error.txt"
  file_shape "$PROBE_PATH" 755
  file_shape "$ROOT_CERT_PATH" 600
  file_shape "$LEAF_CERT_PATH" 600
  file_shape "$LEAF_KEY_PATH" 600
  write_new_record "$output" ''
  write_new_record "$error" ''
  if KYCLASH_SYSTEM_TRUST_ROOT_SHA256="$ROOT_FINGERPRINT" \
    KYCLASH_SYSTEM_TRUST_LEAF_SHA256="$LEAF_FINGERPRINT" \
    "$PROBE_PATH" --root-cert "$ROOT_CERT_PATH" --leaf-cert "$LEAF_CERT_PATH" \
    --leaf-key "$LEAF_KEY_PATH" >>"$output" 2>>"$error"; then
    [ "$expectation" = success ] || die 1
    /usr/bin/grep -Fx 'kyclash_system_trust_probe=passed' "$output" >/dev/null || die 1
    /usr/bin/grep -Fx 'cgo_enabled=0' "$output" >/dev/null || die 1
    [ ! -s "$error" ] || die 1
  else
    [ "$expectation" = failure ] || die 1
    [ ! -s "$output" ] || die 1
    [ "$(/usr/bin/wc -l <"$error" | /usr/bin/tr -d ' ')" = 1 ] || die 1
    /usr/bin/grep -Fx 'KyClash system trust probe failed' "$error" >/dev/null || die 1
  fi
}

prepare() {
  require_safe_root
  [ ! -e "$RUN_ROOT" ] || die 73
  /bin/mkdir -p "$BASE_DIR"
  /bin/chmod 700 "$BASE_DIR"
  /bin/mkdir "$RUN_ROOT"
  /bin/chmod 700 "$RUN_ROOT"
  trap prepare_failure_cleanup EXIT INT TERM

  credential_present && die 73
  # A zero digest is never a valid certificate; this checks the exact run
  # object cannot be accidentally treated as pre-existing.
  [ "$(certificate_count "0000000000000000000000000000000000000000000000000000000000000000")" = 0 ] || die 73

  write_private_file "$ROOT_CONFIG_PATH"
  cat >"$ROOT_CONFIG_PATH" <<'EOF'
[ req ]
distinguished_name = distinguished_name
x509_extensions = extensions
prompt = no
[ distinguished_name ]
commonName = KyClash VM lab root
[ extensions ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
EOF
  /usr/bin/openssl req -new -x509 -newkey rsa:2048 -nodes -days 3 \
    -keyout "$ROOT_KEY_PATH" -out "$ROOT_CERT_PATH" -config "$ROOT_CONFIG_PATH" >/dev/null 2>&1 || die 1
  /bin/chmod 600 "$ROOT_KEY_PATH" "$ROOT_CERT_PATH"

  write_private_file "$LEAF_CONFIG_PATH"
  cat >"$LEAF_CONFIG_PATH" <<'EOF'
[ req ]
distinguished_name = distinguished_name
req_extensions = extensions
prompt = no
[ distinguished_name ]
commonName = 127.0.0.1
[ extensions ]
subjectAltName = IP:127.0.0.1
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
  /usr/bin/openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$LEAF_KEY_PATH" -out "$LEAF_CSR_PATH" -config "$LEAF_CONFIG_PATH" >/dev/null 2>&1 || die 1
  /bin/chmod 600 "$LEAF_KEY_PATH" "$LEAF_CSR_PATH"
  /usr/bin/openssl x509 -req -in "$LEAF_CSR_PATH" -CA "$ROOT_CERT_PATH" -CAkey "$ROOT_KEY_PATH" \
    -CAcreateserial -days 2 -sha256 -out "$LEAF_CERT_PATH" -extfile "$LEAF_CONFIG_PATH" -extensions extensions >/dev/null 2>&1 || die 1
  /bin/chmod 600 "$LEAF_CERT_PATH"
  # The CA signing key is needed only for the leaf-signing command above. It
  # is never consumed by the peer and must not survive fixture preparation.
  /bin/rm -f "$ROOT_KEY_PATH" "$ROOT_CONFIG_PATH" "$LEAF_CONFIG_PATH" "$LEAF_CSR_PATH" "$ROOT_CERT_PATH.srl"
  [ ! -e "$ROOT_KEY_PATH" ] && [ ! -L "$ROOT_KEY_PATH" ] || die 73

  /usr/bin/openssl x509 -in "$ROOT_CERT_PATH" -noout -checkend 0 >/dev/null 2>&1 || die 1
  /usr/bin/openssl x509 -in "$LEAF_CERT_PATH" -noout -checkend 0 >/dev/null 2>&1 || die 1
  /usr/bin/openssl x509 -in "$LEAF_CERT_PATH" -noout -text 2>/dev/null |
    /usr/bin/grep -F 'IP Address:127.0.0.1' >/dev/null || die 1
  ROOT_FINGERPRINT="$(root_fingerprint)"
  LEAF_FINGERPRINT="$(leaf_fingerprint)"
  local root_not_after_text leaf_not_after_text
  root_not_after_text="$(/usr/bin/openssl x509 -in "$ROOT_CERT_PATH" -noout -enddate | /usr/bin/sed 's/^notAfter=//')"
  leaf_not_after_text="$(/usr/bin/openssl x509 -in "$LEAF_CERT_PATH" -noout -enddate | /usr/bin/sed 's/^notAfter=//')"
  ROOT_NOT_AFTER_EPOCH="$(/bin/date -j -u -f '%b %e %T %Y %Z' "$root_not_after_text" '+%s')" || die 1
  LEAF_NOT_AFTER_EPOCH="$(/bin/date -j -u -f '%b %e %T %Y %Z' "$leaf_not_after_text" '+%s')" || die 1
  echo "$ROOT_FINGERPRINT" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 1
  echo "$LEAF_FINGERPRINT" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 1
  [ "$LEAF_NOT_AFTER_EPOCH" -le "$ROOT_NOT_AFTER_EPOCH" ] || die 1
  [ "$LEAF_NOT_AFTER_EPOCH" -ge "$(($(date +%s) + 3600))" ] || die 1
  POLICY_EXPIRY_CEILING_EPOCH="$((LEAF_NOT_AFTER_EPOCH - 300))"
  [ "$POLICY_EXPIRY_CEILING_EPOCH" -gt "$(date +%s)" ] || die 1
  write_manifest "$ROOT_FINGERPRINT" "$LEAF_FINGERPRINT" "$ROOT_NOT_AFTER_EPOCH" "$LEAF_NOT_AFTER_EPOCH" "$POLICY_EXPIRY_CEILING_EPOCH"
  trap - EXIT INT TERM
  file_shape "$ROOT_CERT_PATH" 600
  [ ! -e "$ROOT_KEY_PATH" ] || die 73
  file_shape "$LEAF_CERT_PATH" 600
  file_shape "$LEAF_KEY_PATH" 600
  file_shape "$MANIFEST_PATH" 600
  printf 'kyclash_keychain_trust_fixture=prepared\nroot_certificate_sha256=%s\nleaf_certificate_sha256=%s\npolicy_expiry_ceiling_epoch=%s\n' \
    "$ROOT_FINGERPRINT" "$LEAF_FINGERPRINT" "$POLICY_EXPIRY_CEILING_EPOCH"
}

import_certificate() {
  load_manifest
  [ -f "$PROBE_BEFORE_STATE_PATH" ] && [ "$(cat "$PROBE_BEFORE_STATE_PATH")" = 1 ] || die 73
  [ ! -e "$CERT_INTENT_PATH" ] && [ ! -e "$CERT_STATE_PATH" ] || die 73
  [ ! -e "$CERT_REMOVED_STATE_PATH" ] && [ ! -e "$PROBE_REMOVED_STATE_PATH" ] || die 73
  file_shape "$ROOT_CERT_PATH" 600
  file_shape "$LEAF_CERT_PATH" 600
  local count
  count="$(certificate_count "$ROOT_FINGERPRINT")"
  [ "$count" = 0 ] || die 73
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 0 ] || die 73
  local cert_intent_record
  printf -v cert_intent_record 'schema_version=1\nrun_id=%s\nroot_certificate_sha256=%s\nimporting=1\n' \
    "$RUN_ID" "$ROOT_FINGERPRINT"
  write_new_record "$CERT_INTENT_PATH" "$cert_intent_record"
  /usr/bin/sudo -n /usr/bin/security add-trusted-cert -d -r trustRoot -p ssl \
    -k "$SYSTEM_KEYCHAIN" "$ROOT_CERT_PATH" >/dev/null 2>&1 || die 1
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 1 ] || die 1
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 1 ] || die 1
  /usr/bin/security verify-cert -c "$LEAF_CERT_PATH" -k "$SYSTEM_KEYCHAIN" \
    -p ssl -n 127.0.0.1 -L -q >/dev/null 2>&1 || die 1
  write_new_record "$CERT_STATE_PATH" $'1\n'
  printf 'kyclash_keychain_trust_fixture=certificate-imported\nroot_certificate_sha256=%s\nleaf_certificate_sha256=%s\n' "$ROOT_FINGERPRINT" "$LEAF_FINGERPRINT"
}

probe() {
  load_manifest
  validate_certificate_intent
  [ -f "$CERT_STATE_PATH" ] && [ "$(cat "$CERT_STATE_PATH")" = 1 ] || die 73
  [ -f "$PROBE_BEFORE_STATE_PATH" ] && [ "$(cat "$PROBE_BEFORE_STATE_PATH")" = 1 ] || die 73
  [ ! -e "$PROBE_IMPORTED_STATE_PATH" ] || die 73
  file_shape "$ROOT_CERT_PATH" 600
  file_shape "$LEAF_CERT_PATH" 600
  file_shape "$LEAF_KEY_PATH" 600
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 1 ] || die 1
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 1 ] || die 1
  /usr/bin/security verify-cert -c "$LEAF_CERT_PATH" -k "$SYSTEM_KEYCHAIN" \
    -p ssl -n 127.0.0.1 -L -q >/dev/null 2>&1 || die 1
  run_trust_probe success after-import
  write_new_record "$PROBE_IMPORTED_STATE_PATH" $'1\n'
  printf 'kyclash_keychain_trust_fixture=probe-passed\nroot_certificate_sha256=%s\nleaf_certificate_sha256=%s\n' "$ROOT_FINGERPRINT" "$LEAF_FINGERPRINT"
}

probe_absent() {
  load_manifest
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 0 ] || die 73
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 0 ] || die 73
  if [ -f "$CERT_REMOVED_STATE_PATH" ]; then
    [ "$(cat "$CERT_REMOVED_STATE_PATH")" = 1 ] || die 73
    [ -f "$PROBE_BEFORE_STATE_PATH" ] && [ "$(cat "$PROBE_BEFORE_STATE_PATH")" = 1 ] || die 73
    [ ! -e "$CERT_INTENT_PATH" ] && [ ! -e "$CERT_STATE_PATH" ] || die 73
    [ ! -e "$PROBE_REMOVED_STATE_PATH" ] || die 73
    run_trust_probe failure after-remove
    write_new_record "$PROBE_REMOVED_STATE_PATH" $'1\n'
    printf 'kyclash_keychain_trust_fixture=post-remove-rejection-passed\n'
  else
    [ ! -e "$CERT_INTENT_PATH" ] && [ ! -e "$CERT_STATE_PATH" ] || die 73
    [ ! -e "$PROBE_BEFORE_STATE_PATH" ] && [ ! -e "$PROBE_IMPORTED_STATE_PATH" ] || die 73
    run_trust_probe failure before-import
    write_new_record "$PROBE_BEFORE_STATE_PATH" $'1\n'
    printf 'kyclash_keychain_trust_fixture=pre-import-rejection-passed\n'
  fi
}

prepare_client_key() {
  load_manifest
  [ -f "$POLICY_PREFLIGHT_PATH" ] || die 73
  [ "$(manifest_value credential_preflight)" = absent ] || die 73
  [ ! -e "$CREATION_INTENT_PATH" ] || die 73
  [ ! -e "$CREDENTIAL_STATE_PATH" ] || die 73
  [ ! -e "$PUBLIC_STATE_PATH" ] || die 73
  [ ! -e "$PUBLIC_KEY_PATH" ] || die 73
  [ -d "$RUN_ROOT" ] && [ "$(stat -f '%Lp' "$RUN_ROOT")" = 700 ] || die 73
  file_shape "$MANIFEST_PATH" 600
  # The binary is built on the host and copied into this exact guest run root;
  # it performs the run-bound KyClash test-service lookup and writes only
  # public bytes. The candidate App selects the same namespace only when the
  # explicit networking-system-lab feature is enabled.
  file_shape "$PUBLIC_HELPER_PATH" 755
  write_new_record "$PUBLIC_OUTPUT_PATH" ''
  "$PUBLIC_HELPER_PATH" create --run-id "$RUN_ID" >>"$PUBLIC_OUTPUT_PATH" 2>/dev/null || die 1
  /usr/bin/grep -Fx 'kyclash_keychain_public_lab=created' "$PUBLIC_OUTPUT_PATH" >/dev/null || die 1
  validate_creation_intent
  [ "$(intent_value created)" = 1 ] || die 73
  file_shape "$PUBLIC_KEY_PATH" 600
  [ "$(stat -f '%z' "$PUBLIC_KEY_PATH")" = 32 ] || die 1
  printf 'kyclash_keychain_trust_fixture=client-public-key-created\nclient_public_key_sha256=%s\n' "$(public_key_fingerprint)"
}

policy_revision_preflight() {
  load_manifest
  [ ! -e "$POLICY_PREFLIGHT_PATH" ] && [ ! -L "$POLICY_PREFLIGHT_PATH" ] || die 73
  [ ! -e "$POLICY_PREFLIGHT_OUTPUT_PATH" ] && [ ! -L "$POLICY_PREFLIGHT_OUTPUT_PATH" ] || die 73
  file_shape "$PUBLIC_HELPER_PATH" 755
  write_new_record "$POLICY_PREFLIGHT_OUTPUT_PATH" ''
  "$PUBLIC_HELPER_PATH" policy-revision-preflight --run-id "$RUN_ID" --revision "$REVISION" \
    >>"$POLICY_PREFLIGHT_OUTPUT_PATH" 2>/dev/null || die 1
  /usr/bin/grep -Fx 'kyclash_policy_revision_preflight=passed' "$POLICY_PREFLIGHT_OUTPUT_PATH" >/dev/null || die 1
  file_shape "$POLICY_PREFLIGHT_PATH" 600
  [ "$(stat -f '%z' "$POLICY_PREFLIGHT_PATH")" -le 4096 ] || die 73
  /usr/bin/grep -F '"run_id":"'"$RUN_ID"'"' "$POLICY_PREFLIGHT_PATH" >/dev/null || die 73
  /usr/bin/grep -F '"candidate_revision":'"$REVISION" "$POLICY_PREFLIGHT_PATH" >/dev/null || die 73
  /usr/bin/grep -F '"record_state":"absent"' "$POLICY_PREFLIGHT_PATH" >/dev/null || die 73
  /usr/bin/grep -F '"decision":"new"' "$POLICY_PREFLIGHT_PATH" >/dev/null || die 73
  local expected_app_data_root
  expected_app_data_root="$HOME/Library/Application Support/net.kysion.kyclash"
  /usr/bin/grep -F '"app_data_root":"'"$expected_app_data_root"'"' "$POLICY_PREFLIGHT_PATH" >/dev/null || die 73
  printf 'kyclash_keychain_trust_fixture=policy-revision-preflight-passed\n'
}

mark_keychain_created() {
  load_manifest
  [ "$(manifest_value credential_preflight)" = absent ] || die 73
  credential_present || die 1
  validate_creation_intent
  [ "$(intent_value created)" = 1 ] || die 73
  [ ! -e "$CREDENTIAL_STATE_PATH" ] || die 73
  [ ! -e "$PUBLIC_STATE_PATH" ] || die 73
  file_shape "$PUBLIC_KEY_PATH" 600
  [ "$(stat -f '%z' "$PUBLIC_KEY_PATH")" = 32 ] || die 73
  local public_digest
  public_digest="$(public_key_fingerprint)"
  echo "$public_digest" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 73
  local credential_record
  printf -v credential_record '1\npublic_key_sha256=%s\n' "$public_digest"
  write_new_record "$CREDENTIAL_STATE_PATH" "$credential_record"
  write_new_record "$PUBLIC_STATE_PATH" $'1\n'
  printf 'kyclash_keychain_trust_fixture=credential-owned\n'
}

remove_certificate() {
  load_manifest
  validate_certificate_intent
  [ -f "$CERT_STATE_PATH" ] && [ "$(cat "$CERT_STATE_PATH")" = 1 ] || die 73
  [ -f "$PROBE_IMPORTED_STATE_PATH" ] && [ "$(cat "$PROBE_IMPORTED_STATE_PATH")" = 1 ] || die 73
  [ ! -e "$CERT_REMOVED_STATE_PATH" ] || die 73
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 1 ] || die 73
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 1 ] || die 73
  /usr/bin/sudo -n /usr/bin/security delete-certificate -t -Z "$ROOT_FINGERPRINT" \
    "$SYSTEM_KEYCHAIN" >/dev/null 2>&1 || die 1
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 0 ] || die 1
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 0 ] || die 1
  write_new_record "$CERT_REMOVED_STATE_PATH" $'1\n'
  /bin/rm -f "$CERT_STATE_PATH" "$CERT_INTENT_PATH"
  printf 'kyclash_keychain_trust_fixture=certificate-removed\nroot_certificate_sha256=%s\n' "$ROOT_FINGERPRINT"
}

cleanup() {
  load_manifest
  if [ -f "$CERT_INTENT_PATH" ]; then
    validate_certificate_intent
    local cert_count trust_count
    cert_count="$(certificate_count "$ROOT_FINGERPRINT")"
    trust_count="$(admin_trust_count "$ROOT_FINGERPRINT")"
    if [ "$cert_count" = 1 ] && [ "$trust_count" = 1 ]; then
      /usr/bin/sudo -n /usr/bin/security delete-certificate -t -Z "$ROOT_FINGERPRINT" \
        "$SYSTEM_KEYCHAIN" >/dev/null 2>&1 || die 1
      [ "$(certificate_count "$ROOT_FINGERPRINT")" = 0 ] || die 1
      [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 0 ] || die 1
      [ -e "$CERT_REMOVED_STATE_PATH" ] || write_new_record "$CERT_REMOVED_STATE_PATH" $'1\n'
    elif [ "$cert_count" != 0 ] || [ "$trust_count" != 0 ]; then
      die 73
    elif [ -f "$CERT_STATE_PATH" ]; then
      [ "$(cat "$CERT_STATE_PATH")" = 1 ] || die 73
      [ -e "$CERT_REMOVED_STATE_PATH" ] || write_new_record "$CERT_REMOVED_STATE_PATH" $'1\n'
    fi
    /bin/rm -f "$CERT_STATE_PATH" "$CERT_INTENT_PATH"
  elif [ -e "$CERT_STATE_PATH" ]; then
    die 73
  fi
  if [ -f "$CERT_REMOVED_STATE_PATH" ] && [ ! -e "$PROBE_REMOVED_STATE_PATH" ]; then
    probe_absent
  fi
  if [ -f "$CREDENTIAL_STATE_PATH" ]; then
    [ -f "$CREATION_INTENT_PATH" ] || die 73
    validate_creation_intent
    [ "$(intent_value created)" = 1 ] || die 73
    [ "$(sed -n '1p' "$CREDENTIAL_STATE_PATH")" = 1 ] || die 73
    local recorded_public_digest
    recorded_public_digest="$(sed -n 's/^public_key_sha256=//p' "$CREDENTIAL_STATE_PATH")"
    echo "$recorded_public_digest" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || die 73
    credential_present || die 73
    file_shape "$PUBLIC_KEY_PATH" 600
    [ "$(stat -f '%z' "$PUBLIC_KEY_PATH")" = 32 ] || die 73
    [ "$(public_key_fingerprint)" = "$recorded_public_digest" ] || die 73
    [ -f "$PUBLIC_STATE_PATH" ] || die 73
    [ "$(cat "$PUBLIC_STATE_PATH")" = 1 ] || die 73
  elif [ -e "$PUBLIC_STATE_PATH" ]; then
    die 73
  fi
  if [ -f "$CREATION_INTENT_PATH" ]; then
    validate_creation_intent
    if [ "$(intent_value created)" = 0 ]; then
      # Ownership was never durably committed.  A credential in this window
      # may be foreign or may belong to a crash between put and marker
      # publication; never ask the helper to delete it.  Leave the run
      # unresolved for manual review/work-VM reset.
      if credential_present; then
        die 73
      elif [ -e "$PUBLIC_KEY_PATH" ]; then
        file_shape "$PUBLIC_KEY_PATH" 600
        [ "$(stat -f '%z' "$PUBLIC_KEY_PATH")" = 0 ] || die 73
        /bin/rm -f "$PUBLIC_KEY_PATH"
      fi
    else
      file_shape "$PUBLIC_HELPER_PATH" 755
      [ -e "$PUBLIC_OUTPUT_PATH" ] || write_new_record "$PUBLIC_OUTPUT_PATH" ''
      file_shape "$PUBLIC_OUTPUT_PATH" 600
      "$PUBLIC_HELPER_PATH" cleanup --run-id "$RUN_ID" >>"$PUBLIC_OUTPUT_PATH" 2>/dev/null || die 1
      /usr/bin/grep -Fx 'kyclash_keychain_public_lab=cleanup-passed' "$PUBLIC_OUTPUT_PATH" >/dev/null || die 1
      credential_present && die 1
      [ ! -e "$PUBLIC_KEY_PATH" ] || die 73
    fi
    /bin/rm -f "$CREATION_INTENT_PATH" "$CREDENTIAL_STATE_PATH" "$PUBLIC_STATE_PATH"
  elif [ -e "$CREDENTIAL_STATE_PATH" ] || credential_present; then
    die 73
  fi
  credential_present && die 73
  [ "$(certificate_count "$ROOT_FINGERPRINT")" = 0 ] || die 73
  [ "$(admin_trust_count "$ROOT_FINGERPRINT")" = 0 ] || die 73
  [ -f "$PROBE_BEFORE_STATE_PATH" ] && [ "$(cat "$PROBE_BEFORE_STATE_PATH")" = 1 ] || die 73
  if [ -f "$CERT_REMOVED_STATE_PATH" ]; then
    [ "$(cat "$CERT_REMOVED_STATE_PATH")" = 1 ] || die 73
    [ -f "$PROBE_REMOVED_STATE_PATH" ] && [ "$(cat "$PROBE_REMOVED_STATE_PATH")" = 1 ] || die 73
  fi
  # Delete only exact files this fixture created. An unexpected symlink/file
  # leaves the VM intentionally unresolved.
  [ ! -e "$PUBLIC_KEY_PATH" ] || die 73
  [ ! -e "$CREATION_INTENT_PATH" ] || die 73
  for path in "$ROOT_CERT_PATH" "$LEAF_CERT_PATH" "$LEAF_KEY_PATH" \
    "$MANIFEST_PATH" "$PROBE_PATH" "$PUBLIC_HELPER_PATH" "$PUBLIC_OUTPUT_PATH" \
    "$POLICY_PREFLIGHT_PATH" "$POLICY_PREFLIGHT_OUTPUT_PATH" \
    "$CERT_REMOVED_STATE_PATH" "$PROBE_BEFORE_STATE_PATH" "$PROBE_IMPORTED_STATE_PATH" "$PROBE_REMOVED_STATE_PATH" \
    "$RUN_ROOT/probe-before-import-output.txt" "$RUN_ROOT/probe-before-import-error.txt" \
    "$RUN_ROOT/probe-after-import-output.txt" "$RUN_ROOT/probe-after-import-error.txt" \
    "$RUN_ROOT/probe-after-remove-output.txt" "$RUN_ROOT/probe-after-remove-error.txt"; do
    [ ! -e "$path" ] && continue
    [ ! -L "$path" ] && [ -f "$path" ] || die 73
    [ "$(stat -f '%l' "$path")" = 1 ] || die 73
    [ "$(stat -f '%u' "$path")" = "$(id -u)" ] || die 73
  done
  /bin/rm -f "$ROOT_CERT_PATH" "$LEAF_CERT_PATH" "$LEAF_KEY_PATH" \
    "$MANIFEST_PATH" "$PROBE_PATH" "$PUBLIC_HELPER_PATH" "$PUBLIC_OUTPUT_PATH" \
    "$POLICY_PREFLIGHT_PATH" "$POLICY_PREFLIGHT_OUTPUT_PATH" \
    "$CERT_REMOVED_STATE_PATH" "$PROBE_BEFORE_STATE_PATH" "$PROBE_IMPORTED_STATE_PATH" "$PROBE_REMOVED_STATE_PATH" \
    "$RUN_ROOT/probe-before-import-output.txt" "$RUN_ROOT/probe-before-import-error.txt" \
    "$RUN_ROOT/probe-after-import-output.txt" "$RUN_ROOT/probe-after-import-error.txt" \
    "$RUN_ROOT/probe-after-remove-output.txt" "$RUN_ROOT/probe-after-remove-error.txt"
  [ ! -e "$RUN_ROOT/$PEER_DESCRIPTOR_NAME" ] && [ ! -L "$RUN_ROOT/$PEER_DESCRIPTOR_NAME" ] || die 73
  if [ -e "$RUN_ROOT/$PEER_KEY_NAME" ] || [ -e "$RUN_ROOT/$PEER_MANIFEST_NAME" ]; then
    file_shape "$RUN_ROOT/$PEER_KEY_NAME" 600
    [ "$(stat -f '%z' "$RUN_ROOT/$PEER_KEY_NAME")" = 32 ] || die 73
    file_shape "$RUN_ROOT/$PEER_MANIFEST_NAME" 600
    [ "$(stat -f '%z' "$RUN_ROOT/$PEER_MANIFEST_NAME")" -le 8192 ] || die 73
    /usr/bin/grep -F '"run_id":"'"$RUN_ID"'"' "$RUN_ROOT/$PEER_MANIFEST_NAME" >/dev/null || die 73
  fi
  if [ -e "$RUN_ROOT/$NETWORKING_PEER_NAME" ]; then
    file_shape "$RUN_ROOT/$NETWORKING_PEER_NAME" 755
  fi
  shopt -s nullglob dotglob
  for path in "$RUN_ROOT"/*; do
    case "$(basename "$path")" in
      "$NETWORKING_PEER_NAME"|"$PEER_KEY_NAME"|"$PEER_MANIFEST_NAME") ;;
      *) die 73 ;;
    esac
  done
  shopt -u nullglob dotglob
  # The production policy record is deliberately not deleted by this fixture.
  # The peer's reboot state is likewise left as an exact allowlisted residue.
  # The work VM must be reverted/destroyed to its clean baseline before the
  # next candidate run; deleting App-owned state would widen the destructive
  # filesystem boundary.
  printf 'kyclash_keychain_trust_fixture=scoped-cleanup-passed\npolicy_record_cleanup=deferred-to-work-vm-revert\nrun_root_cleanup=deferred-to-work-vm-revert\n'
}

parse_args "$@"
require_guest
case "$COMMAND" in
  prepare) prepare ;;
  probe-absent) probe_absent ;;
  import-cert) import_certificate ;;
  probe) probe ;;
  prepare-client-key) prepare_client_key ;;
  policy-revision-preflight) policy_revision_preflight ;;
  mark-keychain-created) mark_keychain_created ;;
  remove-cert) remove_certificate ;;
  cleanup) cleanup ;;
  *) usage ;;
esac
