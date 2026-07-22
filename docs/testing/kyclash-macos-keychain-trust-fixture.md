# KyClash disposable-VM Keychain and system-trust fixture

Status: guest-only fixture implemented; runtime evidence is pending the next
authorized run in `kyclash-macos-lab-work`.

This fixture closes the S1.13 review question about how a short-lived guest
certificate is imported and removed by exact SHA-256 fingerprint, and how the
CGO-disabled Go sidecar's unchanged `RootCAs: nil` path observes the macOS
platform trust store. A feature-gated lab binary reuses the production
`MacOsKeychainCredentialStore` and production resolver; it does not change
production `RootCAs` handling or the ordinary package.

## Boundaries

- The script refuses non-Darwin, non-`VirtualMac*`, non-arm64 hardware.
- It requires the exact disposable guest environment markers:
  `KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework`,
  `KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm`,
  and `KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work`.
- It requires cached non-interactive `sudo`; no administrator password is
  accepted through SSH, argv, stdin, environment, or logs.
- The only Keychain generic-password identity is the KyClash test service
  `net.kysion.kyclash.test`, account
  `kyclash.vm.lab.<run_id>`, where `run_id` is exactly 16 lowercase hex
  characters.
- The System Keychain mutation is limited to the generated root certificate.
  The leaf certificate is never imported.
- The canonical run root is
  `/private/var/tmp/kyclash-networking-vm-lab/<run_id>`. The script accepts
  `/var` only after proving the standard root-owned `/var -> private/var`
  system alias, then rejects symlinked canonical path components.
- The root signing key is a guest-local mode-`0600` file only during leaf
  issuance and is deleted before `prepare` succeeds. The leaf key remains
  guest-local under the mode-`0700` run directory for the reboot matrix and is
  removed by exact cleanup. Neither key is printed or copied to the host.

## Fixture lifecycle

Build all three guest fixtures on the host into one new private output root and
copy only their binaries into the selected guest. The Go fixtures are
CGO-disabled arm64 Darwin; neither build nor copy touches host Keychain,
routes, or network state. Builders require a clean committed source tree and
refuse any existing artifact name.

```bash
mkdir -p "$PWD/target/macos-vm-lab/build"
LAB_BUILD_ROOT="$(mktemp -d "$PWD/target/macos-vm-lab/build/fixture.XXXXXX")"
chmod 700 "$LAB_BUILD_ROOT"
export KYCLASH_VM_LAB_BUILD_ROOT="$LAB_BUILD_ROOT"
corepack pnpm macos:production-vm:trust-probe
corepack pnpm macos:production-vm:keychain-helper
corepack pnpm macos:production-vm:peer
corepack pnpm macos:production-vm:copy-fixtures --shell-only
```

The user then prepares the run root in the selected guest's visible Terminal:

```bash
# GUEST
export KYCLASH_RUNNER_ENVIRONMENT=local-virtualization-framework
export KYCLASH_VM_LAB_CONFIRM=authorized-kyclash-virtualization-framework-vm
export KYCLASH_RUNTIME_TARGET=kyclash-macos-lab-work
sudo -v
RUN_ID=0123456789abcdef
REVISION="$(date +%s)"
$HOME/kyclash-macos-vm-keychain-trust-fixture.sh prepare --run-id "$RUN_ID"
```

After the guest root exists, run the full copier on the host (where
`LAB_BUILD_ROOT` was created):

```bash
# HOST
RUN_ID=0123456789abcdef
corepack pnpm macos:production-vm:copy-fixtures \
  --run-id "$RUN_ID" --build-root "$LAB_BUILD_ROOT"
```

Continue the scoped lifecycle in the guest:

```bash
# GUEST
FIXTURE="$HOME/kyclash-macos-vm-keychain-trust-fixture.sh"
"$FIXTURE" probe-absent --run-id "$RUN_ID"
"$FIXTURE" policy-revision-preflight \
  --run-id "$RUN_ID" --revision "$REVISION"
"$FIXTURE" prepare-client-key --run-id "$RUN_ID"
"$FIXTURE" mark-keychain-created --run-id "$RUN_ID"
"$FIXTURE" import-cert --run-id "$RUN_ID"
"$FIXTURE" probe --run-id "$RUN_ID"
# HOST (second terminal): compute EXPIRES_AT from the printed ceiling and keep
# this persistent runner attached while the candidate App connects. The
# runner injects all three guest markers and keeps stdin open; do not replace
# it with a one-shot SSH/background command.
EXPIRES_AT=<smaller-of-now-plus-21600-and-policy_expiry_ceiling_epoch>
corepack pnpm macos:production-vm:peer-run \
  --run-id "$RUN_ID" --expires-at "$EXPIRES_AT"
# Return to the guest terminal only after the App has disconnected and the
# host runner has been explicitly closed; then remove the fixture certificate.
"$FIXTURE" remove-cert --run-id "$RUN_ID"
"$FIXTURE" probe-absent --run-id "$RUN_ID"
"$FIXTURE" cleanup --run-id "$RUN_ID"
```

After the guest prints the ceiling, the host-only candidate preparation must
receive that scalar explicitly (the descriptor schema stays unchanged):

```bash
# HOST: pull only the public descriptor, policy preflight, and ceiling scalar.
PULL_PARENT="$(mktemp -d "$PWD/target/macos-vm-lab/pull.XXXXXX")"
chmod 700 "$PULL_PARENT"
PULL_ROOT="$PULL_PARENT/public-input"
corepack pnpm macos:production-vm:copy-fixtures \
  --pull-run --run-id "$RUN_ID" --output-root "$PULL_ROOT"

node scripts/generate-networking-production-vm-lab.mjs \
  --descriptor "$PULL_ROOT/guest-descriptor.json" \
  --policy-revision-preflight "$PULL_ROOT/policy-revision-preflight.json" \
  --run-root <nonexistent-child-of-a-new-0700-parent> \
  --policy-expiry-ceiling "$(tr -d '\n' < "$PULL_ROOT/policy-expiry-ceiling-epoch.txt")" \
  --revision <same-revision>
```

The script prints only fixed status lines, public SHA-256 values, and the
public `policy_expiry_ceiling_epoch` scalar. The redacted policy revision
preflight records only its run/revision, canonical App-data root and hash,
check time, and the exact `absent`/`new` decision; it is copied to the host and hashed into
the signed candidate marker. The manifest records both the root
and leaf SHA-256 values, exact paths, leaf `NotAfter`, a policy-expiry ceiling
five minutes before `NotAfter`, and the run-bound service/account. Root/leaf
certificates are short-lived RSA-2048 fixtures (three days/two days); policy
and descriptor expiry must be no more than 24 hours and no greater than the
recorded ceiling. Pass that printed epoch explicitly to the host preparation
command as `--policy-expiry-ceiling`; do not copy the guest manifest or any
certificate/key file to the host. It rejects pre-existing generic-password entries,
pre-existing run roots, duplicate certificate fingerprints, symlinks, unsafe
modes, and a certificate count other than exactly one after import.

If cleanup is interrupted after import, run:

```bash
FIXTURE="$HOME/kyclash-macos-vm-keychain-trust-fixture.sh"
"$FIXTURE" remove-cert --run-id "$RUN_ID"
"$FIXTURE" cleanup --run-id "$RUN_ID"
```

Removal calls `security delete-certificate -t -Z <root-sha256>` against
`/Library/Keychains/System.keychain`, then independently proves that exact
fingerprint count and matching admin trust-setting count are zero. It never deletes by common name or a broad
Keychain search. Generic-password deletion is allowed only after preflight
proved the exact account absent and the helper's O_EXCL `credential-creating`
record transitioned to `created=1`. `mark-keychain-created` adds the final
public-key hash record. The helper uses the macOS Security Framework's
create-only `SecItemAdd` operation (`SecKeychain::add_generic_password`), so a
concurrent or foreign item is reported as `created=false` and is never
overwritten. Cleanup re-reads the run-bound test-service Keychain value,
re-derives X25519 public material in memory, requires and compares the
run-bound public file, and only then deletes the exact service/account.
The resolver clears its newly generated candidate bytes on duplicate and
error paths before returning, so a losing race leaves no private material in
ordinary buffers.

The fixture never deletes or restores the durable production policy identity
record. After a candidate run, revert or destroy the exact work VM and require
a clean clone before another run; this is the only supported policy-record
cleanup boundary. Scoped cleanup also requires the peer descriptor/process to
be absent and permits only the exact peer binary, `wg-private.key`, and
`peer-manifest.json` reboot state to remain in the run root. Those files and
the run root are removed by the same mandatory work-VM reset.

## Trust probe contract

The helper at
`network-sidecar/cmd/kyclash-system-trust-probe` is built with
`CGO_ENABLED=0`, `GOOS=darwin`, and `GOARCH=arm64`. It:

1. validates the root and leaf files are bounded regular files;
2. validates root/leaf fingerprints supplied as public environment values;
3. checks a self-signed CA root and a separate server leaf with only numeric
   SAN `127.0.0.1` and server-auth usage;
4. starts a loopback TLS server using the leaf;
5. calls the same `carrier.DialTCP` implementation used by the production
   sidecar with `RootCAs: nil`; and
6. exchanges one KYNP-framed payload and prints only
   `kyclash_system_trust_probe=passed` and `cgo_enabled=0`.

The required evidence sequence is failure before import, success after import,
and failure after `delete-certificate -t`; each transition has a separate
O_EXCL state record. A failure means the fixture has not proved platform trust visibility; it must
not be replaced with an in-memory `x509.CertPool` or a production API
change. The shell script also runs `security verify-cert` against the
numeric loopback leaf before invoking the Go probe.

No VM runtime has been run by this source-only change. The next guest run must
capture only redacted facts: VM model/OS/architecture, root and leaf
fingerprints, import/probe/remove/absence statuses, and final absence of the
run-bound Keychain item and certificate. It must not retain certificate
contents, private keys, Keychain values, or raw security output.
