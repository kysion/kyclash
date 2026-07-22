import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const fixture = path.join(root, 'scripts', 'macos-vm-keychain-trust-fixture.sh')
const builder = path.join(root, 'scripts', 'build-system-trust-probe-macos.mjs')
const keychainBuilder = path.join(
  root,
  'scripts',
  'build-keychain-public-helper-macos.mjs',
)
const peerBuilder = path.join(
  root,
  'scripts',
  'build-networking-system-lab-peer-macos.mjs',
)
const keychainPublicHelper = path.join(
  root,
  'src-tauri',
  'src',
  'bin',
  'kyclash-keychain-public-lab.rs',
)
const credentialsSource = path.join(
  root,
  'src-tauri',
  'src',
  'networking',
  'credentials.rs',
)
const productionComposition = path.join(
  root,
  'src-tauri',
  'src',
  'networking',
  'production_composition.rs',
)
const probe = path.join(
  root,
  'network-sidecar',
  'cmd',
  'kyclash-system-trust-probe',
  'main.go',
)

test('guest Keychain fixture is shell-valid and executable', () => {
  const stat = fs.statSync(fixture)
  assert.equal(stat.isFile(), true)
  assert.equal(stat.mode & 0o111, 0o111)
  const result = spawnSync('/bin/bash', ['-n', fixture], {
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
})

test('fixture keeps the exact trust and cleanup boundary', () => {
  const source = fs.readFileSync(fixture, 'utf8')
  assert.match(source, /VirtualMac\*/u)
  assert.match(source, /kyclash-macos-lab-work/u)
  assert.match(source, /net\.kysion\.kyclash\.test/u)
  assert.match(source, /kyclash\.vm\.lab\.\$RUN_ID/u)
  assert.match(source, /add-trusted-cert -d -r trustRoot/u)
  assert.match(source, /delete-certificate -t -Z "\$ROOT_FINGERPRINT"/u)
  assert.doesNotMatch(source, /delete-certificate -c/u)
  assert.doesNotMatch(source, /add-generic-password/u)
  assert.doesNotMatch(source, /find-generic-password[^\n]*-w/u)
  assert.match(source, /prepare-client-key/u)
  assert.match(source, /credential-creating/u)
  assert.match(source, /set -o noclobber/u)
  assert.match(source, /"\$PUBLIC_HELPER_PATH" cleanup/u)
  assert.match(source, /probe-absent/u)
  assert.match(source, /probe-before-import-failed/u)
  assert.match(source, /probe-after-import-passed/u)
  assert.match(source, /probe-after-remove-failed/u)
  assert.match(source, /dump-trust-settings -d/u)
  assert.match(source, /policy_expiry_ceiling_epoch/u)
  assert.match(source, /policy-revision-preflight/u)
  assert.match(source, /candidate_revision/u)
  assert.match(source, /record_state.*absent/u)
  assert.match(source, /policy_record_cleanup=deferred-to-work-vm-revert/u)
  assert.match(source, /run_root_cleanup=deferred-to-work-vm-revert/u)
  assert.match(source, /kyclash_keychain_trust_fixture=scoped-cleanup-passed/u)
  assert.match(source, /rm -f "\$ROOT_KEY_PATH"/u)
  assert.match(
    source,
    /if credential_present; then\n\s+die 73\n\s+elif \[ -e "\$PUBLIC_KEY_PATH" \]/u,
  )
  assert.doesNotMatch(source, /root_key_path=/u)
  assert.match(
    source,
    /load_manifest\(\) \{[\s\S]*?\[ ! -e "\$ROOT_KEY_PATH" \] && \[ ! -L "\$ROOT_KEY_PATH" \] \|\| die 73/u,
  )
  const cleanup = source.match(/^cleanup\(\) \{([\s\S]*?)\n\}\n\nparse_args/mu)
  assert.ok(cleanup, 'cleanup function must remain structurally discoverable')
  assert.doesNotMatch(
    cleanup[1],
    /\$ROOT_KEY_PATH/u,
    'cleanup must preserve a reappeared root signing key as evidence',
  )
  assert.match(
    source,
    /BASE_DIR="\/private\/var\/tmp\/kyclash-networking-vm-lab"/u,
  )
  assert.doesNotMatch(source, /mv -f "\$temporary" "\$MANIFEST_PATH"/u)
})

test('production Keychain public helper is run-bound and never reuses an item', () => {
  const source = fs.readFileSync(keychainPublicHelper, 'utf8')
  assert.match(source, /net\.kysion\.kyclash\.test/u)
  assert.match(source, /kyclash\.vm\.lab\.\{run_id\}/u)
  assert.match(source, /MacOsKeychainCredentialStore::new_test\(\)/u)
  assert.match(source, /resolve_or_generate_wireguard_material_with_status/u)
  assert.match(source, /if !created/u)
  assert.match(
    source,
    /if !created \{[\s\S]*?return Err\(Error::AlreadyExists\)/u,
  )
  assert.match(source, /create_new\(true\)/u)
  assert.match(source, /credential-creating/u)
  assert.match(source, /PrivateKey::from_private_key\(&X25519/u)
  assert.match(source, /FilePolicyIdentityStore::new/u)
  assert.match(source, /PolicyIdentityLabSnapshot::Missing/u)
  assert.match(source, /transaction\.lab_snapshot\(\)/u)
  assert.match(source, /transaction\.lab_finish\(\)/u)
  assert.match(source, /getpwuid_r/u)
  assert.match(source, /HOME/u)
  assert.doesNotMatch(source, /serde::Deserialize/u)
  assert.match(source, /policy-revision-preflight/u)
  assert.doesNotMatch(source, /println!\([^\n]*private/u)
  assert.doesNotMatch(source, /eprintln!\([^\n]*material/u)

  const explicitGet = source.indexOf('match store.get_test_item(&reference)')
  const resolver = source.indexOf(
    'let (material, created) = match resolve_or_generate_wireguard_material_with_status',
  )
  const intent = source.indexOf('write_creation_intent(&paths)')
  assert.ok(intent >= 0 && explicitGet > intent && resolver > explicitGet)
  assert.match(
    source,
    /require_created_transition\(creation_intent_created\(&paths\)\?\)\?/u,
  )
  assert.match(source, /ownership unprovable/u)
  assert.match(source, /if !paths\.public_key\.exists\(\)/u)
  assert.match(
    source,
    /let public_on_disk = read_public_key\(&paths\.public_key\)\?/u,
  )
  assert.match(source, /get_test_item\(&reference\)/u)
  assert.match(
    fs.readFileSync(credentialsSource, 'utf8'),
    /ERR_SEC_ITEM_NOT_FOUND/u,
  )
})

test('the disposable candidate uses the test Keychain namespace without changing production defaults', () => {
  const credentials = fs.readFileSync(credentialsSource, 'utf8')
  const composition = fs.readFileSync(productionComposition, 'utf8')
  assert.match(credentials, /net\.kysion\.kyclash\.networking/u)
  assert.match(credentials, /net\.kysion\.kyclash\.test/u)
  assert.match(credentials, /feature = "networking-system-lab"/u)
  assert.match(
    composition,
    /MacOsKeychainCredentialStore::new_for_runtime\(\)/u,
  )
})

test('Keychain creation uses an atomic create-only operation', () => {
  const source = fs.readFileSync(credentialsSource, 'utf8')
  const macosCreate = source.match(
    /impl CredentialStore for MacOsKeychainCredentialStore \{([\s\S]*?)\n\}\n\nimpl CredentialStore for MemoryCredentialStore/u,
  )
  assert.ok(
    macosCreate,
    'macOS credential-store implementation must remain discoverable',
  )
  const createOnly = macosCreate[1].match(
    /fn put_if_absent\(([\s\S]*?)\n {4}\}\n\n {4}fn get/u,
  )
  assert.ok(createOnly, 'macOS create-only method must remain discoverable')
  assert.match(createOnly[1], /SecKeychain::default/u)
  assert.match(createOnly[1], /add_generic_password/u)
  assert.match(createOnly[1], /ERR_SEC_DUPLICATE_ITEM/u)
  assert.doesNotMatch(
    createOnly[1],
    /(?:security_framework::)?passwords::set_generic_password\s*\(/u,
  )
  assert.match(
    source,
    /let created = match store\.put_if_absent\(reference, persisted\)/u,
  )
  assert.match(source, /if !created \{[\s\S]*?store\.get\(reference\)\?/u)
  assert.match(source, /bytes\.fill\(0\)/u)
  assert.match(source, /create_only_store_never_overwrites_foreign_material/u)
  assert.match(
    source,
    /resolver_race_returns_foreign_material_without_claiming_ownership/u,
  )
})

test('fixture persists recoverable intent before every external mutation', () => {
  const source = fs.readFileSync(fixture, 'utf8')
  const certIntent = source.indexOf(
    'write_new_record "$CERT_INTENT_PATH" "$cert_intent_record"',
  )
  const certImport = source.indexOf(
    '/usr/bin/security add-trusted-cert -d -r trustRoot',
  )
  assert.ok(certIntent >= 0 && certImport > certIntent)

  const helperSource = fs.readFileSync(keychainPublicHelper, 'utf8')
  const keyIntent = helperSource.indexOf(
    'let mut creation_intent = match write_creation_intent(&paths)',
  )
  const keyMutation = helperSource.indexOf(
    'let (material, created) = match resolve_or_generate_wireguard_material_with_status',
    keyIntent,
  )
  const ownership = helperSource.indexOf(
    'if mark_creation_intent_created(&mut creation_intent, &paths).is_err()',
  )
  assert.ok(
    keyIntent >= 0 && keyMutation > keyIntent && ownership > keyMutation,
  )
  assert.match(
    helperSource,
    /let rolled_back = store\.delete\(&reference\)\.is_ok\(\)/u,
  )
  assert.match(
    helperSource,
    /if rolled_back \{[\s\S]*remove_file\(&paths\.creation_intent\)/u,
  )
  assert.match(source, /if \[ -f "\$CERT_INTENT_PATH" \]; then/u)
  assert.match(source, /if \[ -f "\$CREATION_INTENT_PATH" \]; then/u)
})

test('CGO-disabled probe uses the production nil-RootCAs carrier path', () => {
  const source = fs.readFileSync(probe, 'utf8')
  assert.match(source, /builtWithCGODisabled/u)
  assert.match(source, /carrier\.DialTCP/u)
  assert.match(source, /RootCAs:\s*nil/u)
  assert.doesNotMatch(source, /InsecureSkipVerify/u)
})

test('probe builder is host-build-only and pins the guest target', () => {
  const source = fs.readFileSync(builder, 'utf8')
  assert.match(source, /process\.platform !== 'darwin'/u)
  assert.match(source, /CGO_ENABLED:\s*'0'/u)
  assert.match(source, /GOOS:\s*'darwin'/u)
  assert.match(source, /GOARCH:\s*'arm64'/u)
  assert.match(source, /build_target/u)
  assert.match(source, /runtime_target/u)
})

test('Keychain public helper builder is host-only and provenance-pinned', () => {
  const source = fs.readFileSync(keychainBuilder, 'utf8')
  assert.match(source, /process\.platform !== 'darwin'/u)
  assert.match(source, /os\.arch\(\) !== 'arm64'/u)
  assert.match(source, /networking-system-lab/u)
  assert.match(source, /CARGO_TARGET_DIR/u)
  assert.match(source, /runtime_target: 'kyclash-macos-lab-work'/u)
  assert.match(source, /sha256/u)
  assert.doesNotMatch(source, /security\s+(find|add|delete)-generic-password/u)
})

test('system-lab peer builder is host-only, arm64, and provenance-pinned', () => {
  const source = fs.readFileSync(peerBuilder, 'utf8')
  assert.match(source, /process\.platform !== 'darwin'/u)
  assert.match(source, /process\.arch !== 'arm64'/u)
  assert.match(source, /KYCLASH_VM_LAB_BUILD_ROOT/u)
  assert.match(source, /GOOS: 'darwin'/u)
  assert.match(source, /GOARCH: 'arm64'/u)
  assert.match(source, /kyclash-networking-system-lab/u)
  assert.match(source, /runtime_target: 'kyclash-macos-lab-work'/u)
  assert.match(source, /flag: 'wx'/u)
})
