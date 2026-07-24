import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  atomicPublishJSONNoReplace,
  buildExternalPeerAppRun,
  externalPeerAppEnvironment,
  externalPeerAppOverlay,
} from './build-macos-vm-external-peer-lab-app.mjs'

const root = path.resolve(import.meta.dirname, '..')

const snapshot = (tree = 'a'.repeat(64)) => ({
  commit: '0123456789abcdef0123456789abcdef01234567',
  dirty: true,
  status_sha256: 'b'.repeat(64),
  tree_sha256: tree,
  file_count: 91,
})

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>clash-verge</string>
  <key>CFBundleIdentifier</key><string>net.kysion.kyclash</string>
  <key>CFBundleShortVersionString</key><string>2.5.3</string>
  <key>CFBundleVersion</key><string>2.5.3</string>
</dict>
</plist>
`

const writeAppFixture = (cargoTarget) => {
  const app = path.join(
    cargoTarget,
    'aarch64-apple-darwin',
    'release',
    'bundle',
    'macos',
    'KyClash.app',
  )
  const contents = path.join(app, 'Contents')
  const macos = path.join(contents, 'MacOS')
  const resources = path.join(contents, 'Resources')
  fs.mkdirSync(macos, { recursive: true, mode: 0o755 })
  fs.mkdirSync(resources, { recursive: true, mode: 0o755 })
  for (const directory of [app, contents, macos, resources])
    fs.chmodSync(directory, 0o755)
  fs.writeFileSync(path.join(contents, 'Info.plist'), infoPlist, {
    mode: 0o644,
  })
  fs.writeFileSync(
    path.join(macos, 'clash-verge'),
    Buffer.concat([Buffer.from('cffaedfe0c000001', 'hex'), Buffer.alloc(32)]),
    { mode: 0o755 },
  )
  fs.writeFileSync(
    path.join(resources, 'fixture.txt'),
    Buffer.from('external-peer-app-fixture\n', 'utf8'),
    { mode: 0o644 },
  )
  return app
}

const appTransaction = (destinationParent, overrides = {}) => ({
  destinationParent,
  sourceBefore: () => snapshot(),
  sourceAfter: () => snapshot(),
  buildApp: ({ cargoTarget }) => {
    writeAppFixture(cargoTarget)
  },
  ...overrides,
})

test('external-peer App overlay contains no packaged networking authority', () => {
  const overlay = externalPeerAppOverlay()
  assert.deepEqual(overlay.bundle.externalBin, [])
  assert.deepEqual(overlay.bundle.resources, [])
  assert.deepEqual(overlay.bundle.macOS.files, {})
  assert.equal(overlay.bundle.macOS.signingIdentity, null)
  assert.equal(overlay.bundle.createUpdaterArtifacts, false)
})

test('external-peer App build environment selects only its lab UI', () => {
  const environment = externalPeerAppEnvironment(
    {
      PATH: '/tmp/evil-bin',
      HOME: '/tmp/evil-home',
      TMPDIR: '/tmp/evil-tmp',
      LANG: 'evil',
      LC_ALL: 'evil',
      APPLE_ID: 'must-be-removed',
      TAURI_SIGNING_PRIVATE_KEY: 'must-be-removed',
      VITE_ATTACKER_VALUE: 'must-be-removed',
      VITE_NETWORKING_VM_EXTERNAL_PEER_LAB: 'false',
      NODE_OPTIONS: '--require=/tmp/evil.cjs',
      RUSTFLAGS: '-C linker=/tmp/evil-linker',
      RUSTC_WRAPPER: '/tmp/evil-wrapper',
      CARGO_HOME: '/tmp/evil-cargo',
      CARGO_TARGET_DIR: '/tmp/evil-target',
      CARGO_BUILD_RUSTC_WRAPPER: '/tmp/evil-wrapper',
      GH_TOKEN: 'must-be-removed',
      GITHUB_TOKEN: 'must-be-removed',
      AWS_SECRET_ACCESS_KEY: 'must-be-removed',
      SSH_AUTH_SOCK: '/tmp/evil-agent',
      npm_config_userconfig: '/tmp/evil-npmrc',
      UNKNOWN: 'must-be-removed',
      KEEP: 'yes',
    },
    '/fixed/cargo-target',
    {
      home: '/fixed/home',
      temporaryDirectory: '/fixed/run/tmp',
      pathEntries: [
        '/fixed/run/corepack-shim',
        '/fixed/home/.cargo/bin',
        '/fixed/node/bin',
        '/usr/bin',
        '/bin',
      ],
    },
  )
  assert.deepEqual(Object.keys(environment).sort(), [
    'CARGO_INCREMENTAL',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS',
    'CARGO_PROFILE_RELEASE_DEBUG',
    'CARGO_TARGET_DIR',
    'HOME',
    'LANG',
    'LC_ALL',
    'PATH',
    'TMPDIR',
    'VITE_NETWORKING_DEV',
    'VITE_NETWORKING_PRODUCTION',
    'VITE_NETWORKING_SYSTEM_LAB',
    'VITE_NETWORKING_VM_EXTERNAL_PEER_LAB',
    'VITE_NETWORKING_VM_NETWORK_LAB',
    'VITE_NETWORKING_VM_UTUN_LAB',
  ])
  assert.equal(environment.HOME, '/fixed/home')
  assert.equal(environment.TMPDIR, '/fixed/run/tmp')
  assert.equal(
    environment.PATH,
    [
      '/fixed/run/corepack-shim',
      '/fixed/home/.cargo/bin',
      '/fixed/node/bin',
      '/usr/bin',
      '/bin',
    ].join(path.delimiter),
  )
  assert.equal(environment.LANG, 'C')
  assert.equal(environment.LC_ALL, 'C')
  assert.equal(environment.CARGO_TARGET_DIR, '/fixed/cargo-target')
  assert.equal(environment.CARGO_INCREMENTAL, '0')
  assert.equal(environment.CARGO_PROFILE_RELEASE_DEBUG, '0')
  assert.equal(environment.CARGO_PROFILE_RELEASE_CODEGEN_UNITS, '16')
  assert.equal(environment.VITE_NETWORKING_PRODUCTION, 'false')
  assert.equal(environment.VITE_NETWORKING_VM_UTUN_LAB, 'false')
  assert.equal(environment.VITE_NETWORKING_VM_NETWORK_LAB, 'false')
  assert.equal(environment.VITE_NETWORKING_VM_EXTERNAL_PEER_LAB, 'true')
  for (const name of [
    'APPLE_ID',
    'TAURI_SIGNING_PRIVATE_KEY',
    'VITE_ATTACKER_VALUE',
    'NODE_OPTIONS',
    'RUSTFLAGS',
    'RUSTC_WRAPPER',
    'CARGO_HOME',
    'CARGO_BUILD_RUSTC_WRAPPER',
    'GH_TOKEN',
    'GITHUB_TOKEN',
    'AWS_SECRET_ACCESS_KEY',
    'SSH_AUTH_SOCK',
    'npm_config_userconfig',
    'UNKNOWN',
    'KEEP',
  ])
    assert.equal(Object.hasOwn(environment, name), false)
})

test('external-peer builder is App-only, no-sign, and argument-free', () => {
  const source = fs.readFileSync(
    path.join(root, 'scripts/build-macos-vm-external-peer-lab-app.mjs'),
    'utf8',
  )
  assert.match(source, /'--bundles',[\s\S]*'app'/u)
  assert.match(source, /'--no-sign'/u)
  assert.match(source, /process\.argv\.length !== 2/u)
  assert.match(source, /corepack, \['enable', '--install-directory'/u)
  assert.match(source, /process\.execPath/u)
  assert.match(source, /return externalPeerAppEnvironment\(\{\}, cargoTarget,/u)
  assert.doesNotMatch(source, /\{\s*\.\.\.source\s*\}/u)
  assert.doesNotMatch(source, /externalPeerAppEnvironment\(process\.env/u)
  assert.doesNotMatch(source, /\.(?:dmg|pkg)'/u)
  assert.match(source, /embedded_privileged_payloads: false/u)
})

test('App build publishes a source-bound canonical tree manifest', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-external-peer-app-success.'),
  )
  const completed = buildExternalPeerAppRun(appTransaction(parent))
  assert.equal(fs.existsSync(completed.resultPath), true)
  assert.deepEqual(completed.manifest.source, snapshot())
  assert.equal(
    completed.manifest.info_plist.bundle_identifier,
    'net.kysion.kyclash',
  )
  assert.equal(completed.manifest.info_plist.short_version, '2.5.3')
  assert.equal(
    completed.manifest.main_executable.relative_path,
    'Contents/MacOS/clash-verge',
  )
  assert.match(completed.manifest.main_executable.sha256, /^[0-9a-f]{64}$/u)
  assert.equal(
    completed.manifest.entries.some(
      (entry) =>
        entry.relative_path === 'Contents/Resources/fixture.txt' &&
        entry.type === 'file' &&
        entry.mode === '0644' &&
        entry.byte_length > 0 &&
        /^[0-9a-f]{64}$/u.test(entry.sha256),
    ),
    true,
  )
  assert.equal(
    completed.result.app_tree_manifest_sha256,
    completed.provenance.app_tree_manifest_sha256,
  )
  assert.equal(completed.result.source.tree_sha256, 'a'.repeat(64))
})

test('App source change leaves the fresh result unpublished', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-external-peer-app-source-race.'),
  )
  assert.throws(
    () =>
      buildExternalPeerAppRun(
        appTransaction(parent, {
          sourceAfter: () => snapshot('c'.repeat(64)),
        }),
      ),
    /workspace source changed/u,
  )
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), false)
})

test('App tree tamper during manifest capture is rejected', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-external-peer-app-tree-race.'),
  )
  let app
  let sourceChecks = 0
  assert.throws(
    () =>
      buildExternalPeerAppRun(
        appTransaction(parent, {
          buildApp: ({ cargoTarget }) => {
            app = writeAppFixture(cargoTarget)
          },
          sourceAfter: () => {
            sourceChecks += 1
            if (sourceChecks === 2)
              fs.appendFileSync(
                path.join(app, 'Contents', 'Resources', 'fixture.txt'),
                Buffer.from('tamper', 'utf8'),
              )
            return snapshot()
          },
        }),
      ),
    /App tree changed/u,
  )
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), false)
})

test('truncated App result temporary file is never published', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-external-peer-app-partial.'),
  )
  assert.throws(
    () =>
      buildExternalPeerAppRun(
        appTransaction(parent, {
          publicationHooks: {
            result: {
              afterTempSync: (temporaryPath) =>
                fs.truncateSync(temporaryPath, 1),
            },
          },
        }),
      ),
    /temporary file changed/u,
  )
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), true)
})

test('atomic publication never replaces an existing truncated result', () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-atomic-no-replace.'),
  )
  fs.chmodSync(directory, 0o700)
  const resultPath = path.join(directory, 'result.json')
  fs.writeFileSync(resultPath, Buffer.from('{\n', 'utf8'), {
    mode: 0o600,
  })
  assert.throws(
    () =>
      atomicPublishJSONNoReplace(directory, 'result.json', {
        status: 'complete',
      }),
    /EEXIST/u,
  )
  assert.equal(fs.readFileSync(resultPath, 'utf8'), '{\n')
})
