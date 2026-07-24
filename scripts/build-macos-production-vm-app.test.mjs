import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  collectSourceProvenance,
  createProductionVmAppOverlay,
  parseProductionVmAppOptions,
  sanitizeProductionVmAppEnvironment,
} from './build-macos-production-vm-app.mjs'

const root = path.resolve(import.meta.dirname, '..')
const fixedBuildRuntime = {
  home: '/fixed/home',
  temporaryDirectory: '/fixed/run/tmp',
  pathEntries: [
    '/fixed/run/corepack-shim',
    '/fixed/home/.cargo/bin',
    '/fixed/node/bin',
    '/usr/bin',
    '/bin',
  ],
}

test('production VM App options require explicit bounded lab inputs', () => {
  assert.deepEqual(
    parseProductionVmAppOptions([
      '--lab-public-root',
      '/private/tmp/kyclash-lab/public',
      '--sidecar',
      '/private/tmp/kyclash-lab/kyclash-network-sidecar',
      '--validate-only',
    ]),
    {
      help: false,
      validateOnly: true,
      target: 'aarch64-apple-darwin',
      labProfile: 'vm-utun',
      labPublicRoot: '/private/tmp/kyclash-lab/public',
      sidecar: '/private/tmp/kyclash-lab/kyclash-network-sidecar',
    },
  )
  assert.throws(
    () => parseProductionVmAppOptions([]),
    /missing required option/u,
  )
  assert.throws(
    () =>
      parseProductionVmAppOptions([
        '--lab-public-root',
        '/private/tmp/public',
        '--sidecar',
        '/private/tmp/sidecar',
        '--target',
        'x86_64-apple-darwin',
      ]),
    /arm64-only/u,
  )
  for (const forbidden of ['--endpoint', '--password', '--sign']) {
    assert.throws(
      () =>
        parseProductionVmAppOptions([
          '--lab-public-root',
          '/private/tmp/public',
          '--sidecar',
          '/private/tmp/sidecar',
          forbidden,
          'value',
        ]),
      /unknown option/u,
    )
  }
})

test('VM network profile selects only the private-route lab feature and UI', () => {
  const options = parseProductionVmAppOptions([
    '--lab-public-root',
    '/private/tmp/kyclash-lab/public',
    '--sidecar',
    '/private/tmp/kyclash-lab/kyclash-network-sidecar',
    '--lab-profile',
    'vm-network',
  ])
  assert.equal(options.labProfile, 'vm-network')
  const env = sanitizeProductionVmAppEnvironment(
    {},
    '/private/tmp/cargo-target',
    options.labProfile,
    fixedBuildRuntime,
  )
  assert.equal(env.VITE_NETWORKING_VM_NETWORK_LAB, 'true')
  assert.equal(env.VITE_NETWORKING_VM_EXTERNAL_PEER_LAB, 'false')
  assert.equal(env.VITE_NETWORKING_VM_UTUN_LAB, 'false')
  assert.equal(env.VITE_NETWORKING_PRODUCTION, 'false')
  assert.throws(
    () =>
      parseProductionVmAppOptions([
        '--lab-public-root',
        '/private/tmp/public',
        '--sidecar',
        '/private/tmp/sidecar',
        '--lab-profile',
        'production',
      ]),
    /lab profile/u,
  )
})

test('VM external-peer profile selects only the two-VM lab feature and UI', () => {
  const options = parseProductionVmAppOptions([
    '--lab-public-root',
    '/private/tmp/kyclash-lab/public',
    '--sidecar',
    '/private/tmp/kyclash-lab/kyclash-network-sidecar',
    '--lab-profile',
    'vm-external-peer',
  ])
  assert.equal(options.labProfile, 'vm-external-peer')
  const env = sanitizeProductionVmAppEnvironment(
    {},
    '/private/tmp/cargo-target',
    options.labProfile,
    fixedBuildRuntime,
  )
  assert.equal(env.VITE_NETWORKING_VM_EXTERNAL_PEER_LAB, 'true')
  assert.equal(env.VITE_NETWORKING_VM_NETWORK_LAB, 'false')
  assert.equal(env.VITE_NETWORKING_VM_UTUN_LAB, 'false')
  assert.equal(env.VITE_NETWORKING_PRODUCTION, 'false')
})

test('derived App overlay changes only lab-local bundle controls and sidecar source', () => {
  const reviewed = {
    $schema: 'schema.json',
    bundle: {
      externalBin: ['sidecar/verge-mihomo'],
      macOS: {
        files: {
          'Resources/kyclash-network-sidecar':
            'sidecar/kyclash-network-sidecar-aarch64-apple-darwin',
          'Resources/kyclash-route-helper': 'helpers/kyclash-route-helper',
          'Resources/kyclash-tunnel-broker': 'helpers/kyclash-tunnel-broker',
          'Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist':
            '../macos/route-helper/net.kysion.kyclash.route-helper.plist',
          'Library/LaunchDaemons/net.kysion.kyclash.tunnel-broker.plist':
            '../macos/tunnel-broker/net.kysion.kyclash.tunnel-broker.plist',
        },
        minimumSystemVersion: '13.0',
      },
      resources: {
        '/private/tmp/kyclash-lab/public/resources': 'resources',
      },
    },
  }
  const sidecar = '/private/tmp/kyclash-lab/trusted-sidecar'
  const vmUtunLabOverlay = {
    $schema: 'schema.json',
    bundle: {
      macOS: {
        minimumSystemVersion: '13.0',
      },
    },
  }
  const derived = createProductionVmAppOverlay({
    reviewedOverlay: reviewed,
    vmUtunLabOverlay,
    sidecar,
  })
  assert.equal(
    derived.bundle.macOS.files['Resources/kyclash-network-sidecar'],
    sidecar,
  )
  for (const forbidden of [
    'Resources/kyclash-route-helper',
    'Resources/kyclash-tunnel-broker',
    'Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist',
    'Library/LaunchDaemons/net.kysion.kyclash.tunnel-broker.plist',
  ])
    assert.equal(derived.bundle.macOS.files[forbidden], undefined)
  assert.deepEqual(Object.keys(derived.bundle.macOS.files), [
    'Resources/kyclash-network-sidecar',
  ])
  assert.deepEqual(derived.bundle.resources, reviewed.bundle.resources)
  assert.deepEqual(derived.bundle.externalBin, reviewed.bundle.externalBin)
  assert.equal(derived.bundle.macOS.signingIdentity, null)
  assert.equal(derived.bundle.createUpdaterArtifacts, false)
  assert.equal(derived.bundle.macOS.minimumSystemVersion, '13.0')
  assert.notDeepEqual(derived, reviewed)

  const vmNetworkDerived = createProductionVmAppOverlay({
    reviewedOverlay: reviewed,
    vmUtunLabOverlay,
    vmNetworkLabOverlay: {
      $schema: 'schema.json',
      bundle: { macOS: { minimumSystemVersion: '13.0' } },
    },
    sidecar,
    labProfile: 'vm-network',
  })
  assert.equal(vmNetworkDerived.bundle.macOS.minimumSystemVersion, '13.0')
  assert.equal(
    vmNetworkDerived.bundle.macOS.files['Resources/kyclash-network-sidecar'],
    sidecar,
  )
})

test('build child environment enables only the explicit VM utun lab UI path', () => {
  const env = sanitizeProductionVmAppEnvironment(
    {
      PATH: '/tmp/evil-bin',
      HOME: '/tmp/evil-home',
      TMPDIR: '/tmp/evil-tmp',
      LANG: 'evil',
      LC_ALL: 'evil',
      APPLE_SIGNING_IDENTITY: 'must-not-pass',
      APPLE_TEAM_ID: 'must-not-pass',
      APPLE_PASSWORD: 'must-not-pass',
      TAURI_SIGNING_PRIVATE_KEY: 'must-not-pass',
      NOTARYTOOL_PROFILE: 'must-not-pass',
      VITE_ATTACKER_VALUE: 'must-not-pass',
      VITE_NETWORKING_VM_UTUN_LAB: 'false',
      NODE_OPTIONS: '--require=/tmp/evil.cjs',
      RUSTFLAGS: '-C linker=/tmp/evil-linker',
      RUSTC_WRAPPER: '/tmp/evil-wrapper',
      CARGO_HOME: '/tmp/evil-cargo',
      CARGO_TARGET_DIR: '/tmp/evil-target',
      CARGO_BUILD_RUSTC_WRAPPER: '/tmp/evil-wrapper',
      GH_TOKEN: 'must-not-pass',
      GITHUB_TOKEN: 'must-not-pass',
      AWS_SECRET_ACCESS_KEY: 'must-not-pass',
      SSH_AUTH_SOCK: '/tmp/evil-agent',
      npm_config_userconfig: '/tmp/evil-npmrc',
      UNKNOWN: 'must-not-pass',
      KEEP: 'must-not-pass',
    },
    '/private/tmp/cargo-target',
    'vm-utun',
    fixedBuildRuntime,
  )
  assert.deepEqual(Object.keys(env).sort(), [
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
  assert.equal(env.HOME, fixedBuildRuntime.home)
  assert.equal(env.TMPDIR, fixedBuildRuntime.temporaryDirectory)
  assert.equal(env.PATH, fixedBuildRuntime.pathEntries.join(path.delimiter))
  assert.equal(env.LANG, 'C')
  assert.equal(env.LC_ALL, 'C')
  assert.equal(env.CARGO_TARGET_DIR, '/private/tmp/cargo-target')
  assert.equal(env.VITE_NETWORKING_PRODUCTION, 'false')
  assert.equal(env.VITE_NETWORKING_VM_UTUN_LAB, 'true')
  assert.equal(env.VITE_NETWORKING_VM_NETWORK_LAB, 'false')
  assert.equal(env.VITE_NETWORKING_VM_EXTERNAL_PEER_LAB, 'false')
  assert.equal(env.CARGO_INCREMENTAL, '0')
  assert.equal(env.CARGO_PROFILE_RELEASE_DEBUG, '0')
  assert.equal(env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS, '16')
  assert.equal(env.VITE_NETWORKING_SYSTEM_LAB, 'true')
  assert.equal(env.VITE_NETWORKING_DEV, 'false')
  assert.equal(env.VITE_NETWORKING_VM_UTUN_LAB, 'true')
  for (const name of [
    'APPLE_SIGNING_IDENTITY',
    'APPLE_TEAM_ID',
    'APPLE_PASSWORD',
    'TAURI_SIGNING_PRIVATE_KEY',
    'NOTARYTOOL_PROFILE',
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
    assert.equal(Object.hasOwn(env, name), false)
})

test('package entry is App-only, no-sign, default-off, and non-publishing', () => {
  const source = fs.readFileSync(
    path.join(root, 'scripts', 'build-macos-production-vm-app.mjs'),
    'utf8',
  )
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
  )
  const cargo = fs.readFileSync(
    path.join(root, 'src-tauri', 'Cargo.toml'),
    'utf8',
  )
  assert.equal(
    packageJson.scripts['macos:production-vm:app'],
    'node scripts/build-macos-production-vm-app.mjs',
  )
  assert.match(
    source,
    /'--bundles',\s*'app',\s*'--no-sign',\s*'--features',\s*appFeatures/u,
  )
  assert.match(source, /'networking-vm-utun-lab-app'/u)
  assert.match(source, /'networking-vm-network-lab-app'/u)
  assert.match(source, /'networking-vm-external-peer-lab-app'/u)
  assert.match(source, /unsigned-disposable-vm-network-lab-app/u)
  assert.match(source, /unsigned-disposable-vm-external-peer-lab-app/u)
  assert.match(
    source,
    /2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d/u,
  )
  assert.doesNotMatch(
    source,
    /networking-production,networking-vm-utun-lab-app/u,
  )
  assert.doesNotMatch(source, /KYCLASH-PROD-V1|assertProductionCompileMarker/u)
  assert.doesNotMatch(
    source,
    /designated_requirement|sidecar signature verification/u,
  )
  assert.match(source, /unsigned-disposable-vm-utun-lab-app/u)
  assert.match(source, /resource_marker_grants_production_authority:\s*false/u)
  assert.match(source, /candidate_kind !== 'networking-production-vm-lab'/u)
  assert.match(source, /vm_name !== 'kyclash-macos-lab-work'/u)
  assert.match(source, /validateLabProfile/u)
  assert.match(source, /createUpdaterArtifacts:\s*false/u)
  assert.match(source, /CARGO_INCREMENTAL:\s*'0'/u)
  assert.match(source, /CARGO_PROFILE_RELEASE_DEBUG:\s*'0'/u)
  assert.match(source, /CARGO_PROFILE_RELEASE_CODEGEN_UNITS:\s*'16'/u)
  assert.match(source, /corepack, \['enable', '--install-directory'/u)
  assert.match(
    source,
    /return sanitizeProductionVmAppEnvironment\(\{\}, cargoTarget, labProfile,/u,
  )
  assert.doesNotMatch(source, /\{\s*\.\.\.source\s*\}/u)
  assert.doesNotMatch(source, /process\.env/u)
  assert.doesNotMatch(
    source,
    /sanitizeProductionVmAppEnvironment\(\s*\{[\s\S]{0,80}\.\.\.process\.env/u,
  )
  assert.match(source, /BUILD_RUN_MARKER/u)
  assert.match(source, /pruneGeneratedBuildRuns/u)
  assert.doesNotMatch(source, /['"]--sign['"]/u)
  assert.doesNotMatch(
    source,
    /['"]\/usr\/bin\/notarytool['"]|sshpass|\bscp\b|\bssh\b/iu,
  )
  assert.doesNotMatch(source, /\b(?:curl|fetch)\s*\(/u)
  assert.match(cargo, /default = \["custom-protocol"\]/u)
  assert.doesNotMatch(
    cargo.match(/default = \[[^\]]*\]/u)?.[0] ?? '',
    /networking-production/u,
  )
})

test('build provenance fingerprints dirty source state instead of pretending HEAD is complete', () => {
  const provenance = collectSourceProvenance()
  assert.match(provenance.commit, /^[0-9a-f]{40}$/u)
  assert.equal(typeof provenance.dirty, 'boolean')
  for (const field of [
    'statusSha256',
    'stagedDiffSha256',
    'worktreeDiffSha256',
    'treeSha256',
  ])
    assert.match(provenance[field], /^[0-9a-f]{64}$/u)
})
