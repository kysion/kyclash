import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  collectReviewedBuildInputs,
  parseGeneratorOptions,
  prepareNetworkingProductionVmLab,
  signingMessage,
  validatePolicyRevisionPreflight,
} from './generate-networking-production-vm-lab.mjs'
import {
  PRODUCTION_MARKER_BYTES,
  PRODUCTION_MARKER_SECTION,
  assertProductionCompileMarker,
  inspectMachOMarkers,
} from './macos-package-verifier.mjs'
import {
  LAB_DESCRIPTOR_RESOURCE,
  LAB_MARKER_RESOURCE,
  LAB_OVERLAY_NAME,
  LAB_POLICY_RESOURCE,
  LAB_REVISION_PREFLIGHT_RESOURCE,
  LAB_TRUST_RESOURCE,
  canonicalizeMacOsAbsolutePath,
  createNetworkingProductionOverlay,
  stagePublicResources,
} from './prepare-networking-production-vm-lab.mjs'
import { sealMarkerWithFinalComponentHashes } from './seal-networking-production-vm-lab.mjs'
import {
  VERIFIER_PROFILES,
  parseVerifierOptions,
} from './verify-macos-package.mjs'

const root = path.resolve(import.meta.dirname, '..')
const guestAppDataRoot =
  '/Users/supen/Library/Application Support/net.kysion.kyclash'

test('production VM package scripts point at the reviewed executable chain', () => {
  const scripts = JSON.parse(
    fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
  ).scripts
  assert.equal(
    scripts['macos:production-vm:prepare'],
    'node scripts/generate-networking-production-vm-lab.mjs',
  )
  assert.equal(
    scripts['macos:production-vm:seal'],
    'node scripts/seal-networking-production-vm-lab.mjs',
  )
  assert.equal(
    scripts['macos:production-vm:peer'],
    'node scripts/build-networking-system-lab-peer-macos.mjs',
  )
  assert.equal(
    scripts['macos:production-vm:peer-run'],
    'node scripts/run-networking-vm-lab-peer.mjs',
  )
  assert.equal(
    scripts['macos:production-vm:copy-fixtures'],
    'node scripts/copy-networking-vm-lab-fixtures.mjs',
  )
})

test('production system-lab candidates keep the real Tauri App context', () => {
  const buildScript = fs.readFileSync(
    path.join(root, 'src-tauri', 'build.rs'),
    'utf8',
  )
  const appSource = fs.readFileSync(
    path.join(root, 'src-tauri', 'src', 'lib.rs'),
    'utf8',
  )
  const labOnlyPattern =
    /all\(\s*feature = "networking-system-lab",\s*not\(feature = "networking-production"\),\s*not\(feature = "networking-userspace-lab-app"\)\s*\)/gu
  assert.equal(buildScript.match(labOnlyPattern)?.length, 2)
  assert.equal(appSource.match(labOnlyPattern)?.length, 3)
  assert.match(buildScript, /feature = "networking-userspace-lab-app"/u)
  assert.match(appSource, /feature = "networking-userspace-lab-app"/u)
  assert.match(appSource, /builder\.build\(tauri::generate_context!\(\)\)/u)
})

test('production networking UI keeps polling connected and fallback states', () => {
  const page = fs.readFileSync(
    path.join(root, 'src', 'pages', 'networking.tsx'),
    'utf8',
  )
  assert.match(page, /'connected_primary',\s*'degraded_fallback'/u)
  assert.match(page, /pollingStates\.has\(status\.state\)/u)
  assert.match(page, /cancellableStates\.has\(status\.state\)/u)
})

test('userspace lab App is an explicit non-production resource profile', () => {
  const overlay = JSON.parse(
    fs.readFileSync(
      path.join(
        root,
        'src-tauri',
        'tauri.networking.userspace-lab.macos.conf.json',
      ),
      'utf8',
    ),
  )
  assert.equal(
    overlay.bundle.macOS.files['Resources/kyclash-network-sidecar-lab'],
    'sidecar/kyclash-network-sidecar-lab-aarch64-apple-darwin',
  )
  const appPage = fs.readFileSync(
    path.join(root, 'src', 'pages', 'networking-dev.tsx'),
    'utf8',
  )
  assert.match(appPage, /LAB · userspace/u)
  assert.match(appPage, /QUIC → WSS → TCP/u)
  assert.match(appPage, /does not create utun/u)
  const rust = fs.readFileSync(
    path.join(root, 'src-tauri', 'src', 'cmd', 'networking_userspace_lab.rs'),
    'utf8',
  )
  assert.match(rust, /kyclash-network-sidecar-lab/u)
  assert.match(rust, /routes_installed: false/u)
  assert.match(rust, /SidecarRuntime as _/u)
})

test('production VM contract exposes a guest-to-host public pull only', () => {
  const copier = fs.readFileSync(
    path.join(root, 'scripts', 'copy-networking-vm-lab-fixtures.mjs'),
    'utf8',
  )
  assert.match(copier, /--pull-run/u)
  assert.match(copier, /--output-root/u)
  assert.match(copier, /GUEST_RUN_ROOT/u)
  assert.match(copier, /guest-descriptor\.json/u)
  assert.match(copier, /policy-revision-preflight\.json/u)
  assert.match(copier, /policy-expiry-ceiling-epoch\.txt/u)
  assert.match(copier, /StrictHostKeyChecking=yes/u)
  assert.match(copier, /BatchMode=yes/u)
  assert.match(copier, /VirtualMac\*/u)
  assert.match(copier, /validatePolicyRevisionPreflight/u)
  assert.match(copier, /validateDescriptor/u)
  assert.doesNotMatch(copier, /scp[^\n]*(?:loopback|private-key|Keychain)/iu)
})

const writePolicyRevisionPreflight = (
  directory,
  { runId = '0123456789abcdef', revision = 42, checkedAt = 1_800_000_000 } = {},
) => {
  const filePath = path.join(directory, LAB_REVISION_PREFLIGHT_RESOURCE)
  const value = {
    schema_version: 1,
    run_id: runId,
    candidate_revision: revision,
    record_state: 'absent',
    record_revision: 0,
    record_key_id: null,
    record_envelope_sha256: null,
    app_data_root: guestAppDataRoot,
    app_data_root_sha256: crypto
      .createHash('sha256')
      .update(guestAppDataRoot)
      .digest('hex'),
    checked_at: checkedAt,
    decision: 'new',
  }
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 })
  return filePath
}

const writeName = (bytes, offset, name, width = 16) => {
  const value = Buffer.from(name, 'ascii')
  value.copy(bytes, offset, 0, Math.min(width - 1, value.length))
}

const thinMachO = ({
  cpuType = 0x0100000c,
  marker = null,
  markerSection = PRODUCTION_MARKER_SECTION,
  markerCount = marker === null ? 0 : 1,
  segmentName = '__TEXT',
  sectionSegmentName = '__TEXT',
  sectionFlags = 0,
  relocationCount = 0,
  segmentFileSize,
  segmentVirtualSize,
  sectionFileOffset = 256,
  sectionAddress = 256,
  sectionSize = 16,
  namePaddingByte,
  segmentNamePaddingByte,
} = {}) => {
  const hasMarker = markerCount > 0
  const commandSize = 72 + (hasMarker ? markerCount * 80 : 0)
  const markerOffset = 256
  const totalSize = hasMarker
    ? Math.max(
        markerOffset + markerCount * sectionSize,
        sectionFileOffset + sectionSize,
      )
    : 256
  const bytes = Buffer.alloc(totalSize)
  bytes.writeUInt32LE(0xfeedfacf, 0)
  bytes.writeUInt32LE(cpuType, 4)
  bytes.writeUInt32LE(0, 8)
  bytes.writeUInt32LE(2, 12)
  bytes.writeUInt32LE(1, 16)
  bytes.writeUInt32LE(commandSize, 20)
  bytes.writeUInt32LE(0, 24)
  bytes.writeUInt32LE(0, 28)
  const command = 32
  bytes.writeUInt32LE(0x19, command)
  bytes.writeUInt32LE(commandSize, command + 4)
  writeName(bytes, command + 8, segmentName)
  if (segmentNamePaddingByte !== undefined)
    bytes[command + 8 + Buffer.byteLength(segmentName, 'ascii') + 1] =
      segmentNamePaddingByte
  bytes.writeBigUInt64LE(0n, command + 24)
  bytes.writeBigUInt64LE(BigInt(segmentVirtualSize ?? totalSize), command + 32)
  bytes.writeBigUInt64LE(0n, command + 40)
  bytes.writeBigUInt64LE(BigInt(segmentFileSize ?? totalSize), command + 48)
  bytes.writeUInt32LE(7, command + 56)
  bytes.writeUInt32LE(5, command + 60)
  bytes.writeUInt32LE(markerCount, command + 64)
  bytes.writeUInt32LE(0, command + 68)
  if (hasMarker) {
    for (let index = 0; index < markerCount; index += 1) {
      const section = command + 72 + index * 80
      writeName(bytes, section, markerSection)
      writeName(bytes, section + 16, sectionSegmentName)
      bytes.writeBigUInt64LE(
        BigInt(sectionAddress + index * sectionSize),
        section + 32,
      )
      bytes.writeBigUInt64LE(BigInt(sectionSize), section + 40)
      bytes.writeUInt32LE(sectionFileOffset + index * sectionSize, section + 48)
      bytes.writeUInt32LE(relocationCount, section + 60)
      bytes.writeUInt32LE(sectionFlags, section + 64)
      Buffer.from(marker).copy(
        bytes,
        sectionFileOffset + index * sectionSize,
        0,
        Math.min(sectionSize, marker.length),
      )
      if (namePaddingByte !== undefined)
        bytes[section + Buffer.byteLength(markerSection, 'ascii') + 1] =
          namePaddingByte
    }
  }
  return bytes
}

const fatMachO = (slices) => {
  const headerSize = 8 + slices.length * 20
  let offset = headerSize
  const entries = []
  for (const slice of slices) {
    offset = (offset + 0x3f) & ~0x3f
    entries.push({ offset, bytes: slice })
    offset += slice.length
  }
  const bytes = Buffer.alloc(offset)
  bytes.writeUInt32BE(0xcafebabe, 0)
  bytes.writeUInt32BE(slices.length, 4)
  for (let index = 0; index < slices.length; index += 1) {
    const entry = entries[index]
    const slice = slices[index]
    const entryOffset = 8 + index * 20
    const cpuType = slice.readUInt32LE(4)
    const cpuSubtype = slice.readUInt32LE(8)
    bytes.writeUInt32BE(cpuType, entryOffset)
    bytes.writeUInt32BE(cpuSubtype, entryOffset + 4)
    bytes.writeUInt32BE(entry.offset, entryOffset + 8)
    bytes.writeUInt32BE(slice.length, entryOffset + 12)
    bytes.writeUInt32BE(2, entryOffset + 16)
    slice.copy(bytes, entry.offset)
  }
  return bytes
}

test('parses an exact arm64 production marker structurally', () => {
  const binary = thinMachO({ marker: PRODUCTION_MARKER_BYTES })
  const inspection = inspectMachOMarkers(binary, { targetArch: 'arm64' })
  assert.equal(inspection.selectedMarkers.length, 1)
  assert.equal(inspection.selectedMarkers[0].valid, true)
  assert.doesNotThrow(() =>
    assertProductionCompileMarker(binary, {
      profile: 'networking-production-vm-lab',
      targetArch: 'arm64',
    }),
  )
  assert.throws(
    () =>
      assertProductionCompileMarker(binary, {
        profile: 'release-default',
        targetArch: 'arm64',
      }),
    /release-default/u,
  )
})

test('keeps package verifier profiles closed and explicit', () => {
  assert.deepEqual(
    [...VERIFIER_PROFILES],
    ['release-default', 'networking-production-vm-lab'],
  )
  assert.deepEqual(parseVerifierOptions(['aarch64-apple-darwin']), {
    target: 'aarch64-apple-darwin',
    profile: 'release-default',
    labPublicRoot: undefined,
    resultOutput: undefined,
  })
  assert.deepEqual(
    parseVerifierOptions([
      '--profile',
      'networking-production-vm-lab',
      'aarch64-apple-darwin',
      '--lab-public-root',
      '/private/tmp/kyclash-lab/public',
    ]),
    {
      target: 'aarch64-apple-darwin',
      profile: 'networking-production-vm-lab',
      labPublicRoot: '/private/tmp/kyclash-lab/public',
      resultOutput: undefined,
    },
  )
  assert.throws(
    () => parseVerifierOptions(['--profile', 'networking-production-vm-lab']),
    /absolute --lab-public-root/u,
  )
  assert.throws(
    () =>
      parseVerifierOptions([
        '--profile',
        'release-default',
        '--lab-public-root',
        '/tmp/lab',
      ]),
    /only valid/u,
  )
})

test('rejects wrong marker bytes, duplicate sections, and hidden fat slices', () => {
  const wrong = thinMachO({ marker: Buffer.from('KYCLASH-PROD-V0\0', 'ascii') })
  assert.throws(
    () =>
      assertProductionCompileMarker(wrong, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /marker bytes/u,
  )
  const duplicate = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    markerCount: 2,
  })
  assert.throws(
    () =>
      assertProductionCompileMarker(duplicate, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /exactly one/u,
  )
  const hidden = fatMachO([
    thinMachO({ cpuType: 0x0100000c }),
    thinMachO({ cpuType: 0x01000007, marker: PRODUCTION_MARKER_BYTES }),
  ])
  assert.throws(
    () =>
      assertProductionCompileMarker(hidden, {
        profile: 'release-default',
        targetArch: 'arm64',
      }),
    /release-default/u,
  )
  assert.throws(
    () =>
      assertProductionCompileMarker(hidden, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /exactly one/u,
  )
  const malformed = thinMachO()
  malformed.writeUInt32LE(0xffffffff, 16)
  assert.throws(
    () => inspectMachOMarkers(malformed, { targetArch: 'arm64' }),
    /too many load commands/u,
  )
})

test('rejects forged marker section ranges, names, flags, and non-arm64 slices', () => {
  const outsideFile = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    segmentFileSize: 240,
  })
  assert.throws(
    () =>
      assertProductionCompileMarker(outsideFile, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /outside its containing range/u,
  )
  const outsideVirtual = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    segmentVirtualSize: 16,
  })
  assert.throws(
    () => inspectMachOMarkers(outsideVirtual, { targetArch: 'arm64' }),
    /virtual range/u,
  )
  const sectionNameMismatch = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    sectionSegmentName: '__DATA',
  })
  assert.throws(
    () => inspectMachOMarkers(sectionNameMismatch, { targetArch: 'arm64' }),
    /does not match/u,
  )
  const sectionPadding = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    markerSection: 'x',
    namePaddingByte: 0x41,
  })
  assert.throws(
    () => inspectMachOMarkers(sectionPadding, { targetArch: 'arm64' }),
    /non-NUL name padding/u,
  )
  const segmentPadding = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    segmentName: 'X',
    segmentNamePaddingByte: 0x41,
  })
  assert.throws(
    () => inspectMachOMarkers(segmentPadding, { targetArch: 'arm64' }),
    /non-NUL name padding/u,
  )
  const zerofill = thinMachO({
    marker: PRODUCTION_MARKER_BYTES,
    sectionFlags: 1,
  })
  assert.throws(
    () =>
      assertProductionCompileMarker(zerofill, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /marker bytes/u,
  )
  const fatWithArmMarker = fatMachO([
    thinMachO({ marker: PRODUCTION_MARKER_BYTES }),
    thinMachO({ cpuType: 0x01000007 }),
  ])
  assert.throws(
    () =>
      assertProductionCompileMarker(fatWithArmMarker, {
        profile: 'networking-production-vm-lab',
        targetArch: 'arm64',
      }),
    /arm64-only/u,
  )
})

test('stages ordinary resources and emits an absolute, closed overlay', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-contract-'),
  )
  try {
    const source = path.join(directory, 'ordinary')
    const staged = path.join(directory, 'public', 'resources')
    const output = path.join(
      directory,
      'public',
      'tauri.networking-production-vm-lab.macos.conf.json',
    )
    fs.mkdirSync(source, { recursive: true })
    fs.writeFileSync(path.join(source, 'ordinary.txt'), 'ordinary\n', {
      mode: 0o644,
    })
    const lab = path.join(directory, 'lab')
    fs.mkdirSync(lab)
    for (const name of [
      LAB_MARKER_RESOURCE,
      LAB_POLICY_RESOURCE,
      LAB_TRUST_RESOURCE,
    ]) {
      fs.writeFileSync(path.join(lab, name), '{}\n', { mode: 0o644 })
    }
    const stagedResult = stagePublicResources({
      sourceRoot: source,
      stagedResources: staged,
      ordinaryAllowlist: ['ordinary.txt'],
      labFiles: Object.fromEntries(
        [LAB_MARKER_RESOURCE, LAB_POLICY_RESOURCE, LAB_TRUST_RESOURCE].map(
          (name) => [name, path.join(lab, name)],
        ),
      ),
    })
    assert.deepEqual(
      stagedResult.files.sort(),
      [
        'ordinary.txt',
        LAB_MARKER_RESOURCE,
        LAB_POLICY_RESOURCE,
        LAB_TRUST_RESOURCE,
      ].sort(),
    )
    const result = createNetworkingProductionOverlay({
      stagedResources: staged,
      baseConfig: path.join(
        root,
        'src-tauri',
        'tauri.networking.macos.conf.json',
      ),
      output,
    })
    const overlay = JSON.parse(fs.readFileSync(result.output, 'utf8'))
    assert.deepEqual(overlay.bundle.resources, {
      [path.resolve(staged)]: 'resources',
    })
    assert.deepEqual(overlay.bundle.macOS.files, {
      'Resources/kyclash-network-sidecar':
        'sidecar/kyclash-network-sidecar-aarch64-apple-darwin',
      'Resources/kyclash-route-helper': 'helpers/kyclash-route-helper',
      'Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist':
        '../macos/route-helper/net.kysion.kyclash.route-helper.plist',
    })
    assert.deepEqual(overlay.bundle.externalBin, [
      'sidecar/verge-mihomo',
      'sidecar/verge-mihomo-alpha',
    ])
    assert.equal(fs.statSync(output).mode & 0o777, 0o600)
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('overlay preparation refuses symlinked resources and descriptor staging', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-contract-'),
  )
  try {
    const source = path.join(directory, 'ordinary')
    fs.mkdirSync(source, { recursive: true })
    fs.writeFileSync(path.join(source, 'ordinary.txt'), 'ordinary\n')
    const staged = path.join(directory, 'staged')
    const external = path.join(directory, 'external.txt')
    fs.writeFileSync(external, 'external\n')
    fs.symlinkSync(external, path.join(source, 'link'))
    assert.throws(
      () =>
        stagePublicResources({
          sourceRoot: source,
          stagedResources: staged,
          ordinaryAllowlist: ['ordinary.txt'],
        }),
      /symlink/u,
    )

    fs.rmSync(path.join(source, 'link'))
    const descriptor = path.join(directory, 'guest-descriptor.json')
    fs.writeFileSync(descriptor, '{}\n')
    assert.throws(
      () =>
        stagePublicResources({
          sourceRoot: source,
          stagedResources: staged,
          ordinaryAllowlist: ['ordinary.txt'],
          labFiles: { 'guest-descriptor.json': descriptor },
        }),
      /unsupported lab resource/u,
    )
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('canonicalizes only the documented macOS /var aliases', () => {
  assert.equal(
    canonicalizeMacOsAbsolutePath('/var/tmp/kyclash/run', 'darwin'),
    '/private/var/tmp/kyclash/run',
  )
  assert.equal(
    canonicalizeMacOsAbsolutePath('/tmp/kyclash/run', 'darwin'),
    '/private/tmp/kyclash/run',
  )
  assert.equal(
    canonicalizeMacOsAbsolutePath('/var/tmp/kyclash/run', 'linux'),
    '/var/tmp/kyclash/run',
  )
})

test('secret scanning cannot be bypassed with JSON quoting, NULs, or size', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-secret-scan-'),
  )
  try {
    const source = path.join(directory, 'ordinary')
    fs.mkdirSync(source, { recursive: true })
    const staged = path.join(directory, 'staged')
    const escapedJson = Buffer.from('{"private\\u005fkey":"hidden"}\n')
    fs.writeFileSync(path.join(source, 'ordinary.txt'), escapedJson, {
      mode: 0o644,
    })
    assert.throws(
      () =>
        stagePublicResources({
          sourceRoot: source,
          stagedResources: staged,
          ordinaryAllowlist: ['ordinary.txt'],
        }),
      /prohibited private material/u,
    )
    fs.rmSync(staged, { recursive: true, force: true })
    const largeNulPem = Buffer.concat([
      Buffer.alloc(300 * 1024, 0),
      Buffer.from(
        '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n',
      ),
    ])
    fs.writeFileSync(path.join(source, 'ordinary.txt'), largeNulPem, {
      mode: 0o644,
    })
    assert.throws(
      () =>
        stagePublicResources({
          sourceRoot: source,
          stagedResources: staged,
          ordinaryAllowlist: ['ordinary.txt'],
        }),
      /prohibited private material/u,
    )
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('descriptor validation is side-effect free and rejects non-canonical key bytes', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-descriptor-'),
  )
  try {
    const descriptorPath = path.join(directory, 'guest-descriptor.json')
    const policyRevisionPreflightPath = writePolicyRevisionPreflight(directory)
    const base = {
      schema_version: 1,
      run_id: '0123456789abcdef',
      peer_public_key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      client_public_key: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
      endpoints: [
        { transport: 'quic', url: 'https://127.0.0.1:20001' },
        { transport: 'wss', url: 'wss://127.0.0.1:20002/kynp' },
        { transport: 'tcp', url: 'tcp://127.0.0.1:20003' },
      ],
      echo_addresses: ['10.88.0.2:8080', '[fd00:88::2]:8080'],
      certificate_sha256: 'a'.repeat(64),
      certificate_path:
        '/private/var/tmp/kyclash-networking-vm-lab/0123456789abcdef/loopback-leaf.pem',
      expires_at: 1_800_003_600,
    }
    const nonCanonical = {
      ...base,
      // The final base64 sextet has non-zero unused low bits. Node's decoder
      // accepts it, but the strict contract must reject it.
      peer_public_key: `${base.peer_public_key.slice(0, -2)}F=`,
    }
    fs.writeFileSync(descriptorPath, `${JSON.stringify(nonCanonical)}\n`, {
      mode: 0o644,
    })
    const runRoot = path.join(directory, 'run')
    assert.throws(
      () =>
        prepareNetworkingProductionVmLab({
          descriptorPath,
          policyRevisionPreflightPath,
          runRoot,
          now: 1_800_000_000,
          policyExpiryCeiling: 1_800_004_000,
          requireClean: false,
        }),
      /identity fields/u,
    )
    assert.equal(fs.existsSync(runRoot), false)
    fs.writeFileSync(descriptorPath, `${JSON.stringify(base)}\n`, {
      mode: 0o644,
    })
    const inputs = collectReviewedBuildInputs({
      sourceRoot: path.join(root, 'src-tauri/resources'),
      baseConfig: path.join(root, 'src-tauri/tauri.networking.macos.conf.json'),
      target: 'aarch64-apple-darwin',
    })
    assert.deepEqual(Object.keys(inputs.marker).sort(), [
      'mihomo_alpha_sha256',
      'mihomo_sha256',
      'network_sidecar_sha256',
      'ordinary_resources_inventory_sha256',
      'route_helper_plist_sha256',
      'route_helper_sha256',
    ])
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('full preparation CLI has a stable no-stack failure and policy signer is isolated', () => {
  const invalid = spawnSync(
    process.execPath,
    [
      path.join(root, 'scripts/generate-networking-production-vm-lab.mjs'),
      '--descriptor',
      '/private/tmp/nonexistent/guest-descriptor.json',
      '--policy-revision-preflight',
      '/private/tmp/nonexistent/policy-revision-preflight.json',
      '--run-root',
      '/private/tmp/nonexistent/run',
      '--target',
      'x86_64-apple-darwin',
      '--revision',
      '42',
      '--policy-expiry-ceiling',
      '1800004000',
    ],
    {
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        SECRET_SENTINEL: 'nope',
      },
      encoding: 'utf8',
    },
  )
  assert.notEqual(invalid.status, 0)
  assert.equal(
    invalid.stderr,
    'networking-production-vm-lab requires aarch64-apple-darwin\n',
  )
  assert.equal(invalid.stderr.includes('at '), false)
  assert.equal(invalid.stdout.includes('SECRET_SENTINEL'), false)

  const signer = spawnSync(
    process.execPath,
    [
      path.join(root, 'scripts/generate-networking-production-vm-lab.mjs'),
      '--policy-signer-child',
    ],
    {
      input: JSON.stringify({
        key_id: 'lab.vm.0123456789abcdef',
        algorithm: 'ed25519',
        payload_base64: Buffer.from('{}').toString('base64'),
      }),
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        SECRET_SENTINEL: 'nope',
      },
      encoding: 'utf8',
    },
  )
  assert.equal(signer.status, 0)
  assert.equal(signer.stderr, '')
  const signerOutput = JSON.parse(signer.stdout)
  assert.deepEqual(Object.keys(signerOutput).sort(), [
    'public_key_base64',
    'signature_base64',
  ])
  assert.equal(signer.stdout.includes('PRIVATE'), false)
  const failedSigner = spawnSync(
    process.execPath,
    [
      path.join(root, 'scripts/generate-networking-production-vm-lab.mjs'),
      '--policy-signer-child',
    ],
    { input: '{}', encoding: 'utf8' },
  )
  assert.notEqual(failedSigner.status, 0)
  assert.equal(failedSigner.stderr, 'policy signer child refused\n')
  assert.equal(failedSigner.stderr.includes('at '), false)
})

test('generator CLI rejects unknown, duplicate, and noncanonical values', () => {
  const valid = [
    '--descriptor',
    '/private/tmp/guest-descriptor.json',
    '--policy-revision-preflight',
    '/private/tmp/policy-revision-preflight.json',
    '--run-root',
    '/private/tmp/candidate',
    '--revision',
    '42',
    '--policy-expiry-ceiling',
    '1800004000',
  ]
  assert.deepEqual(parseGeneratorOptions(valid), {
    descriptorPath: '/private/tmp/guest-descriptor.json',
    policyRevisionPreflightPath: '/private/tmp/policy-revision-preflight.json',
    runRoot: '/private/tmp/candidate',
    target: 'aarch64-apple-darwin',
    revision: 42,
    policyExpiryCeiling: 1_800_004_000,
  })
  assert.throws(
    () => parseGeneratorOptions([...valid, '--bogus', 'value']),
    /unknown generator option/u,
  )
  assert.throws(
    () => parseGeneratorOptions([...valid, '--revision', '43']),
    /duplicate generator option/u,
  )
  for (const value of ['0', '01', '1e3', '0x2a', '9007199254740992']) {
    const invalid = [...valid]
    invalid[invalid.indexOf('--revision') + 1] = value
    assert.throws(
      () => parseGeneratorOptions(invalid),
      /canonical positive decimal/u,
    )
  }
  assert.throws(
    () => parseGeneratorOptions(valid.slice(0, -1)),
    /exact name\/value pairs/u,
  )
})

test('generates a run-bound signed policy without serializing a private key', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-generator-'),
  )
  try {
    const descriptorPath = path.join(directory, 'guest-descriptor.json')
    const runId = '0123456789abcdef'
    const policyRevisionPreflightPath = writePolicyRevisionPreflight(
      directory,
      { runId, revision: 42 },
    )
    const descriptor = {
      schema_version: 1,
      run_id: runId,
      peer_public_key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      client_public_key: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
      endpoints: [
        { transport: 'quic', url: 'https://127.0.0.1:20001' },
        { transport: 'wss', url: 'wss://127.0.0.1:20002/kynp' },
        { transport: 'tcp', url: 'tcp://127.0.0.1:20003' },
      ],
      echo_addresses: ['10.88.0.2:8080', '[fd00:88::2]:8080'],
      certificate_sha256: 'a'.repeat(64),
      certificate_path:
        '/private/var/tmp/kyclash-networking-vm-lab/0123456789abcdef/loopback-leaf.pem',
      expires_at: 1_800_003_600,
    }
    fs.writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`, {
      mode: 0o644,
    })
    const result = prepareNetworkingProductionVmLab({
      runRoot: path.join(directory, 'run'),
      descriptorPath,
      policyRevisionPreflightPath,
      now: 1_800_000_000,
      revision: 42,
      policyExpiryCeiling: 1_800_003_900,
      requireClean: false,
    })
    const policy = JSON.parse(fs.readFileSync(result.policyPath, 'utf8'))
    const trust = JSON.parse(fs.readFileSync(result.trustPath, 'utf8'))
    const marker = JSON.parse(
      fs.readFileSync(
        path.join(result.publicRoot, LAB_MARKER_RESOURCE),
        'utf8',
      ),
    )
    const payloadBytes = Buffer.from(policy.payload_base64, 'base64')
    const payload = JSON.parse(payloadBytes.toString('utf8'))
    const publicRaw = Buffer.from(trust.keys[0].public_key_base64, 'base64')
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicRaw,
      ]),
      format: 'der',
      type: 'spki',
    })
    assert.equal(
      crypto.verify(
        null,
        signingMessage(policy.key_id, policy.algorithm, payloadBytes),
        publicKey,
        Buffer.from(policy.signature_base64, 'base64'),
      ),
      true,
    )
    assert.equal(policy.key_id, `lab.vm.${runId}`)
    assert.deepEqual(payload.profile.site.private_cidrs, [
      '10.88.0.2/32',
      'fd00:88::2/128',
    ])
    assert.equal(
      payload.profile.control_plane,
      'https://127.0.0.1:20001/control',
    )
    assert.deepEqual(
      marker.build_inputs,
      collectReviewedBuildInputs({
        sourceRoot: path.join(root, 'src-tauri/resources'),
        baseConfig: path.join(
          root,
          'src-tauri/tauri.networking.macos.conf.json',
        ),
        target: 'aarch64-apple-darwin',
      }).marker,
    )
    assert.equal(
      JSON.parse(
        fs.readFileSync(
          path.join(result.publicRoot, LAB_MARKER_RESOURCE),
          'utf8',
        ),
      ).policy_revision,
      42,
    )
    assert.equal(
      JSON.parse(
        fs.readFileSync(
          path.join(result.publicRoot, LAB_MARKER_RESOURCE),
          'utf8',
        ),
      ).policy_expiry_ceiling_epoch,
      1_800_003_900,
    )
    assert.equal(marker.mihomo_final_sha256, '0'.repeat(64))
    assert.equal(marker.mihomo_alpha_final_sha256, '0'.repeat(64))
    assert.equal(
      marker.policy_revision_preflight_sha256,
      crypto
        .createHash('sha256')
        .update(fs.readFileSync(result.policyRevisionPreflightPath))
        .digest('hex'),
    )
    assert.equal(
      fs.existsSync(path.join(result.publicRoot, 'private.key')),
      false,
    )
    assert.deepEqual(
      fs.readdirSync(result.publicRoot).sort(),
      [
        LAB_DESCRIPTOR_RESOURCE,
        LAB_MARKER_RESOURCE,
        LAB_OVERLAY_NAME,
        LAB_POLICY_RESOURCE,
        LAB_REVISION_PREFLIGHT_RESOURCE,
        LAB_TRUST_RESOURCE,
        'resources',
      ].sort(),
    )
    assert.throws(
      () =>
        prepareNetworkingProductionVmLab({
          runRoot: path.join(directory, 'external-run'),
          descriptorPath,
          policyRevisionPreflightPath,
          sourceRoot: directory,
          now: 1_800_000_000,
          revision: 42,
          policyExpiryCeiling: 1_800_003_900,
          requireClean: false,
        }),
      /reviewed repository root/u,
    )
    assert.equal(fs.existsSync(path.join(directory, 'external-run')), false)
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('preparation binds descriptor expiry to the explicit guest ceiling', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-expiry-'),
  )
  try {
    const descriptorPath = path.join(directory, 'guest-descriptor.json')
    const policyRevisionPreflightPath = writePolicyRevisionPreflight(
      directory,
      { revision: 1_800_000_000 },
    )
    const descriptor = {
      schema_version: 1,
      run_id: '0123456789abcdef',
      peer_public_key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      client_public_key: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
      endpoints: [
        { transport: 'quic', url: 'https://127.0.0.1:20001' },
        { transport: 'wss', url: 'wss://127.0.0.1:20002/kynp' },
        { transport: 'tcp', url: 'tcp://127.0.0.1:20003' },
      ],
      echo_addresses: ['10.88.0.2:8080', '[fd00:88::2]:8080'],
      certificate_sha256: 'a'.repeat(64),
      certificate_path:
        '/private/var/tmp/kyclash-networking-vm-lab/0123456789abcdef/loopback-leaf.pem',
      expires_at: 1_800_003_600,
    }
    fs.writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`, {
      mode: 0o644,
    })
    const runRoot = path.join(directory, 'run')
    assert.throws(
      () =>
        prepareNetworkingProductionVmLab({
          descriptorPath,
          policyRevisionPreflightPath,
          runRoot,
          now: 1_800_000_000,
          policyExpiryCeiling: 1_800_003_599,
          requireClean: false,
        }),
      /descriptor expiry exceeds the guest policy expiry ceiling/u,
    )
    assert.equal(fs.existsSync(runRoot), false)
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('policy revision preflight is run-bound, fresh, and clean-VM-only', () => {
  const base = {
    schema_version: 1,
    run_id: '0123456789abcdef',
    candidate_revision: 42,
    record_state: 'absent',
    record_revision: 0,
    record_key_id: null,
    record_envelope_sha256: null,
    app_data_root: guestAppDataRoot,
    app_data_root_sha256: crypto
      .createHash('sha256')
      .update(guestAppDataRoot)
      .digest('hex'),
    checked_at: 1_800_000_000,
    decision: 'new',
  }
  assert.equal(
    validatePolicyRevisionPreflight({
      preflight: base,
      runId: base.run_id,
      revision: 42,
      now: 1_800_000_010,
    }),
    'new',
  )
  const advance = {
    ...base,
    record_state: 'present',
    record_revision: 41,
    record_key_id: `lab.vm.${base.run_id}`,
    record_envelope_sha256: 'a'.repeat(64),
    decision: 'advance',
  }
  for (const invalid of [
    { ...base, run_id: 'fedcba9876543210' },
    { ...base, checked_at: 1_799_999_000 },
    { ...base, app_data_root: '/Users/supen/../root' },
    { ...base, app_data_root_sha256: '9'.repeat(64) },
    advance,
  ]) {
    assert.throws(
      () =>
        validatePolicyRevisionPreflight({
          preflight: invalid,
          runId: base.run_id,
          revision: 42,
          now: 1_800_000_010,
        }),
      /policy revision preflight/u,
    )
  }
})

test('descriptor certificate path is bound to the exact guest run root', () => {
  const directory = fs.mkdtempSync(
    path.join(root, 'target', 'networking-production-cert-path-'),
  )
  try {
    const descriptorPath = path.join(directory, 'guest-descriptor.json')
    const policyRevisionPreflightPath = writePolicyRevisionPreflight(
      directory,
      { revision: 1_800_000_000 },
    )
    const descriptor = {
      schema_version: 1,
      run_id: '0123456789abcdef',
      peer_public_key: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
      client_public_key: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
      endpoints: [
        { transport: 'quic', url: 'https://127.0.0.1:20001' },
        { transport: 'wss', url: 'wss://127.0.0.1:20002/kynp' },
        { transport: 'tcp', url: 'tcp://127.0.0.1:20003' },
      ],
      echo_addresses: ['10.88.0.2:8080', '[fd00:88::2]:8080'],
      certificate_sha256: 'a'.repeat(64),
      certificate_path: '/private/var/tmp/other-run/loopback-leaf.pem',
      expires_at: 1_800_003_600,
    }
    fs.writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`, {
      mode: 0o644,
    })
    assert.throws(
      () =>
        prepareNetworkingProductionVmLab({
          descriptorPath,
          policyRevisionPreflightPath,
          runRoot: path.join(directory, 'run'),
          now: 1_800_000_000,
          policyExpiryCeiling: 1_800_003_900,
          requireClean: false,
        }),
      /certificate path is not run-bound/u,
    )
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('post-build seal binds final Mihomo hashes to reviewed source inputs', () => {
  const sourceMihomo = '1'.repeat(64)
  const sourceMihomoAlpha = '2'.repeat(64)
  const marker = {
    build_inputs: {
      mihomo_sha256: sourceMihomo,
      mihomo_alpha_sha256: sourceMihomoAlpha,
    },
    mihomo_final_sha256: '0'.repeat(64),
    mihomo_alpha_final_sha256: '0'.repeat(64),
  }
  const sealed = sealMarkerWithFinalComponentHashes({
    marker,
    sourceMihomoSha256: sourceMihomo,
    sourceMihomoAlphaSha256: sourceMihomoAlpha,
    finalMihomoSha256: '3'.repeat(64),
    finalMihomoAlphaSha256: '4'.repeat(64),
  })
  assert.equal(sealed.mihomo_final_sha256, '3'.repeat(64))
  assert.equal(sealed.mihomo_alpha_final_sha256, '4'.repeat(64))
  assert.throws(
    () =>
      sealMarkerWithFinalComponentHashes({
        marker: sealed,
        sourceMihomoSha256: sourceMihomo,
        sourceMihomoAlphaSha256: sourceMihomoAlpha,
        finalMihomoSha256: '5'.repeat(64),
        finalMihomoAlphaSha256: '6'.repeat(64),
      }),
    /already sealed/u,
  )
})
