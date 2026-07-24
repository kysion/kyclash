import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

import {
  rejectDuplicateJsonKeys,
  signingMessage,
  validateDescriptor,
  validateLabProfile,
} from './generate-networking-production-vm-lab.mjs'
import {
  LAB_DESCRIPTOR_RESOURCE,
  LAB_MARKER_RESOURCE,
  LAB_OVERLAY_NAME,
  LAB_POLICY_RESOURCE,
  LAB_TRUST_RESOURCE,
} from './prepare-networking-production-vm-lab.mjs'

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const TARGET = 'aarch64-apple-darwin'
const APP_FEATURES = 'networking-vm-utun-lab-app'
const VM_NETWORK_APP_FEATURES = 'networking-vm-network-lab-app'
const VM_EXTERNAL_PEER_APP_FEATURES = 'networking-vm-external-peer-lab-app'
const BUILD_RUN_MARKER = '.kyclash-production-vm-app-run'
const BASE_NETWORKING_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri',
  'tauri.networking.macos.conf.json',
)
const VM_UTUN_LAB_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri',
  'tauri.networking.vm-utun-lab.macos.conf.json',
)
const VM_NETWORK_LAB_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri',
  'tauri.networking.vm-network-lab.macos.conf.json',
)
const VM_EXTERNAL_PEER_LAB_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri',
  'tauri.networking.vm-external-peer-lab.macos.conf.json',
)
const VM_NETWORK_MIHOMO_CONFIG = path.join(
  PROJECT_ROOT,
  'macos',
  'route-helper',
  'vm-network-lab-mihomo-config.json',
)
const VM_EXTERNAL_PEER_MIHOMO_CONFIG = path.join(
  PROJECT_ROOT,
  'macos',
  'route-helper',
  'vm-external-peer-lab-mihomo-config.json',
)
const SIDECAR_BUNDLE_DESTINATION = 'Resources/kyclash-network-sidecar'
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const HEX16 = /^[0-9a-f]{16}$/u
const HEX40 = /^[0-9a-f]{40}$/u
const HEX64 = /^[0-9a-f]{64}$/u
const VM_NETWORK_MIHOMO_CONFIG_SHA256 =
  '2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d'
const VM_EXTERNAL_PEER_MIHOMO_CONFIG_SHA256 =
  'ff45607149b2afd7bc704cde7fbf4814382cf93b42a960f4760ff9850b09b3a3'

const usage = () =>
  [
    'usage:',
    '  build-macos-production-vm-app.mjs --lab-public-root <absolute-public-root> --sidecar <absolute-lab-sidecar> [--lab-profile vm-utun|vm-network|vm-external-peer] [--target aarch64-apple-darwin] [--validate-only]',
    '',
    'Builds only an unsigned arm64 KyClash.app for the disposable VM lab.',
    'It never signs, notarizes, packages, publishes, connects to a VM, or accepts credentials/endpoints.',
  ].join('\n')

const fail = (message) => {
  throw new Error(message)
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be an object`)
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  )
    fail(`${label} has unexpected fields`)
}

const assertNoSymlinkComponents = (filePath, label) => {
  if (!path.isAbsolute(filePath)) fail(`${label} must be an absolute path`)
  const normalized = path.normalize(filePath)
  const parsed = path.parse(normalized)
  let current = parsed.root
  for (const component of normalized
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, component)
    let stat
    try {
      stat = fs.lstatSync(current)
    } catch (error) {
      fail(
        `${label} is missing: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
    if (stat.isSymbolicLink()) fail(`${label} contains a symlink component`)
  }
  return normalized
}

const requireDirectory = (directory, label) => {
  const absolute = assertNoSymlinkComponents(directory, label)
  const stat = fs.lstatSync(absolute)
  if (!stat.isDirectory()) fail(`${label} must be a directory`)
  if ((stat.mode & 0o022) !== 0)
    fail(`${label} must not be group/other writable`)
  return absolute
}

const readRegularNoFollow = (filePath, label, maximum = 128 * 1024) => {
  const absolute = assertNoSymlinkComponents(filePath, label)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let descriptor
  try {
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | noFollow)
    const before = fs.fstatSync(descriptor)
    const named = fs.lstatSync(absolute)
    if (
      !before.isFile() ||
      named.isSymbolicLink() ||
      before.dev !== named.dev ||
      before.ino !== named.ino ||
      before.size < 1 ||
      before.size > maximum ||
      (before.mode & 0o022) !== 0
    )
      fail(`${label} is not a bounded read-only regular file`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor)
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      bytes.length !== after.size
    )
      fail(`${label} changed while reading`)
    return { path: absolute, bytes, stat: after }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

const strictJsonBytes = (bytes, label) => {
  const text = bytes.toString('utf8')
  rejectDuplicateJsonKeys(text, label)
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail(`${label} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be a JSON object`)
  return value
}

const strictJsonFile = (filePath, label, maximum) => {
  const input = readRegularNoFollow(filePath, label, maximum)
  return { ...input, value: strictJsonBytes(input.bytes, label) }
}

const canonicalBase64 = (value, expectedBytes, label) => {
  if (typeof value !== 'string') fail(`${label} must be canonical base64`)
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length !== expectedBytes || decoded.toString('base64') !== value)
    fail(`${label} must be canonical base64`)
  return decoded
}

const sameBytes = (left, right, label) => {
  if (!left.equals(right)) fail(`${label} differs from the staged resource`)
}

export const parseProductionVmAppOptions = (input) => {
  if (!Array.isArray(input)) fail('options must be an array')
  const argv = input[0] === '--' ? input.slice(1) : [...input]
  if (argv.length === 1 && argv[0] === '--help') return { help: true }
  const values = new Map()
  let validateOnly = false
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index]
    if (option === '--validate-only') {
      if (validateOnly) fail('duplicate option: --validate-only')
      validateOnly = true
      continue
    }
    if (
      option !== '--lab-public-root' &&
      option !== '--sidecar' &&
      option !== '--target' &&
      option !== '--lab-profile'
    )
      fail(`unknown option: ${option}`)
    if (values.has(option)) fail(`duplicate option: ${option}`)
    const value = argv[index + 1]
    if (!value || value.startsWith('--')) fail(`${option} requires a value`)
    values.set(option, value)
    index += 1
  }
  for (const required of ['--lab-public-root', '--sidecar'])
    if (!values.has(required)) fail(`missing required option: ${required}`)
  const target = values.get('--target') ?? TARGET
  if (target !== TARGET) fail('VM-utun lab App build is arm64-only')
  const labProfile = values.get('--lab-profile') ?? 'vm-utun'
  if (!['vm-utun', 'vm-network', 'vm-external-peer'].includes(labProfile))
    fail('lab profile must be vm-utun, vm-network, or vm-external-peer')
  for (const option of ['--lab-public-root', '--sidecar'])
    if (!path.isAbsolute(values.get(option)))
      fail(`${option} must be an absolute path`)
  return {
    help: false,
    validateOnly,
    target,
    labProfile,
    labPublicRoot: path.normalize(values.get('--lab-public-root')),
    sidecar: path.normalize(values.get('--sidecar')),
  }
}

const validateMarkerShape = (marker, now) => {
  exactKeys(
    marker,
    [
      'schema_version',
      'candidate_kind',
      'run_id',
      'source_commit',
      'target',
      'vm_name',
      'policy_key_id',
      'policy_revision',
      'issued_at',
      'expires_at',
      'policy_expiry_ceiling_epoch',
      'policy_envelope_sha256',
      'policy_trust_sha256',
      'guest_descriptor_sha256',
      'policy_revision_preflight_sha256',
      'tauri_overlay_sha256',
      'mihomo_final_sha256',
      'mihomo_alpha_final_sha256',
      'build_inputs',
    ],
    'VM-lab marker',
  )
  if (
    marker.schema_version !== 1 ||
    marker.candidate_kind !== 'networking-production-vm-lab' ||
    marker.target !== TARGET ||
    marker.vm_name !== 'kyclash-macos-lab-work' ||
    !HEX16.test(marker.run_id) ||
    !HEX40.test(marker.source_commit) ||
    marker.policy_key_id !== `lab.vm.${marker.run_id}`
  )
    fail('VM-lab marker identity is invalid')
  for (const field of [
    'policy_envelope_sha256',
    'policy_trust_sha256',
    'guest_descriptor_sha256',
    'policy_revision_preflight_sha256',
    'tauri_overlay_sha256',
    'mihomo_final_sha256',
    'mihomo_alpha_final_sha256',
  ])
    if (!HEX64.test(marker[field])) fail(`VM-lab marker ${field} is invalid`)
  for (const field of [
    'policy_revision',
    'issued_at',
    'expires_at',
    'policy_expiry_ceiling_epoch',
  ])
    if (!Number.isSafeInteger(marker[field]) || marker[field] < 1)
      fail(`VM-lab marker ${field} is invalid`)
  if (
    marker.expires_at <= marker.issued_at ||
    marker.expires_at > marker.policy_expiry_ceiling_epoch ||
    now < marker.issued_at ||
    now >= marker.expires_at
  )
    fail('VM-lab marker is expired or not yet valid')
  const requiredLabBuildInputs = [
    'ordinary_resources_inventory_sha256',
    'network_sidecar_sha256',
    'mihomo_sha256',
    'mihomo_alpha_sha256',
  ]
  const optionalReviewedBuildInputs = [
    'route_helper_sha256',
    'route_helper_plist_sha256',
    'tunnel_broker_sha256',
    'tunnel_broker_plist_sha256',
  ]
  exactKeys(
    marker.build_inputs,
    [...requiredLabBuildInputs, ...optionalReviewedBuildInputs].filter((key) =>
      Object.hasOwn(marker.build_inputs, key),
    ),
    'VM-lab marker build inputs',
  )
  if (
    requiredLabBuildInputs.some(
      (key) => !Object.hasOwn(marker.build_inputs, key),
    )
  )
    fail('VM-lab marker is missing a lab build input')
  for (const digest of Object.values(marker.build_inputs))
    if (!HEX64.test(digest)) fail('VM-lab build-input digest is invalid')
}

const verifyLabPolicy = ({ policy, trust, descriptor, marker }) => {
  exactKeys(
    policy,
    [
      'envelope_version',
      'key_id',
      'algorithm',
      'payload_base64',
      'signature_base64',
    ],
    'VM-lab policy envelope',
  )
  if (
    policy.envelope_version !== 2 ||
    policy.key_id !== marker.policy_key_id ||
    policy.algorithm !== 'ed25519'
  )
    fail('VM-lab policy envelope identity is invalid')
  exactKeys(trust, ['schema_version', 'keys'], 'VM-lab policy trust')
  if (trust.schema_version !== 1 || !Array.isArray(trust.keys))
    fail('VM-lab policy trust is invalid')
  const key = trust.keys.find(
    (candidate) => candidate?.key_id === policy.key_id,
  )
  exactKeys(key, ['key_id', 'public_key_base64'], 'VM-lab policy key')
  const publicRaw = canonicalBase64(
    key.public_key_base64,
    32,
    'VM-lab public key',
  )
  const payloadBytes = canonicalBase64(
    policy.payload_base64,
    Buffer.from(policy.payload_base64, 'base64').length,
    'VM-lab policy payload',
  )
  const signature = canonicalBase64(
    policy.signature_base64,
    64,
    'VM-lab policy signature',
  )
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicRaw]),
    format: 'der',
    type: 'spki',
  })
  if (
    !crypto.verify(
      null,
      signingMessage(policy.key_id, policy.algorithm, payloadBytes),
      publicKey,
      signature,
    )
  )
    fail('VM-lab policy signature is invalid')
  const payload = strictJsonBytes(payloadBytes, 'VM-lab policy payload')
  exactKeys(
    payload,
    ['issued_at', 'expires_at', 'revision', 'profile'],
    'VM-lab policy payload',
  )
  if (
    payload.issued_at !== marker.issued_at ||
    payload.expires_at !== marker.expires_at ||
    payload.revision !== marker.policy_revision
  )
    fail('VM-lab policy lifetime/revision does not match the marker')
  validateDescriptor(descriptor, marker.issued_at)
  if (
    descriptor.run_id !== marker.run_id ||
    descriptor.expires_at !== marker.expires_at
  )
    fail('VM-lab descriptor does not match the marker')
  validateLabProfile(payload.profile, descriptor, marker.run_id)
}

export const createProductionVmAppOverlay = ({
  reviewedOverlay,
  vmUtunLabOverlay,
  vmNetworkLabOverlay,
  vmExternalPeerLabOverlay,
  sidecar,
  labProfile = 'vm-utun',
}) => {
  if (!path.isAbsolute(sidecar)) fail('sidecar mapping must be absolute')
  const selectedOverlay = {
    'vm-utun': vmUtunLabOverlay,
    'vm-network': vmNetworkLabOverlay,
    'vm-external-peer': vmExternalPeerLabOverlay,
  }[labProfile]
  if (!selectedOverlay) fail(`missing ${labProfile} App overlay`)
  const overlayLabel = {
    'vm-utun': 'VM-utun App overlay',
    'vm-network': 'VM-network App overlay',
    'vm-external-peer': 'VM-external-peer App overlay',
  }[labProfile]
  if (!overlayLabel) fail('unknown lab profile')
  exactKeys(selectedOverlay, ['$schema', 'bundle'], overlayLabel)
  exactKeys(selectedOverlay.bundle, ['macOS'], `${overlayLabel} bundle`)
  exactKeys(
    selectedOverlay.bundle.macOS,
    ['minimumSystemVersion'],
    `${overlayLabel} macOS`,
  )
  if (selectedOverlay.bundle.macOS.minimumSystemVersion !== '13.0')
    fail(`${overlayLabel} minimum macOS version must be 13.0`)
  const files = reviewedOverlay.bundle?.macOS?.files
  if (
    !files ||
    typeof files !== 'object' ||
    Array.isArray(files) ||
    files[SIDECAR_BUNDLE_DESTINATION] === undefined
  )
    fail('reviewed overlay lost the fixed network sidecar destination')
  // Reconstruct the lab overlay from its three reviewed non-authority fields.
  // No privileged executable or launchd mapping from the compatibility input
  // can survive this allowlist.
  return {
    $schema: reviewedOverlay.$schema,
    bundle: {
      externalBin: structuredClone(reviewedOverlay.bundle.externalBin),
      macOS: {
        files: {
          [SIDECAR_BUNDLE_DESTINATION]: path.normalize(sidecar),
        },
        ...structuredClone(selectedOverlay.bundle.macOS),
        signingIdentity: null,
      },
      resources: structuredClone(reviewedOverlay.bundle.resources),
      createUpdaterArtifacts: false,
    },
  }
}

const validateCompatibilityLabOverlay = (
  overlay,
  stagedResources,
  baseConfig,
) => {
  exactKeys(overlay, ['$schema', 'bundle'], 'VM-lab compatibility overlay')
  exactKeys(
    overlay.bundle,
    ['externalBin', 'macOS', 'resources'],
    'VM-lab compatibility bundle',
  )
  exactKeys(
    overlay.bundle.macOS,
    ['files', 'minimumSystemVersion'],
    'VM-lab compatibility macOS bundle',
  )
  const resourceMappings = Object.entries(overlay.bundle.resources ?? {})
  if (
    resourceMappings.length !== 1 ||
    path.normalize(resourceMappings[0][0]) !==
      path.normalize(stagedResources) ||
    resourceMappings[0][1] !== 'resources'
  )
    fail('VM-lab compatibility overlay lost its fixed resources mapping')
  if (
    overlay.$schema !== baseConfig.$schema ||
    JSON.stringify(overlay.bundle.externalBin) !==
      JSON.stringify(baseConfig.bundle?.externalBin ?? []) ||
    overlay.bundle.macOS.minimumSystemVersion !==
      baseConfig.bundle?.macOS?.minimumSystemVersion
  )
    fail('VM-lab compatibility overlay changed a fixed non-authority field')
  const reviewedFiles = overlay.bundle.macOS.files
  const currentFiles = baseConfig.bundle?.macOS?.files
  if (
    !reviewedFiles ||
    typeof reviewedFiles !== 'object' ||
    Array.isArray(reviewedFiles) ||
    !currentFiles ||
    typeof currentFiles !== 'object' ||
    Array.isArray(currentFiles) ||
    reviewedFiles[SIDECAR_BUNDLE_DESTINATION] === undefined
  )
    fail('VM-lab compatibility overlay lost its fixed sidecar mapping')
  for (const [destination, source] of Object.entries(reviewedFiles))
    if (currentFiles[destination] !== source)
      fail('VM-lab compatibility overlay contains an unknown file mapping')
}

export const sanitizeProductionVmAppEnvironment = (
  source,
  cargoTarget,
  labProfile = 'vm-utun',
  { home, temporaryDirectory, pathEntries } = {},
) => {
  if (!['vm-utun', 'vm-network', 'vm-external-peer'].includes(labProfile))
    fail('lab profile must be vm-utun, vm-network, or vm-external-peer')
  if (
    source === null ||
    typeof source !== 'object' ||
    Array.isArray(source) ||
    !path.isAbsolute(cargoTarget) ||
    !path.isAbsolute(home ?? '') ||
    !path.isAbsolute(temporaryDirectory ?? '') ||
    !Array.isArray(pathEntries) ||
    pathEntries.length === 0 ||
    pathEntries.some(
      (entry) =>
        typeof entry !== 'string' ||
        !path.isAbsolute(entry) ||
        entry.includes(path.delimiter),
    )
  )
    fail('invalid production VM App environment boundary')
  const fixedPath = [...new Set(pathEntries)].join(path.delimiter)
  return {
    // HOME comes from the effective OS account rather than ambient HOME. It
    // exists only for the installed rustup/Corepack caches; ambient
    // CARGO_HOME and RUSTUP_HOME are never accepted.
    HOME: home,
    // TMPDIR is a fresh private directory inside the exact build run.
    TMPDIR: temporaryDirectory,
    // PATH contains only the run-private pnpm shim, verified account Cargo
    // and current Node bins, plus fixed Apple system directories.
    PATH: fixedPath,
    LANG: 'C',
    LC_ALL: 'C',
    CARGO_TARGET_DIR: cargoTarget,
    CARGO_INCREMENTAL: '0',
    CARGO_PROFILE_RELEASE_DEBUG: '0',
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS: '16',
    VITE_NETWORKING_DEV: 'false',
    VITE_NETWORKING_SYSTEM_LAB: 'true',
    VITE_NETWORKING_PRODUCTION: 'false',
    VITE_NETWORKING_VM_UTUN_LAB: labProfile === 'vm-utun' ? 'true' : 'false',
    VITE_NETWORKING_VM_NETWORK_LAB:
      labProfile === 'vm-network' ? 'true' : 'false',
    VITE_NETWORKING_VM_EXTERNAL_PEER_LAB:
      labProfile === 'vm-external-peer' ? 'true' : 'false',
  }
}

const requireBuildExecutable = (value, label) => {
  if (!path.isAbsolute(value)) fail(`${label} must be absolute`)
  let resolved
  try {
    resolved = fs.realpathSync(value)
  } catch {
    fail(`${label} is unavailable`)
  }
  const stat = fs.statSync(resolved)
  if (!stat.isFile() || (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0)
    fail(`${label} identity is unsafe`)
  return resolved
}

const requirePrivateBuildDirectory = (directory, label) => {
  const absolute = requireDirectory(directory, label)
  if ((fs.lstatSync(absolute).mode & 0o077) !== 0)
    fail(`${label} must be private`)
  return absolute
}

const prepareProductionVmAppEnvironment = ({
  buildRoot,
  cargoTarget,
  labProfile,
  corepackShim,
}) => {
  requirePrivateBuildDirectory(buildRoot, 'VM App build root')
  requirePrivateBuildDirectory(corepackShim, 'VM App Corepack shim')
  const home = requireDirectory(os.userInfo().homedir, 'effective account home')
  const temporaryDirectory = path.join(buildRoot, 'tmp')
  fs.mkdirSync(temporaryDirectory, { mode: 0o700 })
  fs.chmodSync(temporaryDirectory, 0o700)
  requirePrivateBuildDirectory(temporaryDirectory, 'VM App build temporary')

  const cargoDirectory = requireDirectory(
    path.join(home, '.cargo', 'bin'),
    'effective account Cargo bin',
  )
  requireBuildExecutable(path.join(cargoDirectory, 'cargo'), 'Cargo')
  requireBuildExecutable(path.join(cargoDirectory, 'rustc'), 'rustc')
  requireBuildExecutable(process.execPath, 'current Node executable')
  const nodeDirectory = requireDirectory(
    path.dirname(process.execPath),
    'current Node bin',
  )
  const corepack = requireBuildExecutable(
    path.join(nodeDirectory, 'corepack'),
    'Corepack',
  )
  const bootstrapEnvironment = sanitizeProductionVmAppEnvironment(
    {},
    cargoTarget,
    labProfile,
    {
      home,
      temporaryDirectory,
      pathEntries: [
        cargoDirectory,
        nodeDirectory,
        '/usr/bin',
        '/bin',
        '/usr/sbin',
        '/sbin',
      ],
    },
  )
  execFileSync(corepack, ['enable', '--install-directory', corepackShim], {
    cwd: PROJECT_ROOT,
    env: bootstrapEnvironment,
    stdio: 'ignore',
  })
  requireBuildExecutable(path.join(corepackShim, 'pnpm'), 'Corepack pnpm shim')
  return sanitizeProductionVmAppEnvironment({}, cargoTarget, labProfile, {
    home,
    temporaryDirectory,
    pathEntries: [
      corepackShim,
      cargoDirectory,
      nodeDirectory,
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
    ],
  })
}

export const validateProductionVmAppInputs = ({
  labPublicRoot,
  sidecar,
  labProfile = 'vm-utun',
  now = Math.floor(Date.now() / 1000),
}) => {
  if (!['vm-utun', 'vm-network', 'vm-external-peer'].includes(labProfile))
    fail('lab profile must be vm-utun, vm-network, or vm-external-peer')
  if (!Number.isSafeInteger(now) || now < 1)
    fail('now must be a positive epoch')
  const publicRoot = requireDirectory(labPublicRoot, 'VM-lab public root')
  const stagedResources = requireDirectory(
    path.join(publicRoot, 'resources'),
    'VM-lab staged resources',
  )
  const sidecarInput = readRegularNoFollow(
    sidecar,
    `explicit ${labProfile} lab sidecar`,
    128 * 1024 * 1024,
  )
  if ((sidecarInput.stat.mode & 0o111) === 0)
    fail(`explicit ${labProfile} lab sidecar must be executable`)

  const markerInput = strictJsonFile(
    path.join(publicRoot, LAB_MARKER_RESOURCE),
    'VM-lab marker',
    64 * 1024,
  )
  validateMarkerShape(markerInput.value, now)
  const policyInput = strictJsonFile(
    path.join(publicRoot, LAB_POLICY_RESOURCE),
    'VM-lab policy',
    64 * 1024,
  )
  const policyTrustInput = strictJsonFile(
    path.join(publicRoot, LAB_TRUST_RESOURCE),
    'VM-lab policy trust',
    64 * 1024,
  )
  const descriptorInput = strictJsonFile(
    path.join(publicRoot, LAB_DESCRIPTOR_RESOURCE),
    'VM-lab guest descriptor',
    64 * 1024,
  )
  const overlayInput = strictJsonFile(
    path.join(publicRoot, LAB_OVERLAY_NAME),
    'reviewed VM-lab Tauri overlay',
    64 * 1024,
  )
  const baseConfig = strictJsonFile(
    BASE_NETWORKING_CONFIG,
    'base networking Tauri config',
    64 * 1024,
  ).value
  const vmUtunLabOverlay = strictJsonFile(
    VM_UTUN_LAB_CONFIG,
    'VM-utun App Tauri overlay',
    64 * 1024,
  ).value
  const vmNetworkLabOverlay = strictJsonFile(
    VM_NETWORK_LAB_CONFIG,
    'VM-network App Tauri overlay',
    64 * 1024,
  ).value
  const vmExternalPeerLabOverlay = strictJsonFile(
    VM_EXTERNAL_PEER_LAB_CONFIG,
    'VM-external-peer App Tauri overlay',
    64 * 1024,
  ).value
  const mihomoConfigInput = readRegularNoFollow(
    labProfile === 'vm-external-peer'
      ? VM_EXTERNAL_PEER_MIHOMO_CONFIG
      : VM_NETWORK_MIHOMO_CONFIG,
    `fixed ${labProfile} Mihomo configuration`,
    64 * 1024,
  )
  const mihomoConfigSha256 = sha256(mihomoConfigInput.bytes)
  if (
    labProfile === 'vm-network' &&
    mihomoConfigSha256 !== VM_NETWORK_MIHOMO_CONFIG_SHA256
  )
    fail('fixed VM-network Mihomo configuration hash is invalid')
  if (
    labProfile === 'vm-external-peer' &&
    mihomoConfigSha256 !== VM_EXTERNAL_PEER_MIHOMO_CONFIG_SHA256
  )
    fail('fixed VM-external-peer Mihomo configuration hash is invalid')
  validateCompatibilityLabOverlay(
    overlayInput.value,
    stagedResources,
    baseConfig,
  )

  for (const [name, rootBytes] of [
    [LAB_MARKER_RESOURCE, markerInput.bytes],
    [LAB_POLICY_RESOURCE, policyInput.bytes],
    [LAB_TRUST_RESOURCE, policyTrustInput.bytes],
  ]) {
    const staged = readRegularNoFollow(
      path.join(stagedResources, name),
      `staged ${name}`,
      64 * 1024,
    )
    sameBytes(rootBytes, staged.bytes, name)
  }

  const marker = markerInput.value
  if (
    sha256(policyInput.bytes) !== marker.policy_envelope_sha256 ||
    sha256(policyTrustInput.bytes) !== marker.policy_trust_sha256 ||
    sha256(descriptorInput.bytes) !== marker.guest_descriptor_sha256 ||
    sha256(overlayInput.bytes) !== marker.tauri_overlay_sha256
  )
    fail('VM-lab public resource hash does not match the marker')
  verifyLabPolicy({
    policy: policyInput.value,
    trust: policyTrustInput.value,
    descriptor: descriptorInput.value,
    marker,
  })

  const sidecarSha256 = sha256(sidecarInput.bytes)
  // Both VM-lab App profiles are independent of the production sidecar trust manifest.
  // The explicit input is still bounded and executable, while its arm64 shape
  // is checked below; no Team ID, requirement, or signature gates this lab.
  if (
    !sidecarInput.bytes
      .subarray(0, 4)
      .equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))
  )
    fail(`${labProfile} lab sidecar must be a thin arm64 Mach-O executable`)

  return {
    publicRoot,
    stagedResources,
    marker,
    reviewedOverlay: overlayInput.value,
    vmUtunLabOverlay,
    vmNetworkLabOverlay,
    vmExternalPeerLabOverlay,
    labProfile,
    mihomoConfigSha256,
    sidecar: sidecarInput.path,
    sidecarSha256,
  }
}

const commandOutput = (command, args, label) => {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) fail(`${label} failed: ${result.error.message}`)
  if (result.status !== 0)
    fail(`${label} failed: ${(result.stderr || result.stdout).trim()}`)
  return `${result.stdout}${result.stderr}`.trim()
}

const gitBytes = (args, label) => {
  const result = spawnSync('git', args, {
    cwd: PROJECT_ROOT,
    encoding: null,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) fail(`${label} failed: ${result.error.message}`)
  if (result.status !== 0)
    fail(
      `${label} failed: ${Buffer.from(result.stderr ?? [])
        .toString('utf8')
        .trim()}`,
    )
  return Buffer.from(result.stdout ?? [])
}

const gitText = (args, label) => gitBytes(args, label).toString('utf8')

const sourceTreeDigest = () => {
  const paths = gitBytes(
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    'source file inventory',
  )
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .sort()
  const digest = crypto.createHash('sha256')
  for (const relative of paths) {
    if (path.isAbsolute(relative) || relative.startsWith('../'))
      fail('source inventory contains a path outside the workspace')
    const absolute = path.resolve(PROJECT_ROOT, relative)
    if (
      absolute !== PROJECT_ROOT &&
      !absolute.startsWith(`${PROJECT_ROOT}${path.sep}`)
    )
      fail('source inventory escapes the workspace')
    const stat = fs.lstatSync(absolute)
    digest.update(relative)
    digest.update('\0')
    digest.update(String(stat.mode & 0o7777))
    digest.update('\0')
    if (stat.isSymbolicLink()) {
      digest.update('symlink\0')
      digest.update(fs.readlinkSync(absolute))
    } else if (stat.isFile()) {
      if (stat.size > 256 * 1024 * 1024)
        fail(`source file is too large to fingerprint: ${relative}`)
      digest.update('file\0')
      digest.update(fs.readFileSync(absolute))
    } else {
      fail(`source inventory contains an unsupported entry: ${relative}`)
    }
    digest.update('\0')
  }
  return digest.digest('hex')
}

export const collectSourceProvenance = () => {
  const status = gitBytes(
    ['status', '--porcelain=v1', '--untracked-files=all', '-z'],
    'source status inventory',
  )
  const stagedDiff = gitBytes(
    ['diff', '--cached', '--binary', '--no-ext-diff', '--'],
    'staged source diff inventory',
  )
  const worktreeDiff = gitBytes(
    ['diff', '--binary', '--no-ext-diff', '--'],
    'worktree source diff inventory',
  )
  return {
    commit: gitText(['rev-parse', 'HEAD'], 'source commit').trim(),
    dirty: status.length > 0,
    statusSha256: sha256(status),
    stagedDiffSha256: sha256(stagedDiff),
    worktreeDiffSha256: sha256(worktreeDiff),
    treeSha256: sourceTreeDigest(),
  }
}

const sameSourceProvenance = (before, after) =>
  before.commit === after.commit &&
  before.dirty === after.dirty &&
  before.statusSha256 === after.statusSha256 &&
  before.stagedDiffSha256 === after.stagedDiffSha256 &&
  before.worktreeDiffSha256 === after.worktreeDiffSha256 &&
  before.treeSha256 === after.treeSha256

const verifyThinArm64MachOOnMac = (filePath, label) => {
  const architectures = commandOutput(
    '/usr/bin/lipo',
    ['-archs', filePath],
    `${label} architecture verification`,
  )
    .split(/\s+/u)
    .filter(Boolean)
  if (architectures.length !== 1 || architectures[0] !== 'arm64')
    fail(`${label} must be arm64-only`)
}

const verifyLabSidecarOnMac = ({ sidecar }) =>
  verifyThinArm64MachOOnMac(sidecar, 'VM lab sidecar')

const treeDigest = (root) => {
  const entries = []
  const visit = (directory, relative = '') => {
    for (const entry of fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(directory, entry.name)
      const child = relative ? path.join(relative, entry.name) : entry.name
      const stat = fs.lstatSync(absolute)
      if (stat.isSymbolicLink()) fail(`App contains a symlink: ${child}`)
      if (stat.isDirectory()) visit(absolute, child)
      else if (stat.isFile())
        entries.push({ path: child, bytes: fs.readFileSync(absolute) })
      else fail(`App contains an unsupported entry: ${child}`)
    }
  }
  visit(root)
  const digest = crypto.createHash('sha256')
  for (const entry of entries) {
    digest.update(entry.path)
    digest.update('\0')
    digest.update(entry.bytes)
    digest.update('\0')
  }
  return digest.digest('hex')
}

const findForbiddenBundles = (root) => {
  const found = []
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) visit(absolute)
      else if (/\.(?:dmg|pkg)$/iu.test(entry.name)) found.push(absolute)
    }
  }
  visit(root)
  return found
}

const verifyUnsignedApp = (app) => {
  const result = spawnSync('/usr/bin/codesign', ['-d', '--verbose=4', app], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error)
    fail(`App signature inspection failed: ${result.error.message}`)
  const details = `${result.stdout}${result.stderr}`
  if (
    details.includes('Authority=Developer ID Application:') ||
    /TeamIdentifier=(?!not set)/u.test(details)
  )
    fail('no-sign VM-lab App unexpectedly has a distribution identity')
  return result.status === 0 ? 'adhoc-or-linker' : 'absent'
}

const pruneGeneratedBuildRuns = (parent) => {
  for (const entry of fs.readdirSync(parent, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith('run.')) continue
    const run = path.join(parent, entry.name)
    const marker = path.join(run, BUILD_RUN_MARKER)
    let markerBytes
    try {
      markerBytes = fs.readFileSync(marker)
    } catch {
      continue
    }
    if (markerBytes.toString('utf8') !== 'kyclash-production-vm-app\n') continue
    fs.rmSync(run, { recursive: true, force: true })
  }
}

const buildProductionVmApp = (validated) => {
  const labProfile = validated.labProfile ?? 'vm-utun'
  const appFeatures = {
    'vm-utun': APP_FEATURES,
    'vm-network': VM_NETWORK_APP_FEATURES,
    'vm-external-peer': VM_EXTERNAL_PEER_APP_FEATURES,
  }[labProfile]
  if (!appFeatures) fail('unknown lab profile')
  const parent = path.join(
    PROJECT_ROOT,
    'target',
    'macos-vm-lab',
    'build',
    'production-app-nosign',
  )
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 })
  pruneGeneratedBuildRuns(parent)
  const buildRoot = fs.mkdtempSync(path.join(parent, 'run.'))
  fs.chmodSync(buildRoot, 0o700)
  fs.writeFileSync(
    path.join(buildRoot, BUILD_RUN_MARKER),
    'kyclash-production-vm-app\n',
    { flag: 'wx', mode: 0o600 },
  )
  const cargoTarget = path.join(buildRoot, 'cargo-target')
  const sourceProvenance = collectSourceProvenance()
  const derivedConfig = createProductionVmAppOverlay({
    reviewedOverlay: validated.reviewedOverlay,
    vmUtunLabOverlay: validated.vmUtunLabOverlay,
    vmNetworkLabOverlay: validated.vmNetworkLabOverlay,
    vmExternalPeerLabOverlay: validated.vmExternalPeerLabOverlay,
    sidecar: validated.sidecar,
    labProfile,
  })
  const configPath = path.join(buildRoot, 'tauri.production-vm-nosign.json')
  fs.writeFileSync(configPath, `${JSON.stringify(derivedConfig, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600,
  })

  const shim = fs.mkdtempSync(path.join(buildRoot, 'pnpm-shim.'))
  fs.chmodSync(shim, 0o700)
  try {
    const env = prepareProductionVmAppEnvironment({
      buildRoot,
      cargoTarget,
      labProfile,
      corepackShim: shim,
    })
    const tauri = path.join(PROJECT_ROOT, 'node_modules', '.bin', 'tauri')
    requireBuildExecutable(tauri, 'fixed Tauri CLI')
    execFileSync(
      tauri,
      [
        'build',
        '--target',
        TARGET,
        '--bundles',
        'app',
        '--no-sign',
        '--features',
        appFeatures,
        '--config',
        configPath,
      ],
      { cwd: PROJECT_ROOT, env, stdio: 'inherit' },
    )
  } finally {
    fs.rmSync(shim, { recursive: true, force: true })
  }

  const finalSourceProvenance = collectSourceProvenance()
  if (!sameSourceProvenance(sourceProvenance, finalSourceProvenance))
    fail('workspace source changed during the App build; discard this artifact')

  const bundleRoot = path.join(cargoTarget, TARGET, 'release', 'bundle')
  const app = path.join(bundleRoot, 'macos', 'KyClash.app')
  if (!fs.existsSync(app))
    fail(`Tauri did not produce the expected App: ${app}`)
  const executable = path.join(app, 'Contents', 'MacOS', 'clash-verge')
  verifyThinArm64MachOOnMac(executable, `${labProfile} lab App executable`)
  const bundledSidecar = path.join(
    app,
    'Contents',
    'Resources',
    'kyclash-network-sidecar',
  )
  if (sha256(fs.readFileSync(bundledSidecar)) !== validated.sidecarSha256)
    fail('bundled network sidecar differs from the explicit lab input')
  for (const name of [
    LAB_MARKER_RESOURCE,
    LAB_POLICY_RESOURCE,
    LAB_TRUST_RESOURCE,
  ]) {
    const source = path.join(validated.stagedResources, name)
    const bundled = path.join(app, 'Contents', 'Resources', 'resources', name)
    if (sha256(fs.readFileSync(source)) !== sha256(fs.readFileSync(bundled)))
      fail(`bundled VM-lab resource differs: ${name}`)
  }
  const forbidden = findForbiddenBundles(bundleRoot)
  if (forbidden.length > 0)
    fail(`App-only build produced a forbidden package: ${forbidden[0]}`)
  const signature = verifyUnsignedApp(app)
  const result = {
    schema_version: 1,
    status: {
      'vm-utun': 'unsigned-disposable-vm-utun-lab-app',
      'vm-network': 'unsigned-disposable-vm-network-lab-app',
      'vm-external-peer': 'unsigned-disposable-vm-external-peer-lab-app',
    }[labProfile],
    features: [appFeatures],
    runtime_mode: {
      'vm-utun': 'vm_utun_lab',
      'vm-network': 'vm_network_lab',
      'vm-external-peer': 'vm_external_peer_lab',
    }[labProfile],
    production_composition: false,
    production_xpc: false,
    route_mutation: false,
    root_harness_route_fixture:
      labProfile === 'vm-network' || labProfile === 'vm-external-peer',
    mihomo_config_sha256:
      labProfile === 'vm-network' || labProfile === 'vm-external-peer'
        ? validated.mihomoConfigSha256
        : null,
    target: TARGET,
    vm_name: validated.marker.vm_name,
    run_id: validated.marker.run_id,
    resource_marker_schema:
      'legacy-networking-production-vm-lab-compatibility-input',
    resource_marker_grants_production_authority: false,
    marker_source_commit: validated.marker.source_commit,
    build_source_commit: sourceProvenance.commit,
    build_source_dirty: sourceProvenance.dirty,
    build_source_status_sha256: sourceProvenance.statusSha256,
    build_source_staged_diff_sha256: sourceProvenance.stagedDiffSha256,
    build_source_worktree_diff_sha256: sourceProvenance.worktreeDiffSha256,
    build_source_tree_sha256: sourceProvenance.treeSha256,
    app,
    app_tree_sha256: treeDigest(app),
    executable_sha256: sha256(fs.readFileSync(executable)),
    sidecar_sha256: validated.sidecarSha256,
    app_signature: signature,
    updater_artifacts: false,
    packages: false,
  }
  const resultPath = path.join(buildRoot, 'result.json')
  fs.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600,
  })
  return { ...result, result_path: resultPath }
}

const main = () => {
  const options = parseProductionVmAppOptions(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    fail('VM lab App build requires Apple Silicon macOS')
  const validated = validateProductionVmAppInputs(options)
  verifyLabSidecarOnMac(validated)
  if (options.validateOnly) {
    process.stdout.write('production_vm_app_inputs=validated\n')
    process.stdout.write(
      `production_vm_app_run_id=${validated.marker.run_id}\n`,
    )
    process.stdout.write(
      `production_vm_app_sidecar_sha256=${validated.sidecarSha256}\n`,
    )
    return
  }
  const result = buildProductionVmApp(validated)
  process.stdout.write('production_vm_app_build=complete\n')
  process.stdout.write(`production_vm_app_path=${result.app}\n`)
  process.stdout.write(`production_vm_app_sha256=${result.app_tree_sha256}\n`)
  process.stdout.write(`production_vm_app_result=${result.result_path}\n`)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main()
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}
