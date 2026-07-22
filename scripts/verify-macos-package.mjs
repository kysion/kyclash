import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import {
  collectReviewedBuildInputs,
  rejectDuplicateJsonKeys,
  signingMessage,
  validateDescriptor,
  validateLabProfile,
  validatePolicyRevisionPreflight,
} from './generate-networking-production-vm-lab.mjs'
import {
  assertProductionCompileMarker,
  targetArchitectureFromTriple,
} from './macos-package-verifier.mjs'
import {
  LAB_DESCRIPTOR_RESOURCE,
  LAB_MARKER_RESOURCE,
  LAB_OVERLAY_NAME,
  LAB_POLICY_RESOURCE,
  LAB_REVISION_PREFLIGHT_RESOURCE,
  LAB_TRUST_RESOURCE,
  ORDINARY_RESOURCE_ALLOWLIST,
} from './prepare-networking-production-vm-lab.mjs'

export const VERIFIER_PROFILES = Object.freeze([
  'release-default',
  'networking-production-vm-lab',
])

const root = path.resolve(import.meta.dirname, '..')
const packageMetadata = JSON.parse(
  fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
)
const CONTROLLED_EVIDENCE_ROOT = path.join(
  root,
  'target',
  'macos-vm-lab',
  'evidence',
)

const run = (command, args) => execFileSync(command, args, { stdio: 'inherit' })
const output = (command, args) => {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(
      `${command} exited with ${result.status}: ${(result.stderr || result.stdout).trim()}`,
    )
  }
  return `${result.stdout}${result.stderr}`.trim()
}

const assertDeveloperIdApplication = (binary, team) => {
  const details = output('codesign', ['-d', '--verbose=4', binary])
  const lines = details.split('\n')
  const teamIdentifier = lines
    .find((line) => line.startsWith('TeamIdentifier='))
    ?.slice('TeamIdentifier='.length)
  if (teamIdentifier !== team)
    throw new Error(`unexpected Team ID for ${binary}: ${teamIdentifier}`)
  const authorities = lines
    .filter((line) => line.startsWith('Authority='))
    .map((line) => line.slice('Authority='.length))
  if (
    !authorities.some(
      (authority) =>
        authority.startsWith('Developer ID Application: ') &&
        authority.includes(`(${team})`),
    )
  ) {
    throw new Error(
      `${binary} is not signed by the expected Developer ID Application team`,
    )
  }
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const lstatNoSymlink = (filePath, label = filePath) => {
  let stat
  try {
    stat = fs.lstatSync(filePath)
  } catch (error) {
    throw new Error(
      `${label} is missing: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    )
  }
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symlink`)
  return stat
}

const requireRegular = (filePath, label = filePath) => {
  const stat = lstatNoSymlink(filePath, label)
  if (!stat.isFile()) throw new Error(`${label} must be a regular file`)
  if ((stat.mode & 0o022) !== 0)
    throw new Error(`${label} must not be group/other writable`)
  return stat
}

const readRegularBytes = (filePath, label = filePath) => {
  const before = requireRegular(filePath, label)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let descriptor
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow)
  } catch {
    throw new Error(`${label} cannot be opened without following links`)
  }
  try {
    const opened = fs.fstatSync(descriptor)
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      throw new Error(`${label} changed while it was being opened`)
    }
    return fs.readFileSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

const fileSha256 = (filePath) => sha256(readRegularBytes(filePath, filePath))

const requireInstalledResource = (filePath, label = filePath) => {
  const stat = requireRegular(filePath, label)
  const mode = stat.mode & 0o777
  if (mode !== 0o644)
    throw new Error(
      `${label} must be an installed-app-readable 0644 resource, found ${mode.toString(8)}`,
    )
  return stat
}

const requireDirectory = (directory, label = directory) => {
  const stat = lstatNoSymlink(directory, label)
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory`)
  return stat
}

const requireMode = (filePath, expected, label = filePath) => {
  const mode = lstatNoSymlink(filePath, label).mode & 0o777
  if (mode !== expected)
    throw new Error(
      `${label} must be mode ${expected.toString(8)}, found ${mode.toString(8)}`,
    )
}

const bundleContentInventory = (directory) => {
  const entries = []
  const visit = (current, relative = '') => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(current, entry.name)
      const child = relative ? path.join(relative, entry.name) : entry.name
      const stat = lstatNoSymlink(absolute, absolute)
      if (stat.isDirectory()) {
        entries.push({
          path: child,
          type: 'directory',
          mode: stat.mode & 0o777,
        })
        visit(absolute, child)
      } else if (stat.isFile()) {
        entries.push({
          path: child,
          type: 'file',
          mode: stat.mode & 0o777,
          size: stat.size,
          sha256: fileSha256(absolute),
        })
      } else {
        throw new Error(
          `package payload contains unsupported entry: ${absolute}`,
        )
      }
    }
  }
  visit(directory)
  return entries
}

const assertExactInventory = (expectedRoot, actualRoot, label) => {
  const expected = bundleContentInventory(expectedRoot)
  const actual = bundleContentInventory(actualRoot)
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    throw new Error(`${label} path/type/mode/size/hash inventory differs`)
  }
  return expected
}

const exactDirectoryEntries = (directory, expected, label) => {
  const actual = fs.readdirSync(directory).sort()
  const wanted = [...expected].sort()
  if (
    actual.length !== wanted.length ||
    actual.some((entry, index) => entry !== wanted[index])
  ) {
    throw new Error(`${label} contains unexpected or missing entries`)
  }
}

const ordinaryResourceInventorySha256 = (directory) => {
  const inventory = [...ORDINARY_RESOURCE_ALLOWLIST]
    .sort((left, right) => left.localeCompare(right))
    .map((name) => {
      const filePath = path.join(directory, name)
      const stat = requireRegular(filePath, filePath)
      return {
        path: name,
        mode: stat.mode & 0o777,
        size: stat.size,
        sha256: fileSha256(filePath),
      }
    })
  return sha256(Buffer.from(JSON.stringify(inventory), 'utf8'))
}

const xmlAttributes = (text, element, label) => {
  const matches = [...text.matchAll(new RegExp(`<${element}\\b([^>]*)>`, 'gu'))]
  if (matches.length !== 1)
    throw new Error(`${label} must contain one ${element}`)
  const source = matches[0][1]
  const attributes = {}
  let consumed = ''
  for (const match of source.matchAll(
    /\s+([A-Za-z][A-Za-z0-9-]*)="([^"]*)"/gu,
  )) {
    if (Object.hasOwn(attributes, match[1]))
      throw new Error(`${label} contains duplicate ${element} attribute`)
    attributes[match[1]] = match[2]
    consumed += match[0]
  }
  if (consumed !== source)
    throw new Error(`${label} contains malformed ${element} attributes`)
  return attributes
}

const validatePackageInfo = (bytes) => {
  const text = bytes.toString('utf8')
  const rootAttributes = xmlAttributes(text, 'pkg-info', 'PackageInfo')
  exactKeys(
    rootAttributes,
    [
      'overwrite-permissions',
      'relocatable',
      'identifier',
      'postinstall-action',
      'version',
      'format-version',
      'generator-version',
      'install-location',
      'auth',
    ],
    'PackageInfo pkg-info attributes',
  )
  const expected = {
    'overwrite-permissions': 'true',
    relocatable: 'false',
    identifier: 'net.kysion.kyclash',
    'postinstall-action': 'none',
    version: packageMetadata.version,
    'format-version': '2',
    'install-location': '/Applications',
    auth: 'root',
  }
  for (const [name, value] of Object.entries(expected)) {
    if (rootAttributes[name] !== value)
      throw new Error(`PackageInfo ${name} mismatch`)
  }
  if (!rootAttributes['generator-version'])
    throw new Error('PackageInfo generator-version is empty')
  const bundleMatches = [
    ...text.matchAll(
      /<bundle\s+path="\.\/KyClash\.app"\s+id="net\.kysion\.kyclash"\s+CFBundleShortVersionString="([^"]+)"\s+CFBundleVersion="([^"]+)"\s*\/>/gu,
    ),
  ]
  if (
    bundleMatches.length !== 1 ||
    bundleMatches[0][1] !== packageMetadata.version ||
    bundleMatches[0][2] !== packageMetadata.version
  ) {
    throw new Error('PackageInfo KyClash bundle metadata mismatch')
  }
  if (/<scripts?\b/iu.test(text))
    throw new Error('PackageInfo must not declare installer scripts')
  return rootAttributes
}

const assertExpandedPackageMatchesApp = (pkg, app) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(path.dirname(pkg), '.kyclash-pkg-verify-'),
  )
  try {
    const expanded = path.join(temporaryRoot, 'expanded')
    run('pkgutil', ['--expand-full', pkg, expanded])
    exactDirectoryEntries(
      expanded,
      ['Bom', 'PackageInfo', 'Payload'],
      'expanded PKG root',
    )
    const bom = path.join(expanded, 'Bom')
    const packageInfo = path.join(expanded, 'PackageInfo')
    requireRegular(bom, bom)
    requireRegular(packageInfo, packageInfo)
    validatePackageInfo(readRegularBytes(packageInfo, packageInfo))
    const payload = path.join(expanded, 'Payload')
    requireDirectory(payload, payload)
    exactDirectoryEntries(payload, ['KyClash.app'], 'expanded PKG payload')
    const expandedApp = path.join(expanded, 'Payload/KyClash.app')
    requireDirectory(expandedApp, expandedApp)
    assertExactInventory(app, expandedApp, 'expanded PKG App')
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true })
  }
}

const readJsonObject = (filePath, label = filePath) => {
  requireRegular(filePath, label)
  const text = readRegularBytes(filePath, label).toString('utf8')
  rejectDuplicateJsonKeys(text, label)
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw new Error(
      `${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    )
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label} must be a JSON object`)
  return value
}

const exactKeys = (object, keys, label) => {
  const actual = Object.keys(object).sort()
  const expected = [...keys].sort()
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has unexpected fields`)
  }
}

const captureCleanSource = () => {
  const head = output('git', ['-C', root, 'rev-parse', '--verify', 'HEAD'])
  if (!/^[0-9a-f]{40}$/u.test(head))
    throw new Error('current Git HEAD is not a full SHA-1')
  const status = output('git', [
    '-C',
    root,
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
    '--ignored=no',
  ])
  if (status !== '')
    throw new Error('lab verification requires a clean reviewed source tree')
  return head
}

const writeExactNoReplace = (filePath, bytes, mode, controlledRoot, label) => {
  const absolute = path.resolve(filePath)
  const allowedRoot = path.resolve(controlledRoot)
  const relative = path.relative(allowedRoot, absolute)
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error(`${label} must stay inside its controlled output root`)
  }
  const parent = path.dirname(absolute)
  requireDirectory(parent, `${label} parent`)
  if (fs.existsSync(absolute)) {
    const existing = readRegularBytes(absolute, label)
    const existingMode = requireRegular(absolute, label).mode & 0o777
    if (existingMode !== mode || !existing.equals(bytes))
      throw new Error(`${label} already exists with different content or mode`)
    return absolute
  }
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  const descriptor = fs.openSync(
    absolute,
    fs.constants.O_WRONLY |
      fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      noFollow,
    mode,
  )
  try {
    fs.fchmodSync(descriptor, mode)
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
  const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY)
  try {
    fs.fsyncSync(parentDescriptor)
  } finally {
    fs.closeSync(parentDescriptor)
  }
  requireMode(absolute, mode, label)
  return absolute
}

export const parseVerifierOptions = (argv) => {
  let target
  let profile = 'release-default'
  let labPublicRoot
  let resultOutput
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--profile') {
      profile = argv[++index]
    } else if (argument === '--lab-public-root') {
      labPublicRoot = argv[++index]
    } else if (argument === '--result') {
      resultOutput = argv[++index]
    } else if (argument.startsWith('--')) {
      throw new Error(`unknown option: ${argument}`)
    } else if (!target) {
      target = argument
    } else {
      throw new Error(`unexpected argument: ${argument}`)
    }
  }
  target ??= 'aarch64-apple-darwin'
  if (!VERIFIER_PROFILES.includes(profile))
    throw new Error(`unknown package verifier profile: ${profile}`)
  if (profile === 'networking-production-vm-lab') {
    if (!labPublicRoot || !path.isAbsolute(labPublicRoot)) {
      throw new Error(
        'networking-production-vm-lab requires an absolute --lab-public-root',
      )
    }
  } else if (labPublicRoot) {
    throw new Error(
      '--lab-public-root is only valid with networking-production-vm-lab',
    )
  }
  return { target, profile, labPublicRoot, resultOutput }
}

const findPackage = (pkgDir) => {
  requireDirectory(pkgDir, 'PKG output directory')
  const packages = fs
    .readdirSync(pkgDir)
    .filter((name) => name.endsWith('.pkg') && name.includes('KyClash_'))
  if (packages.length !== 1)
    throw new Error(
      `expected exactly one KyClash PKG, found ${packages.length}`,
    )
  return path.join(pkgDir, packages[0])
}

const appResourcePath = (app, name) =>
  path.join(app, 'Contents/Resources/resources', name)

const assertNoProductionResources = (app) => {
  const resources = path.join(app, 'Contents/Resources')
  if (!fs.existsSync(resources)) return
  requireDirectory(resources, resources)
  const userspaceLabSidecar = path.join(
    resources,
    'kyclash-network-sidecar-lab',
  )
  if (fs.existsSync(userspaceLabSidecar)) {
    throw new Error(
      'production package must reject the explicit userspace-lab sidecar resource',
    )
  }
  exactDirectoryEntries(
    resources,
    [
      'icon.icns',
      'kyclash-network-sidecar',
      'kyclash-route-helper',
      'resources',
    ],
    'release-default App resources root',
  )
  const ordinaryResources = path.join(resources, 'resources')
  requireDirectory(ordinaryResources, ordinaryResources)
  exactDirectoryEntries(
    ordinaryResources,
    ORDINARY_RESOURCE_ALLOWLIST,
    'release-default ordinary resources',
  )
  const forbiddenNames = new Set([
    LAB_MARKER_RESOURCE,
    LAB_POLICY_RESOURCE,
    LAB_REVISION_PREFLIGHT_RESOURCE,
    LAB_TRUST_RESOURCE,
  ])
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filePath = path.join(directory, entry.name)
      const stat = lstatNoSymlink(filePath, filePath)
      if (stat.isDirectory()) {
        walk(filePath)
        continue
      }
      if (!stat.isFile())
        throw new Error(`unexpected non-regular resource: ${filePath}`)
      if (forbiddenNames.has(entry.name))
        throw new Error(
          `release-default package contains forbidden production resource: ${entry.name}`,
        )
      if (stat.size > 512 * 1024) continue
      const bytes = fs.readFileSync(filePath)
      if (bytes.includes(0)) continue
      const text = bytes.toString('utf8')
      if (
        /lab\.vm\.|networking-production-vm-lab|KYCLASH-PROD-V1/u.test(text)
      ) {
        throw new Error(
          `release-default package contains lab/production marker material: ${filePath}`,
        )
      }
    }
  }
  walk(resources)
}

const decodeBase64Strict = (value, label, expectedLength) => {
  if (typeof value !== 'string' || value.length === 0)
    throw new Error(`${label} must be non-empty base64`)
  const decoded = Buffer.from(value, 'base64')
  if (
    decoded.toString('base64') !== value ||
    (expectedLength !== undefined && decoded.length !== expectedLength)
  ) {
    throw new Error(`${label} has invalid base64 encoding`)
  }
  return decoded
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
    'lab policy envelope',
  )
  if (
    policy.envelope_version !== 2 ||
    policy.algorithm !== 'ed25519' ||
    policy.key_id !== marker.policy_key_id
  ) {
    throw new Error('lab policy envelope identity mismatch')
  }
  exactKeys(trust, ['schema_version', 'keys'], 'lab policy trust bundle')
  if (
    trust.schema_version !== 1 ||
    !Array.isArray(trust.keys) ||
    trust.keys.length !== 1
  ) {
    throw new Error(
      'lab policy trust bundle must contain exactly the run-bound key',
    )
  }
  const key = trust.keys[0]
  exactKeys(key, ['key_id', 'public_key_base64'], 'lab policy trust key')
  if (key.key_id !== marker.policy_key_id)
    throw new Error('lab policy trust key ID mismatch')
  const publicRaw = decodeBase64Strict(
    key.public_key_base64,
    'lab policy public key',
    32,
  )
  // RFC 8032 test vector used only by Rust unit tests; it must never become a
  // packaged lab authority.
  if (
    publicRaw.toString('hex') ===
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
  ) {
    throw new Error('lab policy uses the forbidden fixed unit-test public key')
  }
  const payloadBytes = decodeBase64Strict(
    policy.payload_base64,
    'lab policy payload',
  )
  const signature = decodeBase64Strict(
    policy.signature_base64,
    'lab policy signature',
    64,
  )
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicRaw,
    ]),
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
  ) {
    throw new Error('lab policy Ed25519 signature is invalid')
  }
  const payloadText = payloadBytes.toString('utf8')
  rejectDuplicateJsonKeys(payloadText, 'lab policy payload')
  let payload
  try {
    payload = JSON.parse(payloadText)
  } catch {
    throw new Error('lab policy payload is not valid JSON')
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('lab policy payload must be an object')
  exactKeys(
    payload,
    ['issued_at', 'expires_at', 'revision', 'profile'],
    'lab policy payload',
  )
  if (
    payload.issued_at !== marker.issued_at ||
    payload.expires_at !== marker.expires_at ||
    payload.revision !== marker.policy_revision
  ) {
    throw new Error('lab policy temporal/revision fields do not match marker')
  }
  if (payload.expires_at > marker.policy_expiry_ceiling_epoch)
    throw new Error('lab policy expiry exceeds the guest policy expiry ceiling')
  validateDescriptor(descriptor, marker.issued_at)
  if (
    descriptor.run_id !== marker.run_id ||
    descriptor.expires_at !== marker.expires_at
  ) {
    throw new Error('guest descriptor run/lifetime does not match marker')
  }
  if (descriptor.expires_at > marker.policy_expiry_ceiling_epoch)
    throw new Error(
      'guest descriptor expiry exceeds the guest policy expiry ceiling',
    )
  validateLabProfile(payload.profile, descriptor, marker.run_id)
  return payload
}

const validateLabOverlay = (overlay, stagedResourcesPath, baseConfig) => {
  exactKeys(overlay, ['$schema', 'bundle'], 'lab overlay')
  if (
    !overlay.bundle ||
    typeof overlay.bundle !== 'object' ||
    Array.isArray(overlay.bundle)
  )
    throw new Error('lab overlay has no bundle object')
  exactKeys(
    overlay.bundle,
    ['externalBin', 'macOS', 'resources'],
    'lab overlay bundle',
  )
  if (
    !overlay.bundle.resources ||
    typeof overlay.bundle.resources !== 'object' ||
    Array.isArray(overlay.bundle.resources)
  )
    throw new Error('lab overlay resources must be an object mapping')
  const resourceMappings = Object.entries(overlay.bundle.resources)
  if (resourceMappings.length !== 1)
    throw new Error('lab overlay must contain exactly one resources mapping')
  const [source, destination] = resourceMappings[0]
  if (!path.isAbsolute(source) || destination !== 'resources')
    throw new Error(
      'lab overlay resources mapping must be absolute -> resources',
    )
  if (path.normalize(source) !== path.normalize(stagedResourcesPath))
    throw new Error('lab overlay does not map the audited staged resource root')
  if (
    !overlay.bundle.macOS?.files ||
    typeof overlay.bundle.macOS.files !== 'object' ||
    Array.isArray(overlay.bundle.macOS.files)
  )
    throw new Error('lab overlay lost macOS.files')
  if (!Array.isArray(overlay.bundle.externalBin))
    throw new Error('lab overlay lost externalBin')
  if (
    overlay.$schema !==
      (baseConfig.$schema ??
        '../node_modules/@tauri-apps/cli/config.schema.json') ||
    JSON.stringify(overlay.bundle.macOS) !==
      JSON.stringify(baseConfig.bundle?.macOS) ||
    JSON.stringify(overlay.bundle.externalBin) !==
      JSON.stringify(baseConfig.bundle?.externalBin ?? [])
  ) {
    throw new Error(
      'lab overlay changed the reviewed macOS files or externalBin mapping',
    )
  }
  return true
}

const assertLabMarker = ({
  markerPath,
  policyPath,
  trustPath,
  descriptorPath,
  policyRevisionPreflightPath,
  overlayPath,
  stagedResourcesPath,
  target,
  now,
  expectedSourceCommit,
}) => {
  const marker = readJsonObject(markerPath, markerPath)
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
    'lab marker',
  )
  if (
    marker.schema_version !== 1 ||
    marker.candidate_kind !== 'networking-production-vm-lab'
  )
    throw new Error('lab marker schema/kind mismatch')
  if (!/^[0-9a-f]{16}$/u.test(marker.run_id))
    throw new Error('lab marker run_id is invalid')
  if (!/^[0-9a-f]{40}$/u.test(marker.source_commit))
    throw new Error('lab marker source_commit is invalid')
  if (marker.target !== target)
    throw new Error(`lab marker target mismatch: ${marker.target}`)
  if (marker.vm_name !== 'kyclash-macos-lab-work')
    throw new Error('lab marker VM binding mismatch')
  if (marker.policy_key_id !== `lab.vm.${marker.run_id}`)
    throw new Error('lab marker policy key binding mismatch')
  for (const field of [
    'policy_envelope_sha256',
    'policy_trust_sha256',
    'guest_descriptor_sha256',
    'policy_revision_preflight_sha256',
    'tauri_overlay_sha256',
    'mihomo_final_sha256',
    'mihomo_alpha_final_sha256',
  ]) {
    if (
      !/^[0-9a-f]{64}$/u.test(marker[field]) ||
      ((field === 'mihomo_final_sha256' ||
        field === 'mihomo_alpha_final_sha256') &&
        /^0{64}$/u.test(marker[field]))
    )
      throw new Error(`lab marker ${field} is invalid`)
  }
  exactKeys(
    marker.build_inputs,
    [
      'ordinary_resources_inventory_sha256',
      'network_sidecar_sha256',
      'route_helper_sha256',
      'route_helper_plist_sha256',
      'mihomo_sha256',
      'mihomo_alpha_sha256',
    ],
    'lab marker build inputs',
  )
  for (const [name, digest] of Object.entries(marker.build_inputs)) {
    if (!/^[0-9a-f]{64}$/u.test(digest))
      throw new Error(`lab marker build input ${name} is invalid`)
  }
  for (const field of [
    'policy_revision',
    'issued_at',
    'expires_at',
    'policy_expiry_ceiling_epoch',
  ]) {
    if (!Number.isSafeInteger(marker[field]) || marker[field] < 0)
      throw new Error(`lab marker ${field} is invalid`)
  }
  if (
    marker.policy_revision === 0 ||
    marker.expires_at <= marker.issued_at ||
    marker.policy_expiry_ceiling_epoch <= marker.issued_at ||
    marker.expires_at > marker.policy_expiry_ceiling_epoch
  )
    throw new Error('lab marker lifetime/revision is invalid')
  if (
    !Number.isSafeInteger(now) ||
    now < marker.issued_at ||
    now >= marker.expires_at
  )
    throw new Error('lab marker is expired or not yet valid')
  if (expectedSourceCommit !== marker.source_commit)
    throw new Error('lab marker source_commit does not match current HEAD')
  if (fileSha256(policyPath) !== marker.policy_envelope_sha256)
    throw new Error('lab policy envelope hash mismatch')
  if (fileSha256(trustPath) !== marker.policy_trust_sha256)
    throw new Error('lab policy trust hash mismatch')
  if (fileSha256(descriptorPath) !== marker.guest_descriptor_sha256)
    throw new Error('guest descriptor hash mismatch')
  if (
    fileSha256(policyRevisionPreflightPath) !==
    marker.policy_revision_preflight_sha256
  )
    throw new Error('policy revision preflight hash mismatch')
  if (fileSha256(overlayPath) !== marker.tauri_overlay_sha256)
    throw new Error('Tauri overlay hash mismatch')
  const policy = readJsonObject(policyPath, policyPath)
  const trust = readJsonObject(trustPath, trustPath)
  const descriptor = readJsonObject(descriptorPath, descriptorPath)
  const policyRevisionPreflight = readJsonObject(
    policyRevisionPreflightPath,
    policyRevisionPreflightPath,
  )
  validatePolicyRevisionPreflight({
    preflight: policyRevisionPreflight,
    runId: marker.run_id,
    revision: marker.policy_revision,
    now: marker.issued_at,
  })
  verifyLabPolicy({ policy, trust, descriptor, marker })
  const overlay = readJsonObject(overlayPath, overlayPath)
  const baseConfigPath = path.join(
    root,
    'src-tauri/tauri.networking.macos.conf.json',
  )
  const baseConfig = readJsonObject(baseConfigPath, baseConfigPath)
  validateLabOverlay(overlay, stagedResourcesPath, baseConfig)
  const reviewedInputs = collectReviewedBuildInputs({
    sourceRoot: path.join(root, 'src-tauri/resources'),
    baseConfig: baseConfigPath,
    target,
  })
  if (
    JSON.stringify(reviewedInputs.marker) !==
    JSON.stringify(marker.build_inputs)
  ) {
    throw new Error(
      'current reviewed build inputs differ from the signed marker',
    )
  }
  if (
    ordinaryResourceInventorySha256(stagedResourcesPath) !==
    marker.build_inputs.ordinary_resources_inventory_sha256
  ) {
    throw new Error('staged ordinary resource inventory differs from marker')
  }
  return marker
}

export const verifyPackage = ({
  target = 'aarch64-apple-darwin',
  profile = 'release-default',
  labPublicRoot,
  now = Math.floor(Date.now() / 1000),
} = {}) => {
  if (!VERIFIER_PROFILES.includes(profile))
    throw new Error(`unknown package verifier profile: ${profile}`)
  if (
    profile === 'networking-production-vm-lab' &&
    target !== 'aarch64-apple-darwin'
  ) {
    throw new Error('networking-production-vm-lab is arm64-only')
  }
  const sourceCommit =
    profile === 'networking-production-vm-lab'
      ? captureCleanSource()
      : undefined
  const targetDir = path.join(root, 'target', target)
  const app = path.join(targetDir, 'release', 'bundle', 'macos', 'KyClash.app')
  const pkgDir = path.join(targetDir, 'release', 'bundle', 'pkg')
  const pkg = findPackage(pkgDir)
  const helper = path.join(app, 'Contents/Resources/kyclash-route-helper')
  const sidecar = path.join(app, 'Contents/Resources/kyclash-network-sidecar')
  const helperPlist = path.join(
    app,
    'Contents/Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist',
  )
  const trust = path.join(
    app,
    `Contents/Resources/resources/kyclash-network-sidecar-${target}.trust.json`,
  )
  const executable = path.join(app, 'Contents/MacOS/clash-verge')
  for (const file of [app, helper, sidecar, helperPlist, trust, executable]) {
    if (file === app) requireDirectory(file, file)
    else requireRegular(file, file)
  }
  const trustMode = fs.statSync(trust).mode & 0o777
  if (trustMode !== 0o644)
    throw new Error(
      `sidecar trust manifest must be an installed-app-readable 0644 resource, found ${trustMode.toString(8)}`,
    )
  run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', app])
  run('codesign', ['--verify', '--strict', '--verbose=2', sidecar])
  run('codesign', ['--verify', '--strict', '--verbose=2', helper])
  const team = process.env.APPLE_TEAM_ID ?? 'RQUQ8Y3S9H'
  for (const binary of [app, sidecar, helper])
    assertDeveloperIdApplication(binary, team)
  run('plutil', ['-lint', helperPlist])
  const packageSignature = output('pkgutil', ['--check-signature', pkg])
  if (
    !packageSignature.includes('Developer ID Installer') ||
    !packageSignature.includes(`(${team})`)
  ) {
    throw new Error(
      'PKG is not signed by the expected Developer ID Installer team',
    )
  }
  const digest = fileSha256(sidecar)
  const trustManifest = readJsonObject(trust, trust)
  if (digest !== trustManifest.sha256)
    throw new Error('sidecar trust manifest hash mismatch')
  const duplicateHelper = path.join(
    app,
    'Contents/Resources/resources/kyclash-route-helper',
  )
  if (fs.existsSync(duplicateHelper))
    throw new Error('route helper duplicated under resources')
  const architecture = targetArchitectureFromTriple(target)
  assertProductionCompileMarker(executable, {
    profile,
    targetArch: architecture,
  })

  let marker
  if (profile === 'release-default') {
    assertNoProductionResources(app)
  } else {
    if (!labPublicRoot || !path.isAbsolute(labPublicRoot))
      throw new Error(
        'networking-production-vm-lab requires an absolute --lab-public-root',
      )
    const publicRoot = path.normalize(labPublicRoot)
    requireDirectory(publicRoot, publicRoot)
    requireMode(publicRoot, 0o700, publicRoot)
    const expectedPublicFiles = new Set([
      LAB_MARKER_RESOURCE,
      LAB_POLICY_RESOURCE,
      LAB_TRUST_RESOURCE,
      LAB_DESCRIPTOR_RESOURCE,
      LAB_REVISION_PREFLIGHT_RESOURCE,
      LAB_OVERLAY_NAME,
    ])
    for (const entry of fs.readdirSync(publicRoot, { withFileTypes: true })) {
      const entryPath = path.join(publicRoot, entry.name)
      const stat = lstatNoSymlink(entryPath, entryPath)
      if (entry.name === 'resources' && stat.isDirectory()) continue
      if (!stat.isFile() || !expectedPublicFiles.has(entry.name)) {
        throw new Error(
          `lab public root contains an unexpected entry: ${entry.name}`,
        )
      }
    }
    const stagedPublicResources = path.join(publicRoot, 'resources')
    requireDirectory(stagedPublicResources, stagedPublicResources)
    requireMode(stagedPublicResources, 0o700, stagedPublicResources)
    const expectedResourceNames = new Set([
      ...ORDINARY_RESOURCE_ALLOWLIST,
      LAB_MARKER_RESOURCE,
      LAB_POLICY_RESOURCE,
      LAB_TRUST_RESOURCE,
    ])
    const actualResourceNames = fs.readdirSync(stagedPublicResources)
    if (
      actualResourceNames.length !== expectedResourceNames.size ||
      actualResourceNames.some((name) => !expectedResourceNames.has(name))
    ) {
      throw new Error(
        'lab staged resources do not match the reviewed closed allowlist',
      )
    }
    for (const name of actualResourceNames) {
      requireRegular(
        path.join(stagedPublicResources, name),
        path.join(stagedPublicResources, name),
      )
    }
    for (const name of [
      LAB_MARKER_RESOURCE,
      LAB_POLICY_RESOURCE,
      LAB_TRUST_RESOURCE,
    ])
      requireMode(path.join(stagedPublicResources, name), 0o644)
    const markerPath = path.join(publicRoot, LAB_MARKER_RESOURCE)
    const policyPath = path.join(publicRoot, LAB_POLICY_RESOURCE)
    const trustPath = path.join(publicRoot, LAB_TRUST_RESOURCE)
    const descriptorPath = path.join(publicRoot, LAB_DESCRIPTOR_RESOURCE)
    const policyRevisionPreflightPath = path.join(
      publicRoot,
      LAB_REVISION_PREFLIGHT_RESOURCE,
    )
    const overlayPath = path.join(publicRoot, LAB_OVERLAY_NAME)
    for (const file of [
      markerPath,
      policyPath,
      trustPath,
      descriptorPath,
      policyRevisionPreflightPath,
      overlayPath,
    ])
      requireRegular(file, file)
    for (const file of [
      markerPath,
      policyPath,
      trustPath,
      descriptorPath,
      policyRevisionPreflightPath,
    ])
      requireMode(file, 0o644, file)
    requireMode(overlayPath, 0o600, overlayPath)
    const appMarkerPath = appResourcePath(app, LAB_MARKER_RESOURCE)
    const appPolicyPath = appResourcePath(app, LAB_POLICY_RESOURCE)
    const appTrustPath = appResourcePath(app, LAB_TRUST_RESOURCE)
    const appDescriptorPath = appResourcePath(app, LAB_DESCRIPTOR_RESOURCE)
    if (fs.existsSync(appDescriptorPath))
      throw new Error(
        'guest descriptor must remain outside the installed App resources',
      )
    for (const file of [appMarkerPath, appPolicyPath, appTrustPath])
      requireInstalledResource(file, file)
    for (const [rootFile, appFile] of [
      [markerPath, appMarkerPath],
      [policyPath, appPolicyPath],
      [trustPath, appTrustPath],
    ]) {
      if (
        !Buffer.from(fs.readFileSync(rootFile)).equals(fs.readFileSync(appFile))
      )
        throw new Error(
          `app resource differs from lab public input: ${path.basename(rootFile)}`,
        )
    }
    const appResourceRoot = path.join(app, 'Contents/Resources/resources')
    requireDirectory(appResourceRoot, appResourceRoot)
    assertExactInventory(
      stagedPublicResources,
      appResourceRoot,
      'staged resources -> signed App resources',
    )
    marker = assertLabMarker({
      markerPath,
      policyPath,
      trustPath,
      descriptorPath,
      policyRevisionPreflightPath,
      overlayPath,
      stagedResourcesPath: stagedPublicResources,
      target,
      now,
      expectedSourceCommit: sourceCommit,
    })
    const exactInputComponents = [
      [
        sidecar,
        marker.build_inputs.network_sidecar_sha256,
        'signed network sidecar',
      ],
      [helper, marker.build_inputs.route_helper_sha256, 'signed route helper'],
      [
        helperPlist,
        marker.build_inputs.route_helper_plist_sha256,
        'route helper plist',
      ],
    ]
    for (const [file, expectedHash, label] of exactInputComponents) {
      if (fileSha256(file) !== expectedHash)
        throw new Error(`${label} differs from the signed build input hash`)
    }
    const finalMihomo = {
      mihomo: path.join(app, 'Contents/MacOS/verge-mihomo'),
      mihomo_alpha: path.join(app, 'Contents/MacOS/verge-mihomo-alpha'),
    }
    for (const [name, file] of Object.entries(finalMihomo)) {
      requireRegular(file, file)
      run('codesign', ['--verify', '--strict', '--verbose=2', file])
      assertDeveloperIdApplication(file, team)
      const expected =
        name === 'mihomo'
          ? marker.mihomo_final_sha256
          : marker.mihomo_alpha_final_sha256
      if (fileSha256(file) !== expected)
        throw new Error(`final ${name} hash differs from the sealed marker`)
    }
    assertExpandedPackageMatchesApp(pkg, app)
    if (captureCleanSource() !== sourceCommit)
      throw new Error('source HEAD changed during lab package verification')
  }
  const packageDigest = fileSha256(pkg)
  writeExactNoReplace(
    `${pkg}.sha256`,
    Buffer.from(`${packageDigest}  ${path.basename(pkg)}\n`),
    0o644,
    pkgDir,
    'PKG SHA-256 output',
  )
  const result = {
    profile,
    target,
    package: pkg,
    package_sha256: packageDigest,
    app_sha256: fileSha256(executable),
    compile_marker:
      profile === 'networking-production-vm-lab' ? 'KYCLASH-PROD-V1' : 'absent',
    status: 'signed-unnotarized-internal',
    ...(profile === 'networking-production-vm-lab'
      ? {
          sidecar_sha256: fileSha256(sidecar),
          route_helper_sha256: fileSha256(helper),
          mihomo_sha256: fileSha256(
            path.join(app, 'Contents/MacOS/verge-mihomo'),
          ),
          mihomo_alpha_sha256: fileSha256(
            path.join(app, 'Contents/MacOS/verge-mihomo-alpha'),
          ),
        }
      : {}),
    ...(marker
      ? {
          run_id: marker.run_id,
          source_commit: marker.source_commit,
          policy_revision_preflight_sha256:
            marker.policy_revision_preflight_sha256,
        }
      : {}),
  }
  console.log(`[INFO] verified KyClash PKG (${profile}): ${pkg}`)
  return result
}

const main = () => {
  const options = parseVerifierOptions(process.argv.slice(2))
  const result = verifyPackage(options)
  if (options.resultOutput) {
    if (!path.isAbsolute(options.resultOutput))
      throw new Error('--result must be an absolute path')
    writeExactNoReplace(
      options.resultOutput,
      Buffer.from(`${JSON.stringify(result, null, 2)}\n`),
      0o600,
      CONTROLLED_EVIDENCE_ROOT,
      'verification result',
    )
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main()

export {
  assertExpandedPackageMatchesApp,
  assertExactInventory,
  bundleContentInventory,
  validateLabOverlay,
  validatePackageInfo,
  writeExactNoReplace,
}
