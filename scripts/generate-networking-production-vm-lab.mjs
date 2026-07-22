import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  LAB_MARKER_RESOURCE,
  LAB_POLICY_RESOURCE,
  LAB_REVISION_PREFLIGHT_RESOURCE,
  LAB_TRUST_RESOURCE,
  ORDINARY_RESOURCE_ALLOWLIST,
  canonicalizeMacOsAbsolutePath,
  createNetworkingProductionOverlay,
  readRegularFileNoFollow,
  stagePublicResources,
  writeFileNoReplace,
} from './prepare-networking-production-vm-lab.mjs'

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const DEFAULT_SOURCE_ROOT = path.join(PROJECT_ROOT, 'src-tauri/resources')
const DEFAULT_BASE_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri/tauri.networking.macos.conf.json',
)
const MAX_LIFETIME_SECONDS = 24 * 60 * 60
export const GUEST_LAB_ROOT = '/private/var/tmp/kyclash-networking-vm-lab'
const POLICY_ALGORITHM = 'ed25519'
const POLICY_DOMAIN = Buffer.from('kyclash-policy-envelope-v2\0', 'ascii')
const POLICY_SIGNER_CHILD_ARG = '--policy-signer-child'
const HEX16 = /^[0-9a-f]{16}$/u
const HEX40 = /^[0-9a-f]{40}$/u
const HEX64 = /^[0-9a-f]{64}$/u
const BASE64_32 = /^[A-Za-z0-9+/]{43}=$/u
const GUEST_APP_DATA_ROOT =
  /^\/Users\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/Library\/Application Support\/net\.kysion\.kyclash$/u
const PENDING_FINAL_COMPONENT_SHA256 = '0'.repeat(64)

const fail = (message) => {
  throw new Error(message)
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const ensureAbsolute = (value, label) => {
  if (typeof value !== 'string' || !path.isAbsolute(value))
    fail(`${label} must be an absolute path`)
  return canonicalizeMacOsAbsolutePath(value)
}

const assertNoSymlinkComponents = (filePath, label = filePath) => {
  const absolute = ensureAbsolute(filePath, label)
  const parsed = path.parse(absolute)
  let current = parsed.root
  for (const component of absolute.slice(parsed.root.length).split(path.sep)) {
    if (!component) continue
    current = path.join(current, component)
    let stat
    try {
      stat = fs.lstatSync(current)
    } catch (error) {
      if (error?.code === 'ENOENT') break
      fail(
        `${label} cannot be inspected: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
    if (stat.isSymbolicLink()) fail(`${label} has a symlinked path component`)
  }
  return absolute
}

const lstatNoSymlink = (filePath, label = filePath) => {
  let stat
  try {
    stat = fs.lstatSync(filePath)
  } catch (error) {
    fail(
      `${label} is missing: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (stat.isSymbolicLink()) fail(`${label} must not be a symlink`)
  return stat
}

const requireDirectory = (directory, label = directory) => {
  const stat = lstatNoSymlink(directory, label)
  if (!stat.isDirectory()) fail(`${label} must be a directory`)
  if ((stat.mode & 0o077) !== 0)
    fail(`${label} must not be group/other accessible`)
  return stat
}

// JSON.parse silently keeps the last value for duplicate object keys.  The
// candidate inputs are trust-boundary files, so perform a small strict lexical
// parse first and reject duplicate keys before handing the value to JSON.parse.
const rejectDuplicateJsonKeys = (text, label) => {
  let index = 0
  const length = text.length
  const whitespace = () => {
    while (index < length && /\s/u.test(text[index])) index += 1
  }
  const parseString = () => {
    if (text[index] !== '"') fail(`${label} contains an invalid JSON string`)
    const start = index
    index += 1
    let escaped = false
    while (index < length) {
      const character = text[index++]
      if (escaped) {
        escaped = false
        continue
      }
      if (character === '\\') {
        escaped = true
        continue
      }
      if (character === '"') {
        try {
          return JSON.parse(text.slice(start, index))
        } catch {
          fail(`${label} contains an invalid JSON string`)
        }
      }
      if (character < ' ') fail(`${label} contains a control character`)
    }
    fail(`${label} contains an unterminated JSON string`)
  }
  const parseValue = () => {
    whitespace()
    const character = text[index]
    if (character === '"') {
      parseString()
      return
    }
    if (character === '{') {
      index += 1
      whitespace()
      const keys = new Set()
      if (text[index] === '}') {
        index += 1
        return
      }
      while (index < length) {
        whitespace()
        const key = parseString()
        if (keys.has(key))
          fail(`${label} contains a duplicate JSON key: ${key}`)
        keys.add(key)
        whitespace()
        if (text[index++] !== ':')
          fail(`${label} contains an invalid JSON object`)
        parseValue()
        whitespace()
        if (text[index] === '}') {
          index += 1
          return
        }
        if (text[index++] !== ',')
          fail(`${label} contains an invalid JSON object`)
      }
      fail(`${label} contains an unterminated JSON object`)
    }
    if (character === '[') {
      index += 1
      whitespace()
      if (text[index] === ']') {
        index += 1
        return
      }
      while (index < length) {
        parseValue()
        whitespace()
        if (text[index] === ']') {
          index += 1
          return
        }
        if (text[index++] !== ',')
          fail(`${label} contains an invalid JSON array`)
      }
      fail(`${label} contains an unterminated JSON array`)
    }
    if (text.startsWith('true', index)) {
      index += 4
      return
    }
    if (text.startsWith('false', index)) {
      index += 5
      return
    }
    if (text.startsWith('null', index)) {
      index += 4
      return
    }
    const number = text
      .slice(index)
      .match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)
    if (number) {
      index += number[0].length
      return
    }
    fail(`${label} contains an invalid JSON value`)
  }
  parseValue()
  whitespace()
  if (index !== length) fail(`${label} contains trailing JSON data`)
}

const readStrictJson = (filePath, label = filePath) => {
  const input = readRegularFileNoFollow(filePath, label)
  const text = input.bytes.toString('utf8')
  rejectDuplicateJsonKeys(text, label)
  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    fail(
      `${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be a JSON object`)
  return { value, bytes: Buffer.from(text) }
}

const exactKeys = (object, keys, label) => {
  const actual = Object.keys(object).sort()
  const expected = [...keys].sort()
  if (
    actual.length !== expected.length ||
    actual.some((key, position) => key !== expected[position])
  )
    fail(`${label} has unexpected fields`)
}

const validBase64Key = (value) => {
  if (typeof value !== 'string' || !BASE64_32.test(value)) return false
  try {
    const decoded = Buffer.from(value, 'base64')
    return decoded.length === 32 && decoded.toString('base64') === value
  } catch {
    return false
  }
}

const validHex = (value, pattern) =>
  typeof value === 'string' && pattern.test(value)

/**
 * The guest trust fixture publishes this as a public epoch scalar (the leaf
 * certificate NotAfter minus its safety margin).  It is deliberately passed
 * out-of-band instead of widening the peer descriptor schema: the descriptor
 * remains the stable public carrier contract, while preparation fails closed
 * when its requested lifetime exceeds the guest-derived ceiling.
 */
export const validatePolicyExpiryCeiling = ({
  now,
  expiresAt,
  policyExpiryCeiling,
}) => {
  if (
    !Number.isSafeInteger(policyExpiryCeiling) ||
    policyExpiryCeiling <= now
  ) {
    fail('policy expiry ceiling must be a future safe integer epoch')
  }
  if (expiresAt > policyExpiryCeiling) {
    fail('descriptor expiry exceeds the guest policy expiry ceiling')
  }
  return policyExpiryCeiling
}

export const validatePolicyRevisionPreflight = ({
  preflight,
  runId,
  revision,
  now,
}) => {
  exactKeys(
    preflight,
    [
      'schema_version',
      'run_id',
      'candidate_revision',
      'record_state',
      'record_revision',
      'record_key_id',
      'record_envelope_sha256',
      'app_data_root',
      'app_data_root_sha256',
      'checked_at',
      'decision',
    ],
    'policy revision preflight',
  )
  if (
    preflight.schema_version !== 1 ||
    preflight.run_id !== runId ||
    preflight.candidate_revision !== revision ||
    !Number.isSafeInteger(preflight.checked_at) ||
    preflight.checked_at < 1 ||
    preflight.checked_at > now + 60 ||
    now - preflight.checked_at > 15 * 60 ||
    typeof preflight.app_data_root !== 'string' ||
    !GUEST_APP_DATA_ROOT.test(preflight.app_data_root) ||
    canonicalizeMacOsAbsolutePath(preflight.app_data_root) !==
      preflight.app_data_root ||
    sha256(Buffer.from(preflight.app_data_root, 'utf8')) !==
      preflight.app_data_root_sha256 ||
    !validHex(preflight.app_data_root_sha256, HEX64)
  ) {
    fail('policy revision preflight identity/time binding is invalid')
  }
  if (preflight.record_state === 'absent') {
    if (
      preflight.record_revision !== 0 ||
      preflight.record_key_id !== null ||
      preflight.record_envelope_sha256 !== null ||
      preflight.decision !== 'new'
    ) {
      fail('absent policy revision preflight is inconsistent')
    }
    return 'new'
  }
  fail('policy revision preflight requires a clean work VM')
}

const parsedLoopbackEndpoint = (endpoint, expectedTransport) => {
  if (!endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint))
    fail('descriptor endpoint must be an object')
  exactKeys(endpoint, ['transport', 'url'], 'descriptor endpoint')
  if (
    endpoint.transport !== expectedTransport ||
    typeof endpoint.url !== 'string'
  )
    fail('descriptor endpoint transport mismatch')
  let parsed
  try {
    parsed = new URL(endpoint.url)
  } catch {
    fail('descriptor endpoint URL is invalid')
  }
  const expectedScheme = { quic: 'https', wss: 'wss', tcp: 'tcp' }[
    expectedTransport
  ]
  if (
    parsed.protocol !== `${expectedScheme}:` ||
    parsed.hostname !== '127.0.0.1' ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    !parsed.port
  )
    fail('descriptor endpoint must be numeric loopback')
  const port = Number(parsed.port)
  if (!Number.isInteger(port) || port < 20000 || port >= 60000)
    fail('descriptor endpoint port is outside the lab range')
  if (expectedTransport === 'wss' && parsed.pathname !== '/kynp')
    fail('descriptor WSS path mismatch')
  if (expectedTransport !== 'wss' && !['', '/'].includes(parsed.pathname))
    fail('descriptor endpoint path is not empty')
  return { transport: expectedTransport, url: endpoint.url, port }
}

const validateDescriptor = (descriptor, now) => {
  exactKeys(
    descriptor,
    [
      'schema_version',
      'run_id',
      'peer_public_key',
      'client_public_key',
      'endpoints',
      'echo_addresses',
      'certificate_sha256',
      'certificate_path',
      'expires_at',
    ],
    'guest descriptor',
  )
  if (
    descriptor.schema_version !== 1 ||
    !validHex(descriptor.run_id, HEX16) ||
    !validBase64Key(descriptor.peer_public_key) ||
    !validBase64Key(descriptor.client_public_key)
  )
    fail('guest descriptor identity fields are invalid')
  if (!Array.isArray(descriptor.endpoints) || descriptor.endpoints.length !== 3)
    fail('guest descriptor must contain three endpoints')
  const endpoints = [
    parsedLoopbackEndpoint(descriptor.endpoints[0], 'quic'),
    parsedLoopbackEndpoint(descriptor.endpoints[1], 'wss'),
    parsedLoopbackEndpoint(descriptor.endpoints[2], 'tcp'),
  ]
  if (new Set(endpoints.map((endpoint) => endpoint.port)).size !== 3)
    fail('guest carrier ports must be distinct')
  if (
    !Array.isArray(descriptor.echo_addresses) ||
    descriptor.echo_addresses.length !== 2 ||
    descriptor.echo_addresses[0] !== '10.88.0.2:8080' ||
    descriptor.echo_addresses[1] !== '[fd00:88::2]:8080'
  )
    fail('guest descriptor private echo contract mismatch')
  if (
    !validHex(descriptor.certificate_sha256, HEX64) ||
    typeof descriptor.certificate_path !== 'string' ||
    !path.isAbsolute(descriptor.certificate_path) ||
    descriptor.certificate_path.includes('\0') ||
    descriptor.certificate_path
      .split(path.sep)
      .some((component) => component === '.' || component === '..')
  )
    fail('guest descriptor certificate fields are invalid')
  const expectedCertificatePath = path.join(
    GUEST_LAB_ROOT,
    descriptor.run_id,
    'loopback-leaf.pem',
  )
  if (
    canonicalizeMacOsAbsolutePath(descriptor.certificate_path, 'darwin') !==
    expectedCertificatePath
  )
    fail('guest descriptor certificate path is not run-bound')
  if (
    !Number.isSafeInteger(descriptor.expires_at) ||
    descriptor.expires_at <= now ||
    descriptor.expires_at > now + MAX_LIFETIME_SECONDS
  )
    fail('guest descriptor expiry is outside the bounded window')
  return { endpoints, expiresAt: descriptor.expires_at }
}

export const validateLabProfile = (profile, descriptor, runId) => {
  exactKeys(
    profile,
    [
      'schema_version',
      'profile_id',
      'control_plane',
      'identity_ref',
      'site',
      'tunnel',
      'transports',
      'policy',
    ],
    'lab policy profile',
  )
  if (
    profile.schema_version !== 1 ||
    profile.profile_id !== `profile.vm.lab.${runId}` ||
    profile.identity_ref !== `keychain:kyclash.vm.lab.${runId}`
  )
    fail('lab policy profile identity mismatch')
  exactKeys(
    profile.site,
    ['id', 'display_name', 'private_cidrs'],
    'lab policy site',
  )
  if (
    profile.site.id !== `site.vm.lab.${runId}` ||
    profile.site.display_name !== 'KyClash disposable macOS VM lab' ||
    JSON.stringify(profile.site.private_cidrs) !==
      JSON.stringify(['10.88.0.2/32', 'fd00:88::2/128'])
  )
    fail('lab policy site constraint mismatch')
  exactKeys(
    profile.tunnel,
    ['local_addresses', 'peer_public_key', 'keepalive_seconds'],
    'lab policy tunnel',
  )
  if (
    JSON.stringify(profile.tunnel.local_addresses) !==
      JSON.stringify(['10.88.0.1/32', 'fd00:88::1/128']) ||
    profile.tunnel.peer_public_key !== descriptor.peer_public_key ||
    profile.tunnel.keepalive_seconds !== 10
  )
    fail('lab policy tunnel constraint mismatch')
  exactKeys(
    profile.transports,
    ['primary', 'fallbacks', 'endpoints'],
    'lab policy transports',
  )
  if (
    profile.transports.primary !== 'quic' ||
    JSON.stringify(profile.transports.fallbacks) !==
      JSON.stringify(['wss', 'tcp']) ||
    !Array.isArray(profile.transports.endpoints) ||
    profile.transports.endpoints.length !== 3
  )
    fail('lab policy fallback order mismatch')
  for (let index = 0; index < 3; index += 1) {
    const expected = descriptor.endpoints[index]
    const actual = profile.transports.endpoints[index]
    exactKeys(actual, ['transport', 'url'], 'lab policy endpoint')
    if (actual.transport !== expected.transport || actual.url !== expected.url)
      fail('lab policy endpoint mismatch')
  }
  let control
  try {
    control = new URL(profile.control_plane)
  } catch {
    fail('lab policy control plane URL is invalid')
  }
  if (
    control.protocol !== 'https:' ||
    control.hostname !== '127.0.0.1' ||
    control.username ||
    control.password ||
    control.search ||
    control.hash ||
    !control.port ||
    Number(control.port) !==
      Number(new URL(descriptor.endpoints[0].url).port) ||
    control.pathname !== '/control'
  )
    fail('lab policy control plane must be numeric loopback')
  exactKeys(
    profile.policy,
    [
      'connect_timeout_seconds',
      'health_interval_seconds',
      'fallback_threshold',
    ],
    'lab policy limits',
  )
  if (
    profile.policy.connect_timeout_seconds !== 5 ||
    profile.policy.health_interval_seconds !== 1 ||
    profile.policy.fallback_threshold !== 1
  )
    fail('lab policy limits mismatch')
  return true
}

const signingMessage = (keyId, algorithm, payloadBytes) =>
  Buffer.concat([
    POLICY_DOMAIN,
    Buffer.from(keyId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(algorithm, 'utf8'),
    Buffer.from([0]),
    payloadBytes,
  ])

const publicRawFromKey = (publicKey) => {
  const der = publicKey.export({ format: 'der', type: 'spki' })
  if (
    der.length !== 44 ||
    der.subarray(0, 12).toString('hex') !== '302a300506032b6570032100'
  )
    fail('unexpected Ed25519 public-key encoding')
  return der.subarray(12)
}

const canonicalBase64 = (value, expectedBytes, label) => {
  if (typeof value !== 'string') fail(`${label} must be base64`)
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length !== expectedBytes || decoded.toString('base64') !== value)
    fail(`${label} is not canonical base64`)
  return decoded
}

const signPolicyInSingleUseChild = ({ keyId, algorithm, payloadBytes }) => {
  const requestBytes = Buffer.from(
    JSON.stringify({
      key_id: keyId,
      algorithm,
      payload_base64: payloadBytes.toString('base64'),
    }),
    'utf8',
  )
  const child = spawnSync(
    process.execPath,
    [fileURLToPath(import.meta.url), POLICY_SIGNER_CHILD_ARG],
    {
      input: requestBytes,
      env: {
        PATH: '/usr/bin:/bin',
        NODE_NO_WARNINGS: '1',
      },
      maxBuffer: 64 * 1024,
    },
  )
  requestBytes.fill(0)
  if (child.error || child.status !== 0) fail('policy signer child failed')
  const stdout = Buffer.isBuffer(child.stdout)
    ? child.stdout
    : Buffer.from(child.stdout ?? '')
  const stderr = Buffer.isBuffer(child.stderr)
    ? child.stderr
    : Buffer.from(child.stderr ?? '')
  if (stderr.length !== 0) {
    stdout.fill(0)
    stderr.fill(0)
    fail('policy signer child wrote unexpected diagnostics')
  }
  const text = stdout.toString('utf8')
  stdout.fill(0)
  const lines = text.split('\n').filter((line) => line.length > 0)
  if (lines.length !== 1)
    fail('policy signer child output is not one JSON record')
  let result
  try {
    result = JSON.parse(lines[0])
  } catch {
    fail('policy signer child output is invalid JSON')
  }
  exactKeys(
    result,
    ['public_key_base64', 'signature_base64'],
    'policy signer child output',
  )
  const publicRaw = canonicalBase64(
    result.public_key_base64,
    32,
    'policy signer public key',
  )
  const signature = canonicalBase64(
    result.signature_base64,
    64,
    'policy signer signature',
  )
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicRaw,
    ]),
    format: 'der',
    type: 'spki',
  })
  const message = signingMessage(keyId, algorithm, payloadBytes)
  const verified = crypto.verify(null, message, publicKey, signature)
  message.fill(0)
  if (!verified) fail('policy signer child signature verification failed')
  return { publicRaw, signature }
}

const runPolicySignerChild = () => {
  try {
    const requestText = fs.readFileSync(0, 'utf8')
    rejectDuplicateJsonKeys(requestText, 'policy signer request')
    const request = JSON.parse(requestText)
    exactKeys(
      request,
      ['key_id', 'algorithm', 'payload_base64'],
      'policy signer request',
    )
    if (
      typeof request.key_id !== 'string' ||
      !/^lab\.vm\.[0-9a-f]{16}$/u.test(request.key_id) ||
      request.algorithm !== POLICY_ALGORITHM
    )
      fail('policy signer request identity is invalid')
    const payloadBytes = canonicalBase64(
      request.payload_base64,
      Buffer.from(request.payload_base64, 'base64').length,
      'policy signer payload',
    )
    if (payloadBytes.length === 0 || payloadBytes.length > 1024 * 1024)
      fail('policy signer payload size is invalid')
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
    const publicRaw = publicRawFromKey(publicKey)
    const message = signingMessage(
      request.key_id,
      request.algorithm,
      payloadBytes,
    )
    const signature = crypto.sign(null, message, privateKey)
    message.fill(0)
    payloadBytes.fill(0)
    process.stdout.write(
      `${JSON.stringify({
        public_key_base64: publicRaw.toString('base64'),
        signature_base64: signature.toString('base64'),
      })}\n`,
    )
  } catch {
    process.stderr.write('policy signer child refused\n')
    process.exitCode = 1
  }
}

const gitHead = () => {
  let head
  try {
    head = execFileSync(
      'git',
      ['-C', PROJECT_ROOT, 'rev-parse', '--verify', 'HEAD'],
      { encoding: 'utf8' },
    ).trim()
  } catch {
    fail('cannot resolve the source Git commit')
  }
  if (!HEX40.test(head)) fail('source Git commit is not a full SHA-1')
  return head
}

const ensureCleanSource = () => {
  const result = spawnSync(
    'git',
    [
      '-C',
      PROJECT_ROOT,
      'status',
      '--porcelain=v1',
      '--untracked-files=all',
      '--ignored=no',
    ],
    { encoding: 'utf8' },
  )
  if (result.error || result.status !== 0 || result.stdout.trim() !== '') {
    fail(
      'source tree has tracked, staged, or untracked changes; commit the reviewed candidate before preparation',
    )
  }
}

const inventory = (directory) => {
  const entries = []
  const walk = (current, relative = '') => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = path.join(current, entry.name)
      const child = relative ? path.join(relative, entry.name) : entry.name
      const stat = lstatNoSymlink(absolute, absolute)
      if (stat.isDirectory()) walk(absolute, child)
      else if (stat.isFile()) {
        const opened = readRegularFileNoFollow(absolute, absolute)
        entries.push({
          path: child,
          mode: opened.stat.mode & 0o777,
          size: opened.stat.size,
          sha256: sha256(opened.bytes),
        })
      } else fail(`${absolute} must be a regular file or directory`)
    }
  }
  walk(directory)
  return entries
}

const assertContainedInProject = (filePath, label) => {
  const relative = path.relative(PROJECT_ROOT, filePath)
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(`${label} must resolve to a file inside the project`)
  }
}

const exactArray = (actual, expected, label) => {
  if (
    !Array.isArray(actual) ||
    JSON.stringify(actual) !== JSON.stringify(expected)
  )
    fail(`${label} does not match the reviewed mapping`)
}

const reviewedInput = (filePath, label, expectedMode) => {
  const absolute = assertNoSymlinkComponents(filePath, label)
  assertContainedInProject(absolute, label)
  const opened = readRegularFileNoFollow(absolute, label)
  const mode = opened.stat.mode & 0o777
  if (mode !== expectedMode)
    fail(`${label} mode must be ${expectedMode.toString(8)}`)
  return {
    path: absolute,
    mode,
    size: opened.stat.size,
    sha256: sha256(opened.bytes),
  }
}

const ordinaryInventorySha256 = (entries) =>
  sha256(Buffer.from(JSON.stringify(entries), 'utf8'))

/**
 * Resolve every ignored/nested build input from the reviewed Tauri mapping.
 * The public marker carries only hashes; absolute host paths stay in-memory.
 */
export const collectReviewedBuildInputs = ({
  sourceRoot,
  baseConfig,
  target,
}) => {
  if (target !== 'aarch64-apple-darwin')
    fail('networking-production-vm-lab requires aarch64-apple-darwin')
  const source = assertNoSymlinkComponents(sourceRoot, 'source resources')
  const sourceStat = lstatNoSymlink(source, 'source resources')
  if (!sourceStat.isDirectory()) fail('source resources must be a directory')
  const ordinary = inventory(source)
  const ordinaryNames = ordinary.map((entry) => entry.path).sort()
  const expectedNames = [...ORDINARY_RESOURCE_ALLOWLIST].sort()
  if (JSON.stringify(ordinaryNames) !== JSON.stringify(expectedNames))
    fail('ordinary resources do not match the reviewed closed allowlist')

  const basePath = assertNoSymlinkComponents(baseConfig, 'base Tauri config')
  const baseInput = readStrictJson(basePath, 'base Tauri config')
  const base = baseInput.value
  if (
    !base.bundle ||
    typeof base.bundle !== 'object' ||
    Array.isArray(base.bundle)
  )
    fail('base Tauri config has no bundle object')
  exactArray(
    base.bundle.externalBin,
    ['sidecar/verge-mihomo', 'sidecar/verge-mihomo-alpha'],
    'base bundle.externalBin',
  )
  const files = base.bundle.macOS?.files
  if (!files || typeof files !== 'object' || Array.isArray(files))
    fail('base Tauri config has no bundle.macOS.files mapping')
  const expectedFiles = {
    'Resources/kyclash-network-sidecar':
      'sidecar/kyclash-network-sidecar-aarch64-apple-darwin',
    'Resources/kyclash-route-helper': 'helpers/kyclash-route-helper',
    'Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist':
      '../macos/route-helper/net.kysion.kyclash.route-helper.plist',
  }
  if (JSON.stringify(files) !== JSON.stringify(expectedFiles))
    fail('base bundle.macOS.files does not match the reviewed mapping')

  const configDirectory = path.dirname(basePath)
  const resolveMapped = (relative, label) =>
    ensureAbsolute(path.resolve(configDirectory, relative), label)
  const fixed = {
    networkSidecar: reviewedInput(
      resolveMapped(
        files['Resources/kyclash-network-sidecar'],
        'network sidecar',
      ),
      'network sidecar',
      0o755,
    ),
    routeHelper: reviewedInput(
      resolveMapped(files['Resources/kyclash-route-helper'], 'route helper'),
      'route helper',
      0o755,
    ),
    routeHelperPlist: reviewedInput(
      resolveMapped(
        files['Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist'],
        'route helper plist',
      ),
      'route helper plist',
      0o644,
    ),
    mihomo: reviewedInput(
      resolveMapped(
        `${base.bundle.externalBin[0]}-${target}`,
        'Mihomo sidecar',
      ),
      'Mihomo sidecar',
      0o755,
    ),
    mihomoAlpha: reviewedInput(
      resolveMapped(
        `${base.bundle.externalBin[1]}-${target}`,
        'Mihomo alpha sidecar',
      ),
      'Mihomo alpha sidecar',
      0o755,
    ),
  }
  return {
    marker: {
      ordinary_resources_inventory_sha256: ordinaryInventorySha256(ordinary),
      network_sidecar_sha256: fixed.networkSidecar.sha256,
      route_helper_sha256: fixed.routeHelper.sha256,
      route_helper_plist_sha256: fixed.routeHelperPlist.sha256,
      mihomo_sha256: fixed.mihomo.sha256,
      mihomo_alpha_sha256: fixed.mihomoAlpha.sha256,
    },
    snapshot: {
      source_root: source,
      base_config_path: basePath,
      base_config_sha256: sha256(baseInput.bytes),
      ordinary,
      fixed,
    },
  }
}

const assertBuildInputsEqual = (before, after) => {
  if (JSON.stringify(before.snapshot) !== JSON.stringify(after.snapshot))
    fail('reviewed build inputs changed during preparation')
}

export const createPolicyArtifacts = ({
  descriptor,
  endpoints,
  now,
  revision,
}) => {
  if (!Array.isArray(endpoints) || endpoints.length !== 3)
    fail('validated descriptor endpoints are required for policy creation')
  const keyId = `lab.vm.${descriptor.run_id}`
  const profile = {
    schema_version: 1,
    profile_id: `profile.vm.lab.${descriptor.run_id}`,
    control_plane: `https://127.0.0.1:${endpoints[0].port}/control`,
    identity_ref: `keychain:kyclash.vm.lab.${descriptor.run_id}`,
    site: {
      id: `site.vm.lab.${descriptor.run_id}`,
      display_name: 'KyClash disposable macOS VM lab',
      private_cidrs: ['10.88.0.2/32', 'fd00:88::2/128'],
    },
    tunnel: {
      local_addresses: ['10.88.0.1/32', 'fd00:88::1/128'],
      peer_public_key: descriptor.peer_public_key,
      keepalive_seconds: 10,
    },
    transports: {
      primary: 'quic',
      fallbacks: ['wss', 'tcp'],
      endpoints: descriptor.endpoints.map(({ transport, url }) => ({
        transport,
        url,
      })),
    },
    policy: {
      connect_timeout_seconds: 5,
      health_interval_seconds: 1,
      fallback_threshold: 1,
    },
  }
  const payload = {
    issued_at: now,
    expires_at: descriptor.expires_at,
    revision,
    profile,
  }
  const payloadBytes = Buffer.from(JSON.stringify(payload))
  const signed = signPolicyInSingleUseChild({
    keyId,
    algorithm: POLICY_ALGORITHM,
    payloadBytes,
  })
  const envelope = {
    envelope_version: 2,
    key_id: keyId,
    algorithm: POLICY_ALGORITHM,
    payload_base64: payloadBytes.toString('base64'),
    signature_base64: signed.signature.toString('base64'),
  }
  const policyBytes = Buffer.from(`${JSON.stringify(envelope)}\n`)
  const trust = {
    schema_version: 1,
    keys: [
      {
        key_id: keyId,
        public_key_base64: signed.publicRaw.toString('base64'),
      },
    ],
  }
  const trustBytes = Buffer.from(`${JSON.stringify(trust)}\n`)
  payloadBytes.fill(0)
  return {
    keyId,
    policyBytes,
    trustBytes,
    profile,
    publicKeyRaw: signed.publicRaw,
  }
}

export const prepareNetworkingProductionVmLab = ({
  runRoot,
  descriptorPath,
  policyRevisionPreflightPath,
  sourceRoot = DEFAULT_SOURCE_ROOT,
  baseConfig = DEFAULT_BASE_CONFIG,
  target = 'aarch64-apple-darwin',
  now = Math.floor(Date.now() / 1000),
  revision = now,
  policyExpiryCeiling,
  requireClean = true,
} = {}) => {
  if (
    !Number.isSafeInteger(now) ||
    now < 1 ||
    !Number.isSafeInteger(revision) ||
    revision < 1
  )
    fail('now/revision must be positive safe integers')
  if (target !== 'aarch64-apple-darwin')
    fail('networking-production-vm-lab requires aarch64-apple-darwin')

  // Descriptor parsing and all semantic validation precede creation of any
  // run-root output. Invalid guest input therefore has no filesystem effect.
  const descriptorFile = assertNoSymlinkComponents(
    descriptorPath,
    'guest descriptor',
  )
  if (path.basename(descriptorFile) !== 'guest-descriptor.json')
    fail('guest descriptor must be named guest-descriptor.json')
  const descriptorInput = readStrictJson(descriptorFile, descriptorFile)
  const descriptor = descriptorInput.value
  const validated = validateDescriptor(descriptor, now)
  const validatedPolicyExpiryCeiling = validatePolicyExpiryCeiling({
    now,
    expiresAt: validated.expiresAt,
    policyExpiryCeiling,
  })
  const preflightFile = assertNoSymlinkComponents(
    policyRevisionPreflightPath,
    'policy revision preflight',
  )
  if (path.basename(preflightFile) !== LAB_REVISION_PREFLIGHT_RESOURCE)
    fail(
      `policy revision preflight must be named ${LAB_REVISION_PREFLIGHT_RESOURCE}`,
    )
  const preflightInput = readStrictJson(
    preflightFile,
    'policy revision preflight',
  )
  validatePolicyRevisionPreflight({
    preflight: preflightInput.value,
    runId: descriptor.run_id,
    revision,
    now,
  })

  const root = ensureAbsolute(runRoot, 'run root')
  assertNoSymlinkComponents(path.dirname(root), 'run root parent')
  const source = assertNoSymlinkComponents(sourceRoot, 'source resources')
  const config = assertNoSymlinkComponents(baseConfig, 'base Tauri config')
  if (path.resolve(source) !== path.resolve(DEFAULT_SOURCE_ROOT))
    fail('candidate source resources must be the reviewed repository root')
  if (path.resolve(config) !== path.resolve(DEFAULT_BASE_CONFIG))
    fail('candidate base Tauri config must be the reviewed repository file')
  const sourceCommit = gitHead()
  if (requireClean) ensureCleanSource()
  const buildInputsBefore = collectReviewedBuildInputs({
    sourceRoot: source,
    baseConfig: config,
    target,
  })

  try {
    fs.mkdirSync(root, { mode: 0o700 })
  } catch (error) {
    fail(
      `refusing to create run root ${root}: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  fs.chmodSync(root, 0o700)
  const publicRoot = path.join(root, 'public')
  const stagedResources = path.join(publicRoot, 'resources')
  const overlayPath = path.join(
    publicRoot,
    'tauri.networking-production-vm-lab.macos.conf.json',
  )
  fs.mkdirSync(publicRoot, { mode: 0o700 })
  fs.chmodSync(publicRoot, 0o700)
  const publicDescriptorPath = path.join(publicRoot, 'guest-descriptor.json')
  writeFileNoReplace(publicDescriptorPath, descriptorInput.bytes, 0o644)
  const publicPolicyRevisionPreflightPath = path.join(
    publicRoot,
    LAB_REVISION_PREFLIGHT_RESOURCE,
  )
  writeFileNoReplace(
    publicPolicyRevisionPreflightPath,
    preflightInput.bytes,
    0o644,
  )
  const artifacts = createPolicyArtifacts({
    descriptor,
    endpoints: validated.endpoints,
    now,
    revision,
  })
  const policyPath = path.join(publicRoot, LAB_POLICY_RESOURCE)
  const trustPath = path.join(publicRoot, LAB_TRUST_RESOURCE)
  writeFileNoReplace(policyPath, artifacts.policyBytes, 0o644)
  writeFileNoReplace(trustPath, artifacts.trustBytes, 0o644)
  stagePublicResources({
    sourceRoot: source,
    stagedResources,
    labFiles: {
      [LAB_POLICY_RESOURCE]: policyPath,
      [LAB_TRUST_RESOURCE]: trustPath,
    },
    ordinaryAllowlist: ORDINARY_RESOURCE_ALLOWLIST,
  })
  createNetworkingProductionOverlay({
    stagedResources,
    baseConfig: config,
    output: overlayPath,
  })
  const marker = {
    schema_version: 1,
    candidate_kind: 'networking-production-vm-lab',
    run_id: descriptor.run_id,
    source_commit: sourceCommit,
    target,
    vm_name: 'kyclash-macos-lab-work',
    policy_key_id: artifacts.keyId,
    policy_revision: revision,
    issued_at: now,
    expires_at: descriptor.expires_at,
    policy_expiry_ceiling_epoch: validatedPolicyExpiryCeiling,
    policy_envelope_sha256: sha256(artifacts.policyBytes),
    policy_trust_sha256: sha256(artifacts.trustBytes),
    guest_descriptor_sha256: sha256(descriptorInput.bytes),
    policy_revision_preflight_sha256: sha256(preflightInput.bytes),
    tauri_overlay_sha256: sha256(
      readRegularFileNoFollow(overlayPath, overlayPath).bytes,
    ),
    mihomo_final_sha256: PENDING_FINAL_COMPONENT_SHA256,
    mihomo_alpha_final_sha256: PENDING_FINAL_COMPONENT_SHA256,
    build_inputs: buildInputsBefore.marker,
  }
  const markerBytes = Buffer.from(`${JSON.stringify(marker)}\n`)
  const markerPath = path.join(publicRoot, LAB_MARKER_RESOURCE)
  writeFileNoReplace(markerPath, markerBytes, 0o644)
  writeFileNoReplace(
    path.join(stagedResources, LAB_MARKER_RESOURCE),
    markerBytes,
    0o644,
  )
  const buildInputsAfter = collectReviewedBuildInputs({
    sourceRoot: source,
    baseConfig: config,
    target,
  })
  assertBuildInputsEqual(buildInputsBefore, buildInputsAfter)
  if (gitHead() !== sourceCommit)
    fail('source Git commit changed during preparation')
  if (requireClean) ensureCleanSource()
  requireDirectory(publicRoot, publicRoot)
  requireDirectory(stagedResources, stagedResources)
  return {
    runRoot: root,
    publicRoot,
    stagedResources,
    overlayPath,
    policyPath,
    trustPath,
    markerPath,
    descriptorPath: publicDescriptorPath,
    policyRevisionPreflightPath: publicPolicyRevisionPreflightPath,
    runId: descriptor.run_id,
    sourceCommit: marker.source_commit,
    target,
    revision,
    expiresAt: validated.expiresAt,
    policyExpiryCeiling: validatedPolicyExpiryCeiling,
    publicKeySha256: sha256(artifacts.publicKeyRaw),
  }
}

const GENERATOR_OPTIONS = new Set([
  '--descriptor',
  '--policy-revision-preflight',
  '--run-root',
  '--target',
  '--revision',
  '--policy-expiry-ceiling',
])

const positiveDecimal = (value, name) => {
  if (!/^[1-9][0-9]*$/u.test(value))
    fail(`${name} must be a canonical positive decimal integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed))
    fail(`${name} must be a canonical positive decimal integer`)
  return parsed
}

export const parseGeneratorOptions = (argv) => {
  if (!Array.isArray(argv) || argv.length % 2 !== 0)
    fail('generator options must be exact name/value pairs')
  const values = new Map()
  for (let position = 0; position < argv.length; position += 2) {
    const name = argv[position]
    const value = argv[position + 1]
    if (!GENERATOR_OPTIONS.has(name)) fail(`unknown generator option: ${name}`)
    if (values.has(name)) fail(`duplicate generator option: ${name}`)
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.startsWith('--')
    )
      fail(`${name} requires a value`)
    values.set(name, value)
  }
  for (const required of [
    '--descriptor',
    '--policy-revision-preflight',
    '--run-root',
    '--revision',
    '--policy-expiry-ceiling',
  ]) {
    if (!values.has(required))
      fail(`missing required generator option: ${required}`)
  }
  return {
    descriptorPath: values.get('--descriptor'),
    policyRevisionPreflightPath: values.get('--policy-revision-preflight'),
    runRoot: values.get('--run-root'),
    target: values.get('--target') ?? 'aarch64-apple-darwin',
    revision: positiveDecimal(values.get('--revision'), '--revision'),
    policyExpiryCeiling: positiveDecimal(
      values.get('--policy-expiry-ceiling'),
      '--policy-expiry-ceiling',
    ),
  }
}

const runCli = () => {
  const {
    descriptorPath,
    policyRevisionPreflightPath,
    runRoot,
    target,
    revision,
    policyExpiryCeiling,
  } = parseGeneratorOptions(process.argv.slice(2))
  const result = prepareNetworkingProductionVmLab({
    descriptorPath,
    policyRevisionPreflightPath,
    runRoot,
    target,
    revision,
    policyExpiryCeiling,
  })
  process.stdout.write(
    `${JSON.stringify({ run_root: result.runRoot, public_root: result.publicRoot, run_id: result.runId, target: result.target, revision: result.revision })}\n`,
  )
}

if (process.argv[2] === POLICY_SIGNER_CHILD_ARG) {
  runPolicySignerChild()
} else if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    runCli()
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}

export {
  exactKeys,
  rejectDuplicateJsonKeys,
  signingMessage,
  validateDescriptor,
}
