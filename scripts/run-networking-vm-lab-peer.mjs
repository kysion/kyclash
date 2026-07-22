import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  GUEST_USER,
  SELECTED_VM_NAME,
  canonicalGuestRunRoot,
  resolveSelectedVmIp,
} from './copy-networking-vm-lab-fixtures.mjs'

// This runner is deliberately host-only orchestration for the disposable
// Virtualization.framework guest. It never starts the App, a sidecar, a
// helper, or a route on the host. The SSH child is intentionally persistent:
// the guest peer treats stdin EOF and parent loss as an ownership signal and
// removes its descriptor before exiting.
export const PEER_RUNNER_ENVIRONMENT = 'local-virtualization-framework'
export const PEER_VM_CONFIRMATION =
  'authorized-kyclash-virtualization-framework-vm'
export const PEER_RUNTIME_TARGET = 'kyclash-macos-lab-work'
export const PEER_ENVIRONMENT = Object.freeze({
  KYCLASH_RUNNER_ENVIRONMENT: PEER_RUNNER_ENVIRONMENT,
  KYCLASH_VM_LAB_CONFIRM: PEER_VM_CONFIRMATION,
  KYCLASH_RUNTIME_TARGET: PEER_RUNTIME_TARGET,
})

export const PEER_BINARY_NAME = 'kyclash-networking-system-lab'
export const PEER_DESCRIPTOR_NAME = 'guest-descriptor.json'
export const PEER_MANIFEST_NAME = 'peer-manifest.json'
export const PEER_CLIENT_PUBLIC_KEY_NAME = 'client-public.key'
export const PEER_ROOT_CERT_NAME = 'loopback-trust-root.pem'
export const PEER_LEAF_CERT_NAME = 'loopback-leaf.pem'
export const PEER_LEAF_KEY_NAME = 'loopback-leaf.key'

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const SSH_ROOT = path.join(PROJECT_ROOT, 'target', 'macos-vm-lab', 'ssh')
const SSH_KEY = path.join(SSH_ROOT, 'id_ed25519')
const SSH_KNOWN_HOSTS = path.join(SSH_ROOT, 'known_hosts')
const HEX16 = /^[0-9a-f]{16}$/u
const IPV4 =
  /^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/u
const DECIMAL = /^[1-9][0-9]*$/u
const MINIMUM_REMAINING_SECONDS = 10 * 60
const MAX_PEER_LIFETIME_SECONDS = 24 * 60 * 60
const DEFAULT_READY_TIMEOUT_MS = 30_000
const MAX_READY_FRAME_BYTES = 8 * 1024

const fail = (message) => {
  throw new Error(message)
}

const usage = () =>
  [
    'usage:',
    '  run-networking-vm-lab-peer.mjs --run-id <16-lowercase-hex> --expires-at <epoch>',
  ].join('\n')

const parsePositiveInteger = (value, label) => {
  if (typeof value !== 'string' || !DECIMAL.test(value))
    fail(`${label} must be a positive decimal integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed <= 0)
    fail(`${label} is outside the safe integer range`)
  return parsed
}

export const peerPaths = (runId) => {
  if (typeof runId !== 'string' || !HEX16.test(runId))
    fail('run id must be exactly 16 lowercase hexadecimal characters')
  const root = canonicalGuestRunRoot(runId)
  return Object.freeze({
    root,
    binary: `${root}/${PEER_BINARY_NAME}`,
    clientPublicKey: `${root}/${PEER_CLIENT_PUBLIC_KEY_NAME}`,
    privateDir: root,
    descriptor: `${root}/${PEER_DESCRIPTOR_NAME}`,
    manifest: `${root}/${PEER_MANIFEST_NAME}`,
    rootCert: `${root}/${PEER_ROOT_CERT_NAME}`,
    leafCert: `${root}/${PEER_LEAF_CERT_NAME}`,
    leafKey: `${root}/${PEER_LEAF_KEY_NAME}`,
  })
}

export const parsePeerRunnerOptions = (argv) => {
  if (!Array.isArray(argv) || argv.length === 0) fail(usage())
  let runId
  let expiresAt
  const seen = new Set()
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index]
    if (option === '--help') {
      if (argv.length !== 1) fail('cannot combine --help with other options')
      return { help: true }
    }
    if (option !== '--run-id' && option !== '--expires-at')
      fail(`unknown option: ${option}`)
    if (seen.has(option)) fail(`duplicate option: ${option}`)
    seen.add(option)
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--'))
      fail(`${option} requires a value`)
    index += 1
    if (option === '--run-id') {
      if (!HEX16.test(value))
        fail('--run-id must be exactly 16 lowercase hexadecimal characters')
      runId = value
    } else {
      expiresAt = parsePositiveInteger(value, '--expires-at')
    }
  }
  if (runId === undefined || expiresAt === undefined)
    fail('peer runner requires --run-id and --expires-at')
  return { help: false, runId, expiresAt }
}

export const validatePeerSpec = (spec, now = Math.floor(Date.now() / 1000)) => {
  if (!spec || typeof spec !== 'object') fail('peer specification is required')
  if (!HEX16.test(spec.runId ?? ''))
    fail('peer specification run id is invalid')
  if (!Number.isSafeInteger(spec.expiresAt) || spec.expiresAt <= 0)
    fail('peer specification expiry is invalid')
  if (!Number.isSafeInteger(now) || now <= 0) fail('current epoch is invalid')
  const remaining = spec.expiresAt - now
  if (remaining < MINIMUM_REMAINING_SECONDS)
    fail('peer specification must remain valid for at least ten minutes')
  if (remaining > MAX_PEER_LIFETIME_SECONDS)
    fail('peer specification exceeds the 24-hour peer lifetime')
  return Object.freeze({ runId: spec.runId, expiresAt: spec.expiresAt })
}

const shellQuote = (value, label) => {
  if (typeof value !== 'string' || value.length === 0)
    fail(`${label} must be a non-empty string`)
  // The command is assembled for the remote login shell. Reject control
  // characters before quoting so a future path change cannot introduce a
  // second command or an escaped newline.
  if (
    [...value].some((character) => {
      const code = character.codePointAt(0)
      return code < 0x20 || code === 0x7f
    })
  )
    fail(`${label} contains a control character`)
  return `'${value.replaceAll("'", "'\\''")}'`
}

export const buildPeerRemoteCommand = (spec, now) => {
  const validated = validatePeerSpec(spec, now)
  const paths = peerPaths(validated.runId)
  const environment = Object.entries(PEER_ENVIRONMENT).map(([key, value]) =>
    shellQuote(`${key}=${value}`, 'guest environment assignment'),
  )
  const argumentsForPeer = [
    paths.binary,
    '--run-id',
    validated.runId,
    '--client-public-key',
    paths.clientPublicKey,
    '--private-dir',
    paths.privateDir,
    '--descriptor',
    paths.descriptor,
    '--manifest',
    paths.manifest,
    '--root-cert',
    paths.rootCert,
    '--leaf-cert',
    paths.leafCert,
    '--leaf-key',
    paths.leafKey,
    '--expires-at',
    String(validated.expiresAt),
  ].map((value, index) =>
    shellQuote(value, index === 0 ? 'peer executable' : 'peer argument'),
  )
  // The markers are assignments to /usr/bin/env in the guest, not host
  // process environment variables. This makes the boundary explicit even
  // when the host's SSH client has no SendEnv configuration.
  return ['/usr/bin/env', ...environment, ...argumentsForPeer].join(' ')
}

const hostEnvironment = () => ({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LC_ALL: 'C',
})

const assertHostAppleSilicon = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    fail('VM peer runner must run on an Apple Silicon macOS host')
}

const assertRegular = (filePath, mode, label) => {
  let stat
  try {
    stat = fs.lstatSync(filePath)
  } catch {
    fail(`${label} is missing`)
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    fail(`${label} must be a regular file`)
  if ((stat.mode & 0o777) !== mode)
    fail(`${label} mode must be ${mode.toString(8)}`)
  if ((stat.mode & 0o022) !== 0)
    fail(`${label} must not be group/other writable`)
}

const assertSshMaterial = () => {
  let root
  try {
    root = fs.lstatSync(SSH_ROOT)
  } catch {
    fail('SSH material directory is missing')
  }
  if (root.isSymbolicLink() || !root.isDirectory() || (root.mode & 0o077) !== 0)
    fail('SSH material directory must be private')
  assertRegular(SSH_KEY, 0o600, 'SSH private key')
  assertRegular(SSH_KNOWN_HOSTS, 0o644, 'SSH known_hosts')
}

const sshArgs = (ip, remoteCommand) => {
  if (!IPV4.test(ip)) fail('selected work VM returned an invalid IPv4 address')
  return [
    '-q',
    '-T',
    '-o',
    'BatchMode=yes',
    '-o',
    'ConnectTimeout=10',
    '-o',
    'ServerAliveInterval=5',
    '-o',
    'ServerAliveCountMax=2',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${SSH_KNOWN_HOSTS}`,
    '-o',
    'IdentitiesOnly=yes',
    '-i',
    SSH_KEY,
    `${GUEST_USER}@${ip}`,
    remoteCommand,
  ]
}

export const buildPeerSshArgs = (ip, spec, now) =>
  sshArgs(ip, buildPeerRemoteCommand(spec, now))

const makeExitPromise = (child) =>
  new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
  })

const attachReadyProtocol = (child, runId, timeoutMs) => {
  if (!child.stdout || typeof child.stdout.on !== 'function')
    fail('persistent peer SSH stdout must be a readable stream')
  // SSH stderr is intentionally discarded, but it must be drained while the
  // session stays alive; otherwise a noisy remote shell could fill the pipe
  // and stall the very stdin ownership channel that keeps the peer running.
  if (child.stderr && typeof child.stderr.on === 'function')
    child.stderr.on('data', () => {})
  let buffer = ''
  let settled = false
  let resolveReady
  let rejectReady
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve
    rejectReady = reject
  })
  const settleFailure = (error) => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    rejectReady(error)
  }
  const consume = (chunk) => {
    buffer += Buffer.from(chunk).toString('utf8')
    if (!settled && buffer.length > MAX_READY_FRAME_BYTES) {
      settleFailure(new Error('persistent peer readiness frame is too large'))
      return
    }
    while (true) {
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      if (line === 'KYCLASH_SYSTEM_LAB_READY' && !settled) {
        settled = true
        clearTimeout(timer)
        resolveReady({ runId })
      }
      // The guest peer has a fixed redacted stdout contract. Ignore any
      // post-ready records here; callers receive readiness only and never
      // accidentally copy private peer output into host logs.
    }
  }
  child.stdout.on('data', consume)
  if (typeof child.once === 'function') {
    child.once('error', (error) =>
      settleFailure(new Error(`persistent peer SSH failed: ${error.message}`)),
    )
    child.once('exit', (code, signal) => {
      if (!settled)
        settleFailure(
          new Error(
            `persistent peer exited before readiness (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
          ),
        )
    })
  }
  const timer = setTimeout(() => {
    settleFailure(new Error('persistent peer readiness timed out'))
  }, timeoutMs)
  return ready
}

// Start a peer without ever closing its stdin. The caller owns the returned
// session and must retain it until Connect/health testing and cleanup finish.
// `spawnImpl` exists solely for contract tests; production uses node:child_process.spawn.
export const startPersistentPeerSession = ({
  ip,
  spec,
  now = Math.floor(Date.now() / 1000),
  readyTimeoutMs = DEFAULT_READY_TIMEOUT_MS,
  spawnImpl = spawn,
} = {}) => {
  assertHostAppleSilicon()
  assertSshMaterial()
  if (!Number.isSafeInteger(readyTimeoutMs) || readyTimeoutMs < 1)
    fail('peer readiness timeout is invalid')
  const validated = validatePeerSpec(spec, now)
  const remoteCommand = buildPeerRemoteCommand(validated, now)
  const args = sshArgs(ip, remoteCommand)
  const child = spawnImpl('/usr/bin/ssh', args, {
    env: hostEnvironment(),
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  if (!child?.stdin || typeof child.stdin.end !== 'function')
    fail('persistent peer SSH stdin must be writable')
  const ready = attachReadyProtocol(child, validated.runId, readyTimeoutMs)
  const exited = makeExitPromise(child)
  let closed = false
  return Object.freeze({
    child,
    args: Object.freeze([...args]),
    runId: validated.runId,
    ready,
    exited,
    // Calling close is the explicit lifecycle boundary. It sends EOF to the
    // guest peer, allowing its parent/EOF watcher to remove the descriptor.
    close() {
      if (closed) return
      closed = true
      if (!child.stdin.destroyed) child.stdin.end()
    },
  })
}

const main = async () => {
  const options = parsePeerRunnerOptions(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  const spec = validatePeerSpec(options)
  const ip = resolveSelectedVmIp()
  const session = startPersistentPeerSession({ ip, spec })
  // Deliberately pipe, never end, the controlling Terminal's stdin. Keeping
  // this process attached is what keeps the guest peer owned and alive.
  process.stdin.pipe(session.child.stdin)
  const stop = () => session.close()
  process.once('SIGINT', stop)
  process.once('SIGTERM', stop)
  try {
    await session.ready
    process.stdout.write(
      `kyclash_vm_peer_ready=1\nselected_vm=${SELECTED_VM_NAME}\nrun_id=${spec.runId}\n`,
    )
    const result = await session.exited
    if (result.code !== 0) fail('persistent peer SSH exited unexpectedly')
  } finally {
    process.stdin.unpipe(session.child.stdin)
    process.removeListener('SIGINT', stop)
    process.removeListener('SIGTERM', stop)
  }
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  })
}

export { shellQuote }
