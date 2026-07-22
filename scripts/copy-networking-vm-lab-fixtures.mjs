import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  rejectDuplicateJsonKeys,
  validateDescriptor,
  validatePolicyRevisionPreflight,
} from './generate-networking-production-vm-lab.mjs'

// Host-only, create-once copier for the disposable networking VM lab.  This
// command never launches KyClash, installs a package, or accepts a password.
export const SELECTED_VM_NAME = 'kyclash-macos-lab-work'
export const GUEST_USER = 'supen'
export const GUEST_FIXTURE_PATH =
  '/Users/supen/kyclash-macos-vm-keychain-trust-fixture.sh'
export const GUEST_RUN_ROOT = '/private/var/tmp/kyclash-networking-vm-lab'
export const GUEST_DESCRIPTOR_NAME = 'guest-descriptor.json'
export const GUEST_PREFLIGHT_NAME = 'policy-revision-preflight.json'
export const GUEST_MANIFEST_NAME = 'manifest.txt'
export const HOST_CEILING_NAME = 'policy-expiry-ceiling-epoch.txt'

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const VM_LAB_SCRIPT = path.join(PROJECT_ROOT, 'scripts', 'macos-vm-lab.sh')
const SSH_ROOT = path.join(PROJECT_ROOT, 'target', 'macos-vm-lab', 'ssh')
const SSH_KEY = path.join(SSH_ROOT, 'id_ed25519')
const SSH_KNOWN_HOSTS = path.join(SSH_ROOT, 'known_hosts')
const FIXTURE_SOURCE = path.join(
  PROJECT_ROOT,
  'scripts',
  'macos-vm-keychain-trust-fixture.sh',
)
const HEX16 = /^[0-9a-f]{16}$/u
const HEX40 = /^[0-9a-f]{40}$/u
const HEX64 = /^[0-9a-f]{64}$/u
const SAFE_BASENAME = /^[A-Za-z0-9._-]+$/u
const IPV4 =
  /^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/u
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0
const GUEST_DESCRIPTOR_MAX_BYTES = 32 * 1024
const GUEST_PREFLIGHT_MAX_BYTES = 64 * 1024

const ARTIFACTS = Object.freeze([
  {
    binary: 'kyclash-system-trust-probe',
    provenance: 'kyclash-system-trust-probe.provenance.json',
    source: 'network-sidecar/cmd/kyclash-system-trust-probe',
  },
  {
    binary: 'kyclash-keychain-public-lab',
    provenance: 'kyclash-keychain-public-lab.provenance.json',
    source: null,
    feature: 'networking-system-lab',
  },
  {
    binary: 'kyclash-networking-system-lab',
    provenance: 'kyclash-networking-system-lab.provenance.json',
    source: 'network-sidecar/cmd/kyclash-networking-system-lab',
  },
])

const fail = (message) => {
  throw new Error(message)
}

const usage = () =>
  [
    'usage:',
    '  copy-networking-vm-lab-fixtures.mjs --shell-only',
    '  copy-networking-vm-lab-fixtures.mjs --run-id <16-lowercase-hex> --build-root <absolute-private-dir>',
    '  copy-networking-vm-lab-fixtures.mjs --pull-run --run-id <16-lowercase-hex> --output-root <new-0700-root> [--guest-root <canonical-run-root>]',
  ].join('\n')

const assertNoSymlinkComponents = (filePath, label = filePath) => {
  const absolute = path.resolve(filePath)
  const parsed = path.parse(absolute)
  let current = parsed.root
  for (const component of absolute
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean)) {
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
    if (stat.isSymbolicLink()) fail(`${label} contains a symlink component`)
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

const assertRegular = (filePath, label, mode) => {
  assertNoSymlinkComponents(filePath, label)
  const stat = lstatNoSymlink(filePath, label)
  if (!stat.isFile()) fail(`${label} must be a regular file`)
  if (mode !== undefined && (stat.mode & 0o777) !== mode)
    fail(`${label} mode must be ${mode.toString(8)}`)
  if ((stat.mode & 0o022) !== 0)
    fail(`${label} must not be group/other writable`)
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    fail(`${label} must be owned by the invoking user`)
  return stat
}

const readNoFollow = (filePath, label) => {
  const absolute = assertNoSymlinkComponents(filePath, label)
  let descriptor
  try {
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | NOFOLLOW)
    const before = fs.fstatSync(descriptor)
    if (!before.isFile()) fail(`${label} must be a regular file`)
    if ((before.mode & 0o022) !== 0)
      fail(`${label} must not be group/other writable`)
    const named = lstatNoSymlink(absolute, label)
    if (before.dev !== named.dev || before.ino !== named.ino)
      fail(`${label} changed while opening`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor)
    if (
      !after.isFile() ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      bytes.length !== after.size
    )
      fail(`${label} changed while reading`)
    return { bytes, stat: after, path: absolute }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(label)) throw error
    fail(
      `${label} cannot be read without following links: ${error instanceof Error ? error.message : String(error)}`,
    )
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const strictJson = (bytes, label) => {
  if (bytes.length > 64 * 1024) fail(`${label} is unexpectedly large`)
  const text = bytes.toString('utf8')
  rejectDuplicateJsonKeys(text, label)
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail(`${label} is not valid JSON`)
  }
  // The reviewed builders emit this exact form. It also rejects duplicate
  // keys instead of allowing JSON.parse's last-value behaviour.
  if (`${JSON.stringify(value, null, 2)}\n` !== text)
    fail(`${label} is not canonical provenance JSON`)
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be a JSON object`)
  return value
}

const strictGuestJson = (bytes, label, maximum) => {
  if (bytes.length === 0 || bytes.length > maximum)
    fail(`${label} size is outside the reviewed bound`)
  const text = bytes.toString('utf8')
  rejectDuplicateJsonKeys(text, label)
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail(`${label} is not valid JSON`)
  }
  // The Go peer and Rust helper both publish compact JSON followed by one
  // newline. Requiring the exact round-trip rejects duplicate keys and hidden
  // trailing records while retaining their public wire representation.
  if (`${JSON.stringify(value)}\n` !== text)
    fail(`${label} is not canonical guest JSON`)
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be a JSON object`)
  return value
}

const exactKeys = (value, expected, label) => {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (
    actual.length !== wanted.length ||
    actual.some((key, i) => key !== wanted[i])
  )
    fail(`${label} has unexpected fields`)
}

const validHex = (value, pattern) =>
  typeof value === 'string' && pattern.test(value)

export const parseCopyOptions = (argv) => {
  if (argv.length === 0) fail(usage())
  let shellOnly = false
  let pullRun = false
  let runId
  let buildRoot
  let outputRoot
  let guestRoot
  const seen = new Set()
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index]
    if (option === '--help') {
      if (argv.length !== 1) fail('cannot combine --help with other options')
      return { help: true }
    }
    if (option === '--shell-only') {
      if (seen.has(option)) fail(`duplicate option: ${option}`)
      seen.add(option)
      shellOnly = true
      continue
    }
    if (option === '--pull-run') {
      if (seen.has(option)) fail(`duplicate option: ${option}`)
      seen.add(option)
      pullRun = true
      continue
    }
    if (
      option !== '--run-id' &&
      option !== '--build-root' &&
      option !== '--output-root' &&
      option !== '--guest-root'
    )
      fail(`unknown option: ${option}`)
    if (seen.has(option)) fail(`duplicate option: ${option}`)
    seen.add(option)
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--'))
      fail(`${option} requires a value`)
    index += 1
    if (option === '--run-id') runId = value
    else if (option === '--build-root') buildRoot = value
    else if (option === '--output-root') outputRoot = value
    else guestRoot = value
  }
  if (
    shellOnly &&
    (pullRun ||
      runId !== undefined ||
      buildRoot !== undefined ||
      outputRoot !== undefined ||
      guestRoot !== undefined)
  )
    fail('--shell-only cannot be combined with pull or copy options')
  if (pullRun && (shellOnly || buildRoot !== undefined))
    fail('--pull-run cannot be combined with --shell-only or --build-root')
  if (
    !shellOnly &&
    !pullRun &&
    (runId === undefined || buildRoot === undefined)
  )
    fail('full fixture copy requires --run-id and --build-root')
  if (pullRun && (runId === undefined || outputRoot === undefined))
    fail('pull run requires --run-id and --output-root')
  if (!pullRun && (outputRoot !== undefined || guestRoot !== undefined))
    fail('--output-root and --guest-root require --pull-run')
  if (runId !== undefined && !HEX16.test(runId))
    fail('--run-id must be exactly 16 lowercase hexadecimal characters')
  if (buildRoot !== undefined && !path.isAbsolute(buildRoot))
    fail('--build-root must be an absolute path')
  if (outputRoot !== undefined && !path.isAbsolute(outputRoot))
    fail('--output-root must be an absolute path')
  if (guestRoot !== undefined && !path.isAbsolute(guestRoot))
    fail('--guest-root must be an absolute path')
  if (
    guestRoot !== undefined &&
    runId !== undefined &&
    guestRoot !== canonicalGuestRunRoot(runId)
  )
    fail('--guest-root must be the exact canonical disposable guest run root')
  return {
    help: false,
    shellOnly,
    pullRun,
    runId,
    buildRoot,
    outputRoot,
    guestRoot,
  }
}

export const canonicalGuestRunRoot = (runId) => {
  if (!HEX16.test(runId))
    fail('run id must be exactly 16 lowercase hexadecimal characters')
  return `${GUEST_RUN_ROOT}/${runId}`
}

const validateGuestRunRoot = (guestRoot, runId) => {
  const expected = canonicalGuestRunRoot(runId)
  if (guestRoot !== expected)
    fail('--guest-root must be the exact canonical disposable guest run root')
  return expected
}

const assertPrivateBuildRoot = (buildRoot) => {
  if (!path.isAbsolute(buildRoot)) fail('build root must be absolute')
  const absolute = assertNoSymlinkComponents(buildRoot, 'build root')
  const stat = lstatNoSymlink(absolute, 'build root')
  if (!stat.isDirectory()) fail('build root must be a directory')
  if ((stat.mode & 0o777) !== 0o700) fail('build root must be private (0700)')
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    fail('build root must be owned by the invoking user')
  return absolute
}

const assertSshMaterial = () => {
  const rootStat = lstatNoSymlink(SSH_ROOT, 'SSH material directory')
  if (!rootStat.isDirectory() || (rootStat.mode & 0o077) !== 0)
    fail('SSH material directory must be private')
  assertRegular(SSH_KEY, 'SSH private key', 0o600)
  assertRegular(SSH_KNOWN_HOSTS, 'SSH known_hosts', 0o644)
}

const assertHostAppleSilicon = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    fail('VM fixture copier must run on an Apple Silicon macOS host')
}

const assertCleanSource = () => {
  const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C' }
  const result = spawnSync(
    '/usr/bin/git',
    [
      '-C',
      PROJECT_ROOT,
      'status',
      '--porcelain=v1',
      '--untracked-files=all',
      '--ignored=no',
    ],
    { encoding: 'utf8', env },
  )
  if (result.error || result.status !== 0 || result.stdout.trim() !== '')
    fail('fixture copy requires the committed reviewed source tree')
  const head = execFileSync(
    '/usr/bin/git',
    ['-C', PROJECT_ROOT, 'rev-parse', '--verify', 'HEAD'],
    { encoding: 'utf8', env },
  ).trim()
  if (!HEX40.test(head)) fail('cannot resolve the reviewed source commit')
  return head
}

const artifactPaths = (buildRoot) =>
  ARTIFACTS.map((artifact) => ({
    ...artifact,
    binaryPath: path.join(buildRoot, artifact.binary),
    provenancePath: path.join(buildRoot, artifact.provenance),
  }))

const validateProvenance = (
  artifact,
  binaryBytes,
  provenanceBytes,
  sourceCommit,
) => {
  const value = strictJson(provenanceBytes, artifact.provenance)
  if (artifact.feature) {
    exactKeys(
      value,
      [
        'schema_version',
        'build_target',
        'runtime_target',
        'feature',
        'binary',
        'source_commit',
        'cargo_version',
        'sha256',
      ],
      artifact.provenance,
    )
    if (
      value.schema_version !== 1 ||
      value.build_target !== 'host-macos-arm64' ||
      value.runtime_target !== SELECTED_VM_NAME ||
      value.feature !== artifact.feature ||
      value.binary !== artifact.binary ||
      value.source_commit !== sourceCommit
    )
      fail(`${artifact.provenance} identity is invalid`)
  } else {
    exactKeys(
      value,
      [
        'schema_version',
        'build_target',
        'runtime_target',
        'target',
        'cgo_enabled',
        'source',
        'source_commit',
        'go_version',
        'go_sha256',
        'sha256',
      ],
      artifact.provenance,
    )
    if (
      value.schema_version !== 1 ||
      value.build_target !== 'host-build' ||
      value.runtime_target !== SELECTED_VM_NAME ||
      value.target !== 'aarch64-apple-darwin' ||
      value.cgo_enabled !== false ||
      value.source !== artifact.source ||
      value.source_commit !== sourceCommit ||
      typeof value.go_version !== 'string' ||
      !validHex(value.go_sha256, HEX64)
    )
      fail(`${artifact.provenance} identity is invalid`)
  }
  if (!validHex(value.sha256, HEX64) || value.sha256 !== sha256(binaryBytes))
    fail(`${artifact.provenance} does not bind binary bytes`)
  return value
}

export const validateBuildArtifacts = (buildRoot, sourceCommit) => {
  if (!validHex(sourceCommit, HEX40)) fail('source commit must be a full SHA-1')
  const root = assertPrivateBuildRoot(buildRoot)
  const records = []
  for (const artifact of artifactPaths(root)) {
    assertRegular(artifact.binaryPath, artifact.binary, 0o755)
    const binary = readNoFollow(artifact.binaryPath, artifact.binary)
    assertRegular(artifact.provenancePath, artifact.provenance, 0o600)
    const provenance = readNoFollow(
      artifact.provenancePath,
      artifact.provenance,
    )
    const metadata = validateProvenance(
      artifact,
      binary.bytes,
      provenance.bytes,
      sourceCommit,
    )
    records.push({
      ...artifact,
      binaryBytes: binary.bytes,
      binarySha256: sha256(binary.bytes),
      provenanceBytes: provenance.bytes,
      provenanceSha256: sha256(provenance.bytes),
      metadata,
    })
  }
  const allowed = new Set([
    ...ARTIFACTS.flatMap((artifact) => [artifact.binary, artifact.provenance]),
    'rust-target',
  ])
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!allowed.has(entry.name))
      fail(`build root contains an unexpected entry: ${entry.name}`)
    if (
      entry.name === 'rust-target' &&
      (entry.isSymbolicLink() || !entry.isDirectory())
    )
      fail('build root rust-target must be a non-symlink directory')
  }
  return records
}

const sshEnvironment = () => ({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LC_ALL: 'C',
  ...(process.env.KYCLASH_TART_BIN
    ? { KYCLASH_TART_BIN: process.env.KYCLASH_TART_BIN }
    : {}),
})

export const resolveSelectedVmIp = () => {
  const result = spawnSync('/bin/bash', [VM_LAB_SCRIPT, 'ip'], {
    encoding: 'utf8',
    env: sshEnvironment(),
  })
  if (result.error || result.status !== 0)
    fail('selected work VM IP resolution failed')
  const output = result.stdout.trim()
  if (!IPV4.test(output))
    fail('selected work VM returned an invalid IPv4 address')
  return output
}

const sshArgs = (ip) => [
  '-q',
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
]

const runRemote = (ip, script, args, label, preserveWhitespace = false) => {
  const result = spawnSync(
    '/usr/bin/ssh',
    [...sshArgs(ip), '/bin/bash', '-s', '--', ...args],
    {
      input: script,
      encoding: 'utf8',
      env: sshEnvironment(),
      maxBuffer: 256 * 1024,
    },
  )
  if (result.error || result.status !== 0)
    fail(`${label} failed on ${SELECTED_VM_NAME}`)
  return preserveWhitespace ? result.stdout : result.stdout.trim()
}

const runScp = (ip, localPath, remotePath, label) => {
  const result = spawnSync(
    '/usr/bin/scp',
    [
      '-q',
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
      localPath,
      `${GUEST_USER}@${ip}:${remotePath}`,
    ],
    { encoding: 'utf8', env: sshEnvironment() },
  )
  if (result.error || result.status !== 0)
    fail(`${label} transfer failed to ${SELECTED_VM_NAME}`)
}

const guestProofScript = `
set -euo pipefail
[ "$(/usr/bin/uname -s)" = "Darwin" ]
[ "$(/usr/bin/uname -m)" = "arm64" ]
case "$(/usr/sbin/sysctl -n hw.model 2>/dev/null)" in VirtualMac*) ;; *) exit 69 ;; esac
[ "$(/usr/bin/id -un)" = "supen" ]
[ "$HOME" = "/Users/supen" ]
[ "$(/usr/bin/stat -f '%u' /Users/supen)" = "$(/usr/bin/id -u)" ]
[ ! -L /Users/supen ]
[ "$(/usr/bin/stat -f '%u' /Users/supen)" = "$(/usr/bin/id -u)" ]
`

const guestPrepareRunScript = `
set -euo pipefail
run_id="$1"
run_root="/private/var/tmp/kyclash-networking-vm-lab/$run_id"
fixture="$2"
fixture_sha256="$3"
case "$run_id" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 64 ;; esac
[ -d "$run_root" ] && [ ! -L "$run_root" ]
[ "$(/usr/bin/stat -f '%Lp:%l:%u' "$run_root")" = "700:2:$(/usr/bin/id -u)" ] || [ "$(/usr/bin/stat -f '%Lp:%u' "$run_root")" = "700:$(/usr/bin/id -u)" ]
[ -f "$fixture" ] && [ ! -L "$fixture" ]
[ "$(/usr/bin/shasum -a 256 "$fixture" | /usr/bin/awk '{print tolower($1)}')" = "$fixture_sha256" ]
[ "$(/usr/bin/stat -f '%Lp:%l:%u' "$fixture")" = "755:1:$(/usr/bin/id -u)" ]
copy_dir="$run_root/.kyclash-fixture-copy"
[ ! -e "$copy_dir" ] && [ ! -L "$copy_dir" ]
/bin/mkdir "$copy_dir"
/bin/chmod 700 "$copy_dir"
`

export const guestLowerHex64Guard = [
  `[ "\${#expected}" -eq 64 ]`,
  'case "$expected" in *[!0-9a-f]*|\'\') exit 64 ;; esac',
].join('\n')

const guestPrepareShellScript = String.raw`
set -euo pipefail
destination="$1"
expected="$2"
tmp="$3"
[ "$(/usr/bin/uname -s)" = "Darwin" ]
[ "$(/usr/bin/uname -m)" = "arm64" ]
case "$(/usr/sbin/sysctl -n hw.model 2>/dev/null)" in VirtualMac*) ;; *) exit 69 ;; esac
[ "$(/usr/bin/id -un)" = "supen" ]
[ "$HOME" = "/Users/supen" ]
[ "$destination" = "/Users/supen/kyclash-macos-vm-keychain-trust-fixture.sh" ]
printf '%s\n' "$tmp" | /usr/bin/grep -Eq '^/Users/supen/kyclash-macos-vm-keychain-trust-fixture\.sh\.copy-[1-9][0-9]*$'
${guestLowerHex64Guard}
[ ! -e "$tmp" ] && [ ! -L "$tmp" ]
`

const guestPublishShellScript = `
set -euo pipefail
expected="$1"
tmp="$2"
destination="$3"
[ -f "$tmp" ] && [ ! -L "$tmp" ]
[ "$(/usr/bin/shasum -a 256 "$tmp" | /usr/bin/awk '{print tolower($1)}')" = "$expected" ]
/bin/chmod 755 "$tmp"
[ "$(/usr/bin/stat -f '%Lp:%l:%u' "$tmp")" = "755:1:$(/usr/bin/id -u)" ]
if [ -e "$destination" ] || [ -L "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] &&
    [ "$(/usr/bin/shasum -a 256 "$destination" | /usr/bin/awk '{print tolower($1)}')" = "$expected" ] || exit 73
  /bin/rm -f "$tmp"
  exit 0
fi
/bin/ln "$tmp" "$destination"
/bin/rm -f "$tmp"
[ "$(/usr/bin/shasum -a 256 "$destination" | /usr/bin/awk '{print tolower($1)}')" = "$expected" ]
`

const fullFinalizeScript = `
set -euo pipefail
run_id="$1"
shift
run_root="/private/var/tmp/kyclash-networking-vm-lab/$run_id"
copy_dir="$run_root/.kyclash-fixture-copy"
[ -d "$copy_dir" ] && [ ! -L "$copy_dir" ]
[ "$(/usr/bin/stat -f '%Lp:%u' "$copy_dir")" = "700:$(/usr/bin/id -u)" ]
while [ "$#" -gt 0 ]; do
  binary="$1"; binary_sha256="$2"; provenance="$3"; provenance_sha256="$4"; shift 4
  case "$binary:$provenance" in
    kyclash-system-trust-probe:kyclash-system-trust-probe.provenance.json|kyclash-keychain-public-lab:kyclash-keychain-public-lab.provenance.json|kyclash-networking-system-lab:kyclash-networking-system-lab.provenance.json) ;; *) exit 64 ;;
  esac
  binary_tmp="$copy_dir/$binary"
  provenance_tmp="$copy_dir/$provenance"
  [ -f "$binary_tmp" ] && [ ! -L "$binary_tmp" ]
  [ -f "$provenance_tmp" ] && [ ! -L "$provenance_tmp" ]
  [ "$(/usr/bin/shasum -a 256 "$binary_tmp" | /usr/bin/awk '{print tolower($1)}')" = "$binary_sha256" ]
  [ "$(/usr/bin/shasum -a 256 "$provenance_tmp" | /usr/bin/awk '{print tolower($1)}')" = "$provenance_sha256" ]
  /bin/chmod 755 "$binary_tmp"
  /bin/chmod 600 "$provenance_tmp"
  [ "$(/usr/bin/stat -f '%Lp:%l:%u' "$binary_tmp")" = "755:1:$(/usr/bin/id -u)" ]
  [ "$(/usr/bin/stat -f '%Lp:%l:%u' "$provenance_tmp")" = "600:1:$(/usr/bin/id -u)" ]
  destination="$run_root/$binary"
  [ ! -e "$destination" ] && [ ! -L "$destination" ]
  /bin/ln "$binary_tmp" "$destination"
  /bin/rm -f "$binary_tmp" "$provenance_tmp"
  [ "$(/usr/bin/shasum -a 256 "$destination" | /usr/bin/awk '{print tolower($1)}')" = "$binary_sha256" ]
done
/bin/rmdir "$copy_dir"
`

// The pull command intentionally streams only the two public JSON records and
// one scalar extracted from the private fixture manifest.  Certificates,
// private keys, Keychain output, peer manifests, and all other run-root files
// are never named by this script and therefore cannot cross the SSH boundary.
const guestPullScript = String.raw`
set -euo pipefail
run_id="$1"
guest_root="$2"
case "$run_id" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 64 ;; esac
case "$guest_root" in /private/var/tmp/kyclash-networking-vm-lab/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 64 ;; esac
[ "$(/usr/bin/uname -s)" = 'Darwin' ]
[ "$(/usr/bin/uname -m)" = 'arm64' ]
case "$(/usr/sbin/sysctl -n hw.model 2>/dev/null)" in VirtualMac*) ;; *) exit 69 ;; esac
[ "$(/usr/bin/id -un)" = 'supen' ]
[ "$HOME" = '/Users/supen' ]
[ ! -L /Users/supen ]
[ "$(/usr/bin/stat -f '%u' /Users/supen)" = "$(/usr/bin/id -u)" ]
[ -L /var ] && [ "$(/usr/bin/readlink /var)" = 'private/var' ]
[ "$(/usr/bin/stat -f '%d' /var)" = "$(/usr/bin/stat -f '%d' /private/var)" ]
for parent in /private /private/var /private/var/tmp /private/var/tmp/kyclash-networking-vm-lab; do
  [ -d "$parent" ] && [ ! -L "$parent" ]
  if [ "$parent" = '/private/var/tmp/kyclash-networking-vm-lab' ]; then
    [ "$(/usr/bin/stat -f '%u' "$parent")" = "$(/usr/bin/id -u)" ]
    [ "$(/usr/bin/stat -f '%Lp' "$parent")" = '700' ]
  else
    [ "$(/usr/bin/stat -f '%u' "$parent")" = '0' ]
  fi
done
[ -d "$guest_root" ] && [ ! -L "$guest_root" ]
[ "$(/usr/bin/stat -f '%Su' "$guest_root")" = 'supen' ]
[ "$(/usr/bin/stat -f '%u' "$guest_root")" = "$(/usr/bin/id -u)" ]
[ "$(/usr/bin/stat -f '%Lp' "$guest_root")" = '700' ]

check_file() {
  path="$1"; mode="$2"; maximum="$3"
  [ -f "$path" ] && [ ! -L "$path" ]
  [ "$(/usr/bin/stat -f '%Su' "$path")" = 'supen' ]
  [ "$(/usr/bin/stat -f '%u' "$path")" = "$(/usr/bin/id -u)" ]
  [ "$(/usr/bin/stat -f '%Lp' "$path")" = "$mode" ]
  [ "$(/usr/bin/stat -f '%l' "$path")" = '1' ]
  size="$(/usr/bin/stat -f '%z' "$path")"
  case "$size" in ''|*[!0-9]*) exit 73 ;; esac
  [ "$size" -le "$maximum" ]
}

descriptor="$guest_root/guest-descriptor.json"
preflight="$guest_root/policy-revision-preflight.json"
manifest="$guest_root/manifest.txt"
check_file "$descriptor" 644 32768
check_file "$preflight" 600 65536
check_file "$manifest" 600 8192

manifest_identity_before="$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp:%z' "$manifest")"
manifest_run_count="$(/usr/bin/awk -F= -v wanted='run_id' '$1 == wanted { value=$2; count++ } END { print count ":" value }' "$manifest")"
[ "$manifest_run_count" = "1:$run_id" ]
ceiling_record="$(/usr/bin/awk -F= '$1 == "policy_expiry_ceiling_epoch" { value=$2; count++ } END { print count ":" value }' "$manifest")"
case "$ceiling_record" in
  1:[1-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*) ;;
  *) exit 73 ;;
esac
ceiling="$(printf '%s\n' "$ceiling_record" | /usr/bin/sed 's/^1://')"
manifest_identity_after="$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp:%z' "$manifest")"
[ "$manifest_identity_before" = "$manifest_identity_after" ]

emit_json() {
  name="$1"; path="$2"
  case "$name" in
    guest-descriptor.json) mode=644; maximum=32768 ;;
    policy-revision-preflight.json) mode=600; maximum=65536 ;;
    *) exit 64 ;;
  esac
  identity_before="$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp:%z' "$path")"
  before="$(/usr/bin/shasum -a 256 "$path" | /usr/bin/awk '{print tolower($1)}')"
  encoded="$(/usr/bin/base64 < "$path" | /usr/bin/tr -d '\n')"
  after="$(/usr/bin/shasum -a 256 "$path" | /usr/bin/awk '{print tolower($1)}')"
  identity_after="$(/usr/bin/stat -f '%d:%i:%l:%u:%Lp:%z' "$path")"
  [ "$before" = "$after" ] && [ "$identity_before" = "$identity_after" ]
  check_file "$path" "$mode" "$maximum"
  printf 'file=%s\nsize=%s\nsha256=%s\nbase64=%s\nend-file\n' \
    "$name" "$(/usr/bin/stat -f '%z' "$path")" "$before" "$encoded"
}

printf 'KYCLASH_PULL_V1\nselected_vm=kyclash-macos-lab-work\nmodel=%s\narch=arm64\n' "$(/usr/sbin/sysctl -n hw.model)"
emit_json guest-descriptor.json "$descriptor"
emit_json policy-revision-preflight.json "$preflight"
ceiling_sha256="$(printf '%s\n' "$ceiling" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print tolower($1)}')"
check_file "$manifest" 600 8192
printf 'ceiling=%s\nceiling_sha256=%s\nend-frame\n' "$ceiling" "$ceiling_sha256"
`

const parsePullFrame = (text) => {
  const lines = text.split('\n')
  if (lines.pop() !== '') fail('guest pull response must end with a newline')
  let index = 0
  const take = (expectedPrefix, label) => {
    const line = lines[index++]
    if (!line?.startsWith(expectedPrefix))
      fail(`guest pull response is missing ${label}`)
    return line.slice(expectedPrefix.length)
  }
  if (lines[index++] !== 'KYCLASH_PULL_V1')
    fail('guest pull response version mismatch')
  const selectedVm = take('selected_vm=', 'selected VM')
  const model = take('model=', 'hardware model')
  const arch = take('arch=', 'architecture')
  if (
    selectedVm !== SELECTED_VM_NAME ||
    !/^VirtualMac[^\n]*$/u.test(model) ||
    arch !== 'arm64'
  )
    fail('guest pull response runtime proof is invalid')
  const files = new Map()
  for (const expectedName of [GUEST_DESCRIPTOR_NAME, GUEST_PREFLIGHT_NAME]) {
    const name = take('file=', 'file name')
    if (name !== expectedName || files.has(name))
      fail('guest pull response file allowlist mismatch')
    const sizeText = take('size=', 'file size')
    const digest = take('sha256=', 'file digest')
    const encoded = take('base64=', 'file bytes')
    if (lines[index++] !== 'end-file')
      fail('guest pull response file terminator mismatch')
    if (
      !/^[1-9][0-9]*$/u.test(sizeText) ||
      !HEX64.test(digest) ||
      encoded.length === 0
    )
      fail('guest pull response file metadata is invalid')
    const expectedSize = Number(sizeText)
    const maximum =
      expectedName === GUEST_DESCRIPTOR_NAME
        ? GUEST_DESCRIPTOR_MAX_BYTES
        : GUEST_PREFLIGHT_MAX_BYTES
    if (!Number.isSafeInteger(expectedSize) || expectedSize > maximum)
      fail('guest pull response file size is outside the reviewed bound')
    let bytes
    try {
      bytes = Buffer.from(encoded, 'base64')
    } catch {
      fail('guest pull response base64 is invalid')
    }
    if (
      bytes.toString('base64') !== encoded ||
      bytes.length !== expectedSize ||
      sha256(bytes) !== digest
    )
      fail('guest pull response file bytes are not hash-bound')
    files.set(name, { bytes, sha256: digest, size: bytes.length })
  }
  const ceilingText = take('ceiling=', 'policy expiry ceiling')
  const ceilingDigest = take('ceiling_sha256=', 'policy expiry ceiling digest')
  if (lines[index++] !== 'end-frame' || index !== lines.length)
    fail('guest pull response has trailing or missing records')
  if (!/^[1-9][0-9]{9,}$/u.test(ceilingText) || !HEX64.test(ceilingDigest))
    fail('guest policy expiry ceiling is invalid')
  const ceilingBytes = Buffer.from(`${ceilingText}\n`, 'utf8')
  if (sha256(ceilingBytes) !== ceilingDigest)
    fail('guest policy expiry ceiling hash mismatch')
  const ceiling = Number(ceilingText)
  if (!Number.isSafeInteger(ceiling))
    fail('guest policy expiry ceiling is not safe')
  return {
    selectedVm,
    model,
    arch,
    files,
    ceiling,
    ceilingSha256: ceilingDigest,
  }
}

const validatePulledPayload = (
  payload,
  runId,
  now = Math.floor(Date.now() / 1000),
) => {
  if (
    !payload ||
    payload.selectedVm !== SELECTED_VM_NAME ||
    payload.arch !== 'arm64'
  )
    fail('guest pull payload runtime proof is invalid')
  const descriptorRecord = payload.files?.get(GUEST_DESCRIPTOR_NAME)
  const preflightRecord = payload.files?.get(GUEST_PREFLIGHT_NAME)
  if (!descriptorRecord || !preflightRecord)
    fail('guest pull payload is missing an allowlisted record')
  const descriptor = strictGuestJson(
    descriptorRecord.bytes,
    GUEST_DESCRIPTOR_NAME,
    GUEST_DESCRIPTOR_MAX_BYTES,
  )
  const validatedDescriptor = validateDescriptor(descriptor, now)
  if (descriptor.run_id !== runId) fail('guest descriptor run id mismatch')
  if (
    !Number.isSafeInteger(payload.ceiling) ||
    payload.ceiling <= now ||
    validatedDescriptor.expiresAt > payload.ceiling
  )
    fail('guest descriptor expiry exceeds the pulled policy ceiling')
  const preflight = strictGuestJson(
    preflightRecord.bytes,
    GUEST_PREFLIGHT_NAME,
    GUEST_PREFLIGHT_MAX_BYTES,
  )
  if (
    !Number.isSafeInteger(preflight.candidate_revision) ||
    preflight.candidate_revision < 1
  )
    fail('guest policy revision is invalid')
  validatePolicyRevisionPreflight({
    preflight,
    runId,
    revision: preflight.candidate_revision,
    now,
  })
  return {
    descriptor,
    preflight,
    descriptorSha256: descriptorRecord.sha256,
    preflightSha256: preflightRecord.sha256,
    ceiling: payload.ceiling,
    ceilingSha256: payload.ceilingSha256,
  }
}

const createPrivateOutputRoot = (outputRoot) => {
  if (!path.isAbsolute(outputRoot)) fail('pull output root must be absolute')
  const absolute = assertNoSymlinkComponents(outputRoot, 'pull output root')
  if (fs.existsSync(absolute)) fail('pull output root must not already exist')
  const parent = path.dirname(absolute)
  const parentStat = lstatNoSymlink(parent, 'pull output root parent')
  if (!parentStat.isDirectory())
    fail('pull output root parent must be a directory')
  fs.mkdirSync(absolute, { mode: 0o700 })
  fs.chmodSync(absolute, 0o700)
  const stat = lstatNoSymlink(absolute, 'pull output root')
  if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700)
    fail('pull output root publication is unsafe')
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    fail('pull output root owner mismatch')
  return absolute
}

const fsyncDirectory = (directory) => {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY)
  try {
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

const publishPulledFile = (root, name, bytes, mode) => {
  const allowedNames = new Set([
    GUEST_DESCRIPTOR_NAME,
    GUEST_PREFLIGHT_NAME,
    HOST_CEILING_NAME,
  ])
  if (
    !SAFE_BASENAME.test(name) ||
    path.dirname(name) !== '.' ||
    !allowedNames.has(name)
  )
    fail('pull output name is not allowlisted')
  const destination = path.join(root, name)
  if (fs.existsSync(destination)) fail(`pull output already exists: ${name}`)
  const temporary = path.join(
    root,
    `.${name}.incoming-${crypto.randomBytes(8).toString('hex')}`,
  )
  let descriptor
  let temporaryOwned = false
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        NOFOLLOW,
      mode,
    )
    temporaryOwned = true
    fs.fchmodSync(descriptor, mode)
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
    fs.closeSync(descriptor)
    descriptor = undefined
    fs.linkSync(temporary, destination)
    fs.unlinkSync(temporary)
    temporaryOwned = false
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
    if (temporaryOwned) {
      try {
        fs.unlinkSync(temporary)
      } catch {
        // Preserve the original publication failure; never remove a path we
        // did not successfully create in this invocation.
      }
    }
  }
  const stat = assertRegular(destination, name, mode)
  if (
    stat.size !== bytes.length ||
    stat.nlink !== 1 ||
    sha256(readNoFollow(destination, name).bytes) !== sha256(bytes)
  )
    fail(`pull output hash verification failed: ${name}`)
  return destination
}

const pullRun = ({ runId, outputRoot, guestRoot }) => {
  assertHostAppleSilicon()
  assertSshMaterial()
  const canonicalRoot = validateGuestRunRoot(
    guestRoot ?? canonicalGuestRunRoot(runId),
    runId,
  )
  const ip = resolveSelectedVmIp()
  const frame = parsePullFrame(
    runRemote(
      ip,
      guestPullScript,
      [runId, canonicalRoot],
      'guest public pull',
      true,
    ),
  )
  const validated = validatePulledPayload(frame, runId)
  const root = createPrivateOutputRoot(outputRoot)
  publishPulledFile(
    root,
    GUEST_DESCRIPTOR_NAME,
    frame.files.get(GUEST_DESCRIPTOR_NAME).bytes,
    0o644,
  )
  publishPulledFile(
    root,
    GUEST_PREFLIGHT_NAME,
    frame.files.get(GUEST_PREFLIGHT_NAME).bytes,
    0o644,
  )
  publishPulledFile(
    root,
    HOST_CEILING_NAME,
    Buffer.from(`${validated.ceiling}\n`, 'utf8'),
    0o644,
  )
  fsyncDirectory(root)
  const publishedNames = fs
    .readdirSync(root, { withFileTypes: true })
    .map((entry) => entry.name)
    .sort()
  const expectedNames = [
    GUEST_DESCRIPTOR_NAME,
    GUEST_PREFLIGHT_NAME,
    HOST_CEILING_NAME,
  ].sort()
  if (JSON.stringify(publishedNames) !== JSON.stringify(expectedNames))
    fail('pull output contains an unexpected entry')
  return {
    mode: 'pull',
    selectedVm: SELECTED_VM_NAME,
    ip,
    runId,
    outputRoot: root,
    guestRoot: canonicalRoot,
    descriptorSha256: validated.descriptorSha256,
    preflightSha256: validated.preflightSha256,
    ceiling: validated.ceiling,
    ceilingSha256: validated.ceilingSha256,
  }
}

const prepareShellOnly = () => {
  assertHostAppleSilicon()
  assertCleanSource()
  assertSshMaterial()
  assertRegular(FIXTURE_SOURCE, 'guest fixture', 0o755)
  const digest = sha256(readNoFollow(FIXTURE_SOURCE, 'guest fixture').bytes)
  const ip = resolveSelectedVmIp()
  runRemote(ip, guestProofScript, [], 'guest VM proof')
  const temporary = `${GUEST_FIXTURE_PATH}.copy-${process.pid}`
  runRemote(
    ip,
    guestPrepareShellScript,
    [GUEST_FIXTURE_PATH, digest, temporary],
    'guest fixture destination preflight',
  )
  runScp(ip, FIXTURE_SOURCE, temporary, 'guest fixture')
  runRemote(
    ip,
    guestPublishShellScript,
    [digest, temporary, GUEST_FIXTURE_PATH],
    'guest fixture publication',
  )
  return { ip, sha256: digest, destination: GUEST_FIXTURE_PATH }
}

const prepareFullCopy = ({ runId, buildRoot }) => {
  assertHostAppleSilicon()
  assertSshMaterial()
  const sourceCommit = assertCleanSource()
  const records = validateBuildArtifacts(buildRoot, sourceCommit)
  const fixture = readNoFollow(FIXTURE_SOURCE, 'guest fixture')
  assertRegular(FIXTURE_SOURCE, 'guest fixture', 0o755)
  const ip = resolveSelectedVmIp()
  runRemote(ip, guestProofScript, [], 'guest VM proof')
  runRemote(
    ip,
    guestPrepareRunScript,
    [runId, GUEST_FIXTURE_PATH, sha256(fixture.bytes)],
    'guest run-root preflight',
  )
  for (const record of records) {
    runScp(
      ip,
      record.binaryPath,
      `${GUEST_RUN_ROOT}/${runId}/.kyclash-fixture-copy/${record.binary}`,
      `${record.binary} binary`,
    )
    runScp(
      ip,
      record.provenancePath,
      `${GUEST_RUN_ROOT}/${runId}/.kyclash-fixture-copy/${record.provenance}`,
      `${record.binary} provenance`,
    )
  }
  const args = [runId]
  for (const record of records)
    args.push(
      record.binary,
      record.binarySha256,
      record.provenance,
      record.provenanceSha256,
    )
  runRemote(ip, fullFinalizeScript, args, 'guest fixture publication')
  return {
    ip,
    runId,
    sourceCommit,
    fixtureSha256: sha256(fixture.bytes),
    artifacts: records.map((record) => ({
      binary: record.binary,
      sha256: record.binarySha256,
      provenanceSha256: record.provenanceSha256,
    })),
  }
}

const main = () => {
  const options = parseCopyOptions(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  const result = options.pullRun
    ? pullRun(options)
    : options.shellOnly
      ? prepareShellOnly()
      : prepareFullCopy({ runId: options.runId, buildRoot: options.buildRoot })
  process.stdout.write(`${JSON.stringify(result)}\n`)
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  try {
    main()
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}

export {
  ARTIFACTS,
  artifactPaths,
  assertPrivateBuildRoot,
  createPrivateOutputRoot,
  guestPullScript,
  parsePullFrame,
  publishPulledFile,
  pullRun,
  validatePulledPayload,
}
