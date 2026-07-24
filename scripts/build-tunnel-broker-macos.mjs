import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin')
  throw new Error('tunnel broker must be built on macOS')

const root = path.resolve(import.meta.dirname, '..')
const source = path.join(root, 'macos', 'tunnel-broker', 'main.swift')
const sidecar = path.join(
  root,
  'src-tauri',
  'sidecar',
  'kyclash-network-sidecar-aarch64-apple-darwin',
)
const trustPath = path.join(
  root,
  'src-tauri',
  'resources',
  'kyclash-network-sidecar-aarch64-apple-darwin.trust.json',
)
const buildRoot = path.join(root, 'target', 'tunnel-broker-build')
const generatedManifest = path.join(buildRoot, 'manifest.generated.swift')
const output = path.join(buildRoot, 'kyclash-tunnel-broker')
const bundledOutput = path.join(
  root,
  'src-tauri',
  'helpers',
  'kyclash-tunnel-broker',
)
const selfTest = process.argv.slice(2).includes('--self-test')

const allowedManifestKeys = [
  'architecture',
  'designated_requirement',
  'schema_version',
  'sha256',
  'team_id',
]
const expectedRequirement =
  'identifier "net.kysion.kyclash.network-sidecar" and anchor apple generic and certificate leaf[subject.OU] = "RQUQ8Y3S9H"'
const brokerRequirement =
  'identifier "net.kysion.kyclash.tunnel-broker" and anchor apple generic and certificate leaf[subject.OU] = "RQUQ8Y3S9H"'
const hasBuildInputs = fs.existsSync(sidecar) && fs.existsSync(trustPath)
// Generated sidecars are intentionally ignored by git. Keep the protocol
// self-test runnable from a clean checkout without pretending that a synthetic
// manifest is production trust evidence; the normal signed build below
// still requires the real sidecar and public trust manifest.
const manifest = hasBuildInputs
  ? JSON.parse(fs.readFileSync(trustPath, 'utf8'))
  : selfTest
    ? {
        schema_version: 1,
        sha256: '0'.repeat(64),
        architecture: 'arm64',
        team_id: 'RQUQ8Y3S9H',
        designated_requirement: expectedRequirement,
      }
    : (() => {
        throw new Error(
          'sidecar and trust manifest are required for a signed broker build',
        )
      })()
if (
  JSON.stringify(Object.keys(manifest).sort()) !==
  JSON.stringify(allowedManifestKeys)
)
  throw new Error('sidecar trust manifest has unknown or missing fields')
if (manifest.schema_version !== 1)
  throw new Error('unsupported sidecar trust manifest schema')
if (manifest.architecture !== 'arm64')
  throw new Error('tunnel broker currently requires the locked arm64 sidecar')
if (manifest.team_id !== 'RQUQ8Y3S9H')
  throw new Error('sidecar trust manifest Team ID is not locked')
if (!/^[0-9a-f]{64}$/.test(manifest.sha256))
  throw new Error('sidecar trust manifest SHA-256 is invalid')
if (manifest.designated_requirement !== expectedRequirement)
  throw new Error('sidecar designated requirement is not locked')

if (hasBuildInputs) {
  const actualSHA256 = crypto
    .createHash('sha256')
    .update(fs.readFileSync(sidecar))
    .digest('hex')
  if (actualSHA256 !== manifest.sha256)
    throw new Error('sidecar bytes do not match the public trust manifest')
} else if (!selfTest) {
  throw new Error(
    'sidecar and trust manifest are required for a signed broker build',
  )
}

fs.mkdirSync(buildRoot, { recursive: true })
const swiftString = (value) => JSON.stringify(value)
fs.writeFileSync(
  generatedManifest,
  [
    'enum TunnelBrokerBuildManifest {',
    `    static let sidecarSHA256 = ${swiftString(manifest.sha256)}`,
    `    static let sidecarArchitecture = ${swiftString(manifest.architecture)}`,
    `    static let sidecarTeamID = ${swiftString(manifest.team_id)}`,
    `    static let sidecarDesignatedRequirement = ${swiftString(manifest.designated_requirement)}`,
    '}',
    '',
  ].join('\n'),
  { mode: 0o600 },
)

const argumentsList = [
  'swiftc',
  '-parse-as-library',
  selfTest ? '-Onone' : '-O',
  '-target',
  'arm64-apple-macos13.0',
  '-framework',
  'Foundation',
  '-framework',
  'Security',
  '-o',
  output,
  source,
  generatedManifest,
]
if (selfTest)
  argumentsList.splice(2, 0, '-D', 'KYCLASH_TUNNEL_BROKER_SELF_TEST')
execFileSync('xcrun', argumentsList, { stdio: 'inherit' })
fs.chmodSync(output, 0o755)

const architectures = execFileSync('/usr/bin/lipo', ['-archs', output], {
  encoding: 'utf8',
}).trim()
if (architectures !== 'arm64')
  throw new Error(`unexpected tunnel broker architecture: ${architectures}`)

if (selfTest) {
  if (os.arch() !== 'arm64')
    throw new Error(
      'arm64 tunnel broker self-test requires an arm64 build host',
    )
  execFileSync(output, ['--self-test'], { stdio: 'inherit' })
} else {
  const identity = process.env.APPLE_SIGNING_IDENTITY
  const teamID = process.env.APPLE_TEAM_ID
  if (!identity || teamID !== 'RQUQ8Y3S9H')
    throw new Error(
      'APPLE_SIGNING_IDENTITY and the locked APPLE_TEAM_ID are required to sign the tunnel broker',
    )
  execFileSync(
    '/usr/bin/codesign',
    [
      '--force',
      '--options',
      'runtime',
      '--timestamp',
      '--identifier',
      'net.kysion.kyclash.tunnel-broker',
      '--sign',
      identity,
      output,
    ],
    { stdio: 'inherit' },
  )
  execFileSync(
    '/usr/bin/codesign',
    ['--verify', '--strict', '--verbose=2', `-R=${brokerRequirement}`, output],
    { stdio: 'inherit' },
  )
  fs.mkdirSync(path.dirname(bundledOutput), { recursive: true })
  fs.copyFileSync(output, bundledOutput)
  fs.chmodSync(bundledOutput, 0o755)
}

console.log(
  `[INFO] ${selfTest ? 'unsigned tunnel broker self-test' : 'signed tunnel broker bundle'} built at ${selfTest ? output : bundledOutput}`,
)
