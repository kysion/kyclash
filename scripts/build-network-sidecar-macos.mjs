import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin')
  throw new Error('macOS sidecar bundle must be built on macOS')

const target = process.argv[2] ?? 'aarch64-apple-darwin'
const targets = {
  'aarch64-apple-darwin': { goarch: 'arm64', architecture: 'arm64' },
  'x86_64-apple-darwin': { goarch: 'amd64', architecture: 'x86_64' },
}
const selected = targets[target]
if (!selected) throw new Error(`unsupported target: ${target}`)

const root = path.resolve(import.meta.dirname, '..')
const source = path.join(root, 'network-sidecar')
const output = path.join(
  root,
  'src-tauri',
  'sidecar',
  `kyclash-network-sidecar-${target}`,
)
const evidence = path.join(source, 'build', target)
fs.mkdirSync(path.dirname(output), { recursive: true })
fs.mkdirSync(evidence, { recursive: true })

const env = {
  ...process.env,
  CGO_ENABLED: '0',
  GOOS: 'darwin',
  GOARCH: selected.goarch,
}
execFileSync(
  'go',
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-ldflags=-buildid=',
    '-o',
    output,
    './cmd/kyclash-network-sidecar',
  ],
  { cwd: source, env, stdio: 'inherit' },
)
fs.chmodSync(output, 0o755)

const identity = process.env.APPLE_SIGNING_IDENTITY
if (!identity)
  throw new Error(
    'APPLE_SIGNING_IDENTITY is required to sign the nested sidecar',
  )
execFileSync(
  '/usr/bin/codesign',
  [
    '--force',
    '--options',
    'runtime',
    '--timestamp',
    '--identifier',
    'net.kysion.kyclash.network-sidecar',
    '--sign',
    identity,
    output,
  ],
  { stdio: 'inherit' },
)
execFileSync(
  '/usr/bin/codesign',
  ['--verify', '--strict', '--verbose=2', output],
  { stdio: 'inherit' },
)

const sha256 = crypto
  .createHash('sha256')
  .update(fs.readFileSync(output))
  .digest('hex')
const teamId = process.env.APPLE_TEAM_ID
if (!teamId || !/^[A-Za-z0-9]{1,64}$/.test(teamId))
  throw new Error('APPLE_TEAM_ID is required')
const designatedRequirement = `identifier "net.kysion.kyclash.network-sidecar" and anchor apple generic and certificate leaf[subject.OU] = "${teamId}"`
const manifest = {
  schema_version: 1,
  sha256,
  architecture: selected.architecture,
  team_id: teamId,
  designated_requirement: designatedRequirement,
}
const trustOutput = path.join(
  root,
  'src-tauri',
  'resources',
  `kyclash-network-sidecar-${target}.trust.json`,
)
fs.writeFileSync(trustOutput, `${JSON.stringify(manifest, null, 2)}\n`, {
  mode: 0o600,
})
fs.writeFileSync(
  path.join(evidence, 'sha256.txt'),
  `${sha256}  ${path.basename(output)}\n`,
)
fs.writeFileSync(
  path.join(evidence, 'provenance.json'),
  `${JSON.stringify(
    {
      schema_version: 1,
      commit: execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: root,
        encoding: 'utf8',
      }).trim(),
      target,
      go_version: execFileSync('go', ['version'], { encoding: 'utf8' }).trim(),
      source: 'network-sidecar/cmd/kyclash-network-sidecar',
      sha256,
    },
    null,
    2,
  )}\n`,
)
execFileSync('go', ['version', '-m', output], {
  cwd: source,
  stdio: [
    'ignore',
    fs.openSync(path.join(evidence, 'dependencies.txt'), 'w'),
    'inherit',
  ],
})
console.log(`[INFO] signed KyClash network sidecar prepared for ${target}`)
