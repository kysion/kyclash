import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin' || process.arch !== 'arm64')
  throw new Error(
    'system trust probe must be built on an Apple Silicon macOS host',
  )

const root = path.resolve(import.meta.dirname, '..')
const defaultOutputRoot = path.join(root, 'target', 'macos-vm-lab', 'build')
const configuredOutputRoot =
  process.env.KYCLASH_VM_LAB_BUILD_ROOT ?? defaultOutputRoot
if (!path.isAbsolute(configuredOutputRoot))
  throw new Error('VM lab build root must be an absolute path')
const outputRoot = path.resolve(configuredOutputRoot)
const output = path.join(outputRoot, 'kyclash-system-trust-probe')
const go =
  process.env.KYCLASH_GO_BIN ||
  path.join(root, 'target', 'toolchains', 'go1.26.5', 'bin', 'go')

if (!path.isAbsolute(go)) throw new Error('Go toolchain path must be absolute')
const goStat = fs.lstatSync(go)
if (!goStat.isFile() || goStat.isSymbolicLink() || (goStat.mode & 0o111) === 0)
  throw new Error('Go toolchain path must be a regular executable')
const sourceStatus = execFileSync(
  'git',
  ['status', '--porcelain=v1', '--untracked-files=all', '--ignored=no'],
  { cwd: root, encoding: 'utf8' },
)
if (sourceStatus.trim() !== '')
  throw new Error('trust probe build requires a clean reviewed source tree')
const sourceCommit = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: root,
  encoding: 'utf8',
}).trim()
const goVersion = execFileSync(go, ['version'], { encoding: 'utf8' }).trim()
const goSha256 = crypto
  .createHash('sha256')
  .update(fs.readFileSync(go))
  .digest('hex')

if (fs.existsSync(outputRoot)) {
  const rootStat = fs.lstatSync(outputRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
    throw new Error('VM lab build root must be a non-symlink directory')
  if ((rootStat.mode & 0o077) !== 0)
    throw new Error('VM lab build root must not be group/other accessible')
} else {
  fs.mkdirSync(outputRoot, { recursive: true, mode: 0o700 })
}
fs.chmodSync(outputRoot, 0o700)
if (fs.existsSync(output) || fs.existsSync(`${output}.provenance.json`))
  throw new Error('refusing to replace an existing trust probe artifact')
execFileSync(
  go,
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-o',
    output,
    './cmd/kyclash-system-trust-probe',
  ],
  {
    cwd: path.join(root, 'network-sidecar'),
    env: {
      ...process.env,
      CGO_ENABLED: '0',
      GOOS: 'darwin',
      GOARCH: 'arm64',
    },
    stdio: 'inherit',
  },
)
fs.chmodSync(output, 0o755)
const stat = fs.lstatSync(output)
if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o755)
  throw new Error('probe output shape is unsafe')
const digest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(output))
  .digest('hex')
const provenance = {
  schema_version: 1,
  build_target: 'host-build',
  runtime_target: 'kyclash-macos-lab-work',
  target: 'aarch64-apple-darwin',
  cgo_enabled: false,
  source: 'network-sidecar/cmd/kyclash-system-trust-probe',
  source_commit: sourceCommit,
  go_version: goVersion,
  go_sha256: goSha256,
  sha256: digest,
}
fs.writeFileSync(
  `${output}.provenance.json`,
  `${JSON.stringify(provenance, null, 2)}\n`,
  { mode: 0o600 },
)
console.log('system_trust_probe_built=host-build')
console.log(`system_trust_probe_sha256=${digest}`)
console.log(`system_trust_probe_path=${output}`)
