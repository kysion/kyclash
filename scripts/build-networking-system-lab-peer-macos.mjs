import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const fail = (message) => {
  throw new Error(message)
}

if (process.platform !== 'darwin' || process.arch !== 'arm64')
  fail('system-lab peer must be built on an Apple Silicon macOS host')
if (process.argv.length !== 2) fail('unexpected arguments')

const root = path.resolve(import.meta.dirname, '..')
const configuredOutputRoot =
  process.env.KYCLASH_VM_LAB_BUILD_ROOT ??
  path.join(root, 'target', 'macos-vm-lab', 'build')
if (!path.isAbsolute(configuredOutputRoot))
  fail('VM lab build root must be an absolute path')
const outputRoot = path.resolve(configuredOutputRoot)
const output = path.join(outputRoot, 'kyclash-networking-system-lab')
const provenancePath = `${output}.provenance.json`
const go =
  process.env.KYCLASH_GO_BIN ??
  path.join(root, 'target', 'toolchains', 'go1.26.5', 'bin', 'go')
if (!path.isAbsolute(go)) fail('Go toolchain path must be absolute')
const goStat = fs.lstatSync(go)
if (!goStat.isFile() || goStat.isSymbolicLink() || (goStat.mode & 0o111) === 0)
  fail('Go toolchain path must be a regular executable')

const sourceStatus = execFileSync(
  'git',
  ['status', '--porcelain=v1', '--untracked-files=all', '--ignored=no'],
  { cwd: root, encoding: 'utf8' },
)
if (sourceStatus.trim() !== '')
  fail('system-lab peer build requires a clean reviewed source tree')
const sourceCommit = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: root,
  encoding: 'utf8',
}).trim()
if (!/^[0-9a-f]{40}$/u.test(sourceCommit))
  fail('cannot resolve the reviewed source commit')

if (fs.existsSync(outputRoot)) {
  const rootStat = fs.lstatSync(outputRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
    fail('VM lab build root must be a non-symlink directory')
  if ((rootStat.mode & 0o077) !== 0)
    fail('VM lab build root must not be group/other accessible')
} else {
  fs.mkdirSync(outputRoot, { recursive: true, mode: 0o700 })
}
fs.chmodSync(outputRoot, 0o700)
if (fs.existsSync(output) || fs.existsSync(provenancePath))
  fail('refusing to replace an existing system-lab peer artifact')

execFileSync(
  go,
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-o',
    output,
    './cmd/kyclash-networking-system-lab',
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
const outputStat = fs.lstatSync(output)
if (
  !outputStat.isFile() ||
  outputStat.isSymbolicLink() ||
  (outputStat.mode & 0o777) !== 0o755
)
  fail('system-lab peer output shape is unsafe')

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')
const digest = sha256(fs.readFileSync(output))
const provenance = {
  schema_version: 1,
  build_target: 'host-build',
  runtime_target: 'kyclash-macos-lab-work',
  target: 'aarch64-apple-darwin',
  cgo_enabled: false,
  source: 'network-sidecar/cmd/kyclash-networking-system-lab',
  source_commit: sourceCommit,
  go_version: execFileSync(go, ['version'], { encoding: 'utf8' }).trim(),
  go_sha256: sha256(fs.readFileSync(go)),
  sha256: digest,
}
fs.writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`, {
  mode: 0o600,
  flag: 'wx',
})
console.log('networking_system_lab_peer_built=host-build')
console.log(`networking_system_lab_peer_sha256=${digest}`)
console.log(`networking_system_lab_peer_path=${output}`)
