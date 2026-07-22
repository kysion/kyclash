import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin' || process.arch !== 'arm64') {
  throw new Error(
    'userspace lab App sidecar must be built on Apple Silicon macOS',
  )
}

const root = path.resolve(import.meta.dirname, '..')
const target = 'aarch64-apple-darwin'
const source = path.join(root, 'network-sidecar')
const output = path.join(
  root,
  'src-tauri',
  'sidecar',
  `kyclash-network-sidecar-lab-${target}`,
)
const evidenceRoot = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'userspace-lab-app',
)
const go =
  process.env.KYCLASH_GO_BIN ??
  path.join(root, 'target', 'toolchains', 'go1.26.5', 'bin', 'go')

if (!path.isAbsolute(go)) throw new Error('KYCLASH_GO_BIN must be absolute')
const goStat = fs.lstatSync(go)
if (
  !goStat.isFile() ||
  goStat.isSymbolicLink() ||
  (goStat.mode & 0o111) === 0
) {
  throw new Error('Go toolchain must be a regular executable')
}

fs.mkdirSync(path.dirname(output), { recursive: true })
fs.mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 })
execFileSync(
  go,
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-ldflags=-buildid=',
    '-o',
    output,
    './cmd/kyclash-network-sidecar-lab',
  ],
  {
    cwd: source,
    env: { ...process.env, CGO_ENABLED: '0', GOOS: 'darwin', GOARCH: 'arm64' },
    stdio: 'inherit',
  },
)
fs.chmodSync(output, 0o755)

const digest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(output))
  .digest('hex')
const provenance = {
  schema_version: 1,
  build_target: 'host-build',
  runtime_target: 'kyclash-macos-lab-work',
  target,
  cgo_enabled: false,
  source: 'network-sidecar/cmd/kyclash-network-sidecar-lab',
  source_commit: execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim(),
  go_version: execFileSync(go, ['version'], { encoding: 'utf8' }).trim(),
  sha256: digest,
}
fs.writeFileSync(
  path.join(evidenceRoot, 'provenance.json'),
  `${JSON.stringify(provenance, null, 2)}\n`,
  { mode: 0o600 },
)
fs.writeFileSync(
  path.join(evidenceRoot, 'sha256.txt'),
  `${digest}  ${path.basename(output)}\n`,
  { mode: 0o600 },
)
console.log('userspace_lab_app_sidecar_built=host-build')
console.log(
  `userspace_lab_app_sidecar_runtime_target=${provenance.runtime_target}`,
)
console.log(`userspace_lab_app_sidecar_sha256=${digest}`)
console.log(`userspace_lab_app_sidecar_path=${output}`)
