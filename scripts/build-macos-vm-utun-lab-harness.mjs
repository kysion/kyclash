import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin' || process.arch !== 'arm64') {
  throw new Error('the VM utun lab harness is an Apple Silicon macOS artifact')
}

const root = path.resolve(import.meta.dirname, '..')
const source = path.join(root, 'network-sidecar')
const output = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'vm-utun-lab',
  'kyclash-vm-utun-lab-harness',
)
const evidenceRoot = path.dirname(output)
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

fs.mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 })
execFileSync(
  go,
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-ldflags=-buildid=',
    '-tags',
    'kyclash_utun',
    '-o',
    output,
    './cmd/kyclash-vm-utun-lab-harness',
  ],
  {
    cwd: source,
    env: { ...process.env, CGO_ENABLED: '0', GOOS: 'darwin', GOARCH: 'arm64' },
    stdio: 'inherit',
  },
)
fs.chmodSync(output, 0o755)
const bytes = fs.readFileSync(output)
if (
  bytes.length < 4 ||
  !bytes.subarray(0, 4).equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))
) {
  throw new Error('harness is not an arm64 Mach-O executable')
}
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex')
const provenance = {
  schema_version: 1,
  artifact: 'kyclash-vm-utun-lab-harness',
  build_target: 'host-build',
  runtime_target: 'kyclash-macos-lab-work',
  target: 'aarch64-apple-darwin',
  go_tags: ['kyclash_utun'],
  cgo_enabled: false,
  source: 'network-sidecar/cmd/kyclash-vm-utun-lab-harness',
  source_commit: execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim(),
  go_version: execFileSync(go, ['version'], { encoding: 'utf8' }).trim(),
  sha256,
}
fs.writeFileSync(
  path.join(evidenceRoot, 'provenance.json'),
  `${JSON.stringify(provenance, null, 2)}\n`,
  { mode: 0o600 },
)
fs.writeFileSync(
  path.join(evidenceRoot, 'sha256.txt'),
  `${sha256}  ${path.basename(output)}\n`,
  { mode: 0o600 },
)
console.log('vm_utun_lab_harness_build_target=host-build')
console.log('vm_utun_lab_harness_runtime_target=kyclash-macos-lab-work')
console.log(`vm_utun_lab_harness_path=${output}`)
console.log(`vm_utun_lab_harness_sha256=${sha256}`)
