import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

// This script is deliberately compile-only on the host.  The resulting
// kyclash_utun binary is runtime-capable and may be executed only inside the
// selected VirtualMac guest by the continuous-delivery skill.
if (process.platform !== 'darwin' || process.arch !== 'arm64')
  throw new Error(
    'the VM network lab harness is an Apple Silicon macOS artifact',
  )

const root = path.resolve(import.meta.dirname, '..')
const source = path.join(root, 'network-sidecar')
const output = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'vm-network-lab',
  'kyclash-vm-network-lab-harness',
)
const evidenceRoot = path.dirname(output)
const mihomo = path.join(
  root,
  'src-tauri',
  'sidecar',
  'verge-mihomo-aarch64-apple-darwin',
)
const go =
  process.env.KYCLASH_GO_BIN ??
  path.join(root, 'target', 'toolchains', 'go1.26.5', 'bin', 'go')
const tags = ['kyclash_utun', 'kyclash_vm_network_lab']

if (!path.isAbsolute(go)) throw new Error('KYCLASH_GO_BIN must be absolute')
const goStat = fs.lstatSync(go)
if (!goStat.isFile() || goStat.isSymbolicLink() || (goStat.mode & 0o111) === 0)
  throw new Error('Go toolchain must be a regular executable')

const mihomoStat = fs.lstatSync(mihomo)
if (
  !mihomoStat.isFile() ||
  mihomoStat.isSymbolicLink() ||
  (mihomoStat.mode & 0o111) === 0 ||
  (mihomoStat.mode & 0o022) !== 0
)
  throw new Error('Mihomo input must be a read-only regular executable')
const mihomoBytes = fs.readFileSync(mihomo)
if (
  mihomoBytes.length < 8 ||
  !mihomoBytes
    .subarray(0, 8)
    .equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01]))
)
  throw new Error('Mihomo input must be a thin arm64 Mach-O executable')
const mihomoSha256 = crypto
  .createHash('sha256')
  .update(mihomoBytes)
  .digest('hex')
const expectedMihomoSymbol =
  'github.com/kysion/kyclash/network-sidecar/internal/vmnetworklab.ExpectedMihomoSHA256'

fs.mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 })
execFileSync(
  go,
  [
    'build',
    '-trimpath',
    '-buildvcs=false',
    '-ldflags',
    `-buildid= -X ${expectedMihomoSymbol}=${mihomoSha256}`,
    '-tags',
    tags.join(','),
    '-o',
    output,
    './cmd/kyclash-vm-network-lab-harness',
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
)
  throw new Error('harness is not an arm64 Mach-O executable')
const sha256 = crypto.createHash('sha256').update(bytes).digest('hex')
const provenance = {
  schema_version: 1,
  artifact: 'kyclash-vm-network-lab-harness',
  build_target: 'host-build',
  runtime_target: 'kyclash-macos-lab-work',
  target: 'aarch64-apple-darwin',
  go_tags: tags,
  cgo_enabled: false,
  execution_policy: 'compile-only-host; execute-only-selected-VirtualMac',
  source: 'network-sidecar/cmd/kyclash-vm-network-lab-harness',
  mihomo_input: 'src-tauri/sidecar/verge-mihomo-aarch64-apple-darwin',
  mihomo_sha256: mihomoSha256,
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
console.log('vm_network_lab_harness_build_target=host-build')
console.log('vm_network_lab_harness_runtime_target=kyclash-macos-lab-work')
console.log(`vm_network_lab_harness_path=${output}`)
console.log(`vm_network_lab_harness_sha256=${sha256}`)
