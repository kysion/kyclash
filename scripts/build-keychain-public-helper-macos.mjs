import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

const fail = (message) => {
  throw new Error(message)
}

// Host-build-only helper. It never opens Keychain and never starts a guest;
// the resulting executable is copied into the already-authorized VM run root.
const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const targetRoot = path.join(PROJECT_ROOT, 'target', 'macos-vm-lab')
const configuredOutputRoot =
  process.env.KYCLASH_VM_LAB_BUILD_ROOT ?? path.join(targetRoot, 'build')
if (!path.isAbsolute(configuredOutputRoot))
  fail('VM lab build root must be an absolute path')
const outputRoot = path.resolve(configuredOutputRoot)
const cargoTarget = path.join(outputRoot, 'rust-target')
const cargoBinary = path.join(
  cargoTarget,
  'debug',
  'kyclash-keychain-public-lab',
)
const outputBinary = path.join(outputRoot, 'kyclash-keychain-public-lab')
const provenancePath = path.join(
  outputRoot,
  'kyclash-keychain-public-lab.provenance.json',
)

if (process.platform !== 'darwin' || os.arch() !== 'arm64')
  fail('the Keychain public helper must be host-built on arm64 macOS')
if (process.argv.length !== 2) fail('unexpected arguments')

if (fs.existsSync(outputRoot)) {
  const rootStat = fs.lstatSync(outputRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
    fail('VM lab build root must be a non-symlink directory')
  if ((rootStat.mode & 0o077) !== 0)
    fail('VM lab build root must not be group/other accessible')
} else {
  fs.mkdirSync(outputRoot, { recursive: true, mode: 0o700 })
}
if (fs.existsSync(outputBinary) || fs.existsSync(provenancePath))
  fail('refusing to replace an existing Keychain public helper artifact')
fs.chmodSync(outputRoot, 0o700)
const sourceStatus = spawnSync(
  'git',
  ['status', '--porcelain=v1', '--untracked-files=all', '--ignored=no'],
  { cwd: PROJECT_ROOT, encoding: 'utf8' },
)
if (
  sourceStatus.error ||
  sourceStatus.status !== 0 ||
  sourceStatus.stdout.trim() !== ''
)
  fail('Keychain public helper build requires a clean reviewed source tree')
const sourceCommit = spawnSync('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: PROJECT_ROOT,
  encoding: 'utf8',
})
if (
  sourceCommit.error ||
  sourceCommit.status !== 0 ||
  !/^[0-9a-f]{40}$/u.test(sourceCommit.stdout.trim())
)
  fail('cannot resolve the reviewed source commit')
const result = spawnSync(
  'cargo',
  [
    'build',
    '-p',
    'clash-verge',
    '--features',
    'networking-system-lab',
    '--bin',
    'kyclash-keychain-public-lab',
  ],
  {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      CARGO_TARGET_DIR: cargoTarget,
      CARGO_INCREMENTAL: '0',
    },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  },
)
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout || '')
  fail(`cargo build failed with status ${result.status}`)
}

const binaryStat = fs.lstatSync(cargoBinary)
if (
  binaryStat.isSymbolicLink() ||
  !binaryStat.isFile() ||
  (binaryStat.mode & 0o111) === 0
)
  fail('cargo did not produce an executable helper')
const temporaryBinary = `${outputBinary}.tmp-${process.pid}`
if (fs.existsSync(temporaryBinary) || fs.existsSync(outputBinary))
  fail('refusing to replace an existing Keychain public helper output')
fs.copyFileSync(cargoBinary, temporaryBinary, fs.constants.COPYFILE_EXCL)
fs.chmodSync(temporaryBinary, 0o755)
fs.renameSync(temporaryBinary, outputBinary)
fs.chmodSync(outputBinary, 0o755)
const digest = crypto
  .createHash('sha256')
  .update(fs.readFileSync(outputBinary))
  .digest('hex')
const provenance = {
  schema_version: 1,
  build_target: 'host-macos-arm64',
  runtime_target: 'kyclash-macos-lab-work',
  feature: 'networking-system-lab',
  binary: 'kyclash-keychain-public-lab',
  source_commit: sourceCommit.stdout.trim(),
  cargo_version: spawnSync('cargo', ['--version'], {
    encoding: 'utf8',
  }).stdout.trim(),
  sha256: digest,
}
if (fs.existsSync(provenancePath))
  fail('refusing to replace an existing helper provenance record')
fs.writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`, {
  mode: 0o600,
})
console.log('keychain_public_helper_built=host-build')
console.log(`keychain_public_helper_sha256=${digest}`)
console.log(`keychain_public_helper_path=${outputBinary}`)
