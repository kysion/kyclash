import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { LAB_MARKER_RESOURCE } from './prepare-networking-production-vm-lab.mjs'

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const HEX40 = /^[0-9a-f]{40}$/u
const HEX64 = /^[0-9a-f]{64}$/u
const PENDING_SHA256 = '0'.repeat(64)

const fail = (message) => {
  throw new Error(message)
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const lstatRegular = (filePath, label = filePath) => {
  const stat = fs.lstatSync(filePath)
  if (
    stat.isSymbolicLink() ||
    !stat.isFile() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o022) !== 0
  )
    fail(`${label} must be one non-writable regular file`)
  return stat
}

const readRegular = (filePath, label = filePath) => {
  const before = lstatRegular(filePath, label)
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  )
  try {
    const opened = fs.fstatSync(descriptor)
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    )
      fail(`${label} changed while opening`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor)
    const named = lstatRegular(filePath, label)
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      named.dev !== opened.dev ||
      named.ino !== opened.ino ||
      bytes.length !== after.size
    )
      fail(`${label} changed while reading`)
    return bytes
  } finally {
    fs.closeSync(descriptor)
  }
}

const readJson = (filePath, label = filePath) => {
  const bytes = readRegular(filePath, label)
  let value
  try {
    value = JSON.parse(bytes.toString('utf8'))
  } catch {
    fail(`${label} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must be a JSON object`)
  return { value, bytes }
}

const writeOwnedReplacement = (filePath, bytes, expectedMode) => {
  const before = lstatRegular(filePath, filePath)
  if ((before.mode & 0o777) !== expectedMode)
    fail(`${filePath} has an unexpected mode`)
  const parent = path.dirname(filePath)
  const parentStat = fs.lstatSync(parent)
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink())
    fail(`${parent} must be a non-symlink directory`)
  const temporary = path.join(
    parent,
    `.${path.basename(filePath)}.seal-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  )
  let descriptor
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      expectedMode,
    )
    fs.fchmodSync(descriptor, expectedMode)
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
    const temporaryStat = fs.fstatSync(descriptor)
    if (
      !temporaryStat.isFile() ||
      temporaryStat.nlink !== 1 ||
      temporaryStat.size !== bytes.length ||
      (temporaryStat.mode & 0o777) !== expectedMode
    )
      fail(`unsafe temporary seal file for ${filePath}`)
    fs.closeSync(descriptor)
    descriptor = undefined
    const current = lstatRegular(filePath, filePath)
    if (current.dev !== before.dev || current.ino !== before.ino)
      fail(`${filePath} changed before sealing`)
    fs.renameSync(temporary, filePath)
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary)
  }
  const published = lstatRegular(filePath, filePath)
  if (
    published.size !== bytes.length ||
    (published.mode & 0o777) !== expectedMode
  )
    fail(`sealed marker publication failed for ${filePath}`)
}

export const sealMarkerWithFinalComponentHashes = ({
  marker,
  sourceMihomoSha256,
  sourceMihomoAlphaSha256,
  finalMihomoSha256,
  finalMihomoAlphaSha256,
}) => {
  if (!marker || typeof marker !== 'object' || Array.isArray(marker))
    fail('lab marker must be an object')
  for (const value of [
    sourceMihomoSha256,
    sourceMihomoAlphaSha256,
    finalMihomoSha256,
    finalMihomoAlphaSha256,
  ]) {
    if (!HEX64.test(value) || value === PENDING_SHA256)
      fail('component hash is invalid')
  }
  if (
    marker.build_inputs?.mihomo_sha256 !== sourceMihomoSha256 ||
    marker.build_inputs?.mihomo_alpha_sha256 !== sourceMihomoAlphaSha256
  )
    fail('Mihomo source inputs differ from the generated marker')
  if (
    marker.mihomo_final_sha256 !== PENDING_SHA256 ||
    marker.mihomo_alpha_final_sha256 !== PENDING_SHA256
  )
    fail('lab marker is already sealed or has invalid final component fields')
  return {
    ...marker,
    mihomo_final_sha256: finalMihomoSha256,
    mihomo_alpha_final_sha256: finalMihomoAlphaSha256,
  }
}

const parseOptions = (argv) => {
  const allowed = new Set(['--lab-public-root', '--target'])
  const values = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]
    const value = argv[index + 1]
    if (
      !allowed.has(name) ||
      values.has(name) ||
      !value ||
      value.startsWith('--')
    )
      fail('candidate sealing arguments are invalid')
    values.set(name, value)
  }
  return values
}

const gitHead = () => {
  const status = spawnSync(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all', '--ignored=no'],
    { cwd: PROJECT_ROOT, encoding: 'utf8' },
  )
  if (status.error || status.status !== 0 || status.stdout.trim() !== '')
    fail('candidate sealing requires a clean reviewed source tree')
  const head = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
  }).trim()
  if (!HEX40.test(head)) fail('cannot resolve the reviewed source commit')
  return head
}

const runCli = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    fail('candidate sealing requires an Apple Silicon macOS host')
  const argv = process.argv.slice(2)
  const options = parseOptions(argv)
  const publicRoot = options.get('--lab-public-root')
  const target = options.get('--target') ?? 'aarch64-apple-darwin'
  if (!publicRoot || !path.isAbsolute(publicRoot))
    fail(
      'usage: seal-networking-production-vm-lab.mjs --lab-public-root <absolute-public-root> [--target aarch64-apple-darwin]',
    )
  if (target !== 'aarch64-apple-darwin')
    fail('networking-production-vm-lab is arm64-only')
  const skipAppCodesign = process.env.KYCLASH_SKIP_APP_CODESIGN === 'true'
  const identity = process.env.APPLE_SIGNING_IDENTITY
  const team = process.env.APPLE_TEAM_ID
  if (!skipAppCodesign && (!identity || team !== 'RQUQ8Y3S9H'))
    fail(
      'Developer ID Application identity and locked Team ID are required unless KYCLASH_SKIP_APP_CODESIGN=true',
    )
  const sourceCommit = gitHead()
  const app = path.join(
    PROJECT_ROOT,
    'target',
    target,
    'release',
    'bundle',
    'macos',
    'KyClash.app',
  )
  const appStat = fs.lstatSync(app)
  if (!appStat.isDirectory() || appStat.isSymbolicLink())
    fail('KyClash.app is not a non-symlink directory')
  const rootMarker = path.join(publicRoot, LAB_MARKER_RESOURCE)
  const stagedMarker = path.join(publicRoot, 'resources', LAB_MARKER_RESOURCE)
  const appMarker = path.join(
    app,
    'Contents',
    'Resources',
    'resources',
    LAB_MARKER_RESOURCE,
  )
  const rootInput = readJson(rootMarker, rootMarker)
  for (const sibling of [stagedMarker, appMarker]) {
    if (!rootInput.bytes.equals(readRegular(sibling, sibling)))
      fail('generated, staged, and App lab markers differ before sealing')
  }
  if (rootInput.value.source_commit !== sourceCommit)
    fail('lab marker source commit differs from current HEAD')

  const sourceMihomo = path.join(
    PROJECT_ROOT,
    'src-tauri',
    'sidecar',
    `verge-mihomo-${target}`,
  )
  const sourceMihomoAlpha = path.join(
    PROJECT_ROOT,
    'src-tauri',
    'sidecar',
    `verge-mihomo-alpha-${target}`,
  )
  const finalMihomo = path.join(app, 'Contents', 'MacOS', 'verge-mihomo')
  const finalMihomoAlpha = path.join(
    app,
    'Contents',
    'MacOS',
    'verge-mihomo-alpha',
  )
  const finalMihomoSha256 = sha256(readRegular(finalMihomo, finalMihomo))
  const finalMihomoAlphaSha256 = sha256(
    readRegular(finalMihomoAlpha, finalMihomoAlpha),
  )
  const marker = sealMarkerWithFinalComponentHashes({
    marker: rootInput.value,
    sourceMihomoSha256: sha256(readRegular(sourceMihomo, sourceMihomo)),
    sourceMihomoAlphaSha256: sha256(
      readRegular(sourceMihomoAlpha, sourceMihomoAlpha),
    ),
    finalMihomoSha256,
    finalMihomoAlphaSha256,
  })
  const markerBytes = Buffer.from(`${JSON.stringify(marker)}\n`)
  writeOwnedReplacement(rootMarker, markerBytes, 0o644)
  writeOwnedReplacement(stagedMarker, markerBytes, 0o644)
  writeOwnedReplacement(appMarker, markerBytes, 0o644)

  if (!skipAppCodesign) {
    execFileSync(
      '/usr/bin/codesign',
      [
        '--force',
        '--options',
        'runtime',
        '--timestamp',
        '--preserve-metadata=identifier,entitlements,requirements,flags',
        '--sign',
        identity,
        app,
      ],
      { stdio: 'inherit' },
    )
    execFileSync(
      '/usr/bin/codesign',
      ['--verify', '--deep', '--strict', '--verbose=2', app],
      { stdio: 'inherit' },
    )
  } else {
    console.log('kyclash_vm_lab_app_codesign=skipped-by-explicit-user-request')
  }
  if (
    sha256(readRegular(finalMihomo, finalMihomo)) !== finalMihomoSha256 ||
    sha256(readRegular(finalMihomoAlpha, finalMihomoAlpha)) !==
      finalMihomoAlphaSha256 ||
    !markerBytes.equals(readRegular(appMarker, appMarker))
  )
    fail('final component or sealed marker changed while re-signing the App')
  console.log('kyclash_vm_lab_candidate_sealed=host-build')
  console.log(`mihomo_final_sha256=${finalMihomoSha256}`)
  console.log(`mihomo_alpha_final_sha256=${finalMihomoAlphaSha256}`)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    runCli()
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}
