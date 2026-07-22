import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

/**
 * Build-input preparation for the disposable networking-production VM
 * candidate.  This module does not sign policy material and does not start a
 * VM; it only copies already-public resources and emits a run-local Tauri
 * configuration whose resource source is absolute and unambiguous.
 */

export const LAB_MARKER_RESOURCE = 'kyclash-networking-vm-lab-candidate.json'
export const LAB_POLICY_RESOURCE = 'kyclash-networking-policy-v2.json'
export const LAB_TRUST_RESOURCE = 'kyclash-networking-policy-keys.json'
export const LAB_DESCRIPTOR_RESOURCE = 'guest-descriptor.json'
export const LAB_REVISION_PREFLIGHT_RESOURCE = 'policy-revision-preflight.json'
export const LAB_OVERLAY_NAME =
  'tauri.networking-production-vm-lab.macos.conf.json'
// This list is intentionally reviewed and closed. Adding an ordinary
// resource requires updating the candidate review rather than silently
// widening the signed VM-candidate input.
export const ORDINARY_RESOURCE_ALLOWLIST = Object.freeze([
  'Country.mmdb',
  'clash-verge-service',
  'clash-verge-service-install',
  'clash-verge-service-uninstall',
  'geoip.dat',
  'geosite.dat',
  'kyclash-network-sidecar-aarch64-apple-darwin.trust.json',
  'set_dns.sh',
  'unset_dns.sh',
])

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..')
const DEFAULT_SOURCE_ROOT = path.join(PROJECT_ROOT, 'src-tauri/resources')
const DEFAULT_BASE_CONFIG = path.join(
  PROJECT_ROOT,
  'src-tauri/tauri.networking.macos.conf.json',
)

const fail = (message) => {
  throw new Error(message)
}

const isAbsolute = (value) =>
  typeof value === 'string' && path.isAbsolute(value)

export const canonicalizeMacOsAbsolutePath = (
  value,
  platform = process.platform,
) => {
  if (typeof value !== 'string' || !path.isAbsolute(value)) return value
  const normalized = path.normalize(value)
  if (platform !== 'darwin') return normalized
  for (const [alias, canonical] of [
    ['/var', '/private/var'],
    ['/tmp', '/private/tmp'],
    ['/etc', '/private/etc'],
  ]) {
    if (normalized === alias || normalized.startsWith(`${alias}${path.sep}`)) {
      return `${canonical}${normalized.slice(alias.length)}`
    }
  }
  return normalized
}

const ensureAbsolute = (value, label) => {
  if (!isAbsolute(value)) fail(`${label} must be an absolute path`)
  return canonicalizeMacOsAbsolutePath(value)
}

const assertNoSymlinkComponents = (filePath, label = filePath) => {
  const normalized = path.normalize(filePath)
  const parsed = path.parse(normalized)
  let current = parsed.root
  const components = normalized
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean)
  for (const component of components) {
    current = path.join(current, component)
    if (!fs.existsSync(current)) break
    const stat = fs.lstatSync(current)
    if (stat.isSymbolicLink())
      fail(`${label} contains symlink component: ${current}`)
  }
}

const lstatNoSymlink = (filePath, label = filePath) => {
  let stat
  try {
    stat = fs.lstatSync(filePath)
  } catch (error) {
    fail(
      `${label} does not exist: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (stat.isSymbolicLink()) fail(`${label} must not be a symlink`)
  return stat
}

const assertRegularPublicFile = (filePath, label = filePath) => {
  const stat = lstatNoSymlink(filePath, label)
  if (!stat.isFile()) fail(`${label} must be a regular file`)
  if ((stat.mode & 0o022) !== 0)
    fail(`${label} must not be group/other writable`)
  return stat
}

const sameFile = (left, right) =>
  left.dev === right.dev && left.ino === right.ino

/**
 * Open and read a public build input through a no-follow descriptor. The
 * path-to-descriptor identity checks make a rename/symlink swap fail closed;
 * the end-of-preparation inventory check protects against in-place changes.
 */
export const readRegularFileNoFollow = (filePath, label = filePath) => {
  const absolute = ensureAbsolute(filePath, label)
  assertNoSymlinkComponents(absolute, label)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let descriptor
  try {
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | noFollow)
  } catch (error) {
    fail(
      `${label} cannot be opened without following links: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  try {
    const before = fs.fstatSync(descriptor)
    if (!before.isFile()) fail(`${label} must be a regular file`)
    if ((before.mode & 0o022) !== 0)
      fail(`${label} must not be group/other writable`)
    const pathBefore = lstatNoSymlink(absolute, label)
    if (!sameFile(before, pathBefore)) fail(`${label} changed while opening`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor)
    const pathAfter = lstatNoSymlink(absolute, label)
    if (
      !sameFile(before, after) ||
      !sameFile(after, pathAfter) ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      bytes.length !== after.size
    ) {
      fail(`${label} changed while reading`)
    }
    return { bytes, stat: after, path: absolute }
  } finally {
    fs.closeSync(descriptor)
  }
}

const fsyncDirectory = (directory) => {
  let descriptor
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY)
    fs.fsyncSync(descriptor)
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

/** Atomically publish a new regular file without replacing an existing name. */
export const writeFileNoReplace = (filePath, bytes, mode = 0o644) => {
  const absolute = ensureAbsolute(filePath, filePath)
  const parent = path.dirname(absolute)
  assertNoSymlinkComponents(parent, `parent of ${absolute}`)
  const parentStat = lstatNoSymlink(parent, `parent of ${absolute}`)
  if (!parentStat.isDirectory())
    fail(`parent of ${absolute} is not a directory`)
  const temporary = path.join(
    parent,
    `.${path.basename(absolute)}.tmp-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  )
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let descriptor
  let temporaryOwned = false
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        noFollow,
      mode,
    )
    temporaryOwned = true
    fs.fchmodSync(descriptor, mode)
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
    const opened = fs.fstatSync(descriptor)
    const named = lstatNoSymlink(temporary, temporary)
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      !sameFile(opened, named) ||
      opened.size !== bytes.length ||
      (opened.mode & 0o777) !== mode
    ) {
      fail(`temporary publication file is unsafe: ${temporary}`)
    }
    fs.closeSync(descriptor)
    descriptor = undefined
    // link(2), unlike rename(2), fails if the destination appeared between
    // validation and publication. Both names are in the same directory.
    fs.linkSync(temporary, absolute)
    const published = lstatNoSymlink(absolute, absolute)
    const linked = lstatNoSymlink(temporary, temporary)
    if (
      !published.isFile() ||
      !sameFile(published, linked) ||
      published.nlink !== 2 ||
      (published.mode & 0o777) !== mode
    ) {
      fail(`published file identity mismatch: ${absolute}`)
    }
    fs.unlinkSync(temporary)
    temporaryOwned = false
    const finalStat = lstatNoSymlink(absolute, absolute)
    if (!finalStat.isFile() || finalStat.nlink !== 1)
      fail(`published file link count is unsafe: ${absolute}`)
    const parentAfter = lstatNoSymlink(parent, `parent of ${absolute}`)
    if (!sameFile(parentStat, parentAfter))
      fail(`parent of ${absolute} changed during publication`)
    fsyncDirectory(parent)
    return finalStat
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor)
    if (temporaryOwned) {
      try {
        fs.unlinkSync(temporary)
      } catch {
        // The original failure is authoritative; the random, scoped temp name
        // is never reused as a successful output.
      }
    }
    throw error
  }
}

const assertDirectoryNoSymlinks = (directory, label = directory) => {
  const stat = lstatNoSymlink(directory, label)
  if (!stat.isDirectory()) fail(`${label} must be a directory`)
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name)
    const entryStat = lstatNoSymlink(entryPath, entryPath)
    if (entryStat.isDirectory()) {
      assertDirectoryNoSymlinks(entryPath, entryPath)
    } else if (!entryStat.isFile()) {
      fail(`${entryPath} must be a regular file`)
    } else if ((entryStat.mode & 0o022) !== 0) {
      fail(`${entryPath} must not be group/other writable`)
    }
  }
  return stat
}

const relativeEntries = (root) => {
  const entries = []
  const visit = (directory, relativeDirectory) => {
    for (const entry of fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const source = path.join(directory, entry.name)
      const relative = path.join(relativeDirectory, entry.name)
      const stat = lstatNoSymlink(source, source)
      if (stat.isDirectory()) visit(source, relative)
      else if (stat.isFile()) entries.push(relative)
      else fail(`${source} must be a regular file or directory`)
    }
  }
  visit(root, '')
  return entries
}

const copyTreeNoSymlinks = (sourceRoot, destinationRoot) => {
  assertDirectoryNoSymlinks(sourceRoot, sourceRoot)
  if (fs.existsSync(destinationRoot))
    fail(`refusing to overwrite staged resource root: ${destinationRoot}`)
  fs.mkdirSync(destinationRoot, { recursive: true, mode: 0o700 })
  const copy = (source, destination) => {
    const stat = lstatNoSymlink(source, source)
    if (stat.isDirectory()) {
      fs.mkdirSync(destination, { mode: 0o700 })
      for (const name of fs.readdirSync(source))
        copy(path.join(source, name), path.join(destination, name))
      return
    }
    if (!stat.isFile()) fail(`${source} must be a regular file`)
    const opened = readRegularFileNoFollow(source, source)
    if (!sameFile(stat, opened.stat))
      fail(`${source} changed before it could be staged`)
    // Preserve executable bits needed by ordinary KyClash resources while
    // stripping all write bits outside the owner.
    writeFileNoReplace(destination, opened.bytes, stat.mode & 0o755)
  }
  for (const name of fs.readdirSync(sourceRoot)) {
    copy(path.join(sourceRoot, name), path.join(destinationRoot, name))
  }
  return relativeEntries(destinationRoot)
}

const parseJsonObject = (filePath, label) => {
  const input = readRegularFileNoFollow(filePath, label)
  let value
  try {
    value = JSON.parse(input.bytes.toString('utf8'))
  } catch (error) {
    fail(
      `${label} must contain valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${label} must contain a JSON object`)
  return value
}

const assertNoPrivateMaterial = (root) => {
  const prohibitedKey = (key) => {
    const normalized = key
      .normalize('NFKC')
      .toLowerCase()
      .replace(/[^a-z0-9]/gu, '')
    return (
      normalized === 'privatekey' ||
      normalized.endsWith('privatekey') ||
      normalized === 'secret' ||
      normalized.endsWith('secret') ||
      normalized === 'password' ||
      normalized.endsWith('password') ||
      normalized === 'token' ||
      normalized.endsWith('token') ||
      normalized === 'seed' ||
      normalized.endsWith('seed')
    )
  }
  const scanJson = (value, relative) => {
    if (Array.isArray(value)) {
      for (const child of value) scanJson(child, relative)
      return
    }
    if (!value || typeof value !== 'object') return
    for (const [key, child] of Object.entries(value)) {
      if (prohibitedKey(key)) {
        fail(
          `staged public resources contain prohibited private material: ${relative}`,
        )
      }
      scanJson(child, relative)
    }
  }
  for (const relative of relativeEntries(root)) {
    const filePath = path.join(root, relative)
    const { bytes } = readRegularFileNoFollow(filePath, filePath)
    // Scan the complete byte stream. Removing NUL bytes only for detection
    // prevents a binary/text ambiguity from hiding a PEM boundary or field.
    const searchable = bytes.toString('latin1').replaceAll('\0', '')
    if (
      /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/iu.test(searchable) ||
      /["']?\s*(?:private[_-]?key|secret|password|token|seed)\s*["']?\s*:/iu.test(
        searchable,
      )
    ) {
      fail(
        `staged public resources contain prohibited private material: ${relative}`,
      )
    }
    try {
      scanJson(JSON.parse(bytes.toString('utf8')), relative)
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith(
          'staged public resources contain prohibited private material:',
        )
      ) {
        throw error
      }
      // Ordinary resources may be binary or non-JSON text. Raw scanning above
      // remains mandatory and size-independent for those files.
    }
  }
}

/**
 * Stage ordinary resources and optional, already-public lab files.  The
 * ordinary tree is copied without following links; callers can then hash the
 * resulting tree and use it as the sole Tauri resource source.
 */
export const stagePublicResources = ({
  sourceRoot = DEFAULT_SOURCE_ROOT,
  stagedResources,
  labFiles = {},
  ordinaryAllowlist = ORDINARY_RESOURCE_ALLOWLIST,
}) => {
  const source = ensureAbsolute(sourceRoot, 'source resources')
  const destination = ensureAbsolute(stagedResources, 'staged resources')
  assertNoSymlinkComponents(source, 'source resources')
  assertNoSymlinkComponents(destination, 'staged resources')
  if (path.resolve(destination) === path.resolve(source))
    fail('staged resources must differ from source resources')
  if (
    !Array.isArray(ordinaryAllowlist) ||
    ordinaryAllowlist.some(
      (name) => typeof name !== 'string' || path.basename(name) !== name,
    )
  ) {
    fail('ordinary resource allowlist must contain only basenames')
  }
  const sourceEntries = relativeEntries(source).sort()
  const expectedEntries = [...ordinaryAllowlist].sort()
  if (
    sourceEntries.length !== expectedEntries.length ||
    sourceEntries.some((name, index) => name !== expectedEntries[index])
  ) {
    fail('ordinary resources do not match the reviewed closed allowlist')
  }
  copyTreeNoSymlinks(source, destination)

  const allowed = new Set([
    LAB_MARKER_RESOURCE,
    LAB_POLICY_RESOURCE,
    LAB_TRUST_RESOURCE,
  ])
  for (const [name, input] of Object.entries(labFiles)) {
    if (!allowed.has(name)) fail(`unsupported lab resource: ${name}`)
    if (
      name.includes('/') ||
      name.includes('\\') ||
      path.basename(name) !== name
    )
      fail(`lab resource name is not a basename: ${name}`)
    const sourceFile = ensureAbsolute(input, `lab resource ${name}`)
    assertRegularPublicFile(sourceFile, sourceFile)
    const destinationFile = path.join(destination, name)
    if (fs.existsSync(destinationFile))
      fail(`lab resource collides with ordinary resource: ${name}`)
    const opened = readRegularFileNoFollow(sourceFile, sourceFile)
    writeFileNoReplace(destinationFile, opened.bytes, 0o644)
  }
  assertDirectoryNoSymlinks(destination, destination)
  assertNoPrivateMaterial(destination)
  return {
    root: destination,
    files: relativeEntries(destination),
  }
}

const cloneJson = (value) => JSON.parse(JSON.stringify(value))

const validateBaseConfig = (base, baseConfigPath) => {
  if (!base || typeof base !== 'object' || Array.isArray(base))
    fail('base Tauri config must be a JSON object')
  if (
    !base.bundle ||
    typeof base.bundle !== 'object' ||
    Array.isArray(base.bundle)
  ) {
    fail(`base Tauri config has no bundle object: ${baseConfigPath}`)
  }
  const macOS = base.bundle.macOS
  if (!macOS || typeof macOS !== 'object' || Array.isArray(macOS))
    fail('base Tauri config has no bundle.macOS object')
  if (
    !macOS.files ||
    typeof macOS.files !== 'object' ||
    Array.isArray(macOS.files)
  )
    fail('base Tauri config must retain bundle.macOS.files')
}

/**
 * Produce the exact run-local overlay.  Tauri's object form for `resources`
 * maps the absolute source directory to the bundle-relative `resources`
 * destination; the existing nested sidecar/helper mappings are copied from
 * the reviewed networking macOS config and cannot silently disappear.
 */
export const createNetworkingProductionOverlay = ({
  stagedResources,
  baseConfig = DEFAULT_BASE_CONFIG,
  output,
}) => {
  const resourceRoot = ensureAbsolute(stagedResources, 'staged resources')
  assertNoSymlinkComponents(resourceRoot, 'staged resources')
  assertDirectoryNoSymlinks(resourceRoot, resourceRoot)
  const baseConfigPath = ensureAbsolute(baseConfig, 'base Tauri config')
  assertNoSymlinkComponents(baseConfigPath, 'base Tauri config')
  assertRegularPublicFile(baseConfigPath, baseConfigPath)
  const base = parseJsonObject(baseConfigPath, baseConfigPath)
  validateBaseConfig(base, baseConfigPath)
  const outputPath = ensureAbsolute(output, 'overlay output')
  assertNoSymlinkComponents(path.dirname(outputPath), 'overlay output')
  if (fs.existsSync(outputPath))
    fail(`refusing to overwrite overlay: ${outputPath}`)
  const overlay = {
    $schema:
      base.$schema ?? '../node_modules/@tauri-apps/cli/config.schema.json',
    bundle: {
      externalBin: cloneJson(base.bundle.externalBin ?? []),
      macOS: cloneJson(base.bundle.macOS),
      resources: {
        [resourceRoot]: 'resources',
      },
    },
  }
  if (!Array.isArray(overlay.bundle.externalBin))
    fail('base bundle.externalBin must be an array')
  if (
    !overlay.bundle.macOS.files ||
    typeof overlay.bundle.macOS.files !== 'object'
  )
    fail('overlay lost bundle.macOS.files')
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 })
  assertNoSymlinkComponents(path.dirname(outputPath), 'overlay output')
  writeFileNoReplace(
    outputPath,
    Buffer.from(`${JSON.stringify(overlay, null, 2)}\n`),
    0o600,
  )
  assertRegularPublicFile(outputPath, outputPath)
  return {
    output: outputPath,
    resourceRoot,
    overlay,
  }
}

const optionValue = (argv, name) => {
  const index = argv.indexOf(name)
  if (index === -1) return undefined
  const value = argv[index + 1]
  if (!value || value.startsWith('--')) fail(`${name} requires a value`)
  return value
}

const runCli = () => {
  const argv = process.argv.slice(2)
  const descriptor = optionValue(argv, '--descriptor')
  const runRoot = optionValue(argv, '--run-root')
  if (descriptor || runRoot) {
    if (!descriptor || !runRoot) {
      fail('full lab preparation requires both --descriptor and --run-root')
    }
    // Keep this historical entry point as a process boundary rather than an
    // ESM import cycle. The generator is the sole implementation of the full
    // candidate CLI and reports errors without a Node stack trace.
    const generatorPath = path.join(
      import.meta.dirname,
      'generate-networking-production-vm-lab.mjs',
    )
    const child = spawnSync(process.execPath, [generatorPath, ...argv], {
      stdio: 'inherit',
    })
    if (child.error) throw child.error
    process.exitCode = child.status ?? 1
    return
  }
  const stagedResources = optionValue(argv, '--resource-root')
  const output = optionValue(argv, '--output')
  const baseConfig = optionValue(argv, '--base-config') ?? DEFAULT_BASE_CONFIG
  if (!stagedResources || !output) {
    fail(
      'usage: prepare-networking-production-vm-lab.mjs --resource-root <absolute-staged-resources> --output <absolute-overlay> [--base-config <absolute-config>]',
    )
  }
  const result = createNetworkingProductionOverlay({
    stagedResources,
    baseConfig,
    output,
  })
  process.stdout.write(
    `${JSON.stringify({ output: result.output, resource_root: result.resourceRoot })}\n`,
  )
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
