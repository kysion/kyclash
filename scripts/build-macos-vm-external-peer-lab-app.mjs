import { execFileSync, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

// Fixed, App-only build for the reviewed external-peer VirtualMac lab. It
// accepts no policy, endpoint, credential, signer, package, or output path.
const root = path.resolve(import.meta.dirname, '..')
const target = 'aarch64-apple-darwin'
const feature = 'networking-vm-external-peer-lab-app'
const buildMarker = '.kyclash-vm-external-peer-lab-app-build'
const outputParent = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'vm-external-peer-lab-app',
)
const expectedBundleIdentifier = 'net.kysion.kyclash'
const expectedBundleExecutable = 'clash-verge'
const arm64MachOHeader = Buffer.from('cffaedfe0c000001', 'hex')

const fail = (message) => {
  throw new Error(message)
}

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const sameSnapshot = (left, right) =>
  JSON.stringify(left) === JSON.stringify(right)

const sameFileIdentity = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mode === right.mode

const syncDirectory = (directory) => {
  const descriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  )
  try {
    const stat = fs.fstatSync(descriptor)
    if (!stat.isDirectory() || stat.isSymbolicLink())
      fail('publication directory identity is unsafe')
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

const readExactDescriptor = (descriptor, length) => {
  const bytes = Buffer.alloc(length)
  let offset = 0
  while (offset < length) {
    const count = fs.readSync(
      descriptor,
      bytes,
      offset,
      length - offset,
      offset,
    )
    if (count === 0) fail('published file was truncated')
    offset += count
  }
  return bytes
}

const verifyPublishedFile = (file, expected) => {
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  )
  try {
    const before = fs.fstatSync(descriptor)
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size !== expected.length
    )
      fail('published file identity is unsafe')
    const observed = readExactDescriptor(descriptor, expected.length)
    const after = fs.fstatSync(descriptor)
    if (!sameFileIdentity(before, after) || !observed.equals(expected))
      fail('published file changed during verification')
  } finally {
    fs.closeSync(descriptor)
  }
}

// Metadata is first written and fsynced under a same-directory temporary
// name. A hard link publishes the fully verified inode without replacement;
// result.json is therefore either absent or complete after interruption.
export const atomicPublishBytesNoReplace = (
  directory,
  name,
  value,
  options = {},
) => {
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value)
  if (
    !path.isAbsolute(directory) ||
    path.basename(name) !== name ||
    !/^[a-z0-9][a-z0-9.-]*$/u.test(name) ||
    bytes.length === 0 ||
    (options.afterTempSync !== undefined &&
      typeof options.afterTempSync !== 'function')
  )
    fail('invalid atomic publication request')
  const directoryStat = fs.lstatSync(directory)
  if (
    !directoryStat.isDirectory() ||
    directoryStat.isSymbolicLink() ||
    (directoryStat.mode & 0o077) !== 0
  )
    fail('publication directory must be private')

  const finalPath = path.join(directory, name)
  const temporaryPath = path.join(
    directory,
    `.${name}.tmp.${process.pid}.${crypto.randomBytes(16).toString('hex')}`,
  )
  let descriptor
  let finalCreated = false
  let complete = false
  let outcome
  let operationError
  try {
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_RDWR |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600,
    )
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
    options.afterTempSync?.(temporaryPath)

    const descriptorStat = fs.fstatSync(descriptor)
    const pathStat = fs.lstatSync(temporaryPath)
    if (
      !descriptorStat.isFile() ||
      descriptorStat.isSymbolicLink() ||
      descriptorStat.nlink !== 1 ||
      (descriptorStat.mode & 0o777) !== 0o600 ||
      descriptorStat.size !== bytes.length ||
      !sameFileIdentity(descriptorStat, pathStat) ||
      !readExactDescriptor(descriptor, bytes.length).equals(bytes)
    )
      fail('atomic publication temporary file changed')

    fs.linkSync(temporaryPath, finalPath)
    finalCreated = true
    const finalStat = fs.lstatSync(finalPath)
    if (
      !finalStat.isFile() ||
      finalStat.isSymbolicLink() ||
      finalStat.nlink !== 2 ||
      !sameFileIdentity(descriptorStat, finalStat)
    )
      fail('atomic no-replace publication identity changed')
    syncDirectory(directory)
    fs.unlinkSync(temporaryPath)
    syncDirectory(directory)
    verifyPublishedFile(finalPath, bytes)
    complete = true
    outcome = {
      path: finalPath,
      byte_length: bytes.length,
      sha256: sha256(bytes),
    }
  } catch (error) {
    operationError = error
  }
  try {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  } catch (error) {
    operationError ??= error
  }
  if (!complete) {
    if (!complete && finalCreated) {
      try {
        fs.unlinkSync(finalPath)
      } catch (error) {
        if (error?.code !== 'ENOENT') operationError ??= error
      }
    }
    try {
      fs.unlinkSync(temporaryPath)
    } catch (error) {
      if (error?.code !== 'ENOENT') operationError ??= error
    }
    try {
      syncDirectory(directory)
    } catch (error) {
      operationError ??= error
    }
  }
  if (operationError !== undefined) throw operationError
  return outcome
}

export const atomicPublishJSONNoReplace = (directory, name, value, options) =>
  atomicPublishBytesNoReplace(
    directory,
    name,
    Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8'),
    options,
  )

export const atomicPublishTextNoReplace = (directory, name, value, options) =>
  atomicPublishBytesNoReplace(
    directory,
    name,
    Buffer.from(value, 'utf8'),
    options,
  )

const requireFixedHost = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    fail('external-peer lab App build requires Apple Silicon macOS')
  if (process.argv.length !== 2)
    fail('external-peer lab App builder accepts no arguments')
}

const git = (gitArguments, options = {}) =>
  execFileSync('/usr/bin/git', gitArguments, {
    cwd: root,
    encoding: options.encoding ?? 'buffer',
    maxBuffer: 256 * 1024 * 1024,
  })

const sourceFiles = () =>
  git(['ls-files', '-co', '--exclude-standard', '-z'])
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .sort()

export const collectExternalPeerAppSource = () => {
  const hasher = crypto.createHash('sha256')
  const files = sourceFiles()
  for (const relative of files) {
    if (relative.includes('\0') || path.isAbsolute(relative))
      fail('invalid source inventory entry')
    const absolute = path.join(root, relative)
    const stat = fs.lstatSync(absolute)
    if (!stat.isFile() || stat.isSymbolicLink())
      fail(`source inventory contains a non-regular file: ${relative}`)
    const bytes = fs.readFileSync(absolute)
    hasher.update(Buffer.from(`${relative.length}:`, 'utf8'))
    hasher.update(Buffer.from(relative, 'utf8'))
    hasher.update(Buffer.from(`${bytes.length}:`, 'utf8'))
    hasher.update(bytes)
  }
  const commit = git(['rev-parse', 'HEAD']).toString('utf8').trim()
  const status = git([
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
  ])
  return {
    commit,
    dirty: status.length !== 0,
    status_sha256: sha256(status),
    tree_sha256: hasher.digest('hex'),
    file_count: files.length,
  }
}

export const externalPeerAppOverlay = () => ({
  $schema: '../node_modules/@tauri-apps/cli/config.schema.json',
  bundle: {
    active: true,
    // The App talks only to the fixed authenticated Unix socket. All real
    // data-plane/helper/Mihomo executables are root-staged inside the client
    // VM and therefore must not be hidden in this App bundle.
    externalBin: [],
    resources: [],
    macOS: {
      files: {},
      minimumSystemVersion: '13.0',
      signingIdentity: null,
    },
    createUpdaterArtifacts: false,
  },
})

export const externalPeerAppEnvironment = (
  source,
  cargoTarget,
  { home, temporaryDirectory, pathEntries } = {},
) => {
  if (
    source === null ||
    typeof source !== 'object' ||
    Array.isArray(source) ||
    !path.isAbsolute(cargoTarget) ||
    !path.isAbsolute(home ?? '') ||
    !path.isAbsolute(temporaryDirectory ?? '') ||
    !Array.isArray(pathEntries) ||
    pathEntries.length === 0 ||
    pathEntries.some(
      (entry) =>
        typeof entry !== 'string' ||
        !path.isAbsolute(entry) ||
        entry.includes(path.delimiter),
    )
  )
    fail('invalid external-peer App environment boundary')
  const fixedPath = [...new Set(pathEntries)].join(path.delimiter)
  return {
    // HOME is derived from the effective OS account, never ambient HOME. It
    // is required only so rustup and Corepack can resolve their installed
    // toolchains/caches without accepting CARGO_HOME/RUSTUP_HOME overrides.
    HOME: home,
    // TMPDIR is a fresh 0700 directory under this build run. No ambient temp
    // or agent socket path is inherited.
    TMPDIR: temporaryDirectory,
    // PATH contains only the run-private pnpm shim, the verified account
    // Cargo bin, the current Node bin, and fixed Apple system directories.
    PATH: fixedPath,
    // A fixed locale avoids ambient command/output behavior.
    LANG: 'C',
    LC_ALL: 'C',
    CARGO_TARGET_DIR: cargoTarget,
    CARGO_INCREMENTAL: '0',
    CARGO_PROFILE_RELEASE_DEBUG: '0',
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS: '16',
    VITE_NETWORKING_DEV: 'false',
    VITE_NETWORKING_SYSTEM_LAB: 'true',
    VITE_NETWORKING_PRODUCTION: 'false',
    VITE_NETWORKING_VM_UTUN_LAB: 'false',
    VITE_NETWORKING_VM_NETWORK_LAB: 'false',
    VITE_NETWORKING_VM_EXTERNAL_PEER_LAB: 'true',
  }
}

const requireBuildExecutable = (value, label) => {
  if (!path.isAbsolute(value)) fail(`${label} must be absolute`)
  let resolved
  try {
    resolved = fs.realpathSync(value)
  } catch {
    fail(`${label} is unavailable`)
  }
  const stat = fs.statSync(resolved)
  if (!stat.isFile() || (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0)
    fail(`${label} identity is unsafe`)
  return resolved
}

const requireBuildDirectory = (value, label, privateDirectory = false) => {
  if (!path.isAbsolute(value)) fail(`${label} must be absolute`)
  const stat = fs.lstatSync(value)
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o022) !== 0 ||
    (privateDirectory && (stat.mode & 0o077) !== 0)
  )
    fail(`${label} identity is unsafe`)
  return value
}

const prepareExternalPeerAppBuildEnvironment = ({ runRoot, cargoTarget }) => {
  requireBuildDirectory(runRoot, 'external-peer App build root', true)
  const home = requireBuildDirectory(
    os.userInfo().homedir,
    'effective account home',
  )
  const temporaryDirectory = path.join(runRoot, 'tmp')
  const corepackShim = path.join(runRoot, 'corepack-shim')
  for (const directory of [temporaryDirectory, corepackShim]) {
    fs.mkdirSync(directory, { mode: 0o700 })
    fs.chmodSync(directory, 0o700)
    requireBuildDirectory(directory, 'run-private build directory', true)
  }

  const cargoDirectory = requireBuildDirectory(
    path.join(home, '.cargo', 'bin'),
    'effective account Cargo bin',
  )
  requireBuildExecutable(path.join(cargoDirectory, 'cargo'), 'Cargo')
  requireBuildExecutable(path.join(cargoDirectory, 'rustc'), 'rustc')
  requireBuildExecutable(process.execPath, 'current Node executable')
  const nodeDirectory = requireBuildDirectory(
    path.dirname(process.execPath),
    'current Node bin',
  )
  const corepack = requireBuildExecutable(
    path.join(nodeDirectory, 'corepack'),
    'Corepack',
  )
  const bootstrapEnvironment = externalPeerAppEnvironment({}, cargoTarget, {
    home,
    temporaryDirectory,
    pathEntries: [
      cargoDirectory,
      nodeDirectory,
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
    ],
  })
  execFileSync(corepack, ['enable', '--install-directory', corepackShim], {
    cwd: root,
    env: bootstrapEnvironment,
    stdio: 'ignore',
  })
  requireBuildExecutable(path.join(corepackShim, 'pnpm'), 'Corepack pnpm shim')
  return externalPeerAppEnvironment({}, cargoTarget, {
    home,
    temporaryDirectory,
    pathEntries: [
      corepackShim,
      cargoDirectory,
      nodeDirectory,
      '/usr/bin',
      '/bin',
      '/usr/sbin',
      '/sbin',
    ],
  })
}

const canonicalMode = (stat) =>
  (stat.mode & 0o7777).toString(8).padStart(4, '0')

const readStableRegularFile = (file, label) => {
  const descriptor = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  )
  try {
    const before = fs.fstatSync(descriptor)
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      before.size < 0
    )
      fail(`${label} identity is unsafe`)
    const bytes = readExactDescriptor(descriptor, before.size)
    const after = fs.fstatSync(descriptor)
    if (!sameFileIdentity(before, after))
      fail(`${label} changed during manifest capture`)
    return { bytes, stat: before }
  } finally {
    fs.closeSync(descriptor)
  }
}

const readInfoPlist = (app) => {
  const plist = path.join(app, 'Contents', 'Info.plist')
  const decoded = JSON.parse(
    execFileSync(
      '/usr/bin/plutil',
      ['-convert', 'json', '-o', '-', '--', plist],
      {
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,
      },
    ),
  )
  const required = [
    'CFBundleIdentifier',
    'CFBundleShortVersionString',
    'CFBundleVersion',
    'CFBundleExecutable',
  ]
  for (const name of required) {
    const value = decoded[name]
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > 128 ||
      [...value].some((character) => {
        const codePoint = character.codePointAt(0)
        return codePoint <= 0x1f || codePoint === 0x7f
      })
    )
      fail(`Info.plist ${name} is invalid`)
  }
  if (decoded.CFBundleIdentifier !== expectedBundleIdentifier)
    fail('KyClash App bundle identifier is unexpected')
  if (decoded.CFBundleExecutable !== expectedBundleExecutable)
    fail('KyClash App executable identity is unexpected')
  return {
    relative_path: 'Contents/Info.plist',
    bundle_identifier: decoded.CFBundleIdentifier,
    short_version: decoded.CFBundleShortVersionString,
    bundle_version: decoded.CFBundleVersion,
    bundle_executable: decoded.CFBundleExecutable,
  }
}

export const createExternalPeerAppTreeManifest = (app, source) => {
  if (!path.isAbsolute(app) || source === null || typeof source !== 'object')
    fail('invalid App tree manifest request')
  const appStat = fs.lstatSync(app)
  if (
    !appStat.isDirectory() ||
    appStat.isSymbolicLink() ||
    (appStat.mode & 0o022) !== 0
  )
    fail('KyClash App root identity is unsafe')

  const entries = [
    {
      relative_path: '.',
      type: 'directory',
      mode: canonicalMode(appStat),
      byte_length: 0,
      sha256: null,
    },
  ]
  const visit = (directory, prefix = '') => {
    const directoryEntries = fs
      .readdirSync(directory, {
        withFileTypes: true,
        encoding: 'utf8',
      })
      .sort((left, right) =>
        Buffer.compare(
          Buffer.from(left.name, 'utf8'),
          Buffer.from(right.name, 'utf8'),
        ),
      )
    for (const entry of directoryEntries) {
      if (
        entry.name.length === 0 ||
        entry.name === '.' ||
        entry.name === '..' ||
        entry.name.includes('/') ||
        entry.name.includes('\0')
      )
        fail('App tree contains an invalid entry name')
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name
      const absolute = path.join(directory, entry.name)
      const stat = fs.lstatSync(absolute)
      if (entry.isSymbolicLink() || stat.isSymbolicLink())
        fail(`App contains symlink: ${relative}`)
      if (entry.isDirectory() && stat.isDirectory()) {
        if ((stat.mode & 0o022) !== 0)
          fail(`App directory is writable by group/other: ${relative}`)
        entries.push({
          relative_path: relative,
          type: 'directory',
          mode: canonicalMode(stat),
          byte_length: 0,
          sha256: null,
        })
        visit(absolute, relative)
      } else if (entry.isFile() && stat.isFile()) {
        const observed = readStableRegularFile(absolute, `App file ${relative}`)
        entries.push({
          relative_path: relative,
          type: 'file',
          mode: canonicalMode(observed.stat),
          byte_length: observed.bytes.length,
          sha256: sha256(observed.bytes),
        })
      } else {
        fail(`App contains unsupported object: ${relative}`)
      }
    }
  }
  visit(app)

  const infoPlist = readInfoPlist(app)
  const executablePath = `Contents/MacOS/${infoPlist.bundle_executable}`
  const executable = entries.find(
    (entry) => entry.relative_path === executablePath && entry.type === 'file',
  )
  if (executable === undefined)
    fail('KyClash App executable is absent from tree manifest')
  const treeSHA256 = sha256(Buffer.from(JSON.stringify(entries), 'utf8'))
  return {
    schema_version: 1,
    app_name: 'KyClash.app',
    source,
    tree_sha256: treeSHA256,
    info_plist: infoPlist,
    main_executable: {
      relative_path: executable.relative_path,
      mode: executable.mode,
      byte_length: executable.byte_length,
      sha256: executable.sha256,
    },
    entries,
  }
}

const verifyThinArm64 = (file) => {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY)
  try {
    const header = Buffer.alloc(8)
    if (fs.readSync(descriptor, header, 0, header.length, 0) !== header.length)
      fail('KyClash App executable is truncated')
    if (!header.equals(arm64MachOHeader))
      fail('KyClash App executable is not thin arm64 Mach-O')
  } finally {
    fs.closeSync(descriptor)
  }
}

const verifyAppOnly = (bundleRoot, app) => {
  const executable = path.join(app, 'Contents', 'MacOS', 'clash-verge')
  verifyThinArm64(executable)
  const forbiddenNames = new Set([
    'kyclash-network-sidecar',
    'kyclash-route-helper',
    'kyclash-tunnel-broker',
    'verge-mihomo',
    'verge-mihomo-alpha',
    'latest.json',
  ])
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (forbiddenNames.has(entry.name))
        fail(`external-peer App contains forbidden payload: ${entry.name}`)
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) visit(absolute)
    }
  }
  visit(app)
  for (const entry of fs.readdirSync(bundleRoot, { withFileTypes: true })) {
    if (entry.name !== 'macos')
      fail(`App-only build produced another bundle kind: ${entry.name}`)
  }
  const macosRoot = path.join(bundleRoot, 'macos')
  const macosEntries = fs.readdirSync(macosRoot)
  if (macosEntries.length !== 1 || macosEntries[0] !== 'KyClash.app')
    fail('App-only build produced an unexpected macOS artifact')

  const signature = spawnSync('/usr/bin/codesign', ['-d', '--verbose=4', app], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const signatureDetails = `${signature.stdout ?? ''}${signature.stderr ?? ''}`
  if (
    signatureDetails.includes('Authority=') ||
    /TeamIdentifier=(?!not set)/u.test(signatureDetails)
  )
    fail('no-sign external-peer App unexpectedly has a signing identity')
  return executable
}

export const buildExternalPeerAppRun = ({
  destinationParent,
  sourceBefore,
  sourceAfter,
  buildApp,
  publicationHooks = {},
}) => {
  if (
    !path.isAbsolute(destinationParent) ||
    typeof sourceBefore !== 'function' ||
    typeof sourceAfter !== 'function' ||
    typeof buildApp !== 'function' ||
    publicationHooks === null ||
    typeof publicationHooks !== 'object'
  )
    fail('invalid external-peer App build transaction')

  const before = sourceBefore()
  fs.mkdirSync(destinationParent, { recursive: true, mode: 0o700 })
  const runRoot = fs.mkdtempSync(path.join(destinationParent, 'run.'))
  fs.chmodSync(runRoot, 0o700)
  fs.writeFileSync(path.join(runRoot, buildMarker), 'vm-external-peer-app\n', {
    flag: 'wx',
    mode: 0o600,
  })
  const cargoTarget = path.join(runRoot, 'cargo-target')
  const configPath = path.join(runRoot, 'tauri.vm-external-peer-app.json')
  fs.writeFileSync(
    configPath,
    `${JSON.stringify(externalPeerAppOverlay(), null, 2)}\n`,
    { flag: 'wx', mode: 0o600 },
  )
  buildApp({ runRoot, cargoTarget, configPath })

  const afterBuild = sourceAfter()
  if (!sameSnapshot(before, afterBuild))
    fail('workspace source changed during external-peer App build; discard it')

  const bundleRoot = path.join(cargoTarget, target, 'release', 'bundle')
  const app = path.join(bundleRoot, 'macos', 'KyClash.app')
  if (!fs.existsSync(app)) fail('Tauri did not produce KyClash.app')
  const executable = verifyAppOnly(bundleRoot, app)
  const manifest = createExternalPeerAppTreeManifest(app, before)

  const afterInspection = sourceAfter()
  if (!sameSnapshot(before, afterInspection))
    fail('workspace source changed during external-peer App build; discard it')
  const verifiedManifest = createExternalPeerAppTreeManifest(app, before)
  if (!sameSnapshot(manifest, verifiedManifest))
    fail('KyClash App tree changed during manifest capture')

  const manifestPublication = atomicPublishJSONNoReplace(
    runRoot,
    'app-tree-manifest.json',
    manifest,
    publicationHooks.manifest,
  )
  const provenance = {
    schema_version: 1,
    status: 'complete',
    build_target: 'host-build-only',
    runtime_execution_performed: false,
    runtime_target: 'kyclash-macos-lab-work',
    peer_target: 'kyclash-macos-lab-peer',
    runtime_mode: 'vm_external_peer_lab',
    feature,
    target,
    source: before,
    app,
    app_tree_manifest: manifestPublication.path,
    app_tree_manifest_sha256: manifestPublication.sha256,
    app_tree_sha256: manifest.tree_sha256,
    executable_sha256: manifest.main_executable.sha256,
    signing_identity: null,
    packages: false,
    updater_artifacts: false,
    embedded_privileged_payloads: false,
  }
  const provenancePublication = atomicPublishJSONNoReplace(
    runRoot,
    'provenance.json',
    provenance,
    publicationHooks.provenance,
  )

  const beforeResult = sourceAfter()
  if (!sameSnapshot(before, beforeResult))
    fail('workspace source changed during external-peer App build; discard it')
  const finalManifest = createExternalPeerAppTreeManifest(app, before)
  if (!sameSnapshot(manifest, finalManifest))
    fail('KyClash App tree changed before result publication')
  verifyThinArm64(executable)

  const result = {
    schema_version: 2,
    status: 'unsigned-disposable-vm-external-peer-lab-app',
    build_target: 'host-build-only',
    runtime_execution_performed: false,
    runtime_target: 'kyclash-macos-lab-work',
    peer_target: 'kyclash-macos-lab-peer',
    runtime_mode: 'vm_external_peer_lab',
    feature,
    target,
    source: before,
    run_root: runRoot,
    app,
    app_tree_manifest: manifestPublication.path,
    app_tree_manifest_sha256: manifestPublication.sha256,
    app_tree_sha256: manifest.tree_sha256,
    info_plist: manifest.info_plist,
    main_executable: manifest.main_executable,
    provenance: provenancePublication.path,
    provenance_sha256: provenancePublication.sha256,
    signing_identity: null,
    packages: false,
    updater_artifacts: false,
    embedded_privileged_payloads: false,
  }
  const resultPublication = atomicPublishJSONNoReplace(
    runRoot,
    'result.json',
    result,
    publicationHooks.result,
  )
  return {
    runRoot,
    resultPath: resultPublication.path,
    result,
    provenance,
    manifest,
  }
}

const build = () => {
  requireFixedHost()
  fs.mkdirSync(outputParent, { recursive: true, mode: 0o700 })
  const tauri = path.join(root, 'node_modules', '.bin', 'tauri')
  const stat = fs.lstatSync(tauri)
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0)
    fail('fixed Tauri CLI is unavailable')
  const completed = buildExternalPeerAppRun({
    destinationParent: outputParent,
    sourceBefore: collectExternalPeerAppSource,
    sourceAfter: collectExternalPeerAppSource,
    buildApp: ({ runRoot, cargoTarget, configPath }) => {
      const environment = prepareExternalPeerAppBuildEnvironment({
        runRoot,
        cargoTarget,
      })
      execFileSync(
        tauri,
        [
          'build',
          '--target',
          target,
          '--bundles',
          'app',
          '--no-sign',
          '--features',
          feature,
          '--config',
          configPath,
        ],
        {
          cwd: root,
          env: environment,
          stdio: 'inherit',
        },
      )
    },
  })
  process.stdout.write('vm_external_peer_app_build=complete\n')
  process.stdout.write(`vm_external_peer_app_path=${completed.result.app}\n`)
  process.stdout.write(
    `vm_external_peer_app_sha256=${completed.result.app_tree_sha256}\n`,
  )
  process.stdout.write(`vm_external_peer_app_result=${completed.resultPath}\n`)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    build()
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}
