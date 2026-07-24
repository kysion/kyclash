import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import {
  atomicPublishJSONNoReplace,
  atomicPublishTextNoReplace,
  collectExternalPeerAppSource,
} from './build-macos-vm-external-peer-lab-app.mjs'

// Layer-A compile only. Nothing produced here may execute on the host or the
// stopped base VM; runtime is limited to the two reviewed disposable guests.
const root = path.resolve(import.meta.dirname, '..')
const sourceRoot = path.join(root, 'network-sidecar')
const outputParent = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'vm-external-peer-lab',
)
const go = path.join(root, 'target', 'toolchains', 'go1.26.5', 'bin', 'go')
const goCache = path.join(
  root,
  'target',
  'macos-vm-lab',
  'cache',
  'external-peer-go-build',
)
const goModCache = path.join(
  root,
  'target',
  'macos-vm-lab',
  'cache',
  'external-peer-go-mod',
)
const mihomo = path.join(
  root,
  'src-tauri',
  'sidecar',
  'verge-mihomo-aarch64-apple-darwin',
)
const expectedMihomoSymbol =
  'github.com/kysion/kyclash/network-sidecar/internal/vmnetworklab.ExpectedMihomoSHA256'
const buildMarker = '.kyclash-vm-external-peer-binaries-build'
const arm64MachOHeader = Buffer.from([
  0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01,
])
export const externalPeerPinnedGoToolchain = Object.freeze({
  relative_path: 'target/toolchains/go1.26.5/bin/go',
  byte_length: 14500160,
  sha256: '3925fc3221ac440ebf7c35361ff663bed0c7bdb2e0a157b75fe993607ffe0a19',
  version: 'go version go1.26.5 darwin/arm64',
})

const clientTags = ['kyclash_utun', 'kyclash_vm_external_peer_lab']
export const externalPeerBinaryArtifacts = Object.freeze([
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-client-stage-layer-a',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-client-bootstrap-ssh-layer-a',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-client-prepare-layer-b',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-client-pin-layer-b',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-supervisor',
    tags: clientTags,
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'client',
    name: 'kyclash-vm-external-peer-lab-harness',
    tags: clientTags,
    runtimeTarget: 'kyclash-macos-lab-work',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer-stage-layer-a',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer-bootstrap-ssh-layer-a',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer-prepare-layer-b',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer-pin-layer-b',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer-root-supervisor',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-peer',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-listener-auditor',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
  {
    role: 'peer',
    name: 'kyclash-vm-external-peer-lab-forced-command',
    tags: [],
    runtimeTarget: 'kyclash-macos-lab-peer',
  },
])

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

export const externalPeerGoBuildEnvironment = () => ({
  CGO_ENABLED: '0',
  GO111MODULE: 'on',
  GOARCH: 'arm64',
  GOARM64: 'v8.0',
  GOAUTH: 'off',
  GOCACHE: goCache,
  GOENV: 'off',
  GOFLAGS: '',
  GOINSECURE: '',
  GOMODCACHE: goModCache,
  GONOPROXY: '',
  GONOSUMDB: '',
  GOOS: 'darwin',
  GOPRIVATE: '',
  GOPROXY: 'https://proxy.golang.org',
  GOSUMDB: 'sum.golang.org',
  GOTELEMETRY: 'off',
  GOTOOLCHAIN: 'local',
  GOVCS: '*:off',
  GOWORK: 'off',
})

const readStableExecutable = (value, label) => {
  const descriptor = fs.openSync(
    value,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  )
  try {
    const before = fs.fstatSync(descriptor)
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      (before.mode & 0o111) === 0 ||
      (before.mode & 0o022) !== 0
    )
      throw new Error(`${label} identity is unsafe`)
    const bytes = fs.readFileSync(descriptor)
    const after = fs.fstatSync(descriptor)
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mode !== after.mode ||
      bytes.length !== before.size
    )
      throw new Error(`${label} changed during verification`)
    return bytes
  } finally {
    fs.closeSync(descriptor)
  }
}

export const inspectExternalPeerPinnedGoToolchain = () => {
  requireExecutable(go, 'pinned Go toolchain')
  const before = readStableExecutable(go, 'pinned Go toolchain')
  if (
    before.length !== externalPeerPinnedGoToolchain.byte_length ||
    sha256(before) !== externalPeerPinnedGoToolchain.sha256
  )
    throw new Error('pinned Go toolchain size or SHA-256 is unexpected')
  const version = execFileSync(go, ['version'], {
    encoding: 'utf8',
    env: externalPeerGoBuildEnvironment(),
  }).trim()
  const after = readStableExecutable(go, 'pinned Go toolchain')
  if (
    after.length !== before.length ||
    sha256(after) !== externalPeerPinnedGoToolchain.sha256 ||
    version !== externalPeerPinnedGoToolchain.version
  )
    throw new Error('pinned Go toolchain identity or version changed')
  return { ...externalPeerPinnedGoToolchain }
}

const requireExecutable = (value, label) => {
  if (!path.isAbsolute(value)) throw new Error(`${label} must be absolute`)
  const stat = fs.lstatSync(value)
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o111) === 0 ||
    (stat.mode & 0o022) !== 0
  )
    throw new Error(`${label} must be a non-writable regular executable`)
}

const requireFixedHost = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    throw new Error(
      'external-peer lab binaries require an Apple Silicon macOS builder',
    )
  if (process.argv.length !== 2)
    throw new Error('external-peer lab binary builder accepts no arguments')
}

const sameSnapshot = (left, right) =>
  JSON.stringify(left) === JSON.stringify(right)

const verifyBuiltArtifact = (output, artifact) => {
  const stat = fs.lstatSync(output)
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.mode & 0o022 ||
    stat.size < arm64MachOHeader.length
  )
    throw new Error(`${artifact.name} output identity is unsafe`)
  const bytes = fs.readFileSync(output)
  if (!bytes.subarray(0, arm64MachOHeader.length).equals(arm64MachOHeader))
    throw new Error(`${artifact.name} is not a thin arm64 Mach-O executable`)
  return {
    artifact: artifact.name,
    role: artifact.role,
    runtime_target: artifact.runtimeTarget,
    source: `network-sidecar/cmd/${artifact.name}`,
    go_tags: artifact.tags,
    byte_length: bytes.length,
    sha256: sha256(bytes),
  }
}

// buildRun publishes nothing until all 14 role-separated artifacts exist and
// the exact source snapshot still matches. A failed run remains in its own
// fresh run.* directory without result.json and can never mix with a prior
// successful run.
export const buildExternalPeerBinaryRun = ({
  destinationParent,
  artifacts = externalPeerBinaryArtifacts,
  sourceBefore,
  sourceAfter,
  buildOne,
  goToolchain,
  mihomoSha256,
  publicationHooks = {},
}) => {
  if (
    !path.isAbsolute(destinationParent) ||
    !Array.isArray(artifacts) ||
    artifacts.length !== 14 ||
    typeof sourceBefore !== 'function' ||
    typeof sourceAfter !== 'function' ||
    typeof buildOne !== 'function' ||
    JSON.stringify(goToolchain) !==
      JSON.stringify(externalPeerPinnedGoToolchain) ||
    !/^[0-9a-f]{64}$/u.test(mihomoSha256) ||
    publicationHooks === null ||
    typeof publicationHooks !== 'object'
  )
    throw new Error('invalid external-peer binary build transaction')

  const before = sourceBefore()
  fs.mkdirSync(destinationParent, { recursive: true, mode: 0o700 })
  const runRoot = fs.mkdtempSync(path.join(destinationParent, 'run.'))
  fs.chmodSync(runRoot, 0o700)
  fs.writeFileSync(path.join(runRoot, buildMarker), 'host-build-only\n', {
    flag: 'wx',
    mode: 0o600,
  })
  const roleRoots = new Map()
  for (const role of ['client', 'peer']) {
    const roleRoot = path.join(runRoot, role)
    fs.mkdirSync(roleRoot, { recursive: false, mode: 0o700 })
    roleRoots.set(role, roleRoot)
  }

  const results = []
  for (const artifact of artifacts) {
    const roleRoot = roleRoots.get(artifact.role)
    if (
      roleRoot === undefined ||
      !/^[a-z0-9-]+$/u.test(artifact.name) ||
      path.basename(artifact.name) !== artifact.name
    )
      throw new Error('invalid external-peer artifact contract')
    const output = path.join(roleRoot, artifact.name)
    if (fs.existsSync(output))
      throw new Error('external-peer artifact destination already exists')
    buildOne(artifact, output)
    fs.chmodSync(output, 0o755)
    results.push(verifyBuiltArtifact(output, artifact))
  }

  const afterBuild = sourceAfter()
  if (!sameSnapshot(before, afterBuild))
    throw new Error(
      'workspace source changed during external-peer binary build; discard it',
    )
  const verifiedResults = artifacts.map((artifact) =>
    verifyBuiltArtifact(
      path.join(roleRoots.get(artifact.role), artifact.name),
      artifact,
    ),
  )
  if (!sameSnapshot(results, verifiedResults))
    throw new Error('external-peer artifact tree changed after compilation')

  const provenance = {
    schema_version: 3,
    lab_profile: 'vm-external-peer',
    status: 'complete',
    build_target: 'host-build-only',
    target: 'aarch64-apple-darwin',
    cgo_enabled: false,
    execution_policy:
      'never-host; never-base; client-only-kyclash-macos-lab-work; peer-only-kyclash-macos-lab-peer',
    source: before,
    go_toolchain: goToolchain,
    go_environment_allowlist: externalPeerGoBuildEnvironment(),
    go_build_flags: [
      '-mod=readonly',
      '-trimpath',
      '-buildvcs=false',
      '-ldflags=-buildid=',
    ],
    mihomo_input: 'src-tauri/sidecar/verge-mihomo-aarch64-apple-darwin',
    mihomo_sha256: mihomoSha256,
    artifacts: results,
  }
  const provenancePublication = atomicPublishJSONNoReplace(
    runRoot,
    'provenance.json',
    provenance,
    publicationHooks.provenance,
  )
  const hashesPublication = atomicPublishTextNoReplace(
    runRoot,
    'sha256.txt',
    `${results
      .map((value) => `${value.sha256}  ${value.role}/${value.artifact}`)
      .join('\n')}\n`,
    publicationHooks.hashes,
  )
  const beforeResult = sourceAfter()
  if (!sameSnapshot(before, beforeResult))
    throw new Error(
      'workspace source changed during external-peer binary build; discard it',
    )
  const finalResults = artifacts.map((artifact) =>
    verifyBuiltArtifact(
      path.join(roleRoots.get(artifact.role), artifact.name),
      artifact,
    ),
  )
  if (!sameSnapshot(results, finalResults))
    throw new Error('external-peer artifact tree changed before publication')
  const result = {
    schema_version: 2,
    status: 'complete',
    build_target: 'host-build-only',
    runtime_targets: {
      client: 'kyclash-macos-lab-work',
      peer: 'kyclash-macos-lab-peer',
    },
    run_root: runRoot,
    provenance: provenancePublication.path,
    provenance_sha256: provenancePublication.sha256,
    sha256: hashesPublication.path,
    sha256_file_sha256: hashesPublication.sha256,
    artifact_count: results.length,
    source: before,
    go_toolchain: goToolchain,
  }
  const resultPublication = atomicPublishJSONNoReplace(
    runRoot,
    'result.json',
    result,
    publicationHooks.result,
  )
  return {
    resultPath: resultPublication.path,
    runRoot,
    result,
    provenance,
  }
}

const build = () => {
  requireFixedHost()
  requireExecutable(mihomo, 'Mihomo input')
  fs.mkdirSync(goCache, { recursive: true, mode: 0o700 })
  fs.chmodSync(goCache, 0o700)
  fs.mkdirSync(goModCache, { recursive: true, mode: 0o700 })
  fs.chmodSync(goModCache, 0o700)
  const mihomoBytes = fs.readFileSync(mihomo)
  if (
    mihomoBytes.length < arm64MachOHeader.length ||
    !mihomoBytes.subarray(0, arm64MachOHeader.length).equals(arm64MachOHeader)
  )
    throw new Error('Mihomo input must be a thin arm64 Mach-O executable')
  const mihomoSha256 = sha256(mihomoBytes)
  const goToolchain = inspectExternalPeerPinnedGoToolchain()
  const completed = buildExternalPeerBinaryRun({
    destinationParent: outputParent,
    sourceBefore: collectExternalPeerAppSource,
    sourceAfter: collectExternalPeerAppSource,
    goToolchain,
    mihomoSha256,
    buildOne: (artifact, output) => {
      const buildArguments = [
        'build',
        '-mod=readonly',
        '-trimpath',
        '-buildvcs=false',
        '-ldflags',
        `-buildid= -X ${expectedMihomoSymbol}=${mihomoSha256}`,
      ]
      if (artifact.tags.length > 0)
        buildArguments.push('-tags', artifact.tags.join(','))
      buildArguments.push('-o', output, `./cmd/${artifact.name}`)
      execFileSync(go, buildArguments, {
        cwd: sourceRoot,
        env: externalPeerGoBuildEnvironment(),
        stdio: 'inherit',
      })
    },
  })
  process.stdout.write('vm_external_peer_binary_build=complete\n')
  process.stdout.write(
    `vm_external_peer_binary_result=${completed.resultPath}\n`,
  )
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
