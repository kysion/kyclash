import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import {
  atomicPublishJSONNoReplace,
  collectExternalPeerAppSource,
} from './build-macos-vm-external-peer-lab-app.mjs'
import {
  externalPeerGoBuildEnvironment,
  externalPeerPinnedGoToolchain,
  inspectExternalPeerPinnedGoToolchain,
} from './build-macos-vm-external-peer-lab-binaries.mjs'

// Layer-A host build only. Importing this module performs no build and no
// runtime command. The fixed CLI may contact the two reviewed guests only
// when a user later executes start-lab after a separate Layer-B approval.
const root = path.resolve(import.meta.dirname, '..')
const sourceRoot = path.join(root, 'network-sidecar')
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
const outputParent = path.join(
  root,
  'target',
  'macos-vm-lab',
  'build',
  'vm-external-peer-lab',
  'host',
)
const artifactName = 'kyclash-vm-external-peer-lab-host-courier'
const buildMarker = '.kyclash-vm-external-peer-host-courier-build'
const arm64MachOHeader = Buffer.from([
  0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01,
])
const commandSurface = Object.freeze([
  'key-init',
  'management-key-init',
  'management-host-key-pin',
  'layer-a-inputs-init',
  'layer-b-inputs-init',
  'layer-b-listener-baseline-approve',
  'start-lab',
])
const tart = Object.freeze({
  relative_path: 'target/tools/tart-2.32.1/tart.app/Contents/MacOS/tart',
  byte_length: 72771024,
  sha256: '05b65d5c14e8b41e8e44b6d9fd1278de4bedbc8b735d9b99f3c748f76f75862d',
})

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const requireFixedHost = () => {
  if (process.platform !== 'darwin' || process.arch !== 'arm64')
    throw new Error('external-peer host courier requires Apple Silicon macOS')
  if (process.argv.length !== 2)
    throw new Error('external-peer host courier builder accepts no arguments')
}

const sameSnapshot = (left, right) =>
  JSON.stringify(left) === JSON.stringify(right)

const verifyArtifact = (output) => {
  const stat = fs.lstatSync(output)
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o022) !== 0 ||
    stat.size < arm64MachOHeader.length
  )
    throw new Error('host courier output identity is unsafe')
  const bytes = fs.readFileSync(output)
  if (!bytes.subarray(0, arm64MachOHeader.length).equals(arm64MachOHeader))
    throw new Error('host courier is not a thin arm64 Mach-O executable')
  return {
    name: artifactName,
    source: 'network-sidecar/cmd/kyclash-vm-external-peer-lab-host-courier',
    byte_length: bytes.length,
    sha256: sha256(bytes),
  }
}

// A run publishes result.json last. Failed or source-raced builds stay in
// their own fresh run.* directory and cannot overwrite or mix with any older
// successful artifact.
export const buildExternalPeerHostCourierRun = ({
  destinationParent,
  sourceBefore,
  sourceAfter,
  buildOne,
  goToolchain,
  publicationHooks = {},
}) => {
  if (
    !path.isAbsolute(destinationParent) ||
    typeof sourceBefore !== 'function' ||
    typeof sourceAfter !== 'function' ||
    typeof buildOne !== 'function' ||
    JSON.stringify(goToolchain) !==
      JSON.stringify(externalPeerPinnedGoToolchain) ||
    publicationHooks === null ||
    typeof publicationHooks !== 'object'
  )
    throw new Error('invalid external-peer host courier build transaction')

  const before = sourceBefore()
  fs.mkdirSync(destinationParent, { recursive: true, mode: 0o700 })
  const runRoot = fs.mkdtempSync(path.join(destinationParent, 'run.'))
  fs.chmodSync(runRoot, 0o700)
  fs.writeFileSync(path.join(runRoot, buildMarker), 'host-build-only\n', {
    flag: 'wx',
    mode: 0o600,
  })
  const output = path.join(runRoot, artifactName)
  buildOne(output)
  fs.chmodSync(output, 0o700)
  const artifact = verifyArtifact(output)

  const afterBuild = sourceAfter()
  if (!sameSnapshot(before, afterBuild))
    throw new Error(
      'workspace source changed during host courier build; discard it',
    )
  const verifiedArtifact = verifyArtifact(output)
  if (!sameSnapshot(artifact, verifiedArtifact))
    throw new Error('host courier changed after compilation')

  const provenance = {
    schema_version: 3,
    status: 'complete',
    lab_profile: 'vm-external-peer',
    build_target: 'host-orchestration-only',
    runtime_execution_performed: false,
    execution_scope:
      'fixed-key-custody, reviewed-public-artifact-courier, and status-observation only',
    target: 'aarch64-apple-darwin',
    cgo_enabled: false,
    command_surface: commandSurface,
    private_root: 'target/macos-vm-lab/private/vm-external-peer-courier',
    source: before,
    go_toolchain: goToolchain,
    go_environment_allowlist: externalPeerGoBuildEnvironment(),
    go_build_flags: [
      '-mod=readonly',
      '-trimpath',
      '-buildvcs=false',
      '-ldflags=-buildid=',
    ],
    fixed_tart: tart,
    artifact,
  }
  const provenancePublication = atomicPublishJSONNoReplace(
    runRoot,
    'provenance.json',
    provenance,
    publicationHooks.provenance,
  )
  const beforeResult = sourceAfter()
  if (!sameSnapshot(before, beforeResult))
    throw new Error(
      'workspace source changed during host courier build; discard it',
    )
  const finalArtifact = verifyArtifact(output)
  if (!sameSnapshot(artifact, finalArtifact))
    throw new Error('host courier changed before result publication')
  const result = {
    schema_version: 2,
    status: 'complete',
    build_target: 'host-orchestration-only',
    runtime_execution_performed: false,
    run_root: runRoot,
    artifact: output,
    artifact_sha256: artifact.sha256,
    provenance: provenancePublication.path,
    provenance_sha256: provenancePublication.sha256,
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
    runRoot,
    resultPath: resultPublication.path,
    result,
    provenance,
  }
}

const build = () => {
  requireFixedHost()
  fs.mkdirSync(goCache, { recursive: true, mode: 0o700 })
  fs.chmodSync(goCache, 0o700)
  fs.mkdirSync(goModCache, { recursive: true, mode: 0o700 })
  fs.chmodSync(goModCache, 0o700)
  const goToolchain = inspectExternalPeerPinnedGoToolchain()
  const completed = buildExternalPeerHostCourierRun({
    destinationParent: outputParent,
    sourceBefore: collectExternalPeerAppSource,
    sourceAfter: collectExternalPeerAppSource,
    goToolchain,
    buildOne: (output) => {
      execFileSync(
        go,
        [
          'build',
          '-mod=readonly',
          '-trimpath',
          '-buildvcs=false',
          '-ldflags',
          '-buildid=',
          '-o',
          output,
          './cmd/kyclash-vm-external-peer-lab-host-courier',
        ],
        {
          cwd: sourceRoot,
          env: externalPeerGoBuildEnvironment(),
          stdio: 'inherit',
        },
      )
    },
  })
  process.stdout.write('vm_external_peer_host_build=complete\n')
  process.stdout.write(`vm_external_peer_host_result=${completed.resultPath}\n`)
  process.stdout.write(
    `vm_external_peer_host_courier=${completed.result.artifact}\n`,
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
