import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  buildExternalPeerBinaryRun,
  externalPeerBinaryArtifacts,
  externalPeerGoBuildEnvironment,
  externalPeerPinnedGoToolchain,
} from './build-macos-vm-external-peer-lab-binaries.mjs'

const arm64MachO = (name) =>
  Buffer.concat([
    Buffer.from('cffaedfe0c0000010000000002000000', 'hex'),
    Buffer.alloc(16),
    Buffer.from(name, 'utf8'),
  ])

const snapshot = (tree = 'a'.repeat(64)) => ({
  commit: '0123456789abcdef0123456789abcdef01234567',
  dirty: true,
  status_sha256: 'b'.repeat(64),
  tree_sha256: tree,
  file_count: 42,
})

const transaction = (destinationParent, overrides = {}) => ({
  destinationParent,
  artifacts: externalPeerBinaryArtifacts,
  sourceBefore: () => snapshot(),
  sourceAfter: () => snapshot(),
  goToolchain: { ...externalPeerPinnedGoToolchain },
  mihomoSha256: 'c'.repeat(64),
  buildOne: (artifact, output) => {
    fs.writeFileSync(output, arm64MachO(artifact.name), {
      flag: 'wx',
      mode: 0o755,
    })
  },
  ...overrides,
})

test('binary build publishes one fresh complete result with dirty-tree provenance', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-binary-builder-success.'),
  )
  const first = buildExternalPeerBinaryRun(transaction(root))
  const second = buildExternalPeerBinaryRun(transaction(root))
  assert.notEqual(first.runRoot, second.runRoot)
  assert.equal(fs.existsSync(first.resultPath), true)
  assert.equal(fs.existsSync(second.resultPath), true)
  assert.equal(first.result.artifact_count, 14)
  assert.equal(first.provenance.artifacts.length, 14)
  assert.equal(first.provenance.source.dirty, true)
  assert.equal(first.provenance.source.tree_sha256, 'a'.repeat(64))
  assert.equal(first.provenance.source.status_sha256, 'b'.repeat(64))
  assert.deepEqual(first.provenance.go_toolchain, externalPeerPinnedGoToolchain)
  assert.deepEqual(
    fs.readdirSync(first.runRoot).filter((name) => name === 'result.json'),
    ['result.json'],
  )
})

test('Go build environment is a closed allowlist despite malicious ambient values', () => {
  const environment = externalPeerGoBuildEnvironment({
    CC: '/tmp/evil-cc',
    CXX: '/tmp/evil-cxx',
    GOENV: '/tmp/evil-goenv',
    GOEXPERIMENT: 'fieldtrack',
    GOFLAGS: '-overlay=/tmp/evil.json -toolexec=/tmp/evil',
    GOROOT: '/tmp/evil-goroot',
    GOTOOLCHAIN: 'auto',
    GOWORK: '/tmp/evil.work',
    PATH: '/tmp/evil-bin',
    TOOLEXEC: '/tmp/evil',
  })
  assert.equal(environment.GOENV, 'off')
  assert.equal(environment.GOWORK, 'off')
  assert.equal(environment.GOTOOLCHAIN, 'local')
  assert.equal(environment.GOFLAGS, '')
  assert.equal(environment.CGO_ENABLED, '0')
  assert.equal(environment.GOPROXY, 'https://proxy.golang.org')
  for (const name of [
    'CC',
    'CXX',
    'GOEXPERIMENT',
    'GOROOT',
    'PATH',
    'TOOLEXEC',
  ])
    assert.equal(Object.hasOwn(environment, name), false)
})

test('mid-build failure never publishes and never mixes with an old result', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-binary-builder-failure.'),
  )
  const old = buildExternalPeerBinaryRun(transaction(root))
  const oldResult = fs.readFileSync(old.resultPath)
  let count = 0
  assert.throws(
    () =>
      buildExternalPeerBinaryRun(
        transaction(root, {
          buildOne: (artifact, output) => {
            count += 1
            if (count === 5) throw new Error('injected build failure')
            fs.writeFileSync(output, arm64MachO(artifact.name), {
              flag: 'wx',
              mode: 0o755,
            })
          },
        }),
      ),
    /injected build failure/u,
  )
  assert.deepEqual(fs.readFileSync(old.resultPath), oldResult)
  const runs = fs
    .readdirSync(root)
    .filter((name) => name.startsWith('run.'))
    .map((name) => path.join(root, name))
  assert.equal(runs.length, 2)
  const unpublished = runs.find((run) => run !== old.runRoot)
  assert.equal(fs.existsSync(path.join(unpublished, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(unpublished, 'provenance.json')), false)
})

test('source change after compilation leaves the fresh run unpublished', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-binary-builder-source-change.'),
  )
  assert.throws(
    () =>
      buildExternalPeerBinaryRun(
        transaction(root, {
          sourceAfter: () => snapshot('d'.repeat(64)),
        }),
      ),
    /workspace source changed/u,
  )
  const [run] = fs.readdirSync(root).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(root, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(root, run, 'provenance.json')), false)
})

test('artifact tree tamper before publication is rejected', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-binary-builder-tree-tamper.'),
  )
  let victim
  assert.throws(
    () =>
      buildExternalPeerBinaryRun(
        transaction(root, {
          buildOne: (artifact, output) => {
            fs.writeFileSync(output, arm64MachO(artifact.name), {
              flag: 'wx',
              mode: 0o755,
            })
            victim ??= output
          },
          sourceAfter: () => {
            fs.appendFileSync(victim, Buffer.from('tamper', 'utf8'))
            return snapshot()
          },
        }),
      ),
    /artifact tree changed/u,
  )
  const [run] = fs.readdirSync(root).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(root, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(root, run, 'provenance.json')), false)
})

test('truncated result temporary file is never published', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-binary-builder-partial-result.'),
  )
  assert.throws(
    () =>
      buildExternalPeerBinaryRun(
        transaction(root, {
          publicationHooks: {
            result: {
              afterTempSync: (temporaryPath) =>
                fs.truncateSync(temporaryPath, 1),
            },
          },
        }),
      ),
    /temporary file changed/u,
  )
  const [run] = fs.readdirSync(root).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(root, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(root, run, 'provenance.json')), true)
})
