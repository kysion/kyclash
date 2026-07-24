import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { externalPeerPinnedGoToolchain } from './build-macos-vm-external-peer-lab-binaries.mjs'
import { buildExternalPeerHostCourierRun } from './build-macos-vm-external-peer-lab-host-courier.mjs'

const arm64MachO = (suffix = 'host-courier') =>
  Buffer.concat([
    Buffer.from('cffaedfe0c0000010000000002000000', 'hex'),
    Buffer.alloc(16),
    Buffer.from(suffix, 'utf8'),
  ])

const snapshot = (tree = 'a'.repeat(64)) => ({
  commit: '0123456789abcdef0123456789abcdef01234567',
  dirty: true,
  status_sha256: 'b'.repeat(64),
  tree_sha256: tree,
  file_count: 77,
})

const transaction = (destinationParent, overrides = {}) => ({
  destinationParent,
  sourceBefore: () => snapshot(),
  sourceAfter: () => snapshot(),
  goToolchain: { ...externalPeerPinnedGoToolchain },
  buildOne: (output) => {
    fs.writeFileSync(output, arm64MachO(), {
      flag: 'wx',
      mode: 0o700,
    })
  },
  ...overrides,
})

test('host courier build publishes a fresh dirty-tree-bound result', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-host-courier-success.'),
  )
  const first = buildExternalPeerHostCourierRun(transaction(parent))
  const second = buildExternalPeerHostCourierRun(transaction(parent))
  assert.notEqual(first.runRoot, second.runRoot)
  assert.equal(fs.existsSync(first.resultPath), true)
  assert.equal(fs.existsSync(second.resultPath), true)
  assert.equal(first.result.source.dirty, true)
  assert.equal(first.result.source.tree_sha256, 'a'.repeat(64))
  assert.equal(first.result.source.status_sha256, 'b'.repeat(64))
  assert.equal(first.provenance.runtime_execution_performed, false)
  assert.deepEqual(first.provenance.go_toolchain, externalPeerPinnedGoToolchain)
  assert.deepEqual(first.provenance.command_surface, [
    'key-init',
    'management-key-init',
    'management-host-key-pin',
    'layer-a-inputs-init',
    'layer-b-inputs-init',
    'layer-b-listener-baseline-approve',
    'start-lab',
  ])
  assert.equal(
    first.provenance.fixed_tart.sha256,
    '05b65d5c14e8b41e8e44b6d9fd1278de4bedbc8b735d9b99f3c748f76f75862d',
  )
})

test('failed build cannot overwrite or mix with an old successful run', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-host-courier-failure.'),
  )
  const old = buildExternalPeerHostCourierRun(transaction(parent))
  const oldResult = fs.readFileSync(old.resultPath)
  assert.throws(
    () =>
      buildExternalPeerHostCourierRun(
        transaction(parent, {
          buildOne: () => {
            throw new Error('injected host build failure')
          },
        }),
      ),
    /injected host build failure/u,
  )
  assert.deepEqual(fs.readFileSync(old.resultPath), oldResult)
  const runs = fs
    .readdirSync(parent)
    .filter((name) => name.startsWith('run.'))
    .map((name) => path.join(parent, name))
  assert.equal(runs.length, 2)
  const failed = runs.find((run) => run !== old.runRoot)
  assert.equal(fs.existsSync(path.join(failed, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(failed, 'provenance.json')), false)
})

test('source change leaves the fresh artifact unpublished', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-host-courier-race.'),
  )
  assert.throws(
    () =>
      buildExternalPeerHostCourierRun(
        transaction(parent, {
          sourceAfter: () => snapshot('c'.repeat(64)),
        }),
      ),
    /workspace source changed/u,
  )
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), false)
})

test('host courier tamper before metadata publication is rejected', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-host-courier-tamper.'),
  )
  let output
  assert.throws(
    () =>
      buildExternalPeerHostCourierRun(
        transaction(parent, {
          buildOne: (candidate) => {
            output = candidate
            fs.writeFileSync(candidate, arm64MachO(), {
              flag: 'wx',
              mode: 0o700,
            })
          },
          sourceAfter: () => {
            fs.appendFileSync(output, Buffer.from('tamper', 'utf8'))
            return snapshot()
          },
        }),
      ),
    /host courier changed/u,
  )
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), false)
})

test('host courier truncated result temporary file is never published', () => {
  const parent = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-host-courier-partial.'),
  )
  assert.throws(
    () =>
      buildExternalPeerHostCourierRun(
        transaction(parent, {
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
  const [run] = fs.readdirSync(parent).filter((name) => name.startsWith('run.'))
  assert.equal(fs.existsSync(path.join(parent, run, 'result.json')), false)
  assert.equal(fs.existsSync(path.join(parent, run, 'provenance.json')), true)
})
