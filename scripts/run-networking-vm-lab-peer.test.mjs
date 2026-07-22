import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { PassThrough } from 'node:stream'
import test from 'node:test'

import {
  PEER_ENVIRONMENT,
  PEER_RUNTIME_TARGET,
  PEER_RUNNER_ENVIRONMENT,
  PEER_VM_CONFIRMATION,
  buildPeerRemoteCommand,
  buildPeerSshArgs,
  parsePeerRunnerOptions,
  peerPaths,
  startPersistentPeerSession,
  validatePeerSpec,
} from './run-networking-vm-lab-peer.mjs'

const NOW = 1_900_000_000
const SPEC = Object.freeze({
  runId: '0123456789abcdef',
  expiresAt: NOW + 3_600,
})

test('peer runner parser requires a run-bound expiry and rejects open options', () => {
  assert.deepEqual(
    parsePeerRunnerOptions([
      '--run-id',
      SPEC.runId,
      '--expires-at',
      String(SPEC.expiresAt),
    ]),
    { help: false, runId: SPEC.runId, expiresAt: SPEC.expiresAt },
  )
  assert.deepEqual(parsePeerRunnerOptions(['--help']), { help: true })
  for (const invalid of [
    [],
    ['--run-id', '0123456789ABCDEf', '--expires-at', '1900003600'],
    ['--run-id', SPEC.runId],
    ['--expires-at', '0', '--run-id', SPEC.runId],
    ['--run-id', SPEC.runId, '--expires-at', '1', '--bogus'],
  ])
    assert.throws(
      () => parsePeerRunnerOptions(invalid),
      /peer|run|expir|option/u,
    )
})

test('peer command is fixed to the disposable guest and binds all private paths to the run id', () => {
  const paths = peerPaths(SPEC.runId)
  assert.equal(
    paths.root,
    `/private/var/tmp/kyclash-networking-vm-lab/${SPEC.runId}`,
  )
  const command = buildPeerRemoteCommand(SPEC, NOW)
  assert.match(command, /^\/usr\/bin\/env /u)
  for (const [key, value] of Object.entries(PEER_ENVIRONMENT))
    assert.match(command, new RegExp(`${key}=${value}`, 'u'))
  for (const value of Object.values(paths))
    assert.match(command, new RegExp(value.replaceAll('/', '\\/'), 'u'))
  assert.match(command, /'--expires-at' '1900003600'/u)
  assert.doesNotMatch(command, /\n|\r|;|&&|\|\|/u)
})

test('SSH invocation is strict and allocates a persistent stdin pipe', () => {
  const args = buildPeerSshArgs('192.0.2.10', SPEC, NOW)
  assert.ok(args.includes('-T'))
  assert.ok(args.includes('BatchMode=yes'))
  assert.ok(args.includes('StrictHostKeyChecking=yes'))
  assert.ok(args.includes('IdentitiesOnly=yes'))
  assert.match(args.at(-2), /^supen@192\.0\.2\.10$/u)
  assert.match(args.at(-1), /KYCLASH_RUNNER_ENVIRONMENT/u)
  assert.match(args.at(-1), /KYCLASH_VM_LAB_CONFIRM/u)
  assert.match(args.at(-1), /KYCLASH_RUNTIME_TARGET/u)
  const source = fs.readFileSync(
    path.join(import.meta.dirname, 'run-networking-vm-lab-peer.mjs'),
    'utf8',
  )
  assert.doesNotMatch(source, /spawnSync|runRemote/u)
  assert.match(source, /stdio:\s*\[\s*'pipe',\s*'pipe',\s*'pipe'\s*\]/u)
  assert.match(source, /process\.stdin\.pipe\(session\.child\.stdin\)/u)
})

test('persistent session keeps stdin open through readiness and closes only explicitly', async (t) => {
  if (
    process.platform !== 'darwin' ||
    process.arch !== 'arm64' ||
    !fs.existsSync(
      path.join(
        import.meta.dirname,
        '..',
        'target/macos-vm-lab/ssh/id_ed25519',
      ),
    )
  ) {
    t.skip('requires the authorized Apple Silicon host SSH fixture')
    return
  }
  const child = new EventEmitter()
  child.stdin = new PassThrough()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.pid = 4242
  let spawnCall
  const session = startPersistentPeerSession({
    ip: '192.0.2.10',
    spec: SPEC,
    now: NOW,
    readyTimeoutMs: 1_000,
    spawnImpl(command, args, options) {
      spawnCall = { command, args, options }
      return child
    },
  })
  assert.equal(spawnCall.command, '/usr/bin/ssh')
  assert.deepEqual(spawnCall.options.stdio, ['pipe', 'pipe', 'pipe'])
  assert.equal(child.stdin.writableEnded, false)
  child.stdout.write('KYCLASH_SYSTEM_LAB_READY\n')
  await session.ready
  assert.equal(child.stdin.writableEnded, false)
  session.close()
  assert.equal(child.stdin.writableEnded, true)
  child.emit('exit', 0, null)
  assert.deepEqual(await session.exited, { code: 0, signal: null })
})

test('expiry validation leaves a bounded handoff window', () => {
  assert.deepEqual(validatePeerSpec(SPEC, NOW), SPEC)
  assert.throws(
    () => validatePeerSpec({ ...SPEC, expiresAt: NOW + 599 }, NOW),
    /ten minutes/u,
  )
  assert.throws(
    () => validatePeerSpec({ ...SPEC, expiresAt: NOW + 86_401 }, NOW),
    /24-hour/u,
  )
})

assert.equal(
  PEER_RUNNER_ENVIRONMENT,
  PEER_ENVIRONMENT.KYCLASH_RUNNER_ENVIRONMENT,
)
assert.equal(PEER_VM_CONFIRMATION, PEER_ENVIRONMENT.KYCLASH_VM_LAB_CONFIRM)
assert.equal(PEER_RUNTIME_TARGET, PEER_ENVIRONMENT.KYCLASH_RUNTIME_TARGET)
