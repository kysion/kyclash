import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  ARTIFACTS,
  GUEST_FIXTURE_PATH,
  GUEST_PREFLIGHT_NAME,
  GUEST_DESCRIPTOR_NAME,
  SELECTED_VM_NAME,
  createPrivateOutputRoot,
  guestLowerHex64Guard,
  guestPullScript,
  parsePullFrame,
  parseCopyOptions,
  publishPulledFile,
  validatePulledPayload,
  validateBuildArtifacts,
} from './copy-networking-vm-lab-fixtures.mjs'

const sha256 = (bytes) =>
  crypto.createHash('sha256').update(bytes).digest('hex')

const runGuestDigestGuard = (value) =>
  spawnSync('/bin/bash', ['-s', '--', value], {
    input: `set -euo pipefail\nexpected="$1"\n${guestLowerHex64Guard}\n`,
    encoding: 'utf8',
  })

test('guest fixture digest guard accepts exactly lowercase SHA-256 hex', () => {
  assert.equal(runGuestDigestGuard('a'.repeat(64)).status, 0)
  for (const invalid of [
    'a'.repeat(63),
    'a'.repeat(65),
    'A'.repeat(64),
    `${'a'.repeat(63)}g`,
    '',
  ])
    assert.notEqual(runGuestDigestGuard(invalid).status, 0)
})

test('copy command parser is closed and separates shell-only from full copy', () => {
  assert.deepEqual(parseCopyOptions(['--shell-only']), {
    help: false,
    shellOnly: true,
    pullRun: false,
    runId: undefined,
    buildRoot: undefined,
    outputRoot: undefined,
    guestRoot: undefined,
  })
  assert.deepEqual(
    parseCopyOptions([
      '--run-id',
      '0123456789abcdef',
      '--build-root',
      '/private/tmp/kyclash-build',
    ]),
    {
      help: false,
      shellOnly: false,
      pullRun: false,
      runId: '0123456789abcdef',
      buildRoot: '/private/tmp/kyclash-build',
      outputRoot: undefined,
      guestRoot: undefined,
    },
  )
  assert.deepEqual(
    parseCopyOptions([
      '--pull-run',
      '--run-id',
      '0123456789abcdef',
      '--output-root',
      '/private/tmp/kyclash-pulled',
    ]),
    {
      help: false,
      shellOnly: false,
      pullRun: true,
      runId: '0123456789abcdef',
      buildRoot: undefined,
      outputRoot: '/private/tmp/kyclash-pulled',
      guestRoot: undefined,
    },
  )
  for (const invalid of [
    ['--shell-only', '--shell-only'],
    ['--bogus', 'x'],
    ['--run-id', '0123456789abcdef'],
    ['--run-id', '0123456789ABCDEf', '--build-root', '/private/tmp/x'],
    ['--run-id', '0123456789abcdef', '--build-root', 'relative'],
    ['--shell-only', '--run-id', '0123456789abcdef'],
    [
      '--pull-run',
      '--run-id',
      '0123456789abcdef',
      '--build-root',
      '/private/tmp/x',
      '--output-root',
      '/private/tmp/y',
    ],
    [
      '--pull-run',
      '--run-id',
      '0123456789abcdef',
      '--output-root',
      '/private/tmp/y',
      '--guest-root',
      '/var/tmp/kyclash-networking-vm-lab/0123456789abcdef',
    ],
  ])
    assert.throws(
      () => parseCopyOptions(invalid),
      /copy|option|run-id|build-root|guest-root/u,
    )
})

test('copy contract pins the selected VM, guest path, and no-secret boundary', () => {
  assert.equal(SELECTED_VM_NAME, 'kyclash-macos-lab-work')
  assert.equal(
    GUEST_FIXTURE_PATH,
    '/Users/supen/kyclash-macos-vm-keychain-trust-fixture.sh',
  )
  const source = fs.readFileSync(
    path.join(import.meta.dirname, 'copy-networking-vm-lab-fixtures.mjs'),
    'utf8',
  )
  assert.match(source, /VirtualMac\*/u)
  assert.match(source, /StrictHostKeyChecking=yes/u)
  assert.match(source, /IdentitiesOnly=yes/u)
  assert.match(source, /BatchMode=yes/u)
  assert.match(source, /O_NOFOLLOW/u)
  assert.match(source, /shasum -a 256/u)
  assert.match(source, /ln.*destination/u)
  assert.doesNotMatch(source, /security\s+(add|delete|find)-generic-password/u)
  assert.match(source, /--pull-run/u)
  assert.match(source, /guest-descriptor\.json/u)
  assert.match(source, /policy-revision-preflight\.json/u)
  assert.match(source, /policy-expiry-ceiling-epoch\.txt/u)
  assert.match(source, /end-frame/u)
  assert.doesNotMatch(source, /scp[^\n]+(loopback|private|Keychain)/iu)
})

test('guest pull shell contract is syntactically valid', () => {
  const result = spawnSync('/bin/bash', ['-n'], {
    input: guestPullScript,
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
})

test('guest pull frame is closed, hash-bound, and semantically validated', () => {
  const now = 1_900_000_000
  const runId = '0123456789abcdef'
  const descriptor = {
    schema_version: 1,
    run_id: runId,
    peer_public_key: Buffer.alloc(32, 1).toString('base64'),
    client_public_key: Buffer.alloc(32, 2).toString('base64'),
    endpoints: [
      { transport: 'quic', url: 'https://127.0.0.1:20101' },
      { transport: 'wss', url: 'wss://127.0.0.1:20102/kynp' },
      { transport: 'tcp', url: 'tcp://127.0.0.1:20103' },
    ],
    echo_addresses: ['10.88.0.2:8080', '[fd00:88::2]:8080'],
    certificate_sha256: 'a'.repeat(64),
    certificate_path: `/private/var/tmp/kyclash-networking-vm-lab/${runId}/loopback-leaf.pem`,
    expires_at: now + 3600,
  }
  const appDataRoot =
    '/Users/supen/Library/Application Support/net.kysion.kyclash'
  const preflight = {
    schema_version: 1,
    run_id: runId,
    candidate_revision: 42,
    record_state: 'absent',
    record_revision: 0,
    record_key_id: null,
    record_envelope_sha256: null,
    app_data_root: appDataRoot,
    app_data_root_sha256: sha256(Buffer.from(appDataRoot)),
    checked_at: now,
    decision: 'new',
  }
  const encode = (name, value) => {
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`)
    return [
      `file=${name}`,
      `size=${bytes.length}`,
      `sha256=${sha256(bytes)}`,
      `base64=${bytes.toString('base64')}`,
      'end-file',
    ].join('\n')
  }
  const ceiling = now + 7200
  const ceilingBytes = Buffer.from(`${ceiling}\n`)
  const frame = [
    'KYCLASH_PULL_V1',
    'selected_vm=kyclash-macos-lab-work',
    'model=VirtualMac2,1',
    'arch=arm64',
    encode(GUEST_DESCRIPTOR_NAME, descriptor),
    encode(GUEST_PREFLIGHT_NAME, preflight),
    `ceiling=${ceiling}`,
    `ceiling_sha256=${sha256(ceilingBytes)}`,
    'end-frame',
    '',
  ].join('\n')
  const payload = parsePullFrame(frame)
  const validated = validatePulledPayload(payload, runId, now)
  assert.equal(validated.descriptor.run_id, runId)
  assert.equal(validated.preflight.candidate_revision, 42)
  assert.equal(validated.ceiling, ceiling)
  assert.throws(
    () =>
      parsePullFrame(
        frame.replace(
          `file=${GUEST_DESCRIPTOR_NAME}`,
          'file=loopback-leaf.pem',
        ),
      ),
    /allowlist|file/u,
  )
})

test('pull output root and files are create-only and hash-verified', () => {
  const parent = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'kyclash-pull-output-')),
  )
  try {
    fs.chmodSync(parent, 0o700)
    const output = createPrivateOutputRoot(path.join(parent, 'public-input'))
    const bytes = Buffer.from('public\n')
    const published = publishPulledFile(
      output,
      'guest-descriptor.json',
      bytes,
      0o644,
    )
    assert.equal(fs.readFileSync(published).toString(), 'public\n')
    assert.throws(
      () => publishPulledFile(output, 'guest-descriptor.json', bytes, 0o644),
      /already exists/u,
    )
    assert.throws(
      () => publishPulledFile(output, 'loopback-leaf.pem', bytes, 0o644),
      /allowlisted/u,
    )
  } finally {
    fs.rmSync(parent, { recursive: true, force: true })
  }
})

test('build artifacts require exact create-only provenance and hashes', () => {
  const root = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'kyclash-copy-contract-')),
  )
  try {
    fs.chmodSync(root, 0o700)
    const sourceCommit = 'a'.repeat(40)
    for (const artifact of ARTIFACTS) {
      const bytes = Buffer.from(`fixture-${artifact.binary}\n`)
      const binaryPath = path.join(root, artifact.binary)
      fs.writeFileSync(binaryPath, bytes, { mode: 0o755 })
      const provenance = artifact.feature
        ? {
            schema_version: 1,
            build_target: 'host-macos-arm64',
            runtime_target: SELECTED_VM_NAME,
            feature: artifact.feature,
            binary: artifact.binary,
            source_commit: sourceCommit,
            cargo_version: 'cargo 1.90.0',
            sha256: sha256(bytes),
          }
        : {
            schema_version: 1,
            build_target: 'host-build',
            runtime_target: SELECTED_VM_NAME,
            target: 'aarch64-apple-darwin',
            cgo_enabled: false,
            source: artifact.source,
            source_commit: sourceCommit,
            go_version: 'go version go1.26.5 darwin/arm64',
            go_sha256: 'b'.repeat(64),
            sha256: sha256(bytes),
          }
      fs.writeFileSync(
        path.join(root, artifact.provenance),
        `${JSON.stringify(provenance, null, 2)}\n`,
        { mode: 0o600 },
      )
    }
    const records = validateBuildArtifacts(root, sourceCommit)
    assert.equal(records.length, 3)
    fs.appendFileSync(path.join(root, ARTIFACTS[0].binary), 'tampered')
    assert.throws(
      () => validateBuildArtifacts(root, sourceCommit),
      /does not bind binary bytes|hash/u,
    )
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
