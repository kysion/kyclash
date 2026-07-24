import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin')
  throw new Error('route helper must be built on macOS')

const root = path.resolve(import.meta.dirname, '..')
const output = path.join(root, 'src-tauri', 'helpers', 'kyclash-route-helper')
mkdirSync(path.dirname(output), { recursive: true })
const bridgeDirectory = mkdtempSync(
  path.join(os.tmpdir(), 'kyclash-route-helper-'),
)
const bridgeObject = path.join(bridgeDirectory, 'route-client.o')
const bridgeSource = path.join(root, 'macos', 'tunnel-broker', 'route-client.m')
const bridgeHeader = path.join(root, 'macos', 'tunnel-broker', 'route-client.h')
try {
  // Compile the root-only broker bridge with ARC as a separate Objective-C
  // object.  Passing the source directly to swiftc silently selects manual
  // reference counting on some toolchains, which rejects the bridge's weak
  // invalidation handlers and can leave an unlinked/untested ABI.
  execFileSync(
    'xcrun',
    [
      'clang',
      '-fobjc-arc',
      '-fblocks',
      '-target',
      'arm64-apple-macos13.0',
      '-mmacosx-version-min=13.0',
      '-I',
      path.dirname(bridgeHeader),
      '-c',
      bridgeSource,
      '-o',
      bridgeObject,
    ],
    { stdio: 'inherit' },
  )
  execFileSync(
    'xcrun',
    [
      'swiftc',
      '-parse-as-library',
      '-O',
      '-target',
      'arm64-apple-macos13.0',
      '-framework',
      'Foundation',
      '-framework',
      'OSLog',
      '-import-objc-header',
      bridgeHeader,
      '-o',
      output,
      path.join(root, 'macos', 'route-helper', 'main.swift'),
      bridgeObject,
    ],
    { stdio: 'inherit' },
  )
} finally {
  rmSync(bridgeDirectory, { recursive: true, force: true })
}
chmodSync(output, 0o755)

// Keep the unprivileged v3 wire/journal contract checks executable in the same
// build path as the production helper binary. These checks do not start the
// listener, call the broker, or mutate the system route table.
execFileSync(output, ['--route-v3-contract-self-test'], { stdio: 'inherit' })
execFileSync(output, ['--route-v3-bridge-self-test'], { stdio: 'inherit' })
execFileSync(output, ['--route-v3-interlock-self-test'], { stdio: 'inherit' })
execFileSync(output, ['--route-v3-durable-store-self-test'], {
  stdio: 'inherit',
})

const identity = process.env.APPLE_SIGNING_IDENTITY
const teamID = process.env.APPLE_TEAM_ID
if (!identity || teamID !== 'RQUQ8Y3S9H')
  throw new Error(
    'APPLE_SIGNING_IDENTITY and the locked APPLE_TEAM_ID are required',
  )
execFileSync(
  '/usr/bin/codesign',
  [
    '--force',
    '--options',
    'runtime',
    '--timestamp',
    '--identifier',
    'net.kysion.kyclash.route-helper',
    '--sign',
    identity,
    output,
  ],
  { stdio: 'inherit' },
)
execFileSync(
  '/usr/bin/codesign',
  ['--verify', '--strict', '--verbose=2', output],
  {
    stdio: 'inherit',
  },
)
