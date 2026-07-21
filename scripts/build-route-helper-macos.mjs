import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin')
  throw new Error('route helper must be built on macOS')

const root = path.resolve(import.meta.dirname, '..')
const output = path.join(root, 'src-tauri', 'helpers', 'kyclash-route-helper')
mkdirSync(path.dirname(output), { recursive: true })
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
    '-o',
    output,
    path.join(root, 'macos', 'route-helper', 'main.swift'),
  ],
  { stdio: 'inherit' },
)
chmodSync(output, 0o755)

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
