import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const root = path.resolve(import.meta.dirname, '..')
const broker = path.join(root, 'src-tauri', 'helpers', 'kyclash-tunnel-broker')
const plist = path.join(
  root,
  'macos',
  'tunnel-broker',
  'net.kysion.kyclash.tunnel-broker.plist',
)
const teamID = 'RQUQ8Y3S9H'
const requirement = `identifier "net.kysion.kyclash.tunnel-broker" and anchor apple generic and certificate leaf[subject.OU] = "${teamID}"`

const fail = (message) => {
  throw new Error(message)
}

const assertNoSymlinkComponents = (value, label) => {
  const absolute = path.resolve(value)
  const parsed = path.parse(absolute)
  let current = parsed.root
  for (const component of absolute
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, component)
    const stat = fs.lstatSync(current)
    if (stat.isSymbolicLink()) fail(`${label} contains a symlink component`)
  }
  return absolute
}

const regularExecutable = (value, label) => {
  const absolute = assertNoSymlinkComponents(value, label)
  const stat = fs.lstatSync(absolute)
  if (!stat.isFile() || (stat.mode & 0o111) === 0)
    fail(`${label} must be an executable regular file`)
  if ((stat.mode & 0o022) !== 0)
    fail(`${label} must not be group/other writable`)
  return absolute
}

const command = (program, args, label) => {
  const result = spawnSync(program, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) fail(`${label}: ${result.error.message}`)
  if (result.status !== 0)
    fail(`${label}: ${(result.stderr || result.stdout || '').trim()}`)
  return `${result.stdout || ''}${result.stderr || ''}`
}

export const verifyTunnelBroker = ({
  brokerPath = broker,
  plistPath = plist,
} = {}) => {
  if (process.platform !== 'darwin')
    fail('tunnel broker verification requires macOS')
  const binary = regularExecutable(brokerPath, 'tunnel broker')
  const plistFile = assertNoSymlinkComponents(plistPath, 'tunnel broker plist')
  const plistStat = fs.lstatSync(plistFile)
  if (!plistStat.isFile() || (plistStat.mode & 0o022) !== 0)
    fail('tunnel broker plist must be a private regular file')

  const architectures = command(
    '/usr/bin/lipo',
    ['-archs', binary],
    'tunnel broker architecture check',
  )
    .trim()
    .split(/\s+/u)
    .filter(Boolean)
  if (architectures.length !== 1 || architectures[0] !== 'arm64')
    fail('tunnel broker must be a thin arm64 Mach-O')

  command(
    '/usr/bin/codesign',
    ['--verify', '--strict', '--verbose=2', `-R=${requirement}`, binary],
    'tunnel broker signature check',
  )
  const details = command(
    '/usr/bin/codesign',
    ['-d', '--verbose=4', binary],
    'tunnel broker identity check',
  )
  if (
    !details
      .split('\n')
      .includes('Identifier=net.kysion.kyclash.tunnel-broker') ||
    !details.split('\n').includes(`TeamIdentifier=${teamID}`)
  )
    fail('tunnel broker identifier or Team ID is not locked')

  command('/usr/bin/plutil', ['-lint', plistFile], 'tunnel broker plist check')
  let decodedPlist
  try {
    decodedPlist = JSON.parse(
      command(
        '/usr/bin/plutil',
        ['-convert', 'json', '-o', '-', plistFile],
        'tunnel broker plist decode',
      ),
    )
  } catch (error) {
    fail(
      `tunnel broker plist is not a decodable dictionary: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  const topLevelKeys = ['BundleProgram', 'Label', 'MachServices']
  const serviceKeys = ['net.kysion.kyclash.tunnel-broker']
  if (
    decodedPlist === null ||
    typeof decodedPlist !== 'object' ||
    Array.isArray(decodedPlist) ||
    JSON.stringify(Object.keys(decodedPlist).sort()) !==
      JSON.stringify(topLevelKeys) ||
    decodedPlist.Label !== 'net.kysion.kyclash.tunnel-broker' ||
    decodedPlist.BundleProgram !== 'Contents/Resources/kyclash-tunnel-broker' ||
    decodedPlist.MachServices === null ||
    typeof decodedPlist.MachServices !== 'object' ||
    Array.isArray(decodedPlist.MachServices) ||
    JSON.stringify(Object.keys(decodedPlist.MachServices).sort()) !==
      JSON.stringify(serviceKeys) ||
    decodedPlist.MachServices['net.kysion.kyclash.tunnel-broker'] !== true
  )
    fail('tunnel broker plist must contain only the locked launch contract')

  return {
    broker: binary,
    plist: plistFile,
    architecture: 'arm64',
    team_id: teamID,
    identifier: 'net.kysion.kyclash.tunnel-broker',
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const result = verifyTunnelBroker()
    process.stdout.write(`tunnel_broker_verified=${result.broker}\n`)
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : String(error)}\n`,
    )
    process.exitCode = 1
  }
}
