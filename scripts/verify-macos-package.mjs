import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const target = process.argv[2] ?? 'aarch64-apple-darwin'
const root = path.resolve(import.meta.dirname, '..')
const targetDir = path.join(root, 'target', target)
const app = path.join(targetDir, 'release', 'bundle', 'macos', 'KyClash.app')
const pkgDir = path.join(targetDir, 'release', 'bundle', 'pkg')
const packages = fs
  .readdirSync(pkgDir)
  .filter((name) => name.endsWith('.pkg') && name.includes('KyClash_'))
if (packages.length !== 1)
  throw new Error(`expected exactly one KyClash PKG, found ${packages.length}`)
const pkg = path.join(pkgDir, packages[0])
const helper = path.join(app, 'Contents/Resources/kyclash-route-helper')
const sidecar = path.join(app, 'Contents/Resources/kyclash-network-sidecar')
const helperPlist = path.join(
  app,
  'Contents/Library/LaunchDaemons/net.kysion.kyclash.route-helper.plist',
)
const trust = path.join(
  app,
  'Contents/Resources/resources/kyclash-network-sidecar-aarch64-apple-darwin.trust.json',
)
const run = (command, args) => execFileSync(command, args, { stdio: 'inherit' })
const output = (command, args) =>
  execFileSync(command, args, { encoding: 'utf8' }).trim()
for (const file of [app, helper, sidecar, helperPlist, trust]) {
  if (!fs.existsSync(file)) throw new Error(`missing package file: ${file}`)
}
run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', app])
run('codesign', ['--verify', '--strict', '--verbose=2', sidecar])
run('codesign', ['--verify', '--strict', '--verbose=2', helper])
const team = process.env.APPLE_TEAM_ID ?? 'RQUQ8Y3S9H'
for (const binary of [sidecar, helper]) {
  const identity = output('codesign', ['-d', '--verbose=4', binary])
    .split('\n')
    .find((line) => line.startsWith('TeamIdentifier='))
    ?.slice('TeamIdentifier='.length)
  if (identity !== team)
    throw new Error(`unexpected Team ID for ${binary}: ${identity}`)
}
run('plutil', ['-lint', helperPlist])
run('pkgutil', ['--check-signature', pkg])
const digest = output('shasum', ['-a', '256', sidecar]).split(/\s+/)[0]
const trustDigest = JSON.parse(fs.readFileSync(trust, 'utf8')).sha256
if (digest !== trustDigest)
  throw new Error('sidecar trust manifest hash mismatch')
if (
  fs.existsSync(
    path.join(app, 'Contents/Resources/resources/kyclash-route-helper'),
  )
) {
  throw new Error('route helper duplicated under resources')
}
fs.writeFileSync(`${pkg}.sha256`, `${output('shasum', ['-a', '256', pkg])}\n`)
console.log(`[INFO] verified KyClash PKG: ${pkg}`)
