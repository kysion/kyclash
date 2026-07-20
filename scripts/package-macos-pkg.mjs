import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const target = process.argv[2]

if (process.platform !== 'darwin') {
  throw new Error('macOS PKG packaging must run on macOS')
}

const archByTarget = {
  'aarch64-apple-darwin': 'aarch64',
  'x86_64-apple-darwin': 'x64',
}
const archByProcess = {
  arm64: 'aarch64',
  x64: 'x64',
}
const arch = target ? archByTarget[target] : archByProcess[process.arch]

if (!arch) {
  throw new Error(`unsupported macOS target: ${target ?? process.arch}`)
}

const packageJson = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
)
const targetDir = target ? path.join('target', target) : 'target'
const appPath = path.resolve(
  targetDir,
  'release',
  'bundle',
  'macos',
  'KyClash.app',
)
const outputDir = path.resolve(targetDir, 'release', 'bundle', 'pkg')
const outputPath = path.join(
  outputDir,
  `KyClash_${packageJson.version}_${arch}.pkg`,
)

if (!fs.existsSync(appPath)) {
  throw new Error(`KyClash application bundle not found: ${appPath}`)
}

fs.mkdirSync(outputDir, { recursive: true })

const args = [
  '--component',
  appPath,
  '--install-location',
  '/Applications',
  '--identifier',
  'net.kysion.kyclash',
  '--version',
  packageJson.version,
]
const installerIdentity = process.env.APPLE_INSTALLER_SIGNING_IDENTITY
if (process.env.CI && !installerIdentity) {
  throw new Error(
    'APPLE_INSTALLER_SIGNING_IDENTITY is required for CI release packages',
  )
}
if (installerIdentity) {
  args.push('--sign', installerIdentity)
}
args.push(outputPath)

execFileSync('pkgbuild', args, { stdio: 'inherit' })
if (installerIdentity) {
  execFileSync('pkgutil', ['--check-signature', outputPath], {
    stdio: 'inherit',
  })
} else {
  execFileSync('pkgutil', ['--payload-files', outputPath], { stdio: 'ignore' })
  console.warn(
    '[WARN] APPLE_INSTALLER_SIGNING_IDENTITY is unset; created an unsigned development PKG',
  )
}
console.log(`[INFO] macOS PKG created: ${outputPath}`)
