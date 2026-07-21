import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'

const read = (path) =>
  readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
const parse = (path) => JSON.parse(read(path))
const failures = []
const requireInvariant = (condition, message) => {
  if (!condition) failures.push(message)
}

const packageJson = parse('package.json')
const tauriConfig = parse('src-tauri/tauri.conf.json')
const overridePaths = [
  'src-tauri/webview2.x64.json',
  'src-tauri/webview2.x86.json',
  'src-tauri/webview2.arm64.json',
]
const githubUpdaterEndpoint =
  'https://github.com/kysion/kyclash/releases/latest/download/latest.json'

requireInvariant(
  tauriConfig.bundle?.createUpdaterArtifacts === false,
  'Tauri updater artifacts must remain disabled',
)
requireInvariant(
  tauriConfig.plugins?.updater === undefined,
  'the base Tauri config must not define an updater endpoint or key',
)
const updaterTemplate = parse('config/tauri.github-updater.template.json')
const updaterCapabilityTemplate = parse(
  'config/tauri.github-updater-capability.template.json',
)
requireInvariant(
  updaterTemplate.bundle?.createUpdaterArtifacts === true,
  'the inert GitHub updater template must create signed updater artifacts',
)
requireInvariant(
  updaterTemplate.plugins?.updater?.endpoints?.length === 1 &&
    updaterTemplate.plugins.updater.endpoints[0] === githubUpdaterEndpoint,
  'the inert updater template must use only the KyClash GitHub Releases endpoint',
)
requireInvariant(
  updaterTemplate.plugins?.updater?.pubkey === '__KYCLASH_UPDATER_PUBLIC_KEY__',
  'the inert updater template must not contain a committed updater key',
)
requireInvariant(
  JSON.stringify(updaterCapabilityTemplate.permissions) ===
    JSON.stringify([
      'updater:allow-check',
      'updater:allow-download-and-install',
    ]) &&
    JSON.stringify(updaterCapabilityTemplate.platforms) ===
      JSON.stringify(['macOS']),
  'the inert updater capability template must remain least-privilege and macOS-only',
)
for (const path of overridePaths) {
  requireInvariant(
    parse(path).plugins?.updater === undefined,
    `${path} must not restore inherited updater configuration`,
  )
}

const disabledCommand = 'node scripts/assert-updater-disabled.mjs'
requireInvariant(
  packageJson.scripts?.updater === disabledCommand &&
    packageJson.scripts?.['updater-fixed-webview2'] === disabledCommand,
  'standard updater generation commands must fail closed',
)

const frontendUpdater = read('src/services/update.ts')
const backendUpdater = read('src-tauri/src/core/updater.rs')
requireInvariant(
  /export const APP_UPDATES_ENABLED = false/.test(frontendUpdater),
  'frontend application updates must remain disabled',
)
requireInvariant(
  /pub const APP_UPDATES_ENABLED: bool = false;/.test(backendUpdater),
  'backend application updates must remain disabled',
)

const releaseWorkflow = read('.github/workflows/release.yml')
for (const forbidden of [
  'includeUpdaterJson: true',
  'pnpm updater',
  'TAURI_SIGNING_PRIVATE_KEY:',
  'TAURI_SIGNING_PRIVATE_KEY_PASSWORD:',
]) {
  requireInvariant(
    !releaseWorkflow.includes(forbidden),
    `release workflow must not contain ${JSON.stringify(forbidden)}`,
  )
}
requireInvariant(
  releaseWorkflow.includes("if: vars.KYCLASH_MACOS_RELEASE_ENABLED == 'true'"),
  'release workflow must remain closed behind the explicit repository authorization variable',
)
for (const target of [
  'x86_64-apple-darwin',
  'x86_64-pc-windows-msvc',
  'aarch64-pc-windows-msvc',
  'unknown-linux',
]) {
  requireInvariant(
    !releaseWorkflow.includes(target),
    `release workflow must not bypass the locked platform order with ${target}`,
  )
}
requireInvariant(
  !existsSync(new URL('../.github/workflows/updater.yml', import.meta.url)),
  'the independently triggerable updater workflow must remain absent',
)
for (const path of [
  '.github/workflows/autobuild.yml',
  '.github/workflows/dev.yml',
  '.github/workflows/telegram-notify.yml',
  '.github/workflows/clean-old-assets.yml',
]) {
  requireInvariant(
    !existsSync(new URL(`../${path}`, import.meta.url)),
    `${path} must remain absent until its external mutation scope is reviewed`,
  )
}

try {
  execFileSync(
    process.execPath,
    ['scripts/verify-updater-metadata.mjs', '--sample'],
    { cwd: new URL('..', import.meta.url), stdio: 'pipe' },
  )
} catch {
  failures.push('the committed updater metadata sample must pass validation')
}

try {
  execFileSync(
    process.execPath,
    ['--test', 'scripts/updater-contract.test.mjs'],
    {
      cwd: new URL('..', import.meta.url),
      stdio: 'pipe',
    },
  )
} catch {
  failures.push('the updater preparation contract tests must pass')
}

if (failures.length > 0) {
  console.error('KyClash updater ownership gate failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

if (!process.argv.includes('--check')) {
  console.error(
    'KyClash application updates are disabled until an owned endpoint, signing key, rollback metadata, and tests are enabled atomically.',
  )
  process.exit(1)
}

console.log('KyClash updater ownership gate passed')
