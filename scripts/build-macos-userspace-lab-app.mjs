import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

if (process.platform !== 'darwin' || process.arch !== 'arm64') {
  throw new Error('the userspace lab App is an Apple Silicon macOS artifact')
}

const root = path.resolve(import.meta.dirname, '..')
const target = process.argv[2] ?? 'aarch64-apple-darwin'
if (target !== 'aarch64-apple-darwin') {
  throw new Error('the userspace lab App currently supports arm64 only')
}

const runNodeScript = (script, args = []) =>
  execFileSync(
    process.execPath,
    [path.join(root, 'scripts', script), ...args],
    {
      cwd: root,
      stdio: 'inherit',
      env: process.env,
    },
  )

runNodeScript('build-networking-userspace-lab-sidecar-macos.mjs', [target])

// Tauri's beforeBuildCommand is intentionally `pnpm run web:build`.  Make a
// disposable Corepack shim available to that child even on a clean host where
// pnpm is not globally installed; no global package-manager state is changed.
const shim = fs.mkdtempSync(path.join(root, 'target', 'pnpm-shim.'))
try {
  execFileSync('corepack', ['enable', '--install-directory', shim], {
    cwd: root,
    stdio: 'ignore',
  })
  const env = {
    ...process.env,
    PATH: `${shim}${path.delimiter}${process.env.PATH ?? ''}`,
    VITE_NETWORKING_DEV: 'true',
    VITE_NETWORKING_SYSTEM_LAB: 'true',
  }
  const tauri = path.join(root, 'node_modules', '.bin', 'tauri')
  execFileSync(
    tauri,
    [
      'build',
      '--target',
      target,
      '--bundles',
      'app',
      '--no-sign',
      '--features',
      'networking-userspace-lab-app',
      '--config',
      'src-tauri/tauri.networking.userspace-lab.macos.conf.json',
    ],
    { cwd: root, env, stdio: 'inherit' },
  )
} finally {
  fs.rmSync(shim, { recursive: true, force: true })
}

const app = path.join(
  root,
  'target',
  target,
  'release',
  'bundle',
  'macos',
  'KyClash.app',
)
const entries = []
const visit = (current, relative = '') => {
  for (const entry of fs
    .readdirSync(current, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const absolute = path.join(current, entry.name)
    const child = relative ? path.join(relative, entry.name) : entry.name
    const stat = fs.lstatSync(absolute)
    if (stat.isSymbolicLink())
      throw new Error(`App contains a symlink: ${child}`)
    if (stat.isDirectory()) {
      visit(absolute, child)
    } else if (stat.isFile()) {
      entries.push({ path: child, bytes: fs.readFileSync(absolute) })
    } else {
      throw new Error(`App contains an unsupported entry: ${child}`)
    }
  }
}
if (!fs.existsSync(app)) throw new Error(`App was not produced: ${app}`)
visit(app)
const digest = crypto.createHash('sha256')
for (const entry of entries) {
  digest.update(entry.path)
  digest.update('\0')
  digest.update(entry.bytes)
  digest.update('\0')
}
const appSha256 = digest.digest('hex')
const executable = path.join(app, 'Contents', 'MacOS', 'clash-verge')
const executableSha256 = crypto
  .createHash('sha256')
  .update(fs.readFileSync(executable))
  .digest('hex')
console.log('userspace_lab_app_build_target=host-build')
console.log('userspace_lab_app_runtime_target=kyclash-macos-lab-work')
console.log(`userspace_lab_app_path=${app}`)
console.log(`userspace_lab_app_sha256=${appSha256}`)
console.log(`userspace_lab_app_executable_sha256=${executableSha256}`)
