import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const root = path.resolve(import.meta.dirname, '..')
const socketDirectory = path.join(root, 'target', 'kyclash-networking-dev')
const socketPath = path.join(socketDirectory, 'verge-mihomo.sock')

const env = {
  ...process.env,
  RUST_BACKTRACE: process.env.RUST_BACKTRACE ?? 'full',
  VITE_NETWORKING_DEV: 'true',
}

// Windows uses the named-pipe path and deliberately ignores this Unix-only
// override. Keep the normal production socket untouched on every platform.
if (process.platform !== 'win32') {
  fs.mkdirSync(socketDirectory, { recursive: true, mode: 0o700 })
  fs.chmodSync(socketDirectory, 0o700)
  env.KYCLASH_IPC_PATH = socketPath
}

const command = process.platform === 'win32' ? 'tauri.cmd' : 'tauri'
const child = spawn(command, ['dev', '-f', 'verge-dev,networking-dev'], {
  cwd: root,
  env,
  stdio: 'inherit',
})

child.on('error', (error) => {
  console.error(
    `[KyClash] failed to start Tauri networking dev: ${error.message}`,
  )
  process.exitCode = 1
})

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal)
    return
  }
  process.exitCode = code ?? 1
})
