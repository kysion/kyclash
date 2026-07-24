import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8')

const cargo = read('src-tauri', 'Cargo.toml')
const packageJson = JSON.parse(read('package.json'))
const command = read('src-tauri', 'src', 'cmd', 'networking_userspace_lab.rs')
const launcher = read('src-tauri', 'src', 'networking', 'vm_utun_lab_socket.rs')
const harness = read(
  'network-sidecar',
  'cmd',
  'kyclash-vm-utun-lab-harness',
  'main.go',
)
const page = read('src', 'pages', 'networking-dev.tsx')
const navigation = read('src', 'pages', '_navigation.tsx')
const review = read(
  'docs',
  'roadmap',
  'kyclash-vm-utun-lab-app-review-20260723.md',
)
const harnessBuilder = read('scripts', 'build-macos-vm-utun-lab-harness.mjs')

test('VM utun lab App feature is explicit, default-off, and lab-derived', () => {
  assert.match(
    cargo,
    /networking-vm-utun-lab-app\s*=\s*\["networking-userspace-lab-app"\]/u,
  )
  assert.doesNotMatch(cargo, /default\s*=\s*\[[^\]]*networking-vm-utun/u)
  assert.match(review, /Status: approved and locked for implementation/u)
  assert.match(review, /decisions are unchanged/iu)
  assert.equal(
    packageJson.scripts['macos:vm-utun-lab:harness'],
    'node scripts/build-macos-vm-utun-lab-harness.mjs',
  )
})

test('root harness is fixed to one confirmed VirtualMac socket and real utun build', () => {
  assert.match(harness, /^\/\/go:build darwin && kyclash_utun$/mu)
  assert.match(
    harness,
    /socketPath\s*=\s*"\/var\/run\/net\.kysion\.kyclash\.vm-utun-lab\.sock"/u,
  )
  assert.match(harness, /effectiveUID != 0/u)
  assert.match(harness, /VirtualMac/u)
  assert.match(harness, /authorized-kyclash-virtualization-framework-vm/u)
  assert.match(harness, /kyclash-macos-lab-work/u)
  assert.match(harness, /GetsockoptXucred/u)
  assert.match(harness, /uid != uint32\(consoleUID\)/u)
  assert.match(harness, /listener\.Close\(\)/u)
  assert.match(harness, /ServeWithBackendContext/u)
  assert.doesNotMatch(harness, /exec\.Command(?:Context)?\([^\n]*route/u)
  assert.doesNotMatch(harness, /sudo|-S|sshpass/u)
  assert.doesNotMatch(harness, /RemoveAll/u)
  assert.match(harnessBuilder, /kyclash_utun/u)
  assert.match(harnessBuilder, /GOOS: 'darwin', GOARCH: 'arm64'/u)
  assert.match(harnessBuilder, /runtime_target.*kyclash-macos-lab-work/su)
})

test('Rust launcher authenticates exact socket metadata and root peer', () => {
  assert.match(
    launcher,
    /VM_UTUN_LAB_SOCKET_PATH:\s*&str\s*=\s*"\/var\/run\/net\.kysion\.kyclash\.vm-utun-lab\.sock"/u,
  )
  assert.match(launcher, /file_type\(\)\.is_socket\(\)/u)
  assert.match(launcher, /metadata\.mode\(\) & 0o777 != 0o600/u)
  assert.match(launcher, /metadata\.uid\(\) != unsafe \{ libc::geteuid\(\) \}/u)
  assert.match(launcher, /libc::LOCAL_PEERCRED/u)
  assert.match(launcher, /required_peer_uid: 0/u)
  assert.match(launcher, /MSG_PEEK \| libc::MSG_DONTWAIT/u)
})

test('App and UI label real-utun lab without claiming routes or production', () => {
  assert.match(command, /const LAB_MODE: &str = "vm_utun_lab"/u)
  assert.match(command, /const LAB_TUNNEL_KIND: &str = "darwin_utun"/u)
  assert.match(command, /routes_installed: false/u)
  assert.match(command, /strip_prefix\("utun"\)/u)
  assert.match(command, /assert!\(!valid_lab_interface\("userspace"\)\)/u)
  assert.match(page, /VM LAB · REAL UTUN · NO ROUTES/u)
  assert.match(page, /routes: not installed/u)
  assert.match(page, /VITE_NETWORKING_VM_UTUN_LAB/u)
  assert.match(navigation, /VM LAB · real utun/u)
})

test('production composition and privileged helpers do not reference the lab socket', () => {
  for (const relative of [
    ['src-tauri', 'src', 'networking', 'production_composition.rs'],
    ['src-tauri', 'src', 'networking', 'tunnel_broker_client.rs'],
    ['macos', 'tunnel-broker', 'main.swift'],
    ['macos', 'route-helper', 'main.swift'],
  ]) {
    const source = read(...relative)
    assert.doesNotMatch(source, /vm-utun-lab|networking-vm-utun-lab-app/u)
  }
})
