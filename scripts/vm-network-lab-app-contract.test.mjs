import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8')

const cargo = read('src-tauri', 'Cargo.toml')
const networkingModule = read('src-tauri', 'src', 'networking', 'mod.rs')
const ipc = read('src-tauri', 'src', 'networking', 'ipc.rs')
const stdio = read('src-tauri', 'src', 'networking', 'stdio_runtime.rs')
const command = read('src-tauri', 'src', 'cmd', 'networking_userspace_lab.rs')
const launcher = read(
  'src-tauri',
  'src',
  'networking',
  'vm_network_lab_socket.rs',
)
const page = read('src', 'pages', 'networking-dev.tsx')
const navigation = read('src', 'pages', '_navigation.tsx')
const layout = read('src', 'pages', '_layout.tsx')
const types = read('src', 'types', 'networking.ts')
const builder = read('scripts', 'build-macos-production-vm-app.mjs')
const harnessBuilder = read('scripts', 'build-macos-vm-network-lab-harness.mjs')
const harness = read(
  'network-sidecar',
  'cmd',
  'kyclash-vm-network-lab-harness',
  'main.go',
)
const review = read(
  'docs',
  'roadmap',
  'kyclash-vm-network-lab-app-review-20260723.md',
)

test('VM network App feature is default-off and mutually exclusive', () => {
  assert.match(
    cargo,
    /networking-vm-network-lab-app\s*=\s*\["networking-userspace-lab-app"\]/u,
  )
  assert.doesNotMatch(
    cargo.match(/default\s*=\s*\[[^\]]*\]/u)?.[0] ?? '',
    /networking-vm-network-lab-app/u,
  )
  assert.match(networkingModule, /compile_error!/u)
  assert.match(
    networkingModule,
    /feature = "networking-vm-network-lab-app"[\s\S]*feature = "networking-vm-utun-lab-app"/u,
  )
  assert.match(
    networkingModule,
    /feature = "networking-vm-network-lab-app"[\s\S]*feature = "networking-production"/u,
  )
  assert.match(review, /Status: approved and locked for implementation/u)
})

test('App launcher accepts only the fixed root peer socket', () => {
  assert.match(
    launcher,
    /VM_NETWORK_LAB_SOCKET_PATH:\s*&str\s*=\s*[\s\S]*"\/var\/run\/net\.kysion\.kyclash\.vm-network-lab\.sock"/u,
  )
  assert.match(launcher, /file_type\(\)\.is_socket\(\)/u)
  assert.match(launcher, /metadata\.mode\(\) & 0o777 != 0o600/u)
  assert.match(launcher, /metadata\.uid\(\) != unsafe \{ libc::geteuid\(\) \}/u)
  assert.match(launcher, /required_peer_uid: 0/u)
  assert.match(launcher, /libc::LOCAL_PEERCRED/u)
  assert.match(launcher, /MSG_PEEK \| libc::MSG_DONTWAIT/u)
})

test('VM mode uses the exact handshake and typed private echo proof', () => {
  for (const value of [
    'vm_network_lab',
    'darwin_utun',
    'lab-vm-network',
    'lab.vm-network.actual-child',
    'utun4094',
  ])
    assert.match(command, new RegExp(value.replaceAll('.', '\\.'), 'u'))
  assert.match(command, /SamplePrivateReachability/u)
  assert.match(command, /IpcResponsePayload::PrivateReachability/u)
  assert.match(command, /if !fact\.reachable/u)
  assert.doesNotMatch(
    command,
    /private_reachable\s*=\s*cfg!\([\s\S]{0,200}health\.reachable/u,
  )
  assert.match(ipc, /SamplePrivateReachability/u)
  assert.match(ipc, /PrivateReachability\(PrivateReachability\)/u)
  assert.match(ipc, /serde\(deny_unknown_fields\)/u)
  assert.match(stdio, /SampleHealth[\s\S]{0,160}SamplePrivateReachability/u)
  assert.match(stdio, /pub runtime_mode: Option<String>/u)
  assert.match(stdio, /pub tunnel_interface: Option<String>/u)
})

test('App visibly reports real utun, private route, echo, and Mihomo', () => {
  assert.match(types, /'vm_network_lab'/u)
  assert.match(types, /private_reachable: boolean/u)
  assert.match(types, /mihomo_coexisting: boolean/u)
  assert.match(page, /VITE_NETWORKING_VM_NETWORK_LAB/u)
  assert.match(page, /VM LAB · REAL UTUN · PRIVATE ROUTE · MIHOMO/u)
  assert.match(page, /status\.routes_installed/u)
  assert.match(page, /status\.private_reachable/u)
  assert.match(page, /status\.mihomo_coexisting/u)
  assert.match(page, /check\?\.private_reachable/u)
  assert.match(page, /check\?\.mihomo_coexisting/u)
  assert.match(navigation, /VM LAB · real utun · private route · Mihomo/u)
  assert.match(layout, /VM LAB · real utun · private route · Mihomo/u)
})

test('App builder selects only the sibling feature and pins Mihomo config', () => {
  assert.match(builder, /--lab-profile vm-utun\|vm-network/u)
  assert.match(
    builder,
    /VM_NETWORK_APP_FEATURES\s*=\s*'networking-vm-network-lab-app'/u,
  )
  assert.match(builder, /VITE_NETWORKING_VM_NETWORK_LAB/u)
  assert.match(builder, /unsigned-disposable-vm-network-lab-app/u)
  assert.match(builder, /runtime_mode:[\s\S]{0,100}'vm_network_lab'/u)
  assert.match(harnessBuilder, /kyclash_utun.*kyclash_vm_network_lab/u)
  assert.match(
    harnessBuilder,
    /compile-only-host; execute-only-selected-VirtualMac/u,
  )

  const configPath = path.join(
    root,
    'macos',
    'route-helper',
    'vm-network-lab-mihomo-config.json',
  )
  const digest = crypto
    .createHash('sha256')
    .update(fs.readFileSync(configPath))
    .digest('hex')
  assert.equal(
    digest,
    '2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d',
  )
  assert.match(builder, new RegExp(digest, 'u'))
})

test('root harness is fixed/no-argument and production paths do not import it', () => {
  assert.match(
    harness,
    /^\/\/go:build darwin && kyclash_utun && kyclash_vm_network_lab$/mu,
  )
  assert.match(harness, /validateArguments\(arguments \[\]string\)/u)
  assert.match(harness, /VirtualMac/u)
  assert.match(harness, /requireFixedSelf/u)
  assert.match(harness, /vmnetworklab\.HarnessPath/u)
  assert.match(harness, /info\.Mode\(\)\.Perm\(\) != 0o500/u)
  assert.match(harness, /GetsockoptXucred/u)
  assert.match(harness, /RuntimeMode:/u)
  assert.match(harness, /TunnelInterface: nil/u)
  assert.match(harness, /MihomoDevice: vmnetworklab\.MihomoInterface/u)
  assert.doesNotMatch(harness, /sudo|-S|sshpass/u)

  for (const relative of [
    ['src-tauri', 'src', 'networking', 'production_composition.rs'],
    ['src-tauri', 'src', 'networking', 'production_service.rs'],
    ['src-tauri', 'src', 'networking', 'tunnel_broker_client.rs'],
    ['macos', 'tunnel-broker', 'main.swift'],
    ['macos', 'route-helper', 'main.swift'],
  ]) {
    const source = read(...relative)
    assert.doesNotMatch(source, /vm-network-lab|networking-vm-network-lab-app/u)
  }
})
