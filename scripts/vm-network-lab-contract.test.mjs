import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8')

test('VM network lab is a distinct default-off feature and socket', () => {
  const cargo = read('src-tauri/Cargo.toml')
  const module = read('src-tauri/src/networking/mod.rs')
  const socket = read('src-tauri/src/networking/vm_network_lab_socket.rs')
  assert.match(
    cargo,
    /networking-vm-network-lab-app\s*=\s*\["networking-userspace-lab-app"\]/u,
  )
  assert.match(module, /networking-vm-network-lab-app/u)
  assert.match(module, /mutually exclusive/u)
  assert.match(
    socket,
    /\/var\/run\/net\.kysion\.kyclash\.vm-network-lab\.sock/u,
  )
  assert.doesNotMatch(
    cargo.match(/default\s*=\s*\[[^\]]*\]/u)?.[0] ?? '',
    /networking-vm-network-lab-app/u,
  )
})

test('host harness builder is compile-only and carries the selected guest boundary', () => {
  const source = read('scripts/build-macos-vm-network-lab-harness.mjs')
  assert.match(source, /GOOS:\s*'darwin'/u)
  assert.match(source, /GOARCH:\s*'arm64'/u)
  assert.match(source, /kyclash_utun.*kyclash_vm_network_lab/isu)
  assert.match(source, /ExpectedMihomoSHA256/u)
  assert.match(source, /verge-mihomo-aarch64-apple-darwin/u)
  assert.match(source, /mihomo_sha256/u)
  assert.match(source, /build_target:\s*'host-build'/u)
  assert.match(source, /execute-only-selected-VirtualMac/u)
  assert.doesNotMatch(source, /execFileSync\([^\n]*output/u)
  assert.doesNotMatch(source, /sshpass|sudo\s+-S|\bssh\b|\bscp\b/u)
})

test('fixed Mihomo lab config has only direct TUN covering-route authority', () => {
  const relative = 'macos/route-helper/vm-network-lab-mihomo-config.json'
  const bytes = fs.readFileSync(path.join(root, relative))
  assert.equal(
    crypto.createHash('sha256').update(bytes).digest('hex'),
    '2ad62e399c953f5298d8de22ee7d762277968f18e186c97d281cfdb67b10df5d',
  )
  const config = JSON.parse(bytes)
  assert.equal(config.mode, 'direct')
  assert.equal(config.tun.enable, true)
  assert.equal(config.tun.device, 'utun4094')
  assert.deepEqual(config.tun['route-address'], ['10.88.0.0/24'])
  assert.deepEqual(config.rules, ['MATCH,DIRECT'])
  for (const forbidden of [
    'dns',
    'external-controller',
    'external-controller-tcp',
    'listeners',
    'proxy-providers',
    'rule-providers',
  ])
    assert.equal(Object.hasOwn(config, forbidden), false, forbidden)
})

test('review locks teardown and null pre-prepare interface semantics', () => {
  const review = read(
    'docs/roadmap/kyclash-vm-network-lab-app-review-20260723.md',
  )
  assert.match(review, /Status: approved and locked/u)
  assert.match(review, /tunnel_interface` is explicitly\s*`null`/u)
  assert.match(review, /teardown_pending/u)
  assert.match(review, /final step/u)
  assert.match(review, /sample_private_reachability/u)
  assert.match(review, /PID, process start-time, executable dev\/inode/u)
})

test('visible guest authorization never transports or injects a password', () => {
  const source = read('scripts/macos-vm-network-lab-authorize.command')
  assert.match(source, /VirtualMac/u)
  assert.match(source, /\/usr\/bin\/sudo -v/u)
  assert.match(source, /\/usr\/bin\/sudo -n -v/u)
  assert.match(source, /authorization=granted/u)
  assert.doesNotMatch(
    source,
    /sshpass|sudo\s+-S|(?:^|\s)expect(?:\s|$)|security\s+find-generic-password|osascript/imu,
  )
})
