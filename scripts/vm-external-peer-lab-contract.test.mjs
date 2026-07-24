import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8')

test('external-peer App is a distinct default-off feature and redacted socket sibling', () => {
  const cargo = read('src-tauri/Cargo.toml')
  const module = read('src-tauri/src/networking/mod.rs')
  const socket = read('src-tauri/src/networking/vm_external_peer_lab_socket.rs')
  const runtime = read('src-tauri/src/networking/stdio_runtime.rs')
  assert.match(cargo, /networking-vm-external-peer-lab-app\s*=/u)
  assert.doesNotMatch(
    cargo.match(/default\s*=\s*\[[^\]]*\]/u)?.[0] ?? '',
    /networking-vm-external-peer-lab-app/u,
  )
  assert.match(module, /networking-vm-external-peer-lab-app/u)
  assert.match(socket, /net\.kysion\.kyclash\.vm-external-peer-lab\.sock/u)
  assert.match(socket, /LOCAL_PEERPID/u)
  assert.match(socket, /LOCAL_PEERTOKEN/u)
  const handshakeStart = runtime.indexOf('pub struct ExternalPeerLabHandshake')
  const handshake = runtime.slice(
    handshakeStart,
    runtime.indexOf('\n    }', handshakeStart) + 6,
  )
  assert.doesNotMatch(
    handshake,
    /pub\s+(?:lab_)?profile|pub\s+endpoint|pub\s+certificate|pub\s+public_key|pub\s+private_key|pub\s+descriptor|pub\s+port|pub\s+path/iu,
  )
})

test('external-peer binary builder is compile-only and role-separated', () => {
  const source = read('scripts/build-macos-vm-external-peer-lab-binaries.mjs')
  assert.match(source, /GOOS:\s*'darwin'/u)
  assert.match(source, /GOARCH:\s*'arm64'/u)
  assert.match(source, /kyclash_utun.*kyclash_vm_external_peer_lab/su)
  assert.match(source, /ExpectedMihomoSHA256/u)
  assert.match(source, /host-build-only/u)
  assert.match(source, /kyclash-macos-lab-work/u)
  assert.match(source, /kyclash-macos-lab-peer/u)
  assert.match(source, /never-host; never-base/u)
  assert.doesNotMatch(
    source,
    /sshpass|sudo\s+-S|\bscp\b|execFileSync\([^)]*['"](?:\/usr\/bin\/)?ssh['"]/u,
  )
  assert.doesNotMatch(source, /execFileSync\([^\n]*output/u)
})

test('guest staging has reviewed SSH bootstrap and pins only reviewed baselines', () => {
  const builder = read('scripts/build-macos-vm-external-peer-lab-binaries.mjs')
  const contract = read(
    'network-sidecar/internal/externalpeergueststaging/contract.go',
  )
  const secureFiles = read(
    'network-sidecar/internal/externalpeergueststaging/secure_files.go',
  )
  const staging = read(
    'network-sidecar/internal/externalpeergueststaging/staging.go',
  )
  const sshBootstrap = read(
    'network-sidecar/internal/externalpeergueststaging/ssh_bootstrap_system.go',
  )
  const supervisor = read(
    'network-sidecar/cmd/kyclash-vm-external-peer-lab-supervisor/main.go',
  )
  const harness = read(
    'network-sidecar/cmd/kyclash-vm-external-peer-lab-harness/main.go',
  )
  const mihomo = read('network-sidecar/internal/vmnetworklab/mihomo_darwin.go')
  const packageJson = JSON.parse(read('package.json'))

  for (const role of ['client', 'peer']) {
    for (const phase of [
      'stage-layer-a',
      'bootstrap-ssh-layer-a',
      'prepare-layer-b',
      'pin-layer-b',
    ])
      assert.match(
        builder,
        new RegExp(`kyclash-vm-external-peer-lab-${role}-${phase}`, 'u'),
      )
  }
  assert.equal(
    packageJson.scripts['macos:vm-external-peer-lab:contract'],
    'node --test scripts/build-macos-vm-external-peer-lab-app.test.mjs scripts/build-macos-vm-external-peer-lab-binaries.test.mjs scripts/build-macos-vm-external-peer-lab-host-courier.test.mjs scripts/vm-external-peer-lab-contract.test.mjs',
  )
  assert.match(
    contract,
    /LayerAStage[\s\S]*LayerASSHBootstrap[\s\S]*LayerBPrepare[\s\S]*LayerBPin/u,
  )
  assert.match(contract, /ApprovedListenerBaselineName/u)
  assert.match(contract, /VirtualMac/u)
  assert.match(secureFiles, /O_NOFOLLOW/u)
  assert.match(secureFiles, /O_EXCL/u)
  assert.match(secureFiles, /Nlink/u)
  assert.match(staging, /externalpeer\.NewListenerBaseline/u)
  assert.match(staging, /bytes\.Equal\(approved\.bytes, candidate\.bytes\)/u)
  assert.match(staging, /EncodeAppManifestV2/u)
  assert.match(staging, /EncodePeerStagingManifest/u)
  assert.match(sshBootstrap, /PasswordAuthentication no/u)
  assert.match(sshBootstrap, /KbdInteractiveAuthentication no/u)
  assert.match(sshBootstrap, /PermitRootLogin no/u)
  assert.match(sshBootstrap, /DisableForwarding yes/u)
  assert.match(sshBootstrap, /peerSSHHostKeySpecs/u)
  assert.match(sshBootstrap, /HostKeyStaging/u)
  assert.match(
    sshBootstrap,
    /runFixedCommand\(\s*ctx, "\/usr\/bin\/ssh-keygen", arguments\.\.\./u,
  )
  assert.match(
    sshBootstrap,
    /"\/usr\/bin\/ssh-keygen", "-y", "-f", privatePath/u,
  )
  assert.match(
    sshBootstrap,
    /Publish each public half before its private half/u,
  )
  assert.doesNotMatch(sshBootstrap, /\/usr\/bin\/ssh-keygen", "-A"/u)
  assert.match(sshBootstrap, /Remote Login: On/u)
  assert.doesNotMatch(
    `${contract}\n${secureFiles}\n${staging}`,
    /sshpass|sudo\s+-S|net-bridged|exec\.Command\([^)]*(?:ssh|tart)/u,
  )
  assert.match(supervisor, /StageRoot,\s*0,\s*0,\s*0o700/u)
  assert.match(harness, /StageRoot[\s\S]*Mode\(\)\.Perm\(\)\s*!=\s*0o700/u)
  assert.match(
    mihomo,
    /validateRootDirectory\(manager\.contract\.StageRoot,\s*0o700\)/u,
  )
})

test('host courier is fixed, sequential, cancel-safe, and source-bound', () => {
  const source = read(
    'scripts/build-macos-vm-external-peer-lab-host-courier.mjs',
  )
  const command = read(
    'network-sidecar/cmd/kyclash-vm-external-peer-lab-host-courier/main.go',
  )
  const layout = read('network-sidecar/internal/externalpeerhost/layout.go')
  const secureFiles = read(
    'network-sidecar/internal/externalpeerhost/secure_files.go',
  )
  const transaction = read(
    'network-sidecar/internal/externalpeerhost/transaction.go',
  )
  const transferRunner = read(
    'network-sidecar/internal/externalpeerhost/transfer_runner.go',
  )
  const startLab = read(
    'network-sidecar/internal/externalpeerhost/start_lab.go',
  )
  const commands = read(
    'network-sidecar/internal/externalpeerhost/remote_commands.go',
  )
  const executor = read(
    'network-sidecar/internal/externalpeerhost/command_executor.go',
  )
  const management = read(
    'network-sidecar/internal/externalpeerhost/management_keys.go',
  )
  const layerBInputs = read(
    'network-sidecar/internal/externalpeerhost/layer_b_inputs.go',
  )
  const layerBApproval = read(
    'network-sidecar/internal/externalpeerhost/layer_b_approval.go',
  )
  const packageJson = JSON.parse(read('package.json'))

  assert.equal(
    packageJson.scripts['macos:vm-external-peer-lab:host-courier'],
    'node scripts/build-macos-vm-external-peer-lab-host-courier.mjs',
  )
  assert.match(source, /host-orchestration-only/u)
  assert.match(
    source,
    /fixed-key-custody, reviewed-public-artifact-courier, and status-observation only/u,
  )
  assert.match(source, /mkdtempSync\(path\.join\(destinationParent, 'run\.'/u)
  assert.match(source, /sourceBefore/u)
  assert.match(source, /sourceAfter/u)
  assert.match(source, /workspace source changed/u)
  assert.match(source, /runtime_execution_performed:\s*false/u)
  assert.doesNotMatch(
    source,
    /sshpass|sudo\s+-S|execFileSync\([^)]*(?:ssh|scp|tart)/iu,
  )
  assert.doesNotMatch(source, /courier-ed25519-private\.bin/u)
  assert.match(command, /"key-init"/u)
  assert.match(command, /"management-key-init"/u)
  assert.match(command, /"management-host-key-pin"/u)
  assert.match(command, /"layer-a-inputs-init"/u)
  assert.match(command, /"layer-b-inputs-init"/u)
  assert.match(command, /"layer-b-listener-baseline-approve"/u)
  assert.match(command, /"start-lab"/u)
  assert.doesNotMatch(
    layerBInputs,
    /PinReviewedManagementHostKeys|publishListenerBaselineApproval/u,
  )
  assert.match(layerBApproval, /ApproveLayerBListenerBaselines/u)
  assert.doesNotMatch(layerBApproval, /publishLayerBPinInputs/u)
  assert.match(command, /signal\.NotifyContext/u)
  assert.match(command, /syscall\.SIGTERM/u)
  assert.doesNotMatch(command, /"sign-transaction"/u)
  assert.doesNotMatch(command, /os\.Getenv|flag\.|exec\.Command/u)
  assert.match(
    layout,
    /target\/macos-vm-lab\/private\/vm-external-peer-courier/u,
  )
  assert.match(secureFiles, /O_NOFOLLOW/u)
  assert.match(secureFiles, /O_EXCL/u)
  assert.match(secureFiles, /stat\.Nlink == 1/u)
  assert.match(transaction, /externalpeer\.SignCourierMessage/u)
  assert.match(transaction, /externalpeer\.CourierRunTicket/u)
  assert.match(transaction, /externalpeer\.CourierClientToPeer/u)
  assert.match(transaction, /externalpeer\.CourierPeerToClient/u)
  assert.match(transaction, /externalpeer\.CourierCancel/u)
  assert.doesNotMatch(transaction, /json\.Marshal|JSON\.stringify/u)
  assert.match(management, /InitializeManagementKeys/u)
  assert.match(management, /PinReviewedManagementHostKeys/u)
  assert.match(management, /ssh\.MarshalPrivateKey/u)
  assert.match(startLab, /SignPeerResponse/u)
  assert.match(startLab, /SignCancellation/u)
  assert.match(startLab, /startupBudget\s*=\s*120\s*\*\s*time\.Second/u)
  assert.match(commands, /--resolver=arp/u)
  assert.match(commands, /StrictHostKeyChecking=yes/u)
  assert.match(commands, /IdentityAgent=none/u)
  assert.match(
    executor,
    /target\/tools\/tart-2\.32\.1\/tart\.app\/Contents\/MacOS\/tart/u,
  )
  assert.match(
    executor,
    /05b65d5c14e8b41e8e44b6d9fd1278de4bedbc8b735d9b99f3c748f76f75862d/u,
  )
  assert.doesNotMatch(executor, /homebrew|EvalSymlinks/u)
  assert.match(
    transferRunner,
    /type FixedTransferRunner interface \{\s*StartLab\(context\.Context\) error\s*\}/su,
  )
  assert.equal(
    execFileSync(
      'git',
      ['check-ignore', 'target/macos-vm-lab/private/vm-external-peer-courier'],
      {
        cwd: root,
        encoding: 'utf8',
      },
    ).trim(),
    'target/macos-vm-lab/private/vm-external-peer-courier',
  )
})

test('external-peer Mihomo fixture is exact and disjoint from the loopback lab', () => {
  const relative = 'macos/route-helper/vm-external-peer-lab-mihomo-config.json'
  const bytes = fs.readFileSync(path.join(root, relative))
  assert.equal(
    crypto.createHash('sha256').update(bytes).digest('hex'),
    'ff45607149b2afd7bc704cde7fbf4814382cf93b42a960f4760ff9850b09b3a3',
  )
  const config = JSON.parse(bytes)
  assert.equal(config.mode, 'direct')
  assert.equal(config.tun.device, 'utun4094')
  assert.deepEqual(config.tun['route-address'], ['10.88.0.0/24'])
  assert.equal(
    config['external-controller-unix'],
    '/private/var/tmp/kyclash-vm-external-peer-lab-root/mihomo.sock',
  )
})

test('external source contract carries private SSH and cleanup truth', () => {
  const constants = read(
    'network-sidecar/internal/vmexternalpeerlab/constants.go',
  )
  const backend = read('network-sidecar/internal/vmexternalpeerlab/backend.go')
  const protocol = read(
    'network-sidecar/internal/vmexternalpeerlab/supervisor_protocol.go',
  )
  assert.match(constants, /OverlaySSH\s*=\s*"10\.88\.0\.2:22"/u)
  assert.match(constants, /SystemSSH\s*=\s*"10\.88\.0\.2:2222"/u)
  assert.match(backend, /OverlaySSHVerified/u)
  assert.match(backend, /SystemSSHVerified/u)
  assert.match(backend, /DeleteRoute[\s\S]*base\.Close[\s\S]*ReleaseRuntime/u)
  assert.match(protocol, /PrepareFixture/u)
  assert.match(protocol, /BindTunnel/u)
  assert.doesNotMatch(protocol, /exec\.Command|\/bin\/sh|\/bin\/bash/u)
})

test('App runtime owns steady health, confirmed cleanup, and serialized UI status', () => {
  const controller = read('src-tauri/src/cmd/networking_external_peer_lab.rs')
  const socket = read('src-tauri/src/networking/vm_external_peer_lab_socket.rs')
  const page = read('src/pages/networking-dev.tsx')

  assert.match(
    controller,
    /loop\s*\{[\s\S]*wait_timeout\(STEADY_STATE_HEALTH_INTERVAL\)[\s\S]*sample_steady_state/u,
  )
  assert.match(
    controller,
    /"steady_health"[\s\S]*IpcRequestPayload::SampleHealth[\s\S]*"steady_private"[\s\S]*IpcRequestPayload::SamplePrivateReachability/u,
  )
  assert.match(controller, /let cleanup = runtime\.stop\(\)/u)
  assert.match(controller, /peer_loss_exit\(error, cleanup\)/u)
  assert.match(
    controller,
    /requested_stop_exit\(cleanup, socket_abort\.was_hard_aborted\(\)\)/u,
  )
  assert.match(
    controller,
    /HANDSHAKE_PENDING[\s\S]*HANDSHAKE_ACTIVE[\s\S]*HANDSHAKE_ABORTING/u,
  )
  assert.doesNotMatch(controller, /ExternalPeerSession|state\.session/u)
  assert.match(socket, /hard_aborted/u)
  assert.match(socket, /positive remote-cleanup acknowledgement/u)

  assert.match(page, /refreshInFlight/u)
  assert.match(page, /responseGeneration/u)
  assert.match(page, /actionBusyRef/u)
  assert.match(
    page,
    /status\?\.phase === 'disconnected' && status\.last_error === null/u,
  )
  assert.doesNotMatch(page, /phase === 'failed'[\s\S]{0,80}canConnect/u)
  assert.match(page, /Interactive login depends on the peer sshd account/u)
  assert.match(page, /one-shot root-supervisor session has been consumed/u)
})

test('Tart exposes only recursively validated dedicated public shares', () => {
  const script = read('scripts/macos-vm-lab.sh')
  assert.match(script, /GUEST_INPUT_ROOT="\$\{LAB_ROOT\}\/guest-share"/u)
  assert.match(
    script,
    /CLIENT_REVIEW_ROOT="\$\{LAB_ROOT\}\/guest-client-output"/u,
  )
  assert.match(script, /require_safe_share_root\(\)/u)
  assert.match(script, /stat -f '%u:%g:%Lp:%d'/u)
  assert.match(script, /find "\$\{share_path\}" -print0/u)
  assert.match(script, /entry_links[\s\S]*!= "1"/u)
  assert.match(script, /entry_mode_value & 0022/u)
  assert.match(script, /CREDENTIAL_MARKER_PATTERN/u)
  assert.match(script, /grep -aEiq -e/u)
  assert.match(script, /share-preflight\)/u)
  assert.match(
    script,
    /run\)[\s\S]*require_safe_share_root "\$\{GUEST_INPUT_ROOT\}" input[\s\S]*require_safe_share_root "\$\{CLIENT_REVIEW_ROOT\}" review[\s\S]*--dir=kyclash-staging:"\$\{GUEST_INPUT_ROOT\}":ro[\s\S]*--dir=kyclash-review-client:"\$\{CLIENT_REVIEW_ROOT\}"/u,
  )
  assert.doesNotMatch(
    script,
    /--dir=[^:\s]+:"?\$\{REPO_ROOT\}|sshpass|sudo\s+-S|--net-bridged/u,
  )
})
