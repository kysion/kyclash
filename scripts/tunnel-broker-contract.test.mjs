import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = fs.readFileSync(
  path.join(root, 'macos', 'tunnel-broker', 'main.swift'),
  'utf8',
)
const clientSource = fs.readFileSync(
  path.join(root, 'macos', 'tunnel-broker', 'client.m'),
  'utf8',
)
const routeClientSource = fs.readFileSync(
  path.join(root, 'macos', 'tunnel-broker', 'route-client.m'),
  'utf8',
)
const routeClientHeader = fs.readFileSync(
  path.join(root, 'macos', 'tunnel-broker', 'route-client.h'),
  'utf8',
)
const registrationSource = fs.readFileSync(
  path.join(root, 'macos', 'route-helper', 'registration.m'),
  'utf8',
)
const routeHelperBuildScript = fs.readFileSync(
  path.join(root, 'scripts', 'build-route-helper-macos.mjs'),
  'utf8',
)
const plistPath = path.join(
  root,
  'macos',
  'tunnel-broker',
  'net.kysion.kyclash.tunnel-broker.plist',
)
const plist = fs.readFileSync(plistPath, 'utf8')
const buildScript = fs.readFileSync(
  path.join(root, 'scripts', 'build-tunnel-broker-macos.mjs'),
  'utf8',
)
const verifierScript = fs.readFileSync(
  path.join(root, 'scripts', 'verify-tunnel-broker-macos.mjs'),
  'utf8',
)

function protocolBody(name) {
  const match = source.match(
    new RegExp(`protocol ${name}(?:\\s*:[^{]+)? \\{([\\s\\S]*?)\\n\\}`, 'u'),
  )
  assert.ok(match, `${name} must exist`)
  return match[1]
}

test('launchd contract exposes only the fixed broker Mach service', () => {
  execFileSync('/usr/bin/plutil', ['-lint', plistPath], { stdio: 'pipe' })
  assert.match(
    plist,
    /<key>Label<\/key>\s*<string>net\.kysion\.kyclash\.tunnel-broker<\/string>/u,
  )
  assert.match(
    plist,
    /<key>BundleProgram<\/key>\s*<string>Contents\/Resources\/kyclash-tunnel-broker<\/string>/u,
  )
  assert.equal(
    (
      plist.match(/<string>net\.kysion\.kyclash\.tunnel-broker<\/string>/gu) ??
      []
    ).length,
    1,
  )
  assert.doesNotMatch(
    plist,
    /ProgramArguments|EnvironmentVariables|WorkingDirectory|UserName/u,
  )
})

test('App XPC surface cannot select a command, path, environment, route, or secret', () => {
  const body = protocolBody('TunnelBrokerAppProtocol')
  assert.match(body, /func start\(reply:/u)
  assert.match(body, /func stop\(_ reference: TunnelReference, reply:/u)
  assert.match(body, /func status\(_ reference: TunnelReference, reply:/u)
  assert.equal((body.match(/\bfunc\b/gu) ?? []).length, 3)
  assert.doesNotMatch(
    body,
    /String|URL|Data|Dictionary|\[|path|argv|argument|environment|route|cidr|dns|secret|profile|shell|file/iu,
  )
})

test('Rust bridge connects only to the fixed service and has no caller-selected launch fields', () => {
  assert.match(
    clientSource,
    /KCTBMachService = @"net\.kysion\.kyclash\.tunnel-broker"/u,
  )
  const exportedCalls = [
    'kyclash_tunnel_broker_client_start',
    'kyclash_tunnel_broker_client_status',
    'kyclash_tunnel_broker_client_stop',
  ]
  for (const call of exportedCalls) {
    assert.match(
      clientSource,
      new RegExp(`KCTBClientReply ${call}\\(void \\*raw\\)`, 'u'),
    )
  }
  assert.equal(
    (
      clientSource.match(
        /KCTBClientReply kyclash_tunnel_broker_client_(?:start|status|stop)\(/gu,
      ) ?? []
    ).length,
    3,
  )
  assert.doesNotMatch(
    clientSource,
    /initWithMachServiceName:\s*(?!KCTBMachService)|NSTask|\/bin\/(?:ba)?sh/u,
  )
  const implementation = clientSource.slice(
    clientSource.indexOf('@implementation KCTBClient'),
  )
  for (const method of ['finishSessionRequest:', 'finishBrokerRequest:']) {
    const methodStart = implementation.indexOf(method)
    const stateRead = implementation.indexOf(
      'KCTBStateCode(reply.state)',
      methodStart,
    )
    assert.ok(methodStart >= 0 && stateRead > methodStart)
    assert.match(
      implementation.slice(methodStart, stateRead),
      /if \(reply == nil\) \{[\s\S]*?KCTBTransportProtocolFailure/u,
      `${method} must reject nil before reading reply fields`,
    )
  }
  const sessionMethodStart = implementation.indexOf('finishSessionRequest:')
  const sessionTerminalBranch = implementation.slice(
    sessionMethodStart,
    implementation.indexOf('if (reply == nil)', sessionMethodStart),
  )
  assert.match(
    sessionTerminalBranch,
    /reply\.inputHandle[^\n]*closeFile[\s\S]*reply\.outputHandle[^\n]*closeFile/u,
    'late session replies must close both transferred pipe descriptors',
  )
})

test('root interlock surface is exact typed hold release status only', () => {
  const body = protocolBody('TunnelBrokerRouteProtocol')
  assert.match(body, /func hold\(_ binding: TunnelRouteBinding, reply:/u)
  assert.match(body, /func release\(_ binding: TunnelRouteBinding, reply:/u)
  assert.match(body, /func status\(_ binding: TunnelRouteBinding, reply:/u)
  assert.equal((body.match(/\bfunc\b/gu) ?? []).length, 3)
  assert.doesNotMatch(
    body,
    /String|URL|Data|Dictionary|\[|path|argv|argument|environment|cidr|dns|secret|profile|shell|file/iu,
  )
})

test('v3 route bridge carries and echoes the complete broker lease tuple', () => {
  assert.match(
    routeClientSource,
    /KCTBRMachService =\s*@"net\.kysion\.kyclash\.tunnel-broker"/u,
  )
  for (const field of [
    'protocolVersion',
    'brokerProtocolVersion',
    'brokerGeneration',
    'sidecarInstanceID',
    'routeLeaseID',
    'operationID',
  ]) {
    assert.match(routeClientSource, new RegExp(`_${field}`, 'u'))
  }
  for (const call of [
    'kyclash_tunnel_broker_route_client_hold',
    'kyclash_tunnel_broker_route_client_release',
    'kyclash_tunnel_broker_route_client_status',
  ]) {
    assert.match(routeClientSource, new RegExp(call, 'u'))
  }
  assert.match(
    routeClientSource,
    /reply\.brokerGeneration == expected\.brokerGeneration/u,
  )
  assert.match(
    routeClientSource,
    /reply\.routeLeaseID isEqualToString:expected\.routeLeaseID/u,
  )
  assert.match(
    routeClientSource,
    /reply\.operationID isEqualToString:expected\.operationID/u,
  )
  assert.match(routeClientSource, /holdV3:reply:/u)
  assert.match(routeClientSource, /releaseV3:reply:/u)
  assert.match(routeClientSource, /statusV3:reply:/u)
  assert.doesNotMatch(
    routeClientSource,
    /NSTask|\/bin\/(?:ba)?sh|EnvironmentVariables|route delete default/u,
  )
})

test('route helper links the root bridge with an explicit ARC C ABI self-test', () => {
  assert.match(routeClientSource, /#import\s+"route-client\.h"/u)
  assert.match(routeClientHeader, /typedef struct\s*\{[\s\S]*transport_status/u)
  assert.match(routeClientHeader, /kyclash_tunnel_broker_route_client_hold/u)
  assert.match(routeClientHeader, /kyclash_tunnel_broker_route_client_release/u)
  assert.match(routeClientHeader, /kyclash_tunnel_broker_route_client_status/u)
  assert.match(routeHelperBuildScript, /clang/u)
  assert.match(routeHelperBuildScript, /-fobjc-arc/u)
  assert.match(routeHelperBuildScript, /-import-objc-header/u)
  assert.match(routeHelperBuildScript, /route-v3-bridge-self-test/u)
  assert.match(routeHelperBuildScript, /route-v3-interlock-self-test/u)
  assert.match(routeHelperBuildScript, /route-v3-durable-store-self-test/u)
  assert.match(routeHelperBuildScript, /route-client\.m/u)
  assert.match(routeHelperBuildScript, /route-client\.o/u)
})

test('v3 helper service is the production listener and legacy v2 is explicitly lab-gated', () => {
  const helperSource = fs.readFileSync(
    path.join(root, 'macos', 'route-helper', 'main.swift'),
    'utf8',
  )
  assert.match(
    helperSource,
    /final class RouteHelperV3Service: NSObject, RouteHelperV3Protocol/u,
  )
  assert.match(
    helperSource,
    /final class RouteHelperV3ListenerDelegate: NSObject, NSXPCListenerDelegate/u,
  )
  assert.match(
    helperSource,
    /connection\.exportedInterface = routeHelperV3Interface\(\)/u,
  )
  assert.match(helperSource, /--route-v3-lab-listener/u)
  assert.match(helperSource, /KYCLASH_ROUTE_HELPER_V2_LAB.*== "1"/u)
  assert.match(helperSource, /--route-v2-lab-listener/u)
  assert.match(helperSource, /runRouteV3ProductionListener()/u)
  assert.match(helperSource, /route_v3_interlock_self_test_ok/u)
  assert.match(helperSource, /final class DurableRouteJournalV3Store/u)
  assert.match(helperSource, /reconcileStartup\(\)/u)
  assert.match(
    helperSource,
    /machServiceName: "net\.kysion\.kyclash\.route-helper"/u,
  )
  assert.match(
    helperSource,
    /route rollback.*broker release|rollback.*before.*release/iu,
  )
  assert.match(
    helperSource,
    /connection\.exportedInterface = routeHelperInterface\(\)/u,
  )
  assert.match(
    helperSource,
    /reply\.state != "released" \|\| reply\.errorCode != nil/u,
  )
})

test('fixed v3 broker and route-helper clients reconnect after transient transport loss', () => {
  const brokerClient = fs.readFileSync(
    path.join(root, 'macos', 'tunnel-broker', 'route-client.m'),
    'utf8',
  )
  const helperClient = fs.readFileSync(
    path.join(root, 'macos', 'route-helper', 'client-v3.m'),
    'utf8',
  )
  for (const body of [brokerClient, helperClient]) {
    assert.match(body, /ensureConnection/u)
    assert.match(body, /_needsReconnect/u)
    assert.match(body, /markTransient:.*epoch:/u)
    assert.match(body, /KCTBRTransportTimeout|KCRV3TransportTimeout/u)
    assert.match(body, /initWithMachServiceName/u)
  }
})

test('production Connect verifies fixed helper/broker code requirements and manifests', () => {
  assert.match(
    registrationSource,
    /kyclash_privileged_networking_verify_bundled_requirements/u,
  )
  assert.match(registrationSource, /SecStaticCodeCheckValidity/u)
  assert.match(registrationSource, /RQUQ8Y3S9H/u)
  assert.match(registrationSource, /Contents\/Library\/LaunchDaemons/u)
  assert.match(registrationSource, /net\.kysion\.kyclash\.route-helper/u)
  assert.match(registrationSource, /net\.kysion\.kyclash\.tunnel-broker/u)
})

test('Swift v3 route service matches the bridge and cannot mix legacy ownership', () => {
  const body = protocolBody('TunnelBrokerRouteV3Protocol')
  assert.match(body, /func holdV3\(_ binding: TunnelRouteBindingV3, reply:/u)
  assert.match(body, /func releaseV3\(_ binding: TunnelRouteBindingV3, reply:/u)
  assert.match(body, /func statusV3\(_ binding: TunnelRouteBindingV3, reply:/u)
  assert.equal((body.match(/\bfunc\b/gu) ?? []).length, 3)
  assert.match(source, /@objc\(KCTunnelRouteBindingV3\)/u)
  assert.match(source, /@objc\(KCTunnelBrokerRouteReplyV3\)/u)
  assert.match(source, /@objc\(KCTunnelBrokerRouteV3Protocol\)/u)
  assert.match(
    source,
    /NSXPCInterface\(with: TunnelBrokerRouteV3Protocol\.self\)/u,
  )
  for (const field of [
    'protocolVersion',
    'brokerProtocolVersion',
    'brokerGeneration',
    'sidecarInstanceID',
    'routeLeaseID',
    'operationID',
  ]) {
    assert.match(source, new RegExp(`let ${field}:`, 'u'))
  }
  assert.match(source, /releasedLegacyRouteLeaseID/u)
  assert.match(source, /releasedRouteBindingV3/u)
  assert.match(source, /retiredRouteBindingV3/u)
  assert.match(source, /retiredRouteBindingV3\.classify\(binding\)/u)
  assert.doesNotMatch(
    body,
    /String|URL|Data|Dictionary|\[|path|argv|argument|environment|cidr|dns|secret|profile|shell|file/iu,
  )
})

test('spawn planner derives one sibling sidecar with fixed empty argv and environment', () => {
  assert.match(
    source,
    /private let sidecarExecutableName = "kyclash-network-sidecar"/u,
  )
  assert.match(source, /let arguments: \[String\] = \[\]/u)
  assert.match(source, /let environment: \[String: String\] = \[:\]/u)
  assert.match(source, /isRegularNonSymlink\(sidecarURL\)/u)
  assert.match(source, /isThinArm64MachO\(data\)/u)
  assert.match(source, /SecStaticCodeCheckValidity/u)
  assert.match(source, /kSecCodeInfoTeamIdentifier/u)
  assert.doesNotMatch(
    source,
    /\/bin\/(?:ba)?sh|ProcessInfo\.processInfo\.environment/u,
  )
})

test('build script pins public manifest and requires a signed bundled broker', () => {
  assert.match(buildScript, /allowedManifestKeys/u)
  assert.match(buildScript, /actualSHA256 !== manifest\.sha256/u)
  assert.match(buildScript, /manifest\.team_id !== 'RQUQ8Y3S9H'/u)
  assert.match(buildScript, /target', 'tunnel-broker-build'/u)
  assert.match(buildScript, /APPLE_SIGNING_IDENTITY/u)
  assert.match(buildScript, /APPLE_TEAM_ID/u)
  assert.match(buildScript, /codesign/u)
  assert.match(buildScript, /net\.kysion\.kyclash\.tunnel-broker/u)
  assert.match(
    buildScript,
    /src-tauri',\s*'helpers',\s*'kyclash-tunnel-broker'/u,
  )
  assert.match(buildScript, /selfTest/u)
})

test('broker verifier requires fixed arm64 Developer ID identity and plist', () => {
  assert.match(verifierScript, /lipo/u)
  assert.match(verifierScript, /--verify/u)
  assert.match(verifierScript, /--strict/u)
  assert.match(verifierScript, /net\.kysion\.kyclash\.tunnel-broker/u)
  assert.match(verifierScript, /RQUQ8Y3S9H/u)
  assert.match(
    verifierScript,
    /const topLevelKeys = \['BundleProgram', 'Label', 'MachServices'\]/u,
  )
  assert.match(
    verifierScript,
    /JSON\.stringify\(Object\.keys\(decodedPlist\)\.sort\(\)\)/u,
  )
  assert.match(
    verifierScript,
    /const serviceKeys = \['net\.kysion\.kyclash\.tunnel-broker'\]/u,
  )
  assert.match(
    verifierScript,
    /decodedPlist\.MachServices\['net\.kysion\.kyclash\.tunnel-broker'\] !== true/u,
  )
  assert.doesNotMatch(verifierScript, /ProgramArguments|EnvironmentVariables/u)
  assert.match(verifierScript, /0o022/u)
})
