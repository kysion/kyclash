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
  assert.match(routeClientSource, /reply\.brokerGeneration == expected\.brokerGeneration/u)
  assert.match(routeClientSource, /reply\.routeLeaseID isEqualToString:expected\.routeLeaseID/u)
  assert.match(routeClientSource, /reply\.operationID isEqualToString:expected\.operationID/u)
  assert.match(routeClientSource, /holdV3:reply:/u)
  assert.match(routeClientSource, /releaseV3:reply:/u)
  assert.match(routeClientSource, /statusV3:reply:/u)
  assert.doesNotMatch(routeClientSource, /NSTask|\/bin\/(?:ba)?sh|EnvironmentVariables|route delete default/u)
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

test('build script pins public manifest and never signs or writes a bundled helper', () => {
  assert.match(buildScript, /allowedManifestKeys/u)
  assert.match(buildScript, /actualSHA256 !== manifest\.sha256/u)
  assert.match(buildScript, /manifest\.team_id !== 'RQUQ8Y3S9H'/u)
  assert.match(buildScript, /target', 'tunnel-broker-build'/u)
  assert.doesNotMatch(
    buildScript,
    /codesign|APPLE_SIGNING_IDENTITY|src-tauri',\s*'helpers'/u,
  )
})
