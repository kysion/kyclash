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
    new RegExp(`protocol ${name} \\{([\\s\\S]*?)\\n\\}`, 'u'),
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
