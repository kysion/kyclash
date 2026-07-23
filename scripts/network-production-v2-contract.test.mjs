import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  PRODUCTION_NETWORK_CARRIER_AUTH_VERSION,
  PRODUCTION_NETWORK_MTU,
  PRODUCTION_NETWORK_QUIC_ALPN,
  PRODUCTION_NETWORK_SCHEMA_VERSION,
  PRODUCTION_NETWORK_WSS_PATH,
  assertProductionNetworkProfileV2,
} from '../src/types/networking-production-v2.ts'

const schema = JSON.parse(
  await readFile(
    new URL(
      '../schemas/kyclash-network-production-v2.schema.json',
      import.meta.url,
    ),
    'utf8',
  ),
)
const fixture = JSON.parse(
  await readFile(
    new URL(
      '../schemas/fixtures/network-production-v2.valid.json',
      import.meta.url,
    ),
    'utf8',
  ),
)
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictTypes: false,
})
const validateSchema = ajv.compile(schema)

const cloneFixture = () => structuredClone(fixture)

const mutationCorpus = [
  {
    name: 'unknown root key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.private_key = 'forbidden'
    },
  },
  {
    name: 'missing root key',
    schemaRejects: true,
    mutate: (profile) => {
      delete profile.identity_ref
    },
  },
  {
    name: 'unknown site key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.alias = 'forbidden'
    },
  },
  {
    name: 'unknown tunnel key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.private_key = 'forbidden'
    },
  },
  {
    name: 'unknown transport key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.mode = 'forbidden'
    },
  },
  {
    name: 'unknown endpoint key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].credential = 'forbidden'
    },
  },
  {
    name: 'unknown policy key',
    schemaRejects: true,
    mutate: (profile) => {
      profile.policy.retry = 1
    },
  },
  {
    name: 'schema v1',
    schemaRejects: true,
    mutate: (profile) => {
      profile.schema_version = 1
    },
  },
  {
    name: 'carrier auth v2',
    schemaRejects: true,
    mutate: (profile) => {
      profile.carrier_auth_version = 2
    },
  },
  {
    name: 'invalid profile id',
    schemaRejects: true,
    mutate: (profile) => {
      profile.profile_id = '/invalid'
    },
  },
  {
    name: 'oversized profile id',
    schemaRejects: true,
    mutate: (profile) => {
      profile.profile_id = `a${'b'.repeat(128)}`
    },
  },
  {
    name: 'invalid site id',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.id = ''
    },
  },
  {
    name: 'invalid identity ref',
    schemaRejects: true,
    mutate: (profile) => {
      profile.identity_ref = 'file:/forbidden'
    },
  },
  {
    name: 'empty display name',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = ''
    },
  },
  {
    name: 'display leading Go trim-space U+0085',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = '\u0085leading'
    },
  },
  {
    name: 'display trailing Go trim-space U+0085',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = 'trailing\u0085'
    },
  },
  {
    name: 'display exceeds 128 Unicode scalars',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = '😀'.repeat(129)
    },
  },
  {
    name: 'display lone high surrogate',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = String.fromCharCode(0xd800)
    },
  },
  {
    name: 'display lone low surrogate',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.display_name = String.fromCharCode(0xdc00)
    },
  },
  {
    name: 'empty control plane',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = ''
    },
  },
  {
    name: 'control plane wrong scheme',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'http://control.example.invalid'
    },
  },
  {
    name: 'control plane uppercase scheme',
    mutate: (profile) => {
      profile.control_plane = 'HTTPS://control.example.invalid'
    },
  },
  {
    name: 'control plane user info',
    mutate: (profile) => {
      profile.control_plane = 'https://user@control.example.invalid'
    },
  },
  {
    name: 'control plane user and password',
    mutate: (profile) => {
      profile.control_plane = 'https://user:password@control.example.invalid'
    },
  },
  {
    name: 'control plane empty user info',
    mutate: (profile) => {
      profile.control_plane = 'https://@control.example.invalid'
    },
  },
  {
    name: 'control plane query',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid?'
    },
  },
  {
    name: 'control plane fragment',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid#'
    },
  },
  {
    name: 'control plane percent encoding',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid/%61pi'
    },
  },
  {
    name: 'control plane encoded host',
    mutate: (profile) => {
      profile.control_plane = 'https://%63ontrol.example.invalid'
    },
  },
  {
    name: 'control plane backslash',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid\\api'
    },
  },
  {
    name: 'control plane Unicode',
    mutate: (profile) => {
      profile.control_plane = 'https://例子.invalid'
    },
  },
  {
    name: 'control plane Unicode path',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid/界'
    },
  },
  {
    name: 'control plane space',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid/a b'
    },
  },
  {
    name: 'control plane forbidden path delimiter',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid/<api>'
    },
  },
  {
    name: 'control plane port above URL range',
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid:65536'
    },
  },
  {
    name: 'control plane empty hostname',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://:443'
    },
  },
  {
    name: 'control plane IPv6 zone',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://[fe80::1%25en0]/'
    },
  },
  {
    name: 'control plane invalid IPv4',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://999.999.999.999'
    },
  },
  {
    name: 'control plane overflow IPv4 octet',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://256.1.1.1'
    },
  },
  {
    name: 'control plane empty DNS label',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://1..2'
    },
  },
  {
    name: 'control plane IPv4 shorthand',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://127.1'
    },
  },
  {
    name: 'control plane uppercase host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://Control.Example.Invalid'
    },
  },
  {
    name: 'control plane numeric final label',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.999'
    },
  },
  {
    name: 'control plane zero port',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid:0'
    },
  },
  {
    name: 'control plane noncanonical port',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = 'https://control.example.invalid:0443'
    },
  },
  {
    name: 'control plane oversized',
    schemaRejects: true,
    mutate: (profile) => {
      profile.control_plane = `https://${'a'.repeat(2050)}.invalid`
    },
  },
  {
    name: 'zero local public key',
    mutate: (profile) => {
      profile.tunnel.local_public_key =
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    },
  },
  {
    name: 'same public keys',
    mutate: (profile) => {
      profile.tunnel.local_public_key = profile.tunnel.peer_public_key
    },
  },
  {
    name: 'missing public key padding',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.local_public_key =
        'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI'
    },
  },
  {
    name: 'noncanonical public key padding bits',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.local_public_key =
        'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiJ='
    },
  },
  {
    name: 'noncanonical X25519 high-bit alias',
    schemaRejects: true,
    mutate: (profile) => {
      const decoded = Buffer.from(profile.tunnel.local_public_key, 'base64')
      decoded[31] |= 0x80
      profile.tunnel.local_public_key = decoded.toString('base64')
    },
  },
  {
    name: 'noncanonical X25519 field alias',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.local_public_key =
        '9v///////////////////////////////////////38='
    },
  },
  {
    name: 'empty local addresses',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.local_addresses = []
    },
  },
  {
    name: 'non-host local prefix',
    mutate: (profile) => {
      profile.tunnel.local_addresses[0] = '10.255.255.0/24'
    },
  },
  {
    name: 'noncanonical local prefix',
    mutate: (profile) => {
      profile.tunnel.local_addresses[0] = '10.255.255.002/32'
    },
  },
  {
    name: 'public local address',
    mutate: (profile) => {
      profile.tunnel.local_addresses[0] = '192.0.2.2/32'
    },
  },
  {
    name: 'duplicate local family',
    mutate: (profile) => {
      profile.tunnel.local_addresses[1] = '10.255.255.3/32'
    },
  },
  {
    name: 'empty private CIDRs',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.private_cidrs = []
    },
  },
  {
    name: 'noncanonical private CIDR',
    mutate: (profile) => {
      profile.site.private_cidrs[0] = '10.127.1.1/16'
    },
  },
  {
    name: 'public private CIDR',
    mutate: (profile) => {
      profile.site.private_cidrs[0] = '203.0.113.0/24'
    },
  },
  {
    name: 'private allowlist boundary crossing',
    mutate: (profile) => {
      profile.site.private_cidrs[0] = '172.0.0.0/11'
    },
  },
  {
    name: 'overlapping private CIDRs',
    mutate: (profile) => {
      profile.site.private_cidrs.push('10.127.1.0/24')
    },
  },
  {
    name: 'private CIDR family mismatch',
    mutate: (profile) => {
      profile.site.private_cidrs = profile.site.private_cidrs.slice(0, 1)
    },
  },
  {
    name: 'host prefix overlaps private route',
    mutate: (profile) => {
      profile.tunnel.local_addresses[0] = '10.127.0.2/32'
    },
  },
  {
    name: 'too many private CIDRs',
    schemaRejects: true,
    mutate: (profile) => {
      profile.site.private_cidrs = Array.from(
        { length: 17 },
        (_, index) => `10.${index}.0.0/16`,
      )
    },
  },
  {
    name: 'keepalive below range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.keepalive_seconds = 0
    },
  },
  {
    name: 'keepalive above range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.tunnel.keepalive_seconds = 65536
    },
  },
  {
    name: 'primary is not QUIC',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.primary = 'wss'
    },
  },
  {
    name: 'fallback order drift',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.fallbacks = ['tcp', 'wss']
    },
  },
  {
    name: 'endpoint order drift',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints.reverse()
    },
  },
  {
    name: 'endpoint host drift',
    mutate: (profile) => {
      profile.transports.endpoints[1].url =
        'wss://other.example.invalid:2444/kynp'
    },
  },
  {
    name: 'endpoint duplicate port',
    mutate: (profile) => {
      profile.transports.endpoints[1].url =
        'wss://peer.example.invalid:2443/kynp'
    },
  },
  {
    name: 'endpoint implicit port',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid'
    },
  },
  {
    name: 'endpoint privileged port',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid:443'
    },
  },
  {
    name: 'endpoint port above range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid:65536'
    },
  },
  {
    name: 'endpoint noncanonical port',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid:02443'
    },
  },
  {
    name: 'endpoint user info',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url =
        'https://user@peer.example.invalid:2443'
    },
  },
  {
    name: 'endpoint query',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid:2443?'
    },
  },
  {
    name: 'endpoint fragment',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid:2443#'
    },
  },
  {
    name: 'endpoint percent encoded host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url =
        'https://%70eer.example.invalid:2443'
    },
  },
  {
    name: 'endpoint IP host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://127.0.0.1:2443'
    },
  },
  {
    name: 'endpoint numeric DNS host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://127.1:2443'
    },
  },
  {
    name: 'endpoint uppercase host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://Peer.Example.Invalid:2443'
    },
  },
  {
    name: 'endpoint malformed DNS label',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer..example.invalid:2443'
    },
  },
  {
    name: 'endpoint single-label host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://localhost:2443'
    },
  },
  {
    name: 'endpoint trailing-dot host',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[0].url = 'https://peer.example.invalid.:2443'
    },
  },
  {
    name: 'WSS path drift',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[1].url =
        'wss://peer.example.invalid:2444/wrong'
    },
  },
  {
    name: 'WSS trailing slash',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[1].url =
        'wss://peer.example.invalid:2444/kynp/'
    },
  },
  {
    name: 'TCP path',
    schemaRejects: true,
    mutate: (profile) => {
      profile.transports.endpoints[2].url = 'tcp://peer.example.invalid:2445/'
    },
  },
  {
    name: 'connect timeout below range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.policy.connect_timeout_seconds = 0
    },
  },
  {
    name: 'health interval above range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.policy.health_interval_seconds = 301
    },
  },
  {
    name: 'fallback threshold above range',
    schemaRejects: true,
    mutate: (profile) => {
      profile.policy.fallback_threshold = 21
    },
  },
  {
    name: 'policy integer required',
    schemaRejects: true,
    mutate: (profile) => {
      profile.policy.fallback_threshold = 1.5
    },
  },
]

test('shared fixture satisfies Draft 2020-12 and the TypeScript contract', () => {
  assert.equal(
    validateSchema(fixture),
    true,
    ajv.errorsText(validateSchema.errors),
  )
  assert.doesNotThrow(() => assertProductionNetworkProfileV2(fixture))
})

test('constants stay paired with the Go and Rust production validators', () => {
  assert.equal(PRODUCTION_NETWORK_SCHEMA_VERSION, 2)
  assert.equal(PRODUCTION_NETWORK_CARRIER_AUTH_VERSION, 1)
  assert.equal(PRODUCTION_NETWORK_QUIC_ALPN, 'kyclash-network/1')
  assert.equal(PRODUCTION_NETWORK_WSS_PATH, '/kynp')
  assert.equal(PRODUCTION_NETWORK_MTU, 1420)
})

test('the same mutation corpus is rejected by the TypeScript assertion', async (context) => {
  for (const mutation of mutationCorpus) {
    await context.test(mutation.name, () => {
      const profile = cloneFixture()
      mutation.mutate(profile)
      assert.throws(() => assertProductionNetworkProfileV2(profile))
    })
  }
})

test('Draft 2020-12 rejects every schema-level negative in the mutation corpus', async (context) => {
  for (const mutation of mutationCorpus.filter(
    ({ schemaRejects }) => schemaRejects,
  )) {
    await context.test(mutation.name, () => {
      const profile = cloneFixture()
      mutation.mutate(profile)
      assert.equal(validateSchema(profile), false)
    })
  }
})

test('Unicode scalar and backend-compatible boundary corpus remains accepted', () => {
  for (const displayName of [
    'A',
    '内\u0085部',
    '\ufeffaccepted',
    'accepted\ufeff',
    '😀',
    '😀'.repeat(128),
  ]) {
    const profile = cloneFixture()
    profile.site.display_name = displayName
    assert.equal(
      validateSchema(profile),
      true,
      ajv.errorsText(validateSchema.errors),
    )
    assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
  }

  const maxControlPlanePrefix = 'https://control.example.invalid/'
  for (const controlPlane of [
    'https://control.example.invalid',
    'https://control.example.invalid:443',
    'https://control.example.invalid/',
    'https://control.example.invalid:8443/api/v2',
    'https://control.example.invalid/a/../b',
    `${maxControlPlanePrefix}${'a'.repeat(
      2048 - maxControlPlanePrefix.length,
    )}`,
  ]) {
    const profile = cloneFixture()
    profile.control_plane = controlPlane
    assert.equal(
      validateSchema(profile),
      true,
      ajv.errorsText(validateSchema.errors),
    )
    assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
  }
})

test('identifier scalar-count boundaries remain accepted', () => {
  const profile = cloneFixture()
  profile.profile_id = `a${'b'.repeat(127)}`
  profile.site.id = `s${'i'.repeat(127)}`
  profile.identity_ref = `keychain:k${'r'.repeat(127)}`
  assert.equal(
    validateSchema(profile),
    true,
    ajv.errorsText(validateSchema.errors),
  )
  assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
})

test('numeric and carrier boundary corpus remains accepted', () => {
  const profile = cloneFixture()
  profile.tunnel.keepalive_seconds = 65535
  profile.policy.connect_timeout_seconds = 300
  profile.policy.health_interval_seconds = 1
  profile.policy.fallback_threshold = 20
  profile.transports.endpoints[0].url = 'https://peer.example.invalid:1024'
  profile.transports.endpoints[1].url = 'wss://peer.example.invalid:65534/kynp'
  profile.transports.endpoints[2].url = 'tcp://peer.example.invalid:65535'
  assert.equal(
    validateSchema(profile),
    true,
    ajv.errorsText(validateSchema.errors),
  )
  assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
})

test('single-family canonical profiles and each private allowlist are accepted', () => {
  for (const [localAddress, privateCIDR] of [
    ['10.255.255.2/32', '10.127.0.0/16'],
    ['172.31.255.2/32', '172.16.0.0/16'],
    ['192.168.255.2/32', '192.168.0.0/24'],
    ['fd00:255::2/128', 'fd00:127::/48'],
  ]) {
    const profile = cloneFixture()
    profile.tunnel.local_addresses = [localAddress]
    profile.site.private_cidrs = [privateCIDR]
    assert.equal(
      validateSchema(profile),
      true,
      ajv.errorsText(validateSchema.errors),
    )
    assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
  }
})

test('the maximum private CIDR count remains accepted', () => {
  const profile = cloneFixture()
  profile.tunnel.local_addresses = ['10.255.255.2/32']
  profile.site.private_cidrs = Array.from(
    { length: 16 },
    (_, index) => `10.${index}.0.0/16`,
  )
  assert.equal(
    validateSchema(profile),
    true,
    ajv.errorsText(validateSchema.errors),
  )
  assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
})

test('canonical nonzero low-order keys remain an explicit backend semantic gate', () => {
  const profile = cloneFixture()
  profile.tunnel.local_public_key =
    'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
  assert.doesNotThrow(() => assertProductionNetworkProfileV2(profile))
})
