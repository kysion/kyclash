export const PRODUCTION_NETWORK_SCHEMA_VERSION = 2 as const
export const PRODUCTION_NETWORK_CARRIER_AUTH_VERSION = 1 as const
export const PRODUCTION_NETWORK_QUIC_ALPN = 'kyclash-network/1' as const
export const PRODUCTION_NETWORK_WSS_PATH = '/kynp' as const
export const PRODUCTION_NETWORK_MTU = 1420 as const

const ROOT_KEYS = [
  'schema_version',
  'carrier_auth_version',
  'profile_id',
  'control_plane',
  'identity_ref',
  'site',
  'tunnel',
  'transports',
  'policy',
] as const
const SITE_KEYS = ['id', 'display_name', 'private_cidrs'] as const
const TUNNEL_KEYS = [
  'local_addresses',
  'local_public_key',
  'peer_public_key',
  'keepalive_seconds',
] as const
const TRANSPORTS_KEYS = ['primary', 'fallbacks', 'endpoints'] as const
const ENDPOINT_KEYS = ['transport', 'url'] as const
const POLICY_KEYS = [
  'connect_timeout_seconds',
  'health_interval_seconds',
  'fallback_threshold',
] as const
const EXPECTED_TRANSPORTS = ['quic', 'wss', 'tcp'] as const

const MAX_PRIVATE_CIDRS = 16
const MAX_PRIVATE_CIDR_TEXT_BYTES = 1024
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/
const CANONICAL_PUBLIC_KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const DECIMAL = /^(?:0|[1-9][0-9]*)$/

type ProductionTransportKindV2 = (typeof EXPECTED_TRANSPORTS)[number]

export interface ProductionNetworkProfileV2 {
  schema_version: typeof PRODUCTION_NETWORK_SCHEMA_VERSION
  carrier_auth_version: typeof PRODUCTION_NETWORK_CARRIER_AUTH_VERSION
  profile_id: string
  control_plane: string
  identity_ref: string
  site: {
    id: string
    display_name: string
    private_cidrs: string[]
  }
  tunnel: {
    local_addresses: string[]
    local_public_key: string
    peer_public_key: string
    keepalive_seconds: number
  }
  transports: {
    primary: 'quic'
    fallbacks: ['wss', 'tcp']
    endpoints: [
      { transport: 'quic'; url: string },
      { transport: 'wss'; url: string },
      { transport: 'tcp'; url: string },
    ]
  }
  policy: {
    connect_timeout_seconds: number
    health_interval_seconds: number
    fallback_threshold: number
  }
}

interface ParsedPrefix {
  address: bigint
  bits: number
  family: 4 | 6
  width: 32 | 128
}

interface ParsedEndpoint {
  host: string
  port: number
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(
  value: unknown,
  expected: readonly string[],
): value is Record<string, unknown> {
  if (!isObject(value)) return false
  const actual = Reflect.ownKeys(value)
  return (
    actual.length === expected.length &&
    actual.every((key) => typeof key === 'string' && expected.includes(key))
  )
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= minimum &&
    value <= maximum
  )
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return false
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false
    }
  }
  return true
}

function isIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 128 &&
    IDENTIFIER.test(value)
  )
}

function isDisplayName(value: unknown): value is string {
  if (typeof value !== 'string' || !isWellFormedUnicode(value)) return false
  const scalars = [...value]
  return (
    scalars.length >= 1 &&
    scalars.length <= 128 &&
    !isGoTrimSpace(scalars[0]) &&
    !isGoTrimSpace(scalars[scalars.length - 1])
  )
}

function isGoTrimSpace(value: string): boolean {
  const scalar = value.codePointAt(0)
  return (
    scalar !== undefined &&
    ((scalar >= 0x0009 && scalar <= 0x000d) ||
      scalar === 0x0020 ||
      scalar === 0x0085 ||
      scalar === 0x00a0 ||
      scalar === 0x1680 ||
      (scalar >= 0x2000 && scalar <= 0x200a) ||
      scalar === 0x2028 ||
      scalar === 0x2029 ||
      scalar === 0x202f ||
      scalar === 0x205f ||
      scalar === 0x3000)
  )
}

function isControlPlane(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 2048 ||
    !/^[\x20-\x7e]+$/.test(value) ||
    /[%\\?#]/.test(value) ||
    !value.startsWith('https://')
  ) {
    return false
  }

  const remainder = value.slice('https://'.length)
  const slash = remainder.indexOf('/')
  const authority = slash < 0 ? remainder : remainder.slice(0, slash)
  const path = slash < 0 ? undefined : remainder.slice(slash + 1)
  if (
    authority.length === 0 ||
    authority.includes('@') ||
    authority.includes('[') ||
    authority.includes(']') ||
    !/^[A-Za-z0-9._~!$&'()*+,;=:\-[\]]+$/.test(authority) ||
    (path !== undefined && !/^[A-Za-z0-9._~!$&'()*+,;=:@\-/]*$/.test(path))
  ) {
    return false
  }

  const separator = authority.lastIndexOf(':')
  if (separator !== authority.indexOf(':')) return false
  const host = separator < 0 ? authority : authority.slice(0, separator)
  const rawPort = separator < 0 ? undefined : authority.slice(separator + 1)
  const finalLabel = host.slice(host.lastIndexOf('.') + 1)
  if (!isDNSOnlyServerName(host) || !/[a-z]/.test(finalLabel)) {
    return false
  }
  if (rawPort === undefined) return true
  if (!DECIMAL.test(rawPort)) return false
  const port = Number(rawPort)
  return (
    Number.isInteger(port) &&
    port > 0 &&
    port <= 65535 &&
    String(port) === rawPort
  )
}

function decodeCanonicalPublicKey(value: unknown): string | undefined {
  if (typeof value !== 'string' || !CANONICAL_PUBLIC_KEY.test(value)) {
    return undefined
  }
  try {
    const decoded = atob(value)
    if (
      decoded.length !== 32 ||
      btoa(decoded) !== value ||
      !isCanonicalX25519Coordinate(decoded) ||
      [...decoded].every((octet) => octet.charCodeAt(0) === 0)
    ) {
      return undefined
    }
    // X25519 low-order-point rejection requires the backend cryptographic
    // primitive. This UI trust boundary deliberately enforces only canonical
    // 32-byte encoding, nonzero material, and pair inequality.
    return decoded
  } catch {
    return undefined
  }
}

function isCanonicalX25519Coordinate(decoded: string): boolean {
  for (let index = 31; index >= 0; index -= 1) {
    const primeOctet = index === 0 ? 0xed : index === 31 ? 0x7f : 0xff
    const octet = decoded.charCodeAt(index)
    if (octet < primeOctet) return true
    if (octet > primeOctet) return false
  }
  return false
}

function parseIPv4(value: string): bigint | undefined {
  const octets = value.split('.')
  if (octets.length !== 4) return undefined
  let result = 0n
  for (const octet of octets) {
    if (!DECIMAL.test(octet)) return undefined
    const parsed = Number(octet)
    if (parsed > 255) return undefined
    result = (result << 8n) | BigInt(parsed)
  }
  return octets.map(Number).join('.') === value ? result : undefined
}

function canonicalIPv6(groups: readonly number[]): string {
  let bestStart = -1
  let bestLength = 0
  for (let start = 0; start < groups.length; start += 1) {
    if (groups[start] !== 0) continue
    let end = start
    while (end < groups.length && groups[end] === 0) end += 1
    const length = end - start
    if (length >= 2 && length > bestLength) {
      bestStart = start
      bestLength = length
    }
    start = end - 1
  }
  if (bestStart < 0) return groups.map((group) => group.toString(16)).join(':')
  const left = groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(':')
  const right = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(':')
  return `${left}::${right}`
}

function parseIPv6(value: string): bigint | undefined {
  if (value.includes('%') || value.includes('.')) return undefined
  const compression = value.indexOf('::')
  if (compression !== value.lastIndexOf('::')) return undefined

  const parseSide = (side: string): number[] | undefined => {
    if (side === '') return []
    const groups = side.split(':')
    if (
      groups.some(
        (group) =>
          !/^[0-9A-Fa-f]{1,4}$/.test(group) ||
          Number.parseInt(group, 16) > 0xffff,
      )
    ) {
      return undefined
    }
    return groups.map((group) => Number.parseInt(group, 16))
  }

  let groups: number[]
  if (compression >= 0) {
    const left = parseSide(value.slice(0, compression))
    const right = parseSide(value.slice(compression + 2))
    if (!left || !right || left.length + right.length >= 8) return undefined
    groups = [
      ...left,
      ...Array(8 - left.length - right.length).fill(0),
      ...right,
    ]
  } else {
    const parsed = parseSide(value)
    if (parsed?.length !== 8) return undefined
    groups = parsed
  }
  if (canonicalIPv6(groups) !== value) return undefined

  return groups.reduce((result, group) => (result << 16n) | BigInt(group), 0n)
}

function prefixMask(width: number, bits: number): bigint {
  if (bits === 0) return 0n
  const hostBits = BigInt(width - bits)
  return ((1n << BigInt(width)) - 1n) ^ ((1n << hostBits) - 1n)
}

function parseCanonicalPrefix(value: string): ParsedPrefix | undefined {
  const slash = value.lastIndexOf('/')
  if (slash <= 0 || slash !== value.indexOf('/')) return undefined
  const rawAddress = value.slice(0, slash)
  const rawBits = value.slice(slash + 1)
  if (!DECIMAL.test(rawBits)) return undefined
  const bits = Number(rawBits)
  if (!Number.isSafeInteger(bits) || String(bits) !== rawBits) return undefined

  const ipv4 = parseIPv4(rawAddress)
  if (ipv4 !== undefined && bits <= 32) {
    return { address: ipv4, bits, family: 4, width: 32 }
  }
  const ipv6 = parseIPv6(rawAddress)
  if (ipv6 !== undefined && bits <= 128) {
    return { address: ipv6, bits, family: 6, width: 128 }
  }
  return undefined
}

function isNetworkPrefix(prefix: ParsedPrefix): boolean {
  return (
    (prefix.address & prefixMask(prefix.width, prefix.bits)) === prefix.address
  )
}

function prefixContains(
  allowed: ParsedPrefix,
  candidate: ParsedPrefix,
): boolean {
  return (
    allowed.family === candidate.family &&
    candidate.bits >= allowed.bits &&
    (candidate.address & prefixMask(candidate.width, allowed.bits)) ===
      allowed.address
  )
}

function prefixesOverlap(left: ParsedPrefix, right: ParsedPrefix): boolean {
  if (left.family !== right.family) return false
  const bits = Math.min(left.bits, right.bits)
  const mask = prefixMask(left.width, bits)
  return (left.address & mask) === (right.address & mask)
}

const PRIVATE_ALLOWLIST = [
  parseCanonicalPrefix('10.0.0.0/8'),
  parseCanonicalPrefix('172.16.0.0/12'),
  parseCanonicalPrefix('192.168.0.0/16'),
  parseCanonicalPrefix('fc00::/7'),
].filter((prefix): prefix is ParsedPrefix => prefix !== undefined)

function isAllowlistedPrivatePrefix(prefix: ParsedPrefix): boolean {
  return PRIVATE_ALLOWLIST.some((allowed) => prefixContains(allowed, prefix))
}

function parseHostPrefixes(
  values: unknown,
): { families: Set<4 | 6>; prefixes: ParsedPrefix[] } | undefined {
  if (!isStringArray(values) || values.length < 1 || values.length > 2) {
    return undefined
  }
  const families = new Set<4 | 6>()
  const prefixes: ParsedPrefix[] = []
  for (const value of values) {
    const prefix = parseCanonicalPrefix(value)
    if (
      !prefix ||
      prefix.bits !== prefix.width ||
      !isAllowlistedPrivatePrefix(prefix) ||
      families.has(prefix.family)
    ) {
      return undefined
    }
    families.add(prefix.family)
    prefixes.push(prefix)
  }
  return { families, prefixes }
}

function parsePrivatePrefixes(
  values: unknown,
): { families: Set<4 | 6>; prefixes: ParsedPrefix[] } | undefined {
  if (
    !isStringArray(values) ||
    values.length < 1 ||
    values.length > MAX_PRIVATE_CIDRS ||
    values.reduce((bytes, value) => bytes + value.length, 0) >
      MAX_PRIVATE_CIDR_TEXT_BYTES
  ) {
    return undefined
  }
  const families = new Set<4 | 6>()
  const prefixes: ParsedPrefix[] = []
  for (const value of values) {
    const prefix = parseCanonicalPrefix(value)
    if (
      !prefix ||
      prefix.bits === 0 ||
      !isNetworkPrefix(prefix) ||
      !isAllowlistedPrivatePrefix(prefix) ||
      prefixes.some((existing) => prefixesOverlap(existing, prefix))
    ) {
      return undefined
    }
    families.add(prefix.family)
    prefixes.push(prefix)
  }
  return { families, prefixes }
}

function sameFamilies(left: Set<4 | 6>, right: Set<4 | 6>): boolean {
  return (
    left.size === right.size && [...left].every((family) => right.has(family))
  )
}

function isDNSOnlyServerName(value: string): boolean {
  if (
    value.length < 1 ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value.endsWith('.') ||
    /^[0-9.]+$/.test(value)
  ) {
    return false
  }
  const labels = value.split('.')
  return (
    labels.length >= 2 &&
    labels.every((label) => label.length <= 63 && DNS_LABEL.test(label))
  )
}

function parseEndpoint(
  value: unknown,
  expectedTransport: ProductionTransportKindV2,
): ParsedEndpoint | undefined {
  if (!hasExactKeys(value, ENDPOINT_KEYS)) return undefined
  const { transport, url } = value
  if (transport !== expectedTransport || typeof url !== 'string') {
    return undefined
  }
  const scheme = expectedTransport === 'quic' ? 'https' : expectedTransport
  const path = expectedTransport === 'wss' ? PRODUCTION_NETWORK_WSS_PATH : ''
  const prefix = `${scheme}://`
  if (
    !url.startsWith(prefix) ||
    !url.endsWith(path) ||
    /[%\\?#\s]/u.test(url)
  ) {
    return undefined
  }
  const authority = url.slice(
    prefix.length,
    path === '' ? undefined : -path.length,
  )
  if (/[/@[\]]/.test(authority)) return undefined
  const separator = authority.lastIndexOf(':')
  if (separator <= 0) return undefined
  const host = authority.slice(0, separator)
  const rawPort = authority.slice(separator + 1)
  if (!DECIMAL.test(rawPort) || !isDNSOnlyServerName(host)) return undefined
  const port = Number(rawPort)
  if (
    !Number.isInteger(port) ||
    port < 1024 ||
    port > 65535 ||
    String(port) !== rawPort ||
    url !== `${prefix}${host}:${port}${path}`
  ) {
    return undefined
  }
  return { host, port }
}

function failContract(): never {
  throw new Error('Invalid KyClash production network profile v2 contract')
}

/**
 * Enforces the complete schema-level and backend-shared semantic profile
 * surface before UI code treats unknown JSON as a production v2 profile.
 * Cryptographic X25519 low-order-point validation remains backend-owned.
 */
export function assertProductionNetworkProfileV2(
  value: unknown,
): asserts value is ProductionNetworkProfileV2 {
  if (
    !hasExactKeys(value, ROOT_KEYS) ||
    value.schema_version !== PRODUCTION_NETWORK_SCHEMA_VERSION ||
    value.carrier_auth_version !== PRODUCTION_NETWORK_CARRIER_AUTH_VERSION ||
    !isIdentifier(value.profile_id) ||
    !isControlPlane(value.control_plane) ||
    typeof value.identity_ref !== 'string' ||
    !value.identity_ref.startsWith('keychain:') ||
    !isIdentifier(value.identity_ref.slice('keychain:'.length)) ||
    !hasExactKeys(value.site, SITE_KEYS) ||
    !isIdentifier(value.site.id) ||
    !isDisplayName(value.site.display_name) ||
    !hasExactKeys(value.tunnel, TUNNEL_KEYS) ||
    !isIntegerInRange(value.tunnel.keepalive_seconds, 1, 65535) ||
    !hasExactKeys(value.transports, TRANSPORTS_KEYS) ||
    value.transports.primary !== 'quic' ||
    !Array.isArray(value.transports.fallbacks) ||
    value.transports.fallbacks.length !== 2 ||
    value.transports.fallbacks[0] !== 'wss' ||
    value.transports.fallbacks[1] !== 'tcp' ||
    !Array.isArray(value.transports.endpoints) ||
    value.transports.endpoints.length !== EXPECTED_TRANSPORTS.length ||
    !hasExactKeys(value.policy, POLICY_KEYS) ||
    !isIntegerInRange(value.policy.connect_timeout_seconds, 1, 300) ||
    !isIntegerInRange(value.policy.health_interval_seconds, 1, 300) ||
    !isIntegerInRange(value.policy.fallback_threshold, 1, 20)
  ) {
    failContract()
  }

  const localKey = decodeCanonicalPublicKey(value.tunnel.local_public_key)
  const peerKey = decodeCanonicalPublicKey(value.tunnel.peer_public_key)
  const local = parseHostPrefixes(value.tunnel.local_addresses)
  const privateRoutes = parsePrivatePrefixes(value.site.private_cidrs)
  if (
    !localKey ||
    !peerKey ||
    localKey === peerKey ||
    !local ||
    !privateRoutes ||
    !sameFamilies(local.families, privateRoutes.families) ||
    local.prefixes.some((host) =>
      privateRoutes.prefixes.some((route) => prefixesOverlap(host, route)),
    )
  ) {
    failContract()
  }

  let expectedHost: string | undefined
  const ports = new Set<number>()
  for (const [index, expectedTransport] of EXPECTED_TRANSPORTS.entries()) {
    const endpoint = parseEndpoint(
      value.transports.endpoints[index],
      expectedTransport,
    )
    if (
      !endpoint ||
      (expectedHost !== undefined && endpoint.host !== expectedHost) ||
      ports.has(endpoint.port)
    ) {
      failContract()
    }
    expectedHost = endpoint.host
    ports.add(endpoint.port)
  }
}
