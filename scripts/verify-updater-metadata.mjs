import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sampleMode = process.argv.includes('--sample')
const positional = process.argv
  .slice(2)
  .filter((argument) => argument !== '--sample')
const metadataPath = path.resolve(
  root,
  positional[0] ?? 'docs/release/examples/latest.json',
)
const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'))
const failures = []
const requireInvariant = (condition, message) => {
  if (!condition) failures.push(message)
}
const semver = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const commit = /^[0-9a-f]{40}$/
const sha256 = /^[0-9a-f]{64}$/
const assetUrl =
  /^https:\/\/github\.com\/kysion\/kyclash\/releases\/download\/v([^/]+)\/([^/]+)$/
const hasOnlyKeys = (value, expected) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join('\0') === [...expected].sort().join('\0')
const compareSemver = (left, right) => {
  const parse = (value) => value.split('-', 1)[0].split('.').map(Number)
  const leftParts = parse(left)
  const rightParts = parse(right)
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] < rightParts[index] ? -1 : 1
    }
  }
  return left === right ? 0 : left.includes('-') ? -1 : 1
}
const isTauriSignature = (value) => {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value) ||
    value.length % 4 !== 0
  ) {
    return false
  }
  const decoded = Buffer.from(value, 'base64').toString('utf8')
  return (
    decoded.startsWith('untrusted comment:') &&
    decoded.includes('\ntrusted comment:')
  )
}

requireInvariant(semver.test(metadata.version), 'version must be semver')
requireInvariant(
  hasOnlyKeys(metadata, [
    'version',
    'notes',
    'pub_date',
    'platforms',
    'kyclash',
  ]),
  'metadata contains missing or unknown top-level fields',
)
requireInvariant(
  typeof metadata.notes === 'string' && metadata.notes.length > 0,
  'notes must be non-empty',
)
requireInvariant(
  typeof metadata.pub_date === 'string' &&
    Number.isFinite(Date.parse(metadata.pub_date)),
  'pub_date must be RFC 3339 compatible',
)
requireInvariant(
  metadata.kyclash?.schema_version === 1,
  'kyclash.schema_version must be 1',
)
requireInvariant(
  hasOnlyKeys(metadata.kyclash, [
    'schema_version',
    'source_commit',
    'rollback_version',
    'channel',
    'sample',
  ]),
  'kyclash metadata contains missing or unknown fields',
)
requireInvariant(
  commit.test(metadata.kyclash?.source_commit ?? ''),
  'kyclash.source_commit must be a full lowercase Git commit',
)
requireInvariant(
  semver.test(metadata.kyclash?.rollback_version ?? ''),
  'kyclash.rollback_version must be semver',
)
requireInvariant(
  ['stable', 'candidate', 'internal'].includes(metadata.kyclash?.channel),
  'kyclash.channel is invalid',
)
requireInvariant(
  typeof metadata.kyclash?.sample === 'boolean',
  'kyclash.sample must be boolean',
)

const platformNames = Object.keys(metadata.platforms ?? {})
requireInvariant(
  platformNames.length === 1 && platformNames[0] === 'darwin-aarch64-app',
  'only the locked darwin-aarch64-app platform is currently allowed',
)
for (const [platform, artifact] of Object.entries(metadata.platforms ?? {})) {
  requireInvariant(
    hasOnlyKeys(artifact, ['url', 'signature', 'sha256', 'size']),
    `${platform} contains missing or unknown fields`,
  )
  const match =
    typeof artifact.url === 'string' ? artifact.url.match(assetUrl) : null
  requireInvariant(
    match?.[1] === metadata.version,
    `${platform} URL tag must match version`,
  )
  requireInvariant(
    match?.[2] === `KyClash_${metadata.version}_aarch64.app.tar.gz`,
    `${platform} asset name must be canonical`,
  )
  requireInvariant(
    isTauriSignature(artifact.signature),
    `${platform} signature must contain a base64-encoded Tauri signature`,
  )
  requireInvariant(
    sha256.test(artifact.sha256 ?? ''),
    `${platform} sha256 is invalid`,
  )
  requireInvariant(
    Number.isSafeInteger(artifact.size) && artifact.size > 0,
    `${platform} size must be a positive integer`,
  )
}

if (sampleMode) {
  requireInvariant(
    metadata.kyclash?.sample === true,
    'sample metadata must set sample=true',
  )
} else {
  requireInvariant(
    metadata.kyclash?.sample === false,
    'release metadata must set sample=false',
  )
  requireInvariant(
    metadata.kyclash?.source_commit !== '0'.repeat(40),
    'release metadata cannot use the sample commit',
  )
  requireInvariant(
    !Object.values(metadata.platforms ?? {}).some(
      (artifact) => artifact.sha256 === '0'.repeat(64),
    ),
    'release metadata cannot use the sample checksum',
  )
  requireInvariant(
    process.env.KYCLASH_RELEASE_VERSION === metadata.version,
    'KYCLASH_RELEASE_VERSION must match metadata version',
  )
  requireInvariant(
    process.env.KYCLASH_RELEASE_COMMIT === metadata.kyclash?.source_commit,
    'KYCLASH_RELEASE_COMMIT must match metadata source_commit',
  )
  if (
    semver.test(metadata.version) &&
    semver.test(metadata.kyclash?.rollback_version ?? '')
  ) {
    requireInvariant(
      compareSemver(metadata.kyclash.rollback_version, metadata.version) < 0,
      'rollback_version must be older than the release version',
    )
  }
}

if (failures.length > 0) {
  console.error('KyClash updater metadata validation failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log(
  `KyClash updater metadata validated: ${path.relative(root, metadataPath)}`,
)
