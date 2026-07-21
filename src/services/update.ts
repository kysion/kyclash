import {
  check,
  type CheckOptions,
  type Update,
} from '@tauri-apps/plugin-updater'

import { version as appVersion } from '@root/package.json'

// Enable only together with KyClash-owned endpoints, signing key, and backend
// APP_UPDATES_ENABLED. Keeping the frontend gate prevents noisy empty-endpoint
// checks while the backend gate also protects against cached upstream updates.
export const APP_UPDATES_ENABLED = false

type VersionParts = {
  main: number[]
  pre: (number | string)[]
}

const SEMVER_FULL_REGEX =
  /^\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const SEMVER_SEARCH_REGEX =
  /v?\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?/i

const normalizeVersion = (input: string | null | undefined): string | null => {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null
  return trimmed.replace(/^v/i, '')
}

const ensureSemver = (input: string | null | undefined): string | null => {
  const normalized = normalizeVersion(input)
  if (!normalized) return null
  return SEMVER_FULL_REGEX.test(normalized) ? normalized : null
}

const extractSemver = (input: string | null | undefined): string | null => {
  if (typeof input !== 'string') return null
  const match = input.match(SEMVER_SEARCH_REGEX)
  if (!match) return null
  return normalizeVersion(match[0])
}

const splitVersion = (version: string | null): VersionParts | null => {
  if (!version) return null
  const [mainPart, preRelease] = version.split('-')
  const main = mainPart
    .split('.')
    .map((part) => Number.parseInt(part, 10))
    .map((num) => (Number.isNaN(num) ? 0 : num))

  const pre =
    preRelease?.split('.').map((token) => {
      const numeric = Number.parseInt(token, 10)
      return Number.isNaN(numeric) ? token : numeric
    }) ?? []

  return { main, pre }
}

const compareVersionParts = (a: VersionParts, b: VersionParts): number => {
  const length = Math.max(a.main.length, b.main.length)
  for (let i = 0; i < length; i += 1) {
    const diff = (a.main[i] ?? 0) - (b.main[i] ?? 0)
    if (diff !== 0) return diff > 0 ? 1 : -1
  }

  if (a.pre.length === 0 && b.pre.length === 0) return 0
  if (a.pre.length === 0) return 1
  if (b.pre.length === 0) return -1

  const preLen = Math.max(a.pre.length, b.pre.length)
  for (let i = 0; i < preLen; i += 1) {
    const aToken = a.pre[i]
    const bToken = b.pre[i]
    if (aToken === undefined) return -1
    if (bToken === undefined) return 1

    if (typeof aToken === 'number' && typeof bToken === 'number') {
      if (aToken > bToken) return 1
      if (aToken < bToken) return -1
      continue
    }

    if (typeof aToken === 'number') return -1
    if (typeof bToken === 'number') return 1

    if (aToken > bToken) return 1
    if (aToken < bToken) return -1
  }

  return 0
}

const compareVersions = (a: string | null, b: string | null): number | null => {
  const partsA = splitVersion(a)
  const partsB = splitVersion(b)
  if (!partsA || !partsB) return null
  return compareVersionParts(partsA, partsB)
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null

const hasExactKeys = (
  value: Record<string, unknown>,
  expected: string[],
): boolean =>
  Object.keys(value).sort().join('\0') === [...expected].sort().join('\0')

const isOwnedUpdateMetadata = (update: Update): boolean => {
  const raw = asRecord(update.rawJson)
  if (
    !raw ||
    !hasExactKeys(raw, [
      'version',
      'notes',
      'pub_date',
      'platforms',
      'kyclash',
    ]) ||
    raw.version !== update.version ||
    typeof raw.notes !== 'string' ||
    raw.notes.trim().length === 0 ||
    typeof raw.pub_date !== 'string' ||
    !Number.isFinite(Date.parse(raw.pub_date))
  ) {
    return false
  }

  const platforms = asRecord(raw.platforms)
  const policy = asRecord(raw.kyclash)
  if (
    !platforms ||
    !hasExactKeys(platforms, ['darwin-aarch64-app']) ||
    !policy ||
    !hasExactKeys(policy, [
      'schema_version',
      'source_commit',
      'rollback_version',
      'channel',
      'sample',
    ])
  ) {
    return false
  }

  const artifact = asRecord(platforms['darwin-aarch64-app'])
  const expectedUrl = `https://github.com/kysion/kyclash/releases/download/v${update.version}/KyClash_${update.version}_aarch64.app.tar.gz`
  const rollbackVersion =
    typeof policy.rollback_version === 'string'
      ? ensureSemver(policy.rollback_version)
      : null
  const version = ensureSemver(update.version)
  return Boolean(
    artifact &&
      hasExactKeys(artifact, ['url', 'signature', 'sha256', 'size']) &&
      artifact.url === expectedUrl &&
      typeof artifact.signature === 'string' &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(artifact.signature) &&
      artifact.signature.length % 4 === 0 &&
      typeof artifact.sha256 === 'string' &&
      /^[0-9a-f]{64}$/.test(artifact.sha256) &&
      Number.isSafeInteger(artifact.size) &&
      Number(artifact.size) > 0 &&
      policy.schema_version === 1 &&
      policy.sample === false &&
      typeof policy.source_commit === 'string' &&
      /^(?!0{40})[0-9a-f]{40}$/.test(policy.source_commit) &&
      typeof policy.channel === 'string' &&
      ['stable', 'candidate', 'internal'].includes(policy.channel) &&
      rollbackVersion &&
      version &&
      compareVersions(rollbackVersion, version) === -1,
  )
}

const resolveRemoteVersion = (update: Update): string | null => {
  const primary = ensureSemver(update.version)
  if (primary) return primary

  const fallbackPrimary = extractSemver(update.version)
  if (fallbackPrimary) return fallbackPrimary

  const raw = update.rawJson ?? {}
  const rawVersion = ensureSemver(
    typeof raw.version === 'string' ? raw.version : null,
  )
  if (rawVersion) return rawVersion

  const tagVersion = extractSemver(
    typeof raw.tag_name === 'string' ? raw.tag_name : null,
  )
  if (tagVersion) return tagVersion

  const nameVersion = extractSemver(
    typeof raw.name === 'string' ? raw.name : null,
  )
  if (nameVersion) return nameVersion

  return null
}

const localVersionNormalized = normalizeVersion(appVersion)

export const checkUpdateSafe = async (
  options?: CheckOptions,
): Promise<Update | null> => {
  if (!APP_UPDATES_ENABLED) return null

  const result = await check({ ...(options ?? {}), allowDowngrades: false })
  if (!result) return null

  if (!isOwnedUpdateMetadata(result)) {
    try {
      await result.close()
    } catch {
      // The rejected metadata is intentionally not echoed to logs.
    }
    console.warn('[updater] rejected non-KyClash update metadata')
    return null
  }

  const remoteVersion = resolveRemoteVersion(result)
  const comparison = compareVersions(remoteVersion, localVersionNormalized)

  if (comparison !== null && comparison <= 0) {
    try {
      await result.close()
    } catch (err) {
      console.warn('[updater] failed to close stale update resource', err)
    }
    return null
  }

  return result
}

export type { CheckOptions }
