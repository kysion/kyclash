import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const targetRoot = path.join(root, 'target')
const version = process.env.KYCLASH_RELEASE_VERSION
const sourceCommit = process.env.KYCLASH_RELEASE_COMMIT
const rollbackVersion = process.env.KYCLASH_ROLLBACK_VERSION
const channel = process.env.KYCLASH_UPDATE_CHANNEL ?? 'internal'
const artifactInput = process.env.KYCLASH_UPDATER_ARTIFACT
const artifactPath = path.resolve(artifactInput ?? '')
const signaturePath = path.resolve(
  process.env.KYCLASH_UPDATER_SIGNATURE ?? `${artifactPath}.sig`,
)
const outputPath = path.resolve(
  process.env.KYCLASH_UPDATER_METADATA_OUTPUT ??
    path.join(targetRoot, 'kyclash-updater', 'latest.json'),
)

if (!version || !sourceCommit || !rollbackVersion || !artifactInput) {
  throw new Error(
    'KYCLASH_RELEASE_VERSION, KYCLASH_RELEASE_COMMIT, KYCLASH_ROLLBACK_VERSION, and KYCLASH_UPDATER_ARTIFACT are required',
  )
}
if (!outputPath.startsWith(`${targetRoot}${path.sep}`)) {
  throw new Error('updater metadata output must remain under target/')
}
const expectedName = `KyClash_${version}_aarch64.app.tar.gz`
if (path.basename(artifactPath) !== expectedName) {
  throw new Error(`updater artifact must be named ${expectedName}`)
}

const artifact = fs.readFileSync(artifactPath)
const signature = fs.readFileSync(signaturePath)
const metadata = {
  version,
  notes: process.env.KYCLASH_RELEASE_NOTES ?? `KyClash ${version}`,
  pub_date: process.env.KYCLASH_RELEASE_DATE ?? new Date().toISOString(),
  platforms: {
    'darwin-aarch64-app': {
      url: `https://github.com/kysion/kyclash/releases/download/v${version}/${expectedName}`,
      signature: signature.toString('base64'),
      sha256: crypto.createHash('sha256').update(artifact).digest('hex'),
      size: artifact.length,
    },
  },
  kyclash: {
    schema_version: 1,
    source_commit: sourceCommit,
    rollback_version: rollbackVersion,
    channel,
    sample: false,
  },
}

fs.mkdirSync(path.dirname(outputPath), { recursive: true })
fs.writeFileSync(outputPath, `${JSON.stringify(metadata, null, 2)}\n`, {
  mode: 0o644,
  flag: 'wx',
})
console.log(path.relative(root, outputPath))
