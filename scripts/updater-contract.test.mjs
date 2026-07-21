import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const targetRoot = path.join(root, 'target')
const runNode = (commandArguments, environment = {}) =>
  execFileSync(process.execPath, commandArguments, {
    cwd: root,
    env: { ...process.env, ...environment },
    stdio: 'pipe',
  })

test('prepares only the owned GitHub updater override', () => {
  fs.mkdirSync(targetRoot, { recursive: true })
  const directory = fs.mkdtempSync(
    path.join(targetRoot, 'updater-config-contract-'),
  )
  const output = path.join(directory, 'updater.json')
  const publicKey = Buffer.from(
    'untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n',
  ).toString('base64')

  runNode(['scripts/prepare-github-updater-config.mjs'], {
    KYCLASH_UPDATER_PUBLIC_KEY: publicKey,
    KYCLASH_UPDATER_CONFIG_OUTPUT: output,
  })
  const config = JSON.parse(fs.readFileSync(output, 'utf8'))
  assert.equal(config.bundle.createUpdaterArtifacts, true)
  assert.deepEqual(config.plugins.updater.endpoints, [
    'https://github.com/kysion/kyclash/releases/latest/download/latest.json',
  ])
  assert.equal(config.plugins.updater.pubkey, publicKey)
  fs.rmSync(directory, { recursive: true })
})

test('builds strict non-publishable local metadata', () => {
  fs.mkdirSync(targetRoot, { recursive: true })
  const directory = fs.mkdtempSync(
    path.join(targetRoot, 'updater-metadata-contract-'),
  )
  const artifact = path.join(directory, 'KyClash_2.5.4_aarch64.app.tar.gz')
  const signature = `${artifact}.sig`
  const output = path.join(directory, 'latest.json')
  fs.writeFileSync(artifact, 'synthetic updater artifact')
  fs.writeFileSync(
    signature,
    'untrusted comment: synthetic test signature\nAAAA\ntrusted comment: synthetic test signature\nAAAA\n',
  )
  const environment = {
    KYCLASH_RELEASE_VERSION: '2.5.4',
    KYCLASH_RELEASE_COMMIT: '1'.repeat(40),
    KYCLASH_ROLLBACK_VERSION: '2.5.3',
    KYCLASH_UPDATER_ARTIFACT: artifact,
    KYCLASH_UPDATER_METADATA_OUTPUT: output,
  }

  runNode(['scripts/build-updater-metadata.mjs'], environment)
  runNode(['scripts/verify-updater-metadata.mjs', output], environment)
  const metadata = JSON.parse(fs.readFileSync(output, 'utf8'))
  assert.equal(metadata.kyclash.sample, false)
  assert.equal(metadata.platforms['darwin-aarch64-app'].size, 26)
  assert.notEqual(
    metadata.platforms['darwin-aarch64-app'].sha256,
    '0'.repeat(64),
  )
  fs.rmSync(directory, { recursive: true })
})

test('sample metadata cannot pass release validation', () => {
  assert.throws(() =>
    runNode(['scripts/verify-updater-metadata.mjs'], {
      KYCLASH_RELEASE_VERSION: '0.0.0',
      KYCLASH_RELEASE_COMMIT: '0'.repeat(40),
    }),
  )
})
