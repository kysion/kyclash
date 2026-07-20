import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const encodedKey = process.env.APPLE_NOTARY_KEY_BASE64
const runnerTemp = process.env.RUNNER_TEMP
const githubEnv = process.env.GITHUB_ENV

if (!process.env.CI || !encodedKey || !runnerTemp || !githubEnv) {
  throw new Error(
    'CI, APPLE_NOTARY_KEY_BASE64, RUNNER_TEMP, and GITHUB_ENV are required',
  )
}

const keyBytes = Buffer.from(encodedKey, 'base64')
if (
  keyBytes.length < 64 ||
  !keyBytes.toString('utf8').includes('BEGIN PRIVATE KEY')
) {
  throw new Error('APPLE_NOTARY_KEY_BASE64 is not a valid private key payload')
}

const keyPath = path.join(runnerTemp, 'AuthKey_KyClash.p8')
fs.writeFileSync(keyPath, keyBytes, { mode: 0o600, flag: 'wx' })
fs.appendFileSync(githubEnv, `APPLE_NOTARY_KEY_PATH=${keyPath}\n`)
