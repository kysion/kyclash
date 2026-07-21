import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const templatePath = path.join(
  root,
  'config',
  'tauri.github-updater.template.json',
)
const targetRoot = path.join(root, 'target')
const outputPath = path.resolve(
  process.env.KYCLASH_UPDATER_CONFIG_OUTPUT ??
    path.join(targetRoot, 'kyclash-updater', 'tauri.github-updater.conf.json'),
)
const publicKey = process.env.KYCLASH_UPDATER_PUBLIC_KEY

if (!publicKey) {
  throw new Error('KYCLASH_UPDATER_PUBLIC_KEY is required')
}
if (!outputPath.startsWith(`${targetRoot}${path.sep}`)) {
  throw new Error('updater config output must remain under target/')
}

let decodedKey
try {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey) || publicKey.length % 4 !== 0) {
    throw new Error('invalid base64')
  }
  decodedKey = Buffer.from(publicKey, 'base64').toString('utf8')
} catch {
  throw new Error('KYCLASH_UPDATER_PUBLIC_KEY must be base64 encoded')
}
if (
  !decodedKey.startsWith('untrusted comment: minisign public key') ||
  decodedKey.includes('PRIVATE KEY') ||
  !/\nRWQ[A-Za-z0-9+/]{53}=?(?:\n|$)/.test(decodedKey)
) {
  throw new Error(
    'KYCLASH_UPDATER_PUBLIC_KEY is not a Tauri minisign public key',
  )
}

const template = fs.readFileSync(templatePath, 'utf8')
const placeholder = '__KYCLASH_UPDATER_PUBLIC_KEY__'
if (template.split(placeholder).length !== 2) {
  throw new Error(
    'updater config template must contain exactly one placeholder',
  )
}
const config = JSON.parse(template.replace(placeholder, publicKey))

fs.mkdirSync(path.dirname(outputPath), { recursive: true })
fs.writeFileSync(outputPath, `${JSON.stringify(config, null, 2)}\n`, {
  mode: 0o644,
  flag: 'wx',
})
console.log(path.relative(root, outputPath))
