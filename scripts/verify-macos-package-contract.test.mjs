import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  assertExactInventory,
  validateLabOverlay,
  validatePackageInfo,
  writeExactNoReplace,
} from './verify-macos-package.mjs'

const packageInfo = ({
  identifier = 'net.kysion.kyclash',
  scripts = '',
} = {}) =>
  Buffer.from(`<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="${identifier}" postinstall-action="none" version="2.5.3" format-version="2" generator-version="test" install-location="/Applications" auth="root">
  <payload numberOfFiles="1" installKBytes="1"/>
  <bundle path="./KyClash.app" id="net.kysion.kyclash" CFBundleShortVersionString="2.5.3" CFBundleVersion="2.5.3"/>
  ${scripts}
</pkg-info>`)

test('PackageInfo is bound to the exact KyClash component contract', () => {
  assert.equal(
    validatePackageInfo(packageInfo()).identifier,
    'net.kysion.kyclash',
  )
  assert.throws(
    () => validatePackageInfo(packageInfo({ identifier: 'example.invalid' })),
    /identifier mismatch/u,
  )
  assert.throws(
    () => validatePackageInfo(packageInfo({ scripts: '<scripts/>' })),
    /installer scripts/u,
  )
})

test('App/PKG inventory comparison rejects extra content and mode drift', () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-package-inventory-'),
  )
  try {
    const expected = path.join(directory, 'expected')
    const actual = path.join(directory, 'actual')
    fs.mkdirSync(expected, { mode: 0o700 })
    fs.mkdirSync(actual, { mode: 0o700 })
    fs.writeFileSync(path.join(expected, 'resource'), 'same\n', { mode: 0o644 })
    fs.writeFileSync(path.join(actual, 'resource'), 'same\n', { mode: 0o644 })
    assert.doesNotThrow(() =>
      assertExactInventory(expected, actual, 'test inventory'),
    )
    fs.chmodSync(path.join(actual, 'resource'), 0o600)
    assert.throws(
      () => assertExactInventory(expected, actual, 'test inventory'),
      /inventory differs/u,
    )
    fs.chmodSync(path.join(actual, 'resource'), 0o644)
    fs.writeFileSync(path.join(actual, 'extra'), 'extra\n', { mode: 0o644 })
    assert.throws(
      () => assertExactInventory(expected, actual, 'test inventory'),
      /inventory differs/u,
    )
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

test('lab overlay schema rejects every unreviewed top-level or bundle field', () => {
  const staged = '/private/tmp/kyclash-lab/public/resources'
  const base = {
    $schema: '../node_modules/@tauri-apps/cli/config.schema.json',
    bundle: {
      externalBin: ['sidecar/verge-mihomo'],
      macOS: { files: { 'Resources/helper': 'helpers/helper' } },
    },
  }
  const overlay = {
    $schema: base.$schema,
    bundle: {
      externalBin: base.bundle.externalBin,
      macOS: base.bundle.macOS,
      resources: { [staged]: 'resources' },
    },
  }
  assert.equal(validateLabOverlay(overlay, staged, base), true)
  assert.throws(
    () => validateLabOverlay({ ...overlay, plugins: {} }, staged, base),
    /unexpected fields/u,
  )
  assert.throws(
    () =>
      validateLabOverlay(
        { ...overlay, bundle: { ...overlay.bundle, targets: ['dmg'] } },
        staged,
        base,
      ),
    /unexpected fields/u,
  )
})

test('verifier output is create-only and never follows a symlink', () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-verifier-output-'),
  )
  try {
    const output = path.join(directory, 'result.txt')
    writeExactNoReplace(
      output,
      Buffer.from('result\n'),
      0o600,
      directory,
      'test result',
    )
    assert.doesNotThrow(() =>
      writeExactNoReplace(
        output,
        Buffer.from('result\n'),
        0o600,
        directory,
        'test result',
      ),
    )
    assert.throws(
      () =>
        writeExactNoReplace(
          output,
          Buffer.from('different\n'),
          0o600,
          directory,
          'test result',
        ),
      /different content/u,
    )
    const target = path.join(directory, 'target.txt')
    const link = path.join(directory, 'link.txt')
    fs.writeFileSync(target, 'target\n', { mode: 0o600 })
    fs.symlinkSync(target, link)
    assert.throws(
      () =>
        writeExactNoReplace(
          link,
          Buffer.from('target\n'),
          0o600,
          directory,
          'test link',
        ),
      /symlink/u,
    )
  } finally {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})
