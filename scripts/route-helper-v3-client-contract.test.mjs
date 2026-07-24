import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = path.join(root, 'macos', 'route-helper', 'client-v3.m')
const header = path.join(root, 'macos', 'route-helper', 'client-v3.h')
const selfTest = path.join(
  root,
  'macos',
  'route-helper',
  'client-v3-self-test.m',
)

test('v3 route-helper bridge has a compilable, fail-closed C ABI', (t) => {
  if (process.platform !== 'darwin') {
    t.skip('Objective-C Foundation bridge requires a macOS runner')
    return
  }

  const temporary = fs.mkdtempSync(
    path.join(os.tmpdir(), 'kyclash-route-helper-v3-client-'),
  )
  try {
    const common = [
      'clang',
      '-fobjc-arc',
      '-fblocks',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-mmacosx-version-min=13.0',
      '-I',
      path.dirname(header),
    ]
    execFileSync('xcrun', [...common, '-fsyntax-only', source], {
      stdio: 'pipe',
    })
    const object = path.join(temporary, 'client-v3.o')
    execFileSync('xcrun', [...common, '-c', source, '-o', object], {
      stdio: 'pipe',
    })
    const executable = path.join(temporary, 'client-v3-self-test')
    execFileSync(
      'xcrun',
      [
        ...common,
        '-framework',
        'Foundation',
        '-o',
        executable,
        selfTest,
        object,
      ],
      { stdio: 'pipe' },
    )
    const output = execFileSync(executable, [], { encoding: 'utf8' })
    assert.match(output, /route_helper_v3_client_self_test_ok/u)
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true })
  }
})
