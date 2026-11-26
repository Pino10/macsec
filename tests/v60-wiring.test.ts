import { describe, expect, it } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { readFileSync } from 'fs'
import { candidateFolders, folderProblem, gunicornArgs, isMobsf } from '../src/main/mobsf'
import { checkPatchId } from '../src/main/patch'

describe('every channel has a handler', () => {
  it('registers a handler for each key of Channels', () => {
    const types = readFileSync(join(__dirname, '../src/shared/types.ts'), 'utf8')
    const block = types.slice(types.indexOf('export interface Channels'))
    const body = block.slice(0, block.indexOf('\n}\n'))
    const keys = [...body.matchAll(/^\s{2}'([a-z0-9-]+:[a-z0-9-]+)'\s*:/gm)].map((m) => m[1])
    expect(keys.length).toBeGreaterThan(50)
    const index = readFileSync(join(__dirname, '../src/main/index.ts'), 'utf8')
    const missing = keys.filter((k) => !new RegExp(`handle(?:Start)?\\(\\s*'${k}'`).test(index))
    expect(missing).toEqual([])
  })
})

describe('patch ids', () => {
  it('accepts only ids MacSec makes', () => {
    expect(checkPatchId('patch-0a1b2c3d')).toBe('patch-0a1b2c3d')
    for (const bad of ['../x', 'patch-../..', 'patch-ZZZZZZZZ', '', 'patch-0a1b2c3d/x']) expect(() => checkPatchId(bad)).toThrow()
  })
})

describe('MobSF folder', () => {
  const make = (venv: boolean): string => {
    const d = mkdtempSync(join(tmpdir(), 'mobsf-'))
    mkdirSync(join(d, 'mobsf/MobSF'), { recursive: true })
    mkdirSync(join(d, 'scripts'), { recursive: true })
    writeFileSync(join(d, 'manage.py'), '')
    writeFileSync(join(d, 'mobsf/MobSF/wsgi.py'), '')
    writeFileSync(join(d, 'scripts/gunicorn_config.py'), '')
    if (venv) {
      mkdirSync(join(d, 'venv/bin'), { recursive: true })
      writeFileSync(join(d, 'venv/bin/gunicorn'), '')
    }
    return d
  }
  it('accepts a full MobSF folder and explains a missing setup', () => {
    expect(folderProblem(make(true))).toBeNull()
    expect(folderProblem(make(false))).toMatch(/setup/i)
  })
  it('refuses relative and unrelated folders', () => {
    expect(folderProblem('relative/path')).not.toBeNull()
    expect(folderProblem(mkdtempSync(join(tmpdir(), 'nomobsf-')))).not.toBeNull()
  })
  it('lists the saved folder first and keeps to the home folder and MacSec', () => {
    const c = candidateFolders('/opt/mobsf', '/Users/x')
    expect(c[0]).toBe('/opt/mobsf')
    expect(c).toContain('/Users/x/Mobile-Security-Framework-MobSF')
    expect(c).toContain('/Users/x/MobSF')
  })
  it('binds to the loopback address only', () => {
    const a = gunicornArgs()
    expect(a).toContain('127.0.0.1:8765')
    expect(a.join(' ')).not.toMatch(/0\.0\.0\.0/)
  })
  it('recognises MobSF by its page and nothing else', async () => {
    const ok = (async () => new Response('<title>Mobile Security Framework - MobSF</title>', { status: 200 })) as unknown as typeof fetch
    const other = (async () => new Response('hello', { status: 200 })) as unknown as typeof fetch
    expect(await isMobsf(8765, ok)).toBe(true)
    expect(await isMobsf(8765, other)).toBe(false)
  })
})
