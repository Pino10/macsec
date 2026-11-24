/** 1.33.2: the mobile session must record the reviewer it ran with. */
import { afterAll, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { startMobileScan } from '../src/main/mobilescan'
import { readSession } from '../src/main/sessions'

const root = mkdtempSync(join(tmpdir(), 'macsec-rev-'))
afterAll(() => rmSync(root, { recursive: true, force: true }))

describe('the mobile session reviewer', () => {
  it('is saved before the scan starts, so the UI and the AI report agree', () => {
    setRoot(root)
    const apk = join(root, 'app.apk')
    writeFileSync(apk, 'not a real zip')
    const info = startMobileScan({ path: apk, reviewer: 'model', online: false })
    expect(readSession(info.id).reviewer).toBe('model')
  })
})
