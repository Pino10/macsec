/** 1.28: a real, redistributable APK fixture and the decode path (zip, AndroidManifest.xml, dex). */
import { describe, expect, it } from 'vitest'
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { join } from 'path'
import { inflateRawSync } from 'zlib'

const APK = join(__dirname, 'fixtures', 'mobile', 'red-screen.apk')
const EXPECTED = '5d1131f6c1b93c6bee9731d1b08d60b82e1162e809c2a8595981660a64a0cbbd'

interface Entry {
  name: string
  method: number
  size: number
  at: number
}

function entries(buf: Buffer): Entry[] {
  let eocd = -1
  for (let i = buf.length - 22; i >= 0; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('No end of central directory')
  const count = buf.readUInt16LE(eocd + 10)
  let p = buf.readUInt32LE(eocd + 16)
  const out: Entry[] = []
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Bad central directory')
    const method = buf.readUInt16LE(p + 10)
    const size = buf.readUInt32LE(p + 20)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const at = buf.readUInt32LE(p + 42)
    out.push({ name: buf.slice(p + 46, p + 46 + nameLen).toString('utf8'), method, size, at })
    p += 46 + nameLen + extraLen + commentLen
  }
  return out
}

function readEntry(buf: Buffer, e: Entry): Buffer {
  if (buf.readUInt32LE(e.at) !== 0x04034b50) throw new Error('Bad local header')
  const nameLen = buf.readUInt16LE(e.at + 26)
  const extraLen = buf.readUInt16LE(e.at + 28)
  const start = e.at + 30 + nameLen + extraLen
  const raw = buf.slice(start, start + e.size)
  return e.method === 0 ? raw : inflateRawSync(raw)
}

describe('the mobile fixture', () => {
  const apk = readFileSync(APK)
  it('is the pinned, real APK, under 10 KB and shipping its own licence note', () => {
    expect(createHash('sha256').update(apk).digest('hex')).toBe(EXPECTED)
    expect(apk.length).toBe(8649)
    const readme = readFileSync(join(__dirname, 'fixtures', 'mobile', 'README.md'), 'utf8')
    expect(readme).toContain('org.vi_server.red_screen')
    expect(readme).toContain('MIT')
    expect(readme).toContain('SHA-256')
  })
  it('decodes the zip, the binary manifest and the dex header', () => {
    const all = entries(apk)
    const manifest = all.find((e) => e.name === 'AndroidManifest.xml')
    expect(manifest, 'AndroidManifest.xml').toBeTruthy()
    const xml = readEntry(apk, manifest!)
    // Android binary XML starts with the RES_XML_TYPE chunk.
    expect(xml.readUInt16LE(0)).toBe(0x0003)
    expect(xml.readUInt16LE(2)).toBe(0x0008)
    // The package name is stored as UTF-16LE in the string pool.
    expect(xml.includes(Buffer.from('org.vi_server.red_screen', 'utf16le'))).toBe(true)
    const dex = all.find((e) => e.name === 'classes.dex')
    expect(dex, 'classes.dex').toBeTruthy()
    expect(readEntry(apk, dex!).slice(0, 4).toString('latin1')).toBe('dex\n')
  })
})
