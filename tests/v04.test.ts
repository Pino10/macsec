/**
 * 0.4: mobile apps, cloud accounts, servers, WordPress, live progress and the optional tools list.
 *
 * Fixtures are real tool output where the tool can run here: mobsfscan 1.1.0 and Androguard 4.1.4
 * on sample apps, naabu 2.3.5 and Nmap on open local ports, the headers of a real Mach-O (ruff, MIT)
 * and two ELF files built here from elf-source.c, with and without hardening. ScoutSuite, PMapper and WPScan need a cloud account or a WordPress site:
 * their fixtures follow the tools' own output code (ScoutSuite's result_encoder and a real rule
 * file, PMapper's Finding.as_dictionary, WPScan's JSON views).
 */
import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { checkAndroidManifest, checkInfoPlist, hardening, hardeningFindings, parseMobsfscan } from '../src/main/scanners/mobile'
import { parseNaabu, parseNmapXml, parsePmapper, parseScoutSuite, parseWpscan, portFindings } from '../src/main/scanners/infra'
import { beginOp, endOp, friendly, percentOf, runTool } from '../src/main/engine'
import { mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { mobileKind, findFiles } from '../src/main/mobilescan'
import { optionalTools } from '../src/main/optional'
import { CATALOG } from '../src/main/toolbox'
import { summaryPrompt } from '../src/main/aisummary'

const fx = (n: string): string => readFileSync(join(__dirname, 'fixtures', n), 'utf8')
const bin = (n: string): Buffer => readFileSync(join(__dirname, 'fixtures', n))

describe('live progress', () => {
  it('reads percentages from tool output', () => {
    expect(percentOf('{"duration":"0:00:15","errors":"0","hosts":"1","matched":"2","percent":"37","requests":"1200"}')).toBe(37)
    expect(percentOf('Scanning... 82% done')).toBe(82)
    expect(percentOf('[12/48] templates')).toBe(25)
    expect(percentOf('nothing here')).toBeNull()
    expect(percentOf('status 404%')).toBeNull()
  })
  it('puts JSON progress into words', () => {
    expect(friendly('{"duration":"0:03:07","errors":"3","hosts":"1","matched":"4","percent":"62","requests":"18233","rps":"25","templates":"7811"}')).toBe('62% done, 7,811 checks, 18,233 requests sent, 4 found so far, 3 timeouts')
    expect(friendly('{"ip":"127.0.0.1","port":3306,"protocol":"tcp"}')).toBe('Open: 127.0.0.1:3306')
    expect(friendly('[INF] Templates loaded for current scan: 7811')).toBe('Templates loaded for current scan: 7811')
  })
  it('passes each line a tool prints to the window as it happens', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ms-live-'))
    const op = beginOp('live-test')
    const seen: string[] = []
    await runTool({ name: 'sh', bin: '/bin/sh', absolute: true, args: ['-c', 'echo "[1/4] reading" >&2; sleep 0.2; printf "\\033[32m50%% done\\033[0m\\n" >&2; echo out'], timeoutMs: 10_000 }, op, dir, (l) => seen.push(l))
    endOp('live-test')
    expect(seen).toEqual(['[1/4] reading', '50% done'])
    expect(seen.map(percentOf)).toEqual([25, 50])
  })
})

describe('mobsfscan', () => {
  const found = parseMobsfscan(fx('mobsfscan.json'), '/tmp/mob')
  it('turns its rules into findings with files and lines', () => {
    const ecb = found.find((f) => f.title.includes('ECB'))!
    expect(ecb).toMatchObject({ tool: 'mobsfscan', category: 'mobile', severity: 'high', file: 'app/src/main/java/com/demo/MainActivity.java', line: 23, cwe: 'CWE-327' })
    expect(ecb.description).toMatch(/OWASP Mobile: M5/)
    expect(found.find((f) => f.file === 'ios/Demo/Info.plist')?.severity).toBe('high')
  })
  it('keeps "the app does not do X" suggestions as info', () => {
    expect(found.filter((f) => !f.file).every((f) => f.severity === 'info')).toBe(true)
    expect(found.find((f) => f.title.includes('logs'))?.severity).toBe('low')
  })
})

describe('Android manifest', () => {
  it('finds risky settings and exported parts', () => {
    const f = checkAndroidManifest(fx('AndroidManifest.xml'))
    const t = f.map((x) => x.title).join('\n')
    expect(t).toMatch(/debuggable/)
    expect(t).toMatch(/unencrypted HTTP/)
    expect(t).toMatch(/minimum API 19/)
    expect(t).toMatch(/ DeepLinkActivity/)
    expect(f.find((x) => x.title.includes('NotesProvider'))?.severity).toBe('high')
    // The launcher and a permission-protected service are fine.
    expect(t).not.toMatch(/MainActivity|SafeService/)
    expect(f.find((x) => x.title.includes('sensitive'))?.description).toContain('READ_SMS')
  })
  it('reads the manifest Androguard decodes from a real .apk', () => {
    const f = checkAndroidManifest(fx('androguard-manifest.xml'))
    expect(f.map((x) => x.title)).toEqual(expect.arrayContaining(['The app is built as debuggable', 'Runs on very old Android (minimum API 9)']))
    expect(f.some((x) => /backup/.test(x.title))).toBe(false)
  })
  it('leaves out what mobsfscan already reported', () => {
    const f = checkAndroidManifest(fx('AndroidManifest.xml'), 'AndroidManifest.xml', new Set(['android_manifest_debugging_enabled', 'android_manifest_usescleartext']))
    expect(f.some((x) => /debuggable|unencrypted/.test(x.title))).toBe(false)
    expect(f.some((x) => /DeepLink/.test(x.title))).toBe(true)
  })
})

describe('iOS Info.plist', () => {
  it('finds App Transport Security turned off, file sharing and URL schemes', () => {
    const f = checkInfoPlist(fx('Info.plist'))
    expect(f.find((x) => x.title.includes('App Transport Security'))?.severity).toBe('high')
    expect(f.some((x) => x.title.includes('Finder'))).toBe(true)
    expect(f.find((x) => x.title.includes('demoapp://'))?.severity).toBe('info')
  })
})

describe('binary hardening', () => {
  it('reads a real Mach-O executable', () => {
    const h = hardening(bin('macho-head.bin'))
    expect(h).toMatchObject({ format: 'mach-o', pie: true, encrypted: false })
  })
  it('reads real ELF executables, hardened and not (built from elf-source.c with gcc)', () => {
    expect(hardening(bin('elf-hardened.bin'))).toMatchObject({ format: 'elf', pie: true, nx: true, canary: true, relro: 'partial', sharedLib: false })
    expect(hardening(bin('elf-weak.bin'))).toMatchObject({ format: 'elf', pie: false, nx: false, canary: false, relro: 'none' })
    const f = hardeningFindings([{ file: 'bin/weak', h: hardening(bin('elf-weak.bin')) }])
    expect(f.map((x) => x.severity)).toEqual(['high', 'medium', 'low', 'low'])
  })
  it('groups missing protections into one finding each', () => {
    const f = hardeningFindings([
      { file: 'lib/arm64-v8a/libold.so', h: { format: 'elf', pie: true, sharedLib: true, canary: false, nx: false, relro: 'none' } },
      { file: 'lib/x86/libold.so', h: { format: 'elf', pie: true, sharedLib: true, canary: false, nx: false, relro: 'none' } },
      { file: 'lib/arm64-v8a/libgood.so', h: { format: 'elf', pie: true, sharedLib: true, canary: true, nx: true, relro: 'partial' } }
    ])
    expect(f.map((x) => [x.severity, x.title])).toEqual([
      ['high', 'Compiled code with an executable stack (2 files)'],
      ['low', 'Compiled code without stack protection (2 files)'],
      ['low', 'Native libraries without RELRO (2 files)']
    ])
  })
  it('ignores files that are not compiled code', () => {
    expect(hardening(Buffer.from('#!/bin/sh\necho hi')).format).toBe('unknown')
  })
})

describe('mobile check', () => {
  it('knows a source folder from a built app', () => {
    expect(mobileKind('/x/App.apk')).toBe('apk')
    expect(mobileKind('/x/App.IPA')).toBe('ipa')
    expect(mobileKind('/x/app')).toBe('source')
  })
  it('finds settings files and skips build output', () => {
    const files = findFiles(join(__dirname, 'fixtures'), (n) => n === 'Info.plist')
    expect(files.map((f) => f.split('/').pop())).toEqual(['Info.plist'])
  })
})

describe('ports', () => {
  it('reads naabu and Nmap output', () => {
    const open = parseNaabu(fx('naabu.jsonl'))
    expect(open).toEqual([{ host: '127.0.0.1', port: 3306 }])
    const named = parseNmapXml(fx('nmap.xml'))
    expect(named.map((p) => [p.port, p.service, p.product])).toEqual([
      [3306, 'mysql', undefined],
      [6379, 'redis', undefined],
      [8765, 'http', 'SimpleHTTPServer 0.6']
    ])
  })
  it('rates services by how dangerous they are to expose', () => {
    const named = parseNmapXml(fx('nmap.xml'))
    const remote = portFindings(named.map((p) => ({ ...p, host: 'server.example.com' })), false)
    expect(remote.map((f) => [f.severity, f.title])).toEqual([
      ['high', 'MySQL is open on port 3306'],
      ['critical', 'Redis is open on port 6379'],
      ['info', 'Port 8765 is open (http SimpleHTTPServer 0.6)']
    ])
    // On this Mac, development databases are expected: lower, but not hidden.
    const local = portFindings(named, true)
    expect(local.map((f) => f.severity)).toEqual(['low', 'medium', 'info'])
  })
})

describe('cloud', () => {
  it('reads ScoutSuite results, flagged rules only', () => {
    const f = parseScoutSuite(fx('scoutsuite_results_azure.js'))
    expect(f).toHaveLength(1)
    expect(f[0]).toMatchObject({ tool: 'ScoutSuite', category: 'cloud', severity: 'high', title: 'App Service Authentication Disabled (2 of 3)', file: 'appservice' })
    expect(f[0].fix).not.toContain('<li>')
    expect(f[0].description).toContain('web_apps.app1.authentication_enabled')
  })
  it('reads PMapper findings', () => {
    const f = parsePmapper(fx('pmapper-analysis.json'))
    expect(f[0]).toMatchObject({ tool: 'PMapper', severity: 'high', title: 'IAM Principal Can Escalate Privileges' })
    expect(f[0].fix).toMatch(/reduce the permissions/)
  })
})

describe('WordPress', () => {
  it('reads WPScan: core, plugins, themes and exposed backups', () => {
    const f = parseWpscan(fx('wpscan.json'), 'https://blog.example.com/')
    const by = (s: string): Record<string, unknown> | undefined => f.find((x) => x.title.includes(s)) as never
    expect(by('Shortcode')).toMatchObject({ severity: 'high', advisory: 'CVE-2023-2745' })
    expect(by('Contact Form 7 <')).toMatchObject({ severity: 'medium', advisory: 'CVE-2023-6449' })
    expect(by('WordPress 6.1.1 is insecure')?.severity).toBe('high')
    expect(by('backup')).toMatchObject({ severity: 'critical', url: 'https://blog.example.com/wp-config.php.bak' })
    expect(by('listing')?.severity).toBe('medium')
    expect(f.some((x) => x.title === 'Headers')).toBe(false)
  })
})

describe('tools', () => {
  it('has every inspect-only tool from the T3MP3ST pack', () => {
    const ids = CATALOG.map((t) => t.id)
    for (const id of ['mobsfscan', 'androguard', 'scoutsuite', 'azure-cli', 'awscli', 'cloudfox', 'pmapper', 'gcloud', 'naabu', 'nmap', 'wpscan', 'radare2', 'ghidra']) expect(ids).toContain(id)
  })
  it('lists the attack tools without installing or running any', () => {
    const list = optionalTools()
    expect(list.map((t) => t.name)).toEqual(expect.arrayContaining(['Metasploit Framework', 'sqlmap', 'Hydra', 'Frida', 'drozer', 'Pacu']))
    expect(list.every((t) => t.homepage.startsWith('https://'))).toBe(true)
    // None of them is in the catalog MacSec installs from.
    expect(CATALOG.some((t) => /metasploit|sqlmap|hydra|frida|drozer|pacu|ffuf|dalfox|hashcat|john/i.test(t.id))).toBe(false)
  })
  it('writes AI prompts for the new kinds of check', () => {
    expect(summaryPrompt('mobile', 'Demo', '', [])).toContain('read-only mobile app security check')
    expect(summaryPrompt('cloud', 'Azure', '', [])).toContain('owns this cloud account')
  })
})
