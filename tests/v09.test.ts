import { latestPerTarget } from '../src/shared/latest'
import { describe, expect, it } from 'vitest'
import { EDITORS, findEditors, isAppBundle, isEditorChoice, openCommand, pickEditor } from '../src/main/seckit/editors'
import { ownNotes } from '../src/main/seckit/ghapi'

describe('Editors and IDEs', () => {
  const have = (paths: string[]) => (p: string) => paths.includes(p)
  it('finds editors in Applications, ~/Applications and JetBrains Toolbox, in order', () => {
    const found = findEditors(['/Applications', '/Users/me/Applications', '/Users/me/Applications/JetBrains Toolbox'], [], have(['/Applications/Zed.app', '/Applications/Visual Studio Code.app', '/Users/me/Applications/JetBrains Toolbox/PhpStorm.app']))
    expect(found.map((f) => f.id)).toEqual(['vscode', 'zed', 'phpstorm'])
    expect(found[2].app).toBe('/Users/me/Applications/JetBrains Toolbox/PhpStorm.app')
  })
  it('uses Spotlight results for apps kept somewhere else', () => {
    const found = findEditors(['/Applications'], ['/Volumes/Tools/Sublime Text.app', '/Applications/Safari.app'], have([]))
    expect(found).toEqual([{ id: 'sublime', name: 'Sublime Text', app: '/Volumes/Tools/Sublime Text.app' }])
  })
  it('falls back to the first editor found when the chosen one was removed (Cursor uninstalled)', () => {
    const found = [{ id: 'vscode', name: 'VS Code', app: '/Applications/Visual Studio Code.app' }]
    expect(pickEditor('cursor', found)?.id).toBe('vscode')
    expect(pickEditor('auto', found)?.id).toBe('vscode')
    expect(pickEditor('auto', [])).toBeNull()
  })
  it('opens each kind its own way, at the line', () => {
    const def = (id: string) => EDITORS.find((e) => e.id === id)!
    expect(openCommand(def('vscode'), '/Applications/Visual Studio Code.app', '/p/a.php', 12)[0]).toEqual({ bin: '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code', args: ['--goto', '/p/a.php:12'] })
    expect(openCommand(def('vscode'), '/Applications/Visual Studio Code.app', '/p')[0].args).toEqual(['--new-window', '/p'])
    expect(openCommand(def('phpstorm'), '/Applications/PhpStorm.app', '/p/a.php', 3)).toEqual([{ bin: '/usr/bin/open', args: ['-na', '/Applications/PhpStorm.app', '--args', '--line', '3', '/p/a.php'] }])
    expect(openCommand(def('zed'), '/Applications/Zed.app', '/p/a.php', 7)[0]).toEqual({ bin: '/Applications/Zed.app/Contents/MacOS/cli', args: ['/p/a.php:7'] })
    expect(openCommand(def('xcode'), '/Applications/Xcode.app', '/p/a.swift', 9)[0]).toEqual({ bin: '/usr/bin/xed', args: ['--line', '9', '/p/a.swift'] })
    expect(openCommand(null, '/Applications/Nova.app', '/p')).toEqual([{ bin: '/usr/bin/open', args: ['-a', '/Applications/Nova.app', '/p'] }])
    // The editor's own command first, then macOS's open as a fallback.
    expect(openCommand(def('cursor'), '/Applications/Cursor.app', '/p').at(-1)?.bin).toBe('/usr/bin/open')
  })
  it('only accepts known choices and real app bundles', () => {
    expect(isEditorChoice('auto') && isEditorChoice('custom') && isEditorChoice('phpstorm')).toBe(true)
    expect(isEditorChoice('rm -rf')).toBe(false)
    expect(isAppBundle('/Applications/Nova.app')).toBe(true)
    expect(isAppBundle('/Applications/../etc/passwd.app')).toBe(false)
    expect(isAppBundle('Nova.app')).toBe(false)
  })
})

describe('Release notes', () => {
  it('keeps only a release’s own section when the whole history was attached', () => {
    const full = '## New in 0.23.2\n\n### Fix\nA.\n\n## New in 0.23.1\n\n### Look\nB.'
    expect(ownNotes(full)).toBe('## New in 0.23.2\n\n### Fix\nA.')
    expect(ownNotes('## Only one\n\nText')).toBe('## Only one\n\nText')
    expect(ownNotes(null)).toBe('')
  })
})


describe('The Overview counts each finding once', () => {
  const s = (id: string, kind: string, target: string, extra: Record<string, unknown> = {}) => ({ id, kind, target, status: 'done', ...extra }) as never
  it('leaves out an audit’s own code review and web scan, which the audit already holds', () => {
    const list = [s('aud', 'audit', 'http://shop.test', { children: ['cr', 'ws'] }), s('ws', 'web', 'http://shop.test'), s('cr', 'code', '/www/shop'), s('cr2', 'code', '/www/blog')]
    expect(latestPerTarget(list).map((x: { id: string }) => x.id)).toEqual(['aud', 'cr2'])
  })
  it('keeps the newest finished test of each target', () => {
    const list = [s('new', 'code', '/www/a', { status: 'running' }), s('mid', 'code', '/www/a'), s('old', 'code', '/www/a'), s('f', 'web', 'x', { status: 'failed' })]
    expect(latestPerTarget(list).map((x: { id: string }) => x.id)).toEqual(['mid'])
    // Testing everything again also reruns failed ones, never running ones.
    expect(latestPerTarget(list, { finished: false }).map((x: { id: string }) => x.id)).toEqual(['mid', 'f'])
  })
})
