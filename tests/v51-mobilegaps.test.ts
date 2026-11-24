/** 1.33: task hijacking, backup, pinning, resilience, WebView, screenshot and Keychain classes. */
import { describe, expect, it } from 'vitest'
import { androidManifestGaps, keychainClasses, pinningGap, resilienceGap, screenshotGap, webviewGap } from '../src/main/mobilegaps'

const manifest = (activity: string, app = '') => `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application ${app}>${activity}</application></manifest>`

describe('Android manifest gaps', () => {
  it('flags an exported singleTask activity with no task affinity', () => {
    const f = androidManifestGaps(manifest('<activity android:name=".Main" android:exported="true" android:launchMode="2"/>'), 'AndroidManifest.xml')
    expect(f.some((x) => x.title.includes('Task-hijacking'))).toBe(true)
  })
  it('does not flag it when a task affinity is set', () => {
    const f = androidManifestGaps(manifest('<activity android:name=".Main" android:exported="true" android:launchMode="2" android:taskAffinity="com.bank.main"/>'), 'AndroidManifest.xml')
    expect(f.some((x) => x.title.includes('Task-hijacking'))).toBe(false)
  })
  it('flags backup without rules, and not with a rules file', () => {
    expect(androidManifestGaps(manifest('', 'android:allowBackup="true"'), 'AndroidManifest.xml').some((x) => /backup/.test(x.title))).toBe(true)
    expect(androidManifestGaps(manifest('', 'android:allowBackup="true" android:dataExtractionRules="@xml/backup"'), 'AndroidManifest.xml').some((x) => /backup/.test(x.title))).toBe(false)
  })
})

describe('network and resilience', () => {
  it('reports no pinning evidence but stays quiet when a pin exists', () => {
    expect(pinningGap('Nothing here', 'android', 'nsc.xml')).toHaveLength(1)
    expect(pinningGap('<pin-set><pin digest="SHA-256">abc</pin></pin-set>', 'android', 'nsc.xml')).toEqual([])
    expect(pinningGap('sha256/AAAAbbbbCCCCddddEEEEffff=', 'ios', 'main.jsbundle')).toEqual([])
  })
  it('flags a banking app with no root/jailbreak/hooking checks', () => {
    expect(resilienceGap('plain code', 'android', 'classes.dex')).toHaveLength(1)
    expect(resilienceGap('Frida and isRooted checks', 'android', 'classes.dex')).toEqual([])
  })
  it('reports a WebView bridge but not a plain app', () => {
    expect(webviewGap('setJavaScriptEnabled(true); addJavascriptInterface(x)', 'android', 'classes.dex')).toHaveLength(1)
    expect(webviewGap('no web view', 'android', 'classes.dex')).toEqual([])
  })
  it('uses the screenshot and Keychain indicators with their caveats', () => {
    expect(screenshotGap('android', 'no flag', false, 'classes.dex')).toHaveLength(1)
    expect(screenshotGap('android', 'FLAG_SECURE', false, 'classes.dex')).toEqual([])
    expect(keychainClasses('kSecAttrAccessibleAlways', 'app')).toHaveLength(1)
    expect(keychainClasses('kSecAttrAccessibleWhenUnlockedThisDeviceOnly', 'app')).toEqual([])
  })
})
