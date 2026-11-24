# Mobile fixtures

## red-screen.apk

- Package: `org.vi_server.red_screen`
- Version: 1.1 (versionCode 2)
- Licence: MIT
- Source: https://github.com/vi/redscreen.apk
- F-Droid page: https://f-droid.org/packages/org.vi_server.red_screen/
- Downloaded from: https://f-droid.org/repo/org.vi_server.red_screen_2.apk
- Size: 8,649 bytes
- SHA-256: pinned in `tests/v48-mobile-fixture.test.ts`
- Why this one: it is tiny, a real signed APK, MIT licensed, and has a manifest and
  a dex file, which is enough to test the decode path without shipping a large app.
  It is a red screen, so nothing in it is sensitive.

The IPA limit: an iOS IPA cannot generally be redistributed, and dynamic testing
needs Xcode, a signing identity and a device. The mobile tests cover static APK
decoding only.
