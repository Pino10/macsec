// Ad-hoc signs the app after packaging. Apple Silicon refuses to run unsigned code, and
// Electron's fuses change the binary, which breaks Electron's own signature. Without this,
// macOS reports the downloaded app as "damaged". An ad-hoc signature needs no Apple account;
// users still confirm the first launch in System Settings > Privacy & Security.
const { execFileSync } = require('child_process')
const path = require('path')

exports.default = async function adhocSign(context) {
  if (context.electronPlatformName !== 'darwin') return
  const app = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`)
  execFileSync('codesign', ['--force', '--deep', '--sign', '-', app], { stdio: 'inherit' })
  execFileSync('codesign', ['--verify', '--deep', '--strict', '--verbose=2', app], { stdio: 'inherit' })
}
