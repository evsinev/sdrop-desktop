#!/bin/sh
# macOS: wraps the probe binary into target/Probe.app (bundle id, pnesecrets:// scheme, any file
# type for drops on the Dock icon) and opens it. Notifications and open_urls need a bundle.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
cargo build -p pnesecrets --bin probe
APP=target/Probe.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp target/debug/probe "$APP/Contents/MacOS/probe"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.payneteasy.secrets.probe</string>
  <key>CFBundleName</key><string>Probe</string>
  <key>CFBundleExecutable</key><string>probe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleURLTypes</key>
  <array><dict>
    <key>CFBundleURLName</key><string>com.payneteasy.secrets.probe</string>
    <key>CFBundleURLSchemes</key><array><string>pnesecrets</string></array>
  </dict></array>
  <key>CFBundleDocumentTypes</key>
  <array><dict>
    <key>CFBundleTypeName</key><string>Any file</string>
    <key>CFBundleTypeRole</key><string>Viewer</string>
    <key>LSHandlerRank</key><string>Alternate</string>
    <key>LSItemContentTypes</key><array><string>public.data</string></array>
  </dict></array>
</dict>
</plist>
PLIST
codesign --force --sign - "$APP" >/dev/null 2>&1 || true
echo "$ROOT/$APP"
