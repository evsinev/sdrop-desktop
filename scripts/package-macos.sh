#!/bin/sh
# macOS: target/<target>/release/pnesecrets → dist/<out>.dmg with "Payneteasy Secrets.app"
# (bundle id, pnesecrets:// scheme, any file type for drops on the Dock icon). Ad-hoc signed:
# no Developer ID yet. Usage: package-macos.sh <rust target> <dmg file name>
set -eu
TARGET=$1; OUT=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
WORK=$(mktemp -d)
APP="$WORK/root/Payneteasy Secrets.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "target/$TARGET/release/pnesecrets" "$APP/Contents/MacOS/pnesecrets"
ICONSET="$WORK/icon.iconset"
mkdir "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s packaging/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2))
  sips -z $d $d packaging/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/pnesecrets.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.payneteasy.secrets</string>
  <key>CFBundleName</key><string>Payneteasy Secrets</string>
  <key>CFBundleDisplayName</key><string>Payneteasy Secrets</string>
  <key>CFBundleExecutable</key><string>pnesecrets</string>
  <key>CFBundleIconFile</key><string>pnesecrets</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleURLTypes</key>
  <array><dict>
    <key>CFBundleURLName</key><string>com.payneteasy.secrets</string>
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
codesign --force --deep --sign - "$APP"
ln -s /Applications "$WORK/root/Applications"
mkdir -p dist
hdiutil create -volname "Payneteasy Secrets" -srcfolder "$WORK/root" -ov -format UDZO "dist/$OUT" >/dev/null
echo "dist/$OUT"
