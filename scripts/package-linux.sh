#!/bin/sh
# Linux: target/<target>/release/pnesecrets → dist/<name>.tar.gz and dist/<name>.deb
# (binary, .desktop entry, icon). Usage: package-linux.sh <rust target> <base name> <deb arch>
set -eu
TARGET=$1; NAME=$2; ARCH=$3
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
WORK=$(mktemp -d)
DESKTOP='[Desktop Entry]
Type=Application
Name=Payneteasy Secrets
Comment=One-time secrets, encrypted on this computer
Exec=pnesecrets
Icon=pnesecrets
Categories=Utility;Security;
StartupWMClass=com.payneteasy.secrets
Terminal=false'
mkdir -p dist "$WORK/tar/$NAME"
cp "target/$TARGET/release/pnesecrets" "$WORK/tar/$NAME/"
cp packaging/icon.png "$WORK/tar/$NAME/pnesecrets.png"
printf '%s\n' "$DESKTOP" > "$WORK/tar/$NAME/pnesecrets.desktop"
tar -C "$WORK/tar" -czf "dist/$NAME.tar.gz" "$NAME"
DEB="$WORK/deb"
mkdir -p "$DEB/DEBIAN" "$DEB/usr/bin" "$DEB/usr/share/applications" "$DEB/usr/share/pixmaps"
install -m 0755 "target/$TARGET/release/pnesecrets" "$DEB/usr/bin/pnesecrets"
install -m 0644 packaging/icon.png "$DEB/usr/share/pixmaps/pnesecrets.png"
printf '%s\n' "$DESKTOP" > "$DEB/usr/share/applications/pnesecrets.desktop"
cat > "$DEB/DEBIAN/control" <<CONTROL
Package: pnesecrets
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: Payneteasy
Depends: libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, libvulkan1, libfontconfig1, libfreetype6, libdbus-1-3, libx11-xcb1, libxcb1
Description: Payneteasy Secrets desktop client
 One-time links for passwords, keys and files, encrypted on this computer.
CONTROL
dpkg-deb --root-owner-group --build "$DEB" "dist/$NAME.deb" >/dev/null
echo "dist/$NAME.tar.gz dist/$NAME.deb"
