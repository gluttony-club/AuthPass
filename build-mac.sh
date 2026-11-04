#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Darwin ]] || { echo 'Run this script on macOS with Go and Xcode CLT.' >&2; exit 1; }
dmg=false
for arg in "$@"; do case "$arg" in --dmg) dmg=true;; *) echo "Unknown argument: $arg" >&2; exit 1;; esac; done
VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')} || true
VERSION=${VERSION:-1.1.1}
[[ $VERSION =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || { echo "Invalid version: $VERSION" >&2; exit 1; }
mkdir -p dist
bins=()
# Build each architecture with cgo explicitly targeting that CPU, so an
# x86_64 slice can be cross-compiled on Apple Silicon (and vice versa).
# -trimpath keeps local source paths (such as the home directory) out of the binary.
for arch in arm64 amd64; do
  case $arch in arm64) carch=arm64;; amd64) carch=x86_64;; esac
  if ! GOOS=darwin GOARCH=$arch CGO_ENABLED=1 CC="clang -arch $carch" MACOSX_DEPLOYMENT_TARGET=13.0 \
    CGO_CFLAGS="-mmacosx-version-min=13.0" CGO_LDFLAGS="-mmacosx-version-min=13.0" \
    go build -trimpath -ldflags '-s -w' -o "dist/helper-$arch" ./cmd/authpass; then
    echo "Error: $arch build failed; refusing to produce a single-architecture app." >&2
    exit 1
  fi
  bins+=("dist/helper-$arch")
done
app='dist/AuthPass.app'
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
lipo -create "${bins[@]}" -output "$app/Contents/MacOS/authpass"
lipo "$app/Contents/MacOS/authpass" -verify_arch arm64 x86_64 || { echo 'Error: universal binary is missing arm64 or x86_64.' >&2; exit 1; }
if strings - "$app/Contents/MacOS/authpass" | grep -qF -e "$HOME" -e "$PWD"; then
  echo 'Error: binary contains local build paths.' >&2; exit 1
fi
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>authpass</string>
<key>CFBundleName</key><string>AuthPass</string>
<key>CFBundleIdentifier</key><string>club.gluttony.authpass</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${VERSION}</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
if command -v codesign >/dev/null; then
  codesign --force --deep -s - "$app" || echo 'Warning: ad-hoc signing failed.' >&2
fi
if $dmg; then
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
  cp -R "$app" "$stage/"
  ln -s /Applications "$stage/Applications"
  hdiutil create -volname 'AuthPass' -srcfolder "$stage" -ov -format UDZO 'dist/AuthPass.dmg'
fi
echo "Built $app version $VERSION ($(lipo -archs "$app/Contents/MacOS/authpass"))"
