#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Darwin ]] || { echo 'Run this script on macOS with Go and Xcode CLT.' >&2; exit 1; }
dmg=false
for arg in "$@"; do case "$arg" in --dmg) dmg=true;; *) echo "Unknown argument: $arg" >&2; exit 1;; esac; done
VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')} || true
VERSION=${VERSION:-1.1.0}
[[ $VERSION =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || { echo "Invalid version: $VERSION" >&2; exit 1; }
mkdir -p dist
bins=()
for arch in arm64 amd64; do
  if GOOS=darwin GOARCH=$arch CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET=13.0 CGO_CFLAGS="-mmacosx-version-min=13.0" CGO_LDFLAGS="-mmacosx-version-min=13.0" go build -ldflags '-s -w' -o "dist/helper-$arch" ./cmd/authpass; then
    bins+=("dist/helper-$arch")
  else
    echo "Warning: $arch build failed; continuing with available architectures." >&2
  fi
done
[[ ${#bins[@]} -gt 0 ]] || { echo 'No architecture built successfully.' >&2; exit 1; }
app='dist/AuthPass.app'
mkdir -p "$app/Contents/MacOS"
if [[ ${#bins[@]} -eq 2 ]]; then
  lipo -create "${bins[@]}" -output "$app/Contents/MacOS/authpass"
else
  cp "${bins[0]}" "$app/Contents/MacOS/authpass"
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
echo "Built $app version $VERSION (${#bins[@]} architecture(s))"
