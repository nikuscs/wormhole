#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
CONFIGURATION=${CONFIGURATION:-release}
OUTPUT=${1:-"$ROOT/build"}
APP="$OUTPUT/Wormhole Menu Bar.app"
CONTENTS="$APP/Contents"
RESOURCES="$CONTENTS/Resources"
MACOS="$CONTENTS/MacOS"

cd "$ROOT"
swift build -c "$CONFIGURATION" --product WormholeMenuBar
BIN_DIR=$(swift build -c "$CONFIGURATION" --show-bin-path)

rm -rf "$APP"
mkdir -p "$MACOS" "$RESOURCES"
cp "$BIN_DIR/WormholeMenuBar" "$MACOS/WormholeMenuBar"
for bundle in "$BIN_DIR"/*.bundle; do
    [ -e "$bundle" ] || continue
    cp -R "$bundle" "$RESOURCES/"
done

ICON_SOURCE="$ROOT/Sources/WormholeMenuBar/Resources/app-icon.svg"
ICONSET=$(mktemp -d)/Wormhole.iconset
mkdir -p "$ICONSET"
BASE="$ICONSET/icon_512x512@2x.png"
sips -z 1024 1024 -s format png "$ICON_SOURCE" --out "$BASE" >/dev/null
for spec in "16 16x16" "32 16x16@2x" "32 32x32" "64 32x32@2x" "128 128x128" "256 128x128@2x" "256 256x256" "512 256x256@2x" "512 512x512"; do
    size=${spec%% *}
    name=${spec#* }
    sips -z "$size" "$size" "$BASE" --out "$ICONSET/icon_$name.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$RESOURCES/Wormhole.icns"

cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>WormholeMenuBar</string>
  <key>CFBundleIconFile</key><string>Wormhole</string>
  <key>CFBundleIdentifier</key><string>dev.wormhole.menubar</string>
  <key>CFBundleName</key><string>Wormhole Menu Bar</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

plutil -lint "$CONTENTS/Info.plist" >/dev/null
codesign --force --deep --sign - "$APP" >/dev/null
printf 'Built %s\n' "$APP"
