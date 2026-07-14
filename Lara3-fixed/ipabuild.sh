#!/bin/bash
set -eo pipefail
cd "$(dirname "$0")"

APP="lara"
SCHEME="lara"
CONFIG="Release"
ENTITLEMENTS="Config/lara.entitlements"
DERIVED="build/DerivedData"

if [[ "$*" == *--debug* ]]; then
    CONFIG="Debug"
fi

echo "[*] lara IPA build - config=$CONFIG"
echo "[*] entitlements: $ENTITLEMENTS"

if ! command -v ldid >/dev/null 2>&1; then
    echo "[!] ldid not found. Install: brew install ldid" >&2
    exit 1
fi

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "[!] entitlements file not found: $ENTITLEMENTS" >&2
    exit 1
fi

rm -rf build && mkdir -p build

set +e
xcodebuild \
    -project "$APP.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration "$CONFIG" \
    -derivedDataPath "$DERIVED" \
    -destination 'generic/platform=iOS' \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_ENTITLEMENTS="" \
    CODE_SIGNING_ALLOWED=NO \
    2>&1 | tee build/xcodebuild.log
BUILD_STATUS=${PIPESTATUS[0]}
set -e

if [ "$BUILD_STATUS" -ne 0 ] || ! grep -q "BUILD SUCCEEDED" build/xcodebuild.log; then
    echo "[!] BUILD FAILED (exit code: $BUILD_STATUS)"
    tail -150 build/xcodebuild.log
    exit 1
fi
echo "[✓] xcodebuild: BUILD SUCCEEDED"

APP_PATH="$DERIVED/Build/Products/$CONFIG-iphoneos/$APP.app"
if [ ! -d "$APP_PATH" ]; then
    echo "[*] Searching for .app in DerivedData..."
    FOUND=$(find "$DERIVED" -name "$APP.app" -type d 2>/dev/null | head -1)
    if [ -z "$FOUND" ]; then
        echo "[!] .app not found"
        exit 1
    fi
    echo "[*] Found at: $FOUND"
    APP_PATH="$FOUND"
fi

TARGET="build/$APP.app"
cp -r "$APP_PATH" "$TARGET"

echo "[*] Removing old signature..."
codesign --remove "$TARGET" 2>/dev/null || true
rm -rf "$TARGET/_CodeSignature" "$TARGET/embedded.mobileprovision" 2>/dev/null || true

FW_DIR="$TARGET/Frameworks"
if [ -d "$FW_DIR" ]; then
    for item in "$FW_DIR"/*; do
        [ -e "$item" ] || continue
        NAME=$(basename "$item")
        if [ -d "$item" ]; then
            BIN="$item/${NAME%.framework}"
            [ -f "$BIN" ] && ldid -S "$BIN"
        elif [ -f "$item" ]; then
            ldid -S "$item"
        fi
    done
fi

echo "[*] Signing main binary..."
ldid -S"$ENTITLEMENTS" "$TARGET/$APP"

echo "[*] Packaging IPA..."
cd build
mkdir -p Payload
cp -r "$APP.app" "Payload/$APP.app"
IPA_NAME="$APP.ipa"
[ "$CONFIG" = "Debug" ] && IPA_NAME="$APP.debug.ipa"
zip -qr "$IPA_NAME" Payload
rm -rf Payload
cd ..

echo ""
echo "[✓] IPA: build/$IPA_NAME"
ls -lh "build/$IPA_NAME"
