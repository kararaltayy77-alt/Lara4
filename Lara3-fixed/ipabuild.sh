#!/bin/bash
set -eo pipefail
cd "$(dirname "$0")"

# Change to project directory
cd Lara3-fixed

APP="lara"
SCHEME="lara"
CONFIG="Release"
ENTITLEMENTS="Config/lara.entitlements"
DERIVED="build/DerivedData"

# Support --debug flag
if [[ "$*" == *--debug* ]]; then
    CONFIG="Debug"
fi

echo "[*] lara IPA build - config=$CONFIG"
echo "[*] entitlements: $ENTITLEMENTS"

# Verify ldid is installed
if ! command -v ldid >/dev/null 2>&1; then
    echo "[!] ldid not found. Install: brew install ldid" >&2
    exit 1
fi

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "[!] entitlements file not found: $ENTITLEMENTS" >&2
    exit 1
fi

# Clean build directory
rm -rf build && mkdir -p build

# Build without code signing - ldid handles signing completely
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

# Locate the .app bundle
APP_PATH="$DERIVED/Build/Products/$CONFIG-iphoneos/$APP.app"
if [ ! -d "$APP_PATH" ]; then
    echo "[*] .app not found at expected path, searching..."
    FOUND=$(find "$DERIVED" -name "$APP.app" -type d 2>/dev/null | head -1)
    if [ -z "$FOUND" ]; then
        echo "[!] .app not found in DerivedData"
        exit 1
    fi
    echo "[*] Found at: $FOUND"
    APP_PATH="$FOUND"
fi

TARGET="build/$APP.app"
cp -r "$APP_PATH" "$TARGET"

# Sign with ldid
echo "[*] Removing old code signature..."
codesign --remove "$TARGET" 2>/dev/null || true
rm -rf "$TARGET/_CodeSignature" "$TARGET/embedded.mobileprovision" 2>/dev/null || true

# Sign frameworks first
FW_DIR="$TARGET/Frameworks"
if [ -d "$FW_DIR" ]; then
    for item in "$FW_DIR"/*; do
        [ -e "$item" ] || continue
        NAME=$(basename "$item")
        if [ -d "$item" ]; then
            BIN="$item/${NAME%.framework}"
            if [ -f "$BIN" ]; then
                echo "[*] Signing framework: $NAME"
                ldid -S "$BIN"
            fi
        elif [ -f "$item" ]; then
            echo "[*] Signing dylib: $NAME"
            ldid -S "$item"
        fi
    done
fi

# Sign main binary with entitlements
echo "[*] Signing main binary with entitlements"
ldid -S"$ENTITLEMENTS" "$TARGET/$APP"

# Verify critical entitlements
echo "[*] Verifying critical entitlements:"
EMBEDDED=$(ldid -e "$TARGET/$APP" 2>/dev/null || true)
MISSING=0
for key in "no-sandbox" "proc_info-allow" "platform-application"; do
    if echo "$EMBEDDED" | grep -q "$key"; then
        echo "    [✓] $key"
    else
        echo "    [!] MISSING: $key"
        MISSING=1
    fi
done

if [ "$MISSING" -ne 0 ]; then
    echo "[!] Critical entitlements missing - aborting"
    exit 1
fi

# Package IPA
echo "[*] Packaging IPA..."
cd build
mkdir -p Payload
cp -r "$APP.app" "Payload/$APP.app"
IPA_NAME="$APP.ipa"
if [ "$CONFIG" = "Debug" ]; then
    IPA_NAME="$APP.debug.ipa"
fi
zip -qr "$IPA_NAME" Payload
rm -rf Payload
cd ..

echo ""
echo "[✓] Build Complete"
echo "[✓] IPA: build/$IPA_NAME"
ls -lh "build/$IPA_NAME"
