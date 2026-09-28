#!/usr/bin/env bash
#
# Builds "Gryphon Agent.app" from cmd/client-mac.
#
#   build/macos/package.sh dev       universal .app in tmp/, ad-hoc signed;
#                                    launches on this machine, nowhere else
#   build/macos/package.sh release   Developer ID signed, notarized, stapled,
#                                    and wrapped in a DMG in tmp/
#
# Release needs:
#   SIGN_IDENTITY   the "Developer ID Application: Name (TEAMID)" identity,
#                   as `security find-identity -v -p codesigning` prints it
#   NOTARY_PROFILE  a keychain profile made once with
#                   `xcrun notarytool store-credentials <name>`
#   VERSION         optional; defaults to the highest v* tag in the repo
#   BUNDLE_ID       optional; defaults below. Pick one in the iOS app's
#                   domain before the first release and never change it --
#                   it is what the user's firewall and login-item grants
#                   are tied to.
set -euo pipefail

MODE="${1:-dev}"
case "$MODE" in dev|release) ;; *) echo "usage: $0 dev|release" >&2; exit 2 ;; esac

cd "$(dirname "$0")/../.."
BUNDLE_ID="${BUNDLE_ID:-com.gryphon.agent}"
APP_NAME="Gryphon Agent"
OUT=tmp
APP="$OUT/$APP_NAME.app"
WORK="$OUT/macos-build"

# Versions. CFBundleShortVersionString must look like 1.2.3, so it is the
# highest release tag in the repository -- not `git describe`, which only sees
# tags that are ancestors of the current commit, and the release tags sit on
# master's merge commits where a development branch never sees them.
# CFBundleVersion must increase per build, so it is the commit count. Pass
# VERSION=1.2.3 to override. The Go binary itself still reports what the
# toolchain stamps from the commit it is built from (see build-linux in the
# Taskfile for why a release is best built from master at its tag).
VERSION="${VERSION:-$(git tag --list 'v[0-9]*' --sort=-v:refname | head -1 | sed 's/^v//')}"
VERSION="${VERSION:-0.0.0}"
BUILD="$(git rev-list --count HEAD 2>/dev/null || echo 1)"

rm -rf "$APP" "$WORK"; mkdir -p "$WORK" "$APP/Contents/MacOS" "$APP/Contents/Resources"

# What the binary itself reports, in the menu and the log. Left to the Go
# toolchain it would be a pseudo-version stamped from the commit -- on a
# development branch something like 1.0.6-0.20260913211146-f77a85fa150b,
# which names a release that this is not. So: a release build reports the
# release, and a dev build reports the commit and says it is a dev build.
if [ "$MODE" = release ]; then
  APP_VERSION="$VERSION"
else
  APP_VERSION="dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  git diff --quiet 2>/dev/null || APP_VERSION="$APP_VERSION+dirty"
fi

echo "==> building universal binary ($VERSION build $BUILD, $BUNDLE_ID, reports $APP_VERSION)"
LDFLAGS="-s -w -X main.bundleID=$BUNDLE_ID -X github.com/gocodedotca/gryphon-agent/pkg/version.Override=$APP_VERSION"
for arch in arm64 amd64; do
  CGO_ENABLED=1 GOOS=darwin GOARCH=$arch \
    go build -trimpath -ldflags="$LDFLAGS" -o "$WORK/client-mac-$arch" ./cmd/client-mac
done
lipo -create -output "$APP/Contents/MacOS/client-mac" "$WORK/client-mac-arm64" "$WORK/client-mac-amd64"

echo "==> assembling bundle"
sed -e "s/__BUNDLE_ID__/$BUNDLE_ID/" -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" \
  build/macos/Info.plist > "$APP/Contents/Info.plist"
echo -n APPL???? > "$APP/Contents/PkgInfo"

# Finder icon from the committed PNG.
ICONSET="$WORK/AppIcon.iconset"; mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z $size $size build/macos/AppIcon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z $double $double build/macos/AppIcon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

if [ "$MODE" = dev ]; then
  echo "==> ad-hoc signing"
  codesign --force --sign - --entitlements build/macos/entitlements.plist "$APP"
  echo "built $APP"
  exit 0
fi

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to the Developer ID Application identity}"
: "${NOTARY_PROFILE:?set NOTARY_PROFILE to the notarytool keychain profile}"

echo "==> signing with $SIGN_IDENTITY"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp \
  --entitlements build/macos/entitlements.plist "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> notarizing the app"
ditto -c -k --keepParent "$APP" "$WORK/app.zip"
xcrun notarytool submit "$WORK/app.zip" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"

echo "==> making the DMG"
DMG="$OUT/$APP_NAME $VERSION.dmg"
rm -f "$DMG"
STAGE="$WORK/dmg"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature -v "$DMG"

echo "built $DMG"
