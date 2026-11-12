#!/bin/bash
# Builds dist/Embalm.dmg: a disk image holding a standard macOS installer package.
#
#   bash release/build-dmg.sh
#
# The installer shows the licence, lets the user install for everyone or just
# themselves, lets them leave out the Finder actions, shows progress, and
# afterwards offers to move the disk image to the Trash.
#
# The app inside is the shareable build (release/build-release.sh --public).
# It is signed ad hoc, not with a Developer ID, so on another Mac the first open
# of a downloaded copy needs approval in System Settings, Privacy & Security.
set -euo pipefail
export LC_ALL=C COPYFILE_DISABLE=1
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/release/installer"
DIST="$REPO/dist"

[ "${EMBALM_REUSE_ZIP:-}" = 1 ] || bash "$REPO/release/build-release.sh" --public

# Work outside the repository (a synced folder adds attributes that break signatures).
TMP="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT
unzip -q "$DIST/Embalm-Setup.zip" -d "$TMP/unzipped"
APP="$TMP/unzipped/Embalm-Setup/Embalm.app"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"

echo "==> Building the installer package (version $VERSION)…"
mkdir -p "$TMP/approot" "$TMP/actionsroot" "$TMP/scripts" "$TMP/pkgs" "$TMP/resources" "$TMP/dmg"
ditto "$APP" "$TMP/approot/Embalm.app"
codesign --verify --strict "$TMP/approot/Embalm.app"

# shellcheck disable=SC1091
. "$REPO/release/support/quickaction.sh"
make_quick_action "Embalm"  "public.data"          "$TMP/actionsroot/Embalm.workflow"
make_quick_action "Mummify" "com.embalm.container" "$TMP/actionsroot/Mummify.workflow"

cp "$SRC/postinstall" "$SRC/cleanup.sh" "$TMP/scripts/"
chmod 755 "$TMP/scripts/postinstall" "$TMP/scripts/cleanup.sh"
find "$TMP/approot" "$TMP/actionsroot" -type d -exec chmod 755 {} +
xattr -cr "$TMP/approot" "$TMP/actionsroot" "$TMP/scripts" 2>/dev/null || true

# Never let the installer "relocate" the app to some other copy it finds on the Mac.
pkgbuild --analyze --root "$TMP/approot" "$TMP/component.plist" >/dev/null
/usr/libexec/PlistBuddy -c 'Delete :0:BundleIsRelocatable' "$TMP/component.plist" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c 'Add :0:BundleIsRelocatable bool false' "$TMP/component.plist"
pkgbuild --root "$TMP/approot" --component-plist "$TMP/component.plist" --install-location /Applications \
    --identifier com.embalm.pkg.app --version "$VERSION" --ownership recommended \
    --scripts "$TMP/scripts" "$TMP/pkgs/app.pkg" >/dev/null
pkgbuild --root "$TMP/actionsroot" --install-location /Library/Services \
    --identifier com.embalm.pkg.actions --version "$VERSION" --ownership recommended \
    "$TMP/pkgs/actions.pkg" >/dev/null

# pkgbuild stamps each package with the build machine's OS build number. Remove it.
for p in app actions; do
    pkgutil --expand "$TMP/pkgs/$p.pkg" "$TMP/pkgs/$p.x"
    sed -i '' -E 's/ generator-version="[^"]*"//' "$TMP/pkgs/$p.x/PackageInfo"
    rm "$TMP/pkgs/$p.pkg"
    pkgutil --flatten "$TMP/pkgs/$p.x" "$TMP/pkgs/$p.pkg"
    rm -rf "$TMP/pkgs/$p.x"
done

cp "$SRC/LICENSE.txt" "$TMP/resources/"
sed "s/@VERSION@/$VERSION/g" "$SRC/distribution.xml" > "$TMP/distribution.xml"
productbuild --distribution "$TMP/distribution.xml" --resources "$TMP/resources" \
    --package-path "$TMP/pkgs" "$TMP/dmg/Install Embalm.pkg" >/dev/null

echo "==> Scanning the package for anything identifying…"
pkgutil --expand-full "$TMP/dmg/Install Embalm.pkg" "$TMP/expanded"
python3 -I "$REPO/release/private-scan.py" "$TMP/expanded"

echo "==> Creating the disk image…"
rm -f "$DIST/Embalm.dmg"
hdiutil create -volname "Embalm" -srcfolder "$TMP/dmg" -fs HFS+ -format UDZO -ov "$DIST/Embalm.dmg" >/dev/null 2>&1
hdiutil verify "$DIST/Embalm.dmg" >/dev/null 2>&1 && echo "    disk image verifies"

echo
echo "Done: $DIST/Embalm.dmg"
echo "SHA-256: $(shasum -a 256 "$DIST/Embalm.dmg" | awk '{print $1}')"
