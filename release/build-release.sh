#!/bin/bash
# Builds the anonymized release package for an Apple Silicon Mac.
#
#   bash release/build-release.sh [--repro] [--public]
#
# Output (in ./dist):
#   Embalm-Setup.zip     the package to transfer
#   RELEASE-INFO.txt     fingerprints and the one command to run on the target Mac
#
# --repro builds a second time from scratch and checks the two zips are identical.
# --public makes a package that may be shared: it bundles only the freely licensed
#          typeface (TeX Gyre Heros) and leaves the commercial one out.
set -euo pipefail
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=946684800 COPYFILE_DISABLE=1

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIPLE=arm64-apple-macosx12.0
FIXED_TOUCH=200001010000
REPRO=0; PUBLIC=0
for a in "$@"; do
    case "$a" in --repro) REPRO=1 ;; --public) PUBLIC=1 ;; *) echo "unknown option: $a"; exit 64 ;; esac
done
FONT_FILES="TeXGyreHeros-Regular.otf TeXGyreHeros-Bold.otf"
[ "$PUBLIC" -eq 1 ] || FONT_FILES="$FONT_FILES CourierCode-Roman.ttf"
FONTS=1
for f in $FONT_FILES; do
    [ -f "$REPO/release/fonts/$f" ] || FONTS=0
done
[ "$FONTS" -eq 1 ] || echo "note: release/fonts is incomplete, so this build uses system typefaces (see release/fetch-fonts.sh)"

build_package() {   # $1 = output directory
    # Work outside the repository: a synced folder (iCloud Drive, Dropbox) puts
    # Finder attributes back on the app bundle, which makes code signing fail.
    local DIST="$1" TMP
    TMP="$(cd "$(mktemp -d)" && pwd -P)"
    local WORK="$TMP/work" STAGE="$TMP/stage/Embalm-Setup"
    rm -rf "$DIST"; mkdir -p "$DIST" "$WORK" "$STAGE/support"

    echo "==> Building (clean, paths remapped, debug info dropped)…"
    build_product() {
        swift build -c release --triple "$TRIPLE" --scratch-path "$WORK/build" --product "$1" \
            -Xswiftc -gnone \
            -Xswiftc -file-prefix-map -Xswiftc "$REPO=/src" \
            -Xswiftc -file-prefix-map -Xswiftc "$TMP=/build" \
            -Xswiftc -file-prefix-map -Xswiftc "$HOME=/home" \
            -Xswiftc -enable-upcoming-feature -Xswiftc ConciseMagicFile \
            -Xcc -ffile-prefix-map="$REPO=/src" -Xcc -ffile-prefix-map="$TMP=/build" -Xcc -g0 \
            -Xlinker -S 2>&1 | grep -E "error|Build complete" || true
    }
    cd "$REPO"
    build_product EmbalmGUI
    local BINDIR
    BINDIR="$(swift build -c release --triple "$TRIPLE" --scratch-path "$WORK/build" --show-bin-path)"
    [ -x "$BINDIR/EmbalmGUI" ] || { echo "build failed"; exit 1; }

    finalize_binary() {   # remove toolchain traces, then strip
        local src="$1" dst="$2" rp
        cp "$src" "$dst"
        for rp in $(otool -l "$dst" | awk '/LC_RPATH/{f=1} f&&/ path /{print $2; f=0}'); do
            case "$rp" in /usr/lib/swift|@loader_path) ;; *) install_name_tool -delete_rpath "$rp" "$dst" 2>/dev/null ;; esac
        done
        vtool -set-build-version macos 12.0 12.0 -replace -output "$dst.tmp" "$dst" >/dev/null 2>&1 && mv "$dst.tmp" "$dst"
        strip -x "$dst" 2>/dev/null
    }

    echo "==> Assembling Embalm.app…"
    local APP="$STAGE/Embalm.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    finalize_binary "$BINDIR/EmbalmGUI" "$APP/Contents/MacOS/Embalm"
    cp "$REPO/release/Info.plist" "$APP/Contents/Info.plist"
    if [ "$FONTS" -eq 1 ]; then
        mkdir -p "$APP/Contents/Resources/Fonts"
        for f in $FONT_FILES; do cp "$REPO/release/fonts/$f" "$APP/Contents/Resources/Fonts/"; done
    fi

    swiftc -O "$REPO/app/icon-gen.swift" -o "$WORK/icon-gen" 2>/dev/null
    make_icns() {   # name, kind
        local name="$1" kind="$2" set="$WORK/$1.iconset" s
        "$WORK/icon-gen" "$WORK/$name-1024.png" 1024 "$kind"
        mkdir -p "$set"
        for s in 16 32 128 256 512; do
            sips -z "$s" "$s" "$WORK/$name-1024.png" --out "$set/icon_${s}x${s}.png" >/dev/null
            sips -z $((s*2)) $((s*2)) "$WORK/$name-1024.png" --out "$set/icon_${s}x${s}@2x.png" >/dev/null
        done
        iconutil -c icns "$set" -o "$APP/Contents/Resources/$name.icns"
    }
    make_icns Embalm doc      # the page-and-ankh art is the app icon too
    make_icns EmbalmDoc doc

    echo "==> Signing (ad hoc, hardened runtime, sandbox entitlements)…"
    codesign --force --options runtime --timestamp=none \
        --entitlements "$REPO/release/Embalm.entitlements" --sign - "$APP" 2>&1 | grep -v "replacing existing" || true
    codesign --verify --strict "$APP" || { echo "signing failed"; exit 1; }
    codesign -d --entitlements - "$APP" 2>/dev/null | grep -q "com.apple.security.app-sandbox" || { echo "signing failed: sandbox entitlement missing"; exit 1; }

    cp "$REPO/release/setup.sh" "$STAGE/setup.sh"
    cp "$REPO/release/support/quickaction.sh" "$STAGE/support/"
    cat > "$STAGE/README.txt" <<'TXT'
Embalm

Encrypts a file so that only your password can open it. Everything happens on
this Mac. Nothing is ever sent anywhere.

To install and run the privacy assessment, open Terminal and run:

    bash /Applications/Embalm-Setup/setup.sh

To re-run only the assessment later:   bash setup.sh --assess
To remove everything:                  bash setup.sh --uninstall
TXT

    echo "==> Normalising (permissions, attributes, timestamps) and writing the manifest…"
    xattr -cr "$STAGE" 2>/dev/null || true
    find "$STAGE" -type d -exec chmod 755 {} +
    find "$STAGE" -type f -exec chmod 644 {} +
    chmod 755 "$APP/Contents/MacOS/Embalm" "$STAGE/setup.sh" "$STAGE"/support/*.sh
    ( cd "$STAGE"
      find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | while IFS= read -r f; do shasum -a 256 "$f"; done > SHA256SUMS
      chmod 644 SHA256SUMS )
    find "$STAGE" -exec touch -h -t "$FIXED_TOUCH" {} +

    echo "==> Creating the zip…"
    ( cd "$TMP/stage" && find Embalm-Setup | LC_ALL=C sort | zip -X -D -q "$DIST/Embalm-Setup.zip" -@ )
    rm -rf "$TMP"
}

OUT="$REPO/dist"
build_package "$OUT"

echo "==> Scanning the finished package for anything identifying…"
CHECK="$(mktemp -d)"; trap 'rm -rf "$CHECK"' EXIT
unzip -q "$OUT/Embalm-Setup.zip" -d "$CHECK"
python3 -I "$REPO/release/private-scan.py" "$CHECK"
echo "==> Checking the zip extracts and verifies cleanly…"
( cd "$CHECK/Embalm-Setup" && shasum -a 256 -c SHA256SUMS >/dev/null ) && echo "    all files match the manifest"

ZIP_SHA="$(shasum -a 256 "$OUT/Embalm-Setup.zip" | awk '{print $1}')"
ROOT="$(shasum -a 256 "$CHECK/Embalm-Setup/SHA256SUMS" | awk '{print $1}')"

if [ "$REPRO" -eq 1 ]; then
    echo "==> Reproducibility: building a second time from scratch…"
    build_package "$REPO/dist-repro" >/dev/null 2>&1
    ZIP2="$(shasum -a 256 "$REPO/dist-repro/Embalm-Setup.zip" | awk '{print $1}')"
    if [ "$ZIP_SHA" = "$ZIP2" ]; then echo "    IDENTICAL: both builds produced the same zip"
    else echo "    DIFFERENT: $ZIP_SHA vs $ZIP2"
         diff <(unzip -p "$REPO/dist-repro/Embalm-Setup.zip" Embalm-Setup/SHA256SUMS) "$CHECK/Embalm-Setup/SHA256SUMS" | head || true; fi
    rm -rf "$REPO/dist-repro"
fi

cat > "$OUT/RELEASE-INFO.txt" <<INFO
Embalm release package
Zip file:              Embalm-Setup.zip
Zip SHA-256:           $ZIP_SHA
Manifest fingerprint:  $ROOT

On the target Mac: put Embalm-Setup.zip in /Applications, open it (double-click), then
run this single command in Terminal:

cd /Applications/Embalm-Setup && { [ "\$(shasum -a 256 SHA256SUMS | awk '{print \$1}')" = "$ROOT" ] && shasum -a 256 -c SHA256SUMS >/dev/null && bash setup.sh; } || echo "STOP: verification or setup did not complete. Do not use this package."
INFO
echo; echo "Done."; cat "$OUT/RELEASE-INFO.txt"
