#!/bin/bash
# Embalm: setup and privacy assessment for macOS on Apple Silicon.
#
#   bash setup.sh              verify, install, then assess (the normal case)
#   bash setup.sh --assess     re-run the verification and assessment only
#   bash setup.sh --uninstall  remove everything this script installed
#
# Uses only tools present on a stock macOS. Makes no network connection.
set -u
export LC_ALL=C
PATH=/usr/bin:/bin:/usr/sbin:/sbin

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS="${EMBALM_APPS_DIR:-/Applications}"
SUPPORT="$HOME/Library/Application Support/Embalm"
SERVICES="$HOME/Library/Services"
TESTING="${EMBALM_SETUP_TEST:-}"
MODE=install
for a in "$@"; do
    case "$a" in
        --assess) MODE=assess ;;
        --uninstall) MODE=uninstall ;;
        -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 64 ;;
    esac
done

PASS=0; FAIL=0; WARN=0
section() { printf '\n== %s\n' "$*"; }
ok()   { printf '  [ OK ] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '  [WARN] %s\n' "$*"; WARN=$((WARN+1)); }
info() { printf '         %s\n' "$*"; }
chk()  { local label="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi; }
has()  { /usr/bin/grep -a -q -F -- "$2" "$1"; }

quit_running() { pgrep -x Embalm >/dev/null 2>&1 && { pkill -x Embalm; sleep 1; }; return 0; }

# ---------------------------------------------------------------- uninstall
if [ "$MODE" = uninstall ]; then
    section "Uninstalling"
    quit_running
    rm -rf "$APPS/Embalm.app" "$HOME/Applications/Embalm.app" "$SUPPORT" \
           "$SERVICES/Embalm.workflow" "$SERVICES/Mummify.workflow" \
           "$HOME/Library/Containers/com.embalm.Embalm" 2>/dev/null
    [ -z "$TESTING" ] && /System/Library/CoreServices/pbs -flush >/dev/null 2>&1
    ok "Removed the app, helper tool, Quick Actions and the app's private container"
    info "Files you embalmed or recovered are yours and were not touched."
    exit 0
fi

printf 'Embalm: setup and privacy assessment\n'
printf '====================================\n'

# ---------------------------------------------------------------- 1. preflight
section "1. This Mac"
[ "$(id -u)" -ne 0 ] && ok "Running as a normal user, not root" || bad "Do not run this as root"
OSV="$(sw_vers -productVersion 2>/dev/null)"; OSMAJOR="${OSV%%.*}"
if [ "${OSMAJOR:-0}" -ge 12 ] 2>/dev/null; then ok "macOS $OSV (12 or newer is required)"; else bad "macOS $OSV is too old (12 or newer is required)"; fi
ARCH="$(uname -m)"
if [ "$ARCH" = arm64 ]; then ok "Apple Silicon ($ARCH)"; else bad "This build is for Apple Silicon only; this Mac reports $ARCH"; fi
for t in shasum codesign plutil xattr ditto find grep sed awk; do command -v "$t" >/dev/null 2>&1 || bad "Required system tool missing: $t"; done
if [ "$FAIL" -gt 0 ]; then
    printf '\nCannot continue. PRIVACY CHECK: FAILED\n'; exit 1
fi

# ---------------------------------------------------------------- 2. integrity
section "2. Package integrity"
[ -f "$HERE/SHA256SUMS" ] || { bad "SHA256SUMS is missing, so the package cannot be verified"; printf '\nPRIVACY CHECK: FAILED\n'; exit 1; }
ROOT_HASH="$(shasum -a 256 "$HERE/SHA256SUMS" | awk '{print $1}')"
info "Manifest fingerprint: $ROOT_HASH"
info "Compare this with the value you recorded when you built the package."

# Where is the app right now: still in the setup folder, or already installed?
if [ -d "$HERE/Embalm.app" ]; then APP_NOW="$HERE/Embalm.app"
elif [ -d "$APPS/Embalm.app" ]; then APP_NOW="$APPS/Embalm.app"
elif [ -d "$HOME/Applications/Embalm.app" ]; then APP_NOW="$HOME/Applications/Embalm.app"
else APP_NOW=""; fi

verify_payload() { ( cd "$HERE" && /usr/bin/grep -v ' Embalm\.app/' SHA256SUMS | shasum -a 256 -c - ); }
verify_app()     { ( cd "$(dirname "$1")" && /usr/bin/grep ' Embalm\.app/' "$HERE/SHA256SUMS" | shasum -a 256 -c - ); }
chk "Every support file matches its recorded SHA-256" verify_payload
if [ -n "$APP_NOW" ]; then
    chk "Every file inside Embalm.app matches its recorded SHA-256" verify_app "$APP_NOW"
else
    bad "Embalm.app was not found"
fi
expected_names() { sed 's/^[0-9a-f]\{64\}  //' "$HERE/SHA256SUMS" | sort; }
actual_names() {
    ( cd "$HERE" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' )
    if [ ! -d "$HERE/Embalm.app" ] && [ -n "$APP_NOW" ]; then ( cd "$(dirname "$APP_NOW")" && find Embalm.app -type f ); fi
}
if [ "$(actual_names | sort)" = "$(expected_names)" ]; then ok "No extra or missing files"; else bad "The file set differs from the manifest"; fi
[ -z "$(find "$HERE" "${APP_NOW:-$HERE}" \( -name .DS_Store -o -name __MACOSX -o -name '*.dSYM' -o -name '*.swiftmodule' -o -name '*.swiftdoc' \) 2>/dev/null)" ] \
    && ok "No stray metadata, debug or build files" || bad "Stray metadata or build files found"
if [ "$FAIL" -gt 0 ]; then
    printf '\nThe package failed verification, so nothing was installed.\nPRIVACY CHECK: FAILED\n'; exit 1
fi

# ---------------------------------------------------------------- 3. install
if [ "$MODE" = install ]; then
    section "3. Installing"
    xattr -cr "$HERE" 2>/dev/null          # integrity is already proven above
    chmod 755 "$HERE/embalm" "$HERE"/support/*.sh 2>/dev/null
    if [ -d "$HERE/Embalm.app" ]; then
        quit_running
        DEST="$APPS/Embalm.app"
        if ! { rm -rf "$DEST" 2>/dev/null && mv "$HERE/Embalm.app" "$DEST" 2>/dev/null; }; then
            mkdir -p "$HOME/Applications"; DEST="$HOME/Applications/Embalm.app"
            rm -rf "$DEST"; mv "$HERE/Embalm.app" "$DEST" 2>/dev/null || ditto "$HERE/Embalm.app" "$DEST"
            warn "Could not write to $APPS, so the app went to ~/Applications"
        fi
        xattr -cr "$DEST" 2>/dev/null
        APP_NOW="$DEST"
        ok "Installed $DEST"
    fi
    mkdir -p "$SUPPORT" "$SERVICES"
    install -m 755 "$HERE/embalm" "$SUPPORT/embalm"
    install -m 755 "$HERE/support/embalm-seal.sh" "$SUPPORT/embalm-seal.sh"
    install -m 755 "$HERE/support/embalm-open.sh" "$SUPPORT/embalm-open.sh"
    ok "Installed the command-line helper and Quick Action scripts"
    # shellcheck disable=SC1091
    . "$HERE/support/quickaction.sh"
    make_quick_action "Embalm"  "embalm-seal.sh" "public.zip-archive" "$SERVICES/Embalm.workflow"
    make_quick_action "Mummify" "embalm-open.sh" "public.data"        "$SERVICES/Mummify.workflow"
    ok "Added the right-click actions Embalm (zip files) and Mummify (any file)"
    if [ -z "$TESTING" ]; then
        /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP_NOW" >/dev/null 2>&1
        /System/Library/CoreServices/pbs -flush >/dev/null 2>&1
        ok "Registered the app so .embalm files open in it"
    fi
fi
[ -n "$APP_NOW" ] || { printf '\nPRIVACY CHECK: FAILED (app not installed)\n'; exit 1; }
BIN="$APP_NOW/Contents/MacOS/Embalm"
CLI="$SUPPORT/embalm"; [ -x "$CLI" ] || CLI="$HERE/embalm"

# ---------------------------------------------------------------- 4. signature and permissions
section "4. Signature and permissions"
chk "The app's code signature is valid and unmodified" codesign --verify --strict --deep "$APP_NOW"
chk "The helper tool's code signature is valid" codesign --verify --strict "$CLI"
SIGINFO="$(codesign -dvv "$APP_NOW" 2>&1)"
case "$SIGINFO" in *"(runtime)"*|*"runtime"*) ok "Hardened runtime is on" ;; *) bad "Hardened runtime is off" ;; esac
case "$SIGINFO" in *"Signature=adhoc"*) ok "Signed ad hoc: no Apple ID, developer name or certificate is embedded" ;; *) bad "Unexpected signing identity" ;; esac
case "$SIGINFO" in *"Authority="*) bad "A certificate authority chain is present" ;; *) ok "No certificate chain or team identifier" ;; esac
ENT="$(codesign -d --entitlements :- "$APP_NOW" 2>/dev/null)"
ent_val() { printf '%s' "$ENT" | plutil -p - 2>/dev/null | sed -n "s/^  \"$1\" => \(.*\)$/\1/p"; }
[ "$(ent_val com.apple.security.app-sandbox)" = true ] && ok "The App Sandbox is required by the signature" || bad "App Sandbox entitlement missing"
[ "$(ent_val com.apple.security.files.user-selected.read-write)" = true ] && ok "File access is limited to files you choose" || bad "File-access entitlement missing"
NETKEYS=0
for k in network.client network.server device.camera device.microphone personal-information.location personal-information.addressbook files.downloads.read-write files.all; do
    [ -n "$(ent_val "com.apple.security.$k")" ] && { bad "Unexpected permission granted: $k"; NETKEYS=1; }
done
[ "$NETKEYS" -eq 0 ] && ok "No network, camera, microphone, contacts, location or folder permissions"
[ "$(printf '%s' "$ENT" | plutil -p - 2>/dev/null | /usr/bin/grep -c '=>')" -eq 2 ] && ok "Exactly two permissions are requested, nothing else" || bad "The app requests extra permissions"

# ---------------------------------------------------------------- 5. binary audit
section "5. What is inside the program files"
PLIST="$APP_NOW/Contents/Info.plist"
audit() {   # $1 = label, $2 = file
    local label="$1" f="$2" bad_found=0 p
    for p in "/Users/" "/private/" "/var/folders" ".build/" "CommandLineTools" "Xcode.app" "DerivedData"; do
        has "$f" "$p" && { bad "$label contains a build path fragment: $p"; bad_found=1; }
    done
    has "$f" "__DWARF" && { bad "$label contains debug information"; bad_found=1; }
    [ "$bad_found" -eq 0 ] && ok "$label has no build paths, user names or debug information"
    local net=0
    for p in NSURLSession NSURLConnection CFNetwork NWConnection nw_connection NWPathMonitor NetworkExtension SystemConfiguration WebKit _getaddrinfo _gethostbyname _getnameinfo _sendto _recvfrom; do
        has "$f" "$p" && { bad "$label references a network API: $p"; net=1; }
    done
    [ "$net" -eq 0 ] && ok "$label references no networking API"
}
audit "The app" "$BIN"
audit "The helper tool" "$CLI"
has "$CLI" "_socket" && bad "The helper tool references raw sockets" || ok "The helper tool has no socket calls at all"
if has "$BIN" "_socket" && has "$BIN" "_connect"; then
    ok "The app's only socket calls belong to its self-check"
    info "It tries to open a connection to prove the sandbox refuses it (see section 6)."
fi
KEYS="$(plutil -p "$PLIST" 2>/dev/null | /usr/bin/grep -c -E 'DTXcode|DTSDK|DTCompiler|DTPlatform|BuildMachineOSBuild')"
[ "$KEYS" -eq 0 ] && ok "The app's Info.plist records no build machine, Xcode or SDK details" || bad "Info.plist records build-environment details"
[ -z "$(plutil -p "$PLIST" | /usr/bin/grep -i -E 'http://|https://')" ] && ok "No web addresses anywhere in Info.plist" || bad "Info.plist contains a web address"

# ---------------------------------------------------------------- 6. live test
section "6. Live test (this takes a few seconds)"
SC="$("$BIN" --self-check 2>&1)"; SC_CODE=$?
printf '%s\n' "$SC" | sed 's/^/    /'
if [ "$SC_CODE" -eq 0 ]; then
    ok "The app's own checks passed: sandbox active, network blocked by macOS, cryptography verified"
else
    bad "The app's own checks failed (see above)"
fi
CC="$("$CLI" selfcheck 2>&1)"; CC_CODE=$?
[ "$CC_CODE" -eq 0 ] && ok "The helper tool's cryptography checks passed" || { bad "The helper tool's checks failed"; printf '%s\n' "$CC" | sed 's/^/    /'; }

# ---------------------------------------------------------------- 7. host posture (advice)
section "7. How well this Mac protects the files (advice, does not affect the verdict)"
FV="$(fdesetup status 2>/dev/null)"
case "$FV" in *"is On"*) ok "FileVault disk encryption is on" ;; *) warn "FileVault is off. Turn it on: embalmed and recovered files are otherwise readable from the disk." ;; esac
case "$(csrutil status 2>/dev/null)" in *enabled*) ok "System Integrity Protection is on" ;; *) warn "System Integrity Protection is off" ;; esac
case "$(spctl --status 2>/dev/null)" in *enabled*) ok "Gatekeeper is on" ;; *) warn "Gatekeeper is off" ;; esac
case "$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)" in *enabled*) ok "The macOS firewall is on" ;; *) warn "The macOS firewall is off" ;; esac
case "$(tmutil destinationinfo 2>&1)" in *"No destinations"*) ok "No Time Machine backup copies recovered files" ;; *) warn "Time Machine is configured: recovered (decrypted) files will be backed up. Exclude their folder if that is not wanted." ;; esac
if [ "$(defaults read com.apple.finder FXICloudDriveDesktop 2>/dev/null)" = 1 ] || [ "$(defaults read com.apple.finder FXICloudDriveDocuments 2>/dev/null)" = 1 ]; then
    warn "iCloud Drive syncs Desktop or Documents: recovered files saved there are uploaded to iCloud. Save them elsewhere."
else ok "Desktop and Documents are not synced to iCloud"; fi
[ -z "$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)" ] && ok "Automatic login is off" || warn "Automatic login is on: anyone who starts this Mac can open your files"
info "Recovered files are ordinary files. Spotlight, Quick Look and backups treat them like any other file."

# ---------------------------------------------------------------- verdict
printf '\n=====================================================================\n'
if [ "$FAIL" -eq 0 ]; then
    printf '  PRIVACY CHECK: PASSED\n'
    printf '  %s checks passed, 0 failed, %s advisory note(s) about this Mac.\n' "$PASS" "$WARN"
    printf '=====================================================================\n\n'
    printf 'Use Embalm:\n'
    printf '  - Open Embalm from Applications, then drop a file on it.\n'
    printf '  - Right-click a zip file: Quick Actions > Embalm.\n'
    printf '  - Double-click any .embalm file, or right-click it: Open With > Embalm.\n'
    printf '  - Embalmed files from email, a drive folder or a USB stick open the same way,\n'
    printf '    even if they were renamed on the way.\n\n'
    printf 'Installed in: %s, ~/Library/Application Support/Embalm,\n' "$APP_NOW"
    printf '              ~/Library/Services (two Quick Actions), and the sandbox container.\n'
    [ -d "$HERE" ] && printf 'You can delete %s now; re-run it with --assess to re-check later.\n' "$HERE"
    exit 0
else
    printf '  PRIVACY CHECK: FAILED\n'
    printf '  %s checks passed, %s failed. Do not rely on this install until the failures are resolved.\n' "$PASS" "$FAIL"
    printf '=====================================================================\n'
    exit 1
fi
