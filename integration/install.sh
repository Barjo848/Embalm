#!/bin/bash
# install.sh — build Embalm and wire up the Finder right-click menu.
#
# Installs:
#   * the `embalm` engine binary and the two wrapper scripts into
#     ~/Library/Application Support/Embalm/
#   * two Quick Actions ("Embalm", "Mummify") into ~/Library/Services/
#
# Run from anywhere:  bash integration/install.sh
# Uninstall:          bash integration/install.sh --uninstall

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Destinations can be overridden (used by the test harness) so the installer can
# be exercised without touching the real ~/Library.
APP_SUPPORT="${EMBALM_APP_SUPPORT:-$HOME/Library/Application Support/Embalm}"
SERVICES_DIR="${EMBALM_SERVICES_DIR:-$HOME/Library/Services}"
FLUSH_SERVICES=1
[ -n "${EMBALM_SERVICES_DIR:-}" ] && FLUSH_SERVICES=0

uninstall() {
    echo "Removing Quick Actions and installed files…"
    rm -rf "$SERVICES_DIR/Embalm.workflow" "$SERVICES_DIR/Mummify.workflow"
    rm -rf "$APP_SUPPORT"
    /System/Library/CoreServices/pbs -flush >/dev/null 2>&1 || true
    echo "Done. You may need to log out and back in for the menu to disappear."
    exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall

echo "==> Building the embalm engine (release)…"
( cd "$REPO_ROOT" && swift build -c release )
BIN="$REPO_ROOT/.build/release/embalm"
[ -x "$BIN" ] || { echo "Build did not produce $BIN" >&2; exit 1; }

echo "==> Installing engine and scripts to: $APP_SUPPORT"
mkdir -p "$APP_SUPPORT"
cp "$BIN" "$APP_SUPPORT/embalm"
cp "$REPO_ROOT/integration/scripts/embalm-seal.sh" "$APP_SUPPORT/embalm-seal.sh"
cp "$REPO_ROOT/integration/scripts/embalm-open.sh" "$APP_SUPPORT/embalm-open.sh"
chmod +x "$APP_SUPPORT/embalm" "$APP_SUPPORT/embalm-seal.sh" "$APP_SUPPORT/embalm-open.sh"

# Emit a Quick Action .workflow bundle.
#   $1 = menu name (e.g. Embalm)       $2 = wrapper script filename
#   $3 = NSSendFileTypes UTI           $4 = output bundle path
make_quick_action() {
    local menu="$1" wrapper="$2" uti="$3" dest="$4"
    rm -rf "$dest"
    mkdir -p "$dest/Contents"

    cat > "$dest/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>${menu}</string>
			</dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSApplicationIdentifier</key>
				<string>com.apple.finder</string>
			</dict>
			<key>NSSendFileTypes</key>
			<array>
				<string>${uti}</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
PLIST

    # The action runs: exec <wrapper> "$@"  (input passed as arguments; the
    # wrapper also accepts paths on stdin as a fallback).
    local command="exec \"\$HOME/Library/Application Support/Embalm/${wrapper}\" \"\$@\""

    cat > "$dest/Contents/document.wflow" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key>
	<string>528</string>
	<key>AMApplicationVersion</key>
	<string>2.10</string>
	<key>AMDocumentVersion</key>
	<string>2</string>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.path</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>2.0.3</string>
				<key>AMApplication</key>
				<array>
					<string>Automator</string>
				</array>
				<key>AMParameterProperties</key>
				<dict>
					<key>COMMAND_STRING</key>
					<dict/>
					<key>CheckedForUserDefaultShell</key>
					<dict/>
					<key>inputMethod</key>
					<dict/>
					<key>shell</key>
					<dict/>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.path</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run Shell Script.action</string>
				<key>ActionName</key>
				<string>Run Shell Script</string>
				<key>ActionParameters</key>
				<dict>
					<key>COMMAND_STRING</key>
					<string>${command}</string>
					<key>CheckedForUserDefaultShell</key>
					<true/>
					<key>inputMethod</key>
					<integer>1</integer>
					<key>shell</key>
					<string>/bin/bash</string>
					<key>source</key>
					<string></string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.Automator.RunShellScript</string>
				<key>CFBundleVersion</key>
				<string>2.0.3</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunShellScriptAction</string>
				<key>InputUUID</key>
				<string>C0FFEE00-0000-4000-8000-000000000001</string>
				<key>Keywords</key>
				<array>
					<string>Shell</string>
					<string>Script</string>
					<string>Command</string>
					<string>Run</string>
					<string>Unix</string>
				</array>
				<key>OutputUUID</key>
				<string>C0FFEE00-0000-4000-8000-000000000002</string>
				<key>UUID</key>
				<string>C0FFEE00-0000-4000-8000-000000000003</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict/>
				<key>showWhenRun</key>
				<false/>
			</dict>
			<key>isViewVisible</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByProvider</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>0</integer>
		<key>processesInput</key>
		<integer>0</integer>
		<key>serviceApplicationBundleID</key>
		<string>com.apple.finder</string>
		<key>serviceInputRestriction</key>
		<string>0</string>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceMenuName</key>
		<string>${menu}</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
PLIST

    # Validate both plists before we rely on them.
    plutil -lint "$dest/Contents/Info.plist" >/dev/null
    plutil -lint "$dest/Contents/document.wflow" >/dev/null
}

echo "==> Creating Quick Actions in: $SERVICES_DIR"
mkdir -p "$SERVICES_DIR"
# "Embalm" shows for zip archives; "Mummify" shows for all files (there is no
# registered UTI for .embalm), and the wrapper ignores non-.embalm selections.
make_quick_action "Embalm"  "embalm-seal.sh" "public.zip-archive" "$SERVICES_DIR/Embalm.workflow"
make_quick_action "Mummify" "embalm-open.sh" "public.data"        "$SERVICES_DIR/Mummify.workflow"

if [ "$FLUSH_SERVICES" -eq 1 ]; then
    echo "==> Refreshing the Services menu…"
    /System/Library/CoreServices/pbs -flush >/dev/null 2>&1 || true
fi

cat <<DONE

Installed.

Right-click a .zip in Finder  ->  Quick Actions / Services  ->  "Embalm".
Right-click a .embalm file     ->  Quick Actions / Services  ->  "Mummify".

If the items don't appear immediately:
  * Open System Settings > Keyboard > Keyboard Shortcuts > Services and make
    sure "Embalm" and "Mummify" are checked, or
  * log out and back in (the Services cache refreshes on login).

The command-line tool is also available at:
  $APP_SUPPORT/embalm
DONE
