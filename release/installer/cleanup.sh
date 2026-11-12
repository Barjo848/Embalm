#!/bin/sh
# Waits for the installer to close, then offers to eject the Embalm disk image
# and move it to the Trash. Does nothing if anything looks unexpected.
pkg="$1"
mount="$(dirname "$pkg")"
trap '/bin/rm -f "$0"' EXIT
image="$(/usr/bin/hdiutil info | /usr/bin/awk -v m="$mount" '
    /^image-path/ { sub(/^image-path[ \t]*:[ \t]*/, ""); img = $0 }
    index($0, m) && substr($0, length($0) - length(m) + 1) == m { print img; exit }')"
[ -n "$image" ] && [ -f "$image" ] || exit 0
n=0
while /usr/bin/pgrep -x Installer >/dev/null 2>&1; do
    n=$((n + 1)); [ "$n" -lt 900 ] || exit 0
    sleep 1
done
answer="$(/usr/bin/osascript - "$(basename "$image")" 2>/dev/null <<'AS'
on run argv
    return button returned of (display dialog "Embalm is installed. Move “" & (item 1 of argv) & "” to the Trash?" buttons {"Keep", "Move to Trash"} default button "Move to Trash" with title "Embalm")
end run
AS
)"
[ "$answer" = "Move to Trash" ] || exit 0
/usr/bin/hdiutil detach "$mount" >/dev/null 2>&1 || exit 0
dest="$HOME/.Trash/$(basename "$image")"
[ ! -e "$dest" ] || dest="$HOME/.Trash/$(date +%H%M%S) $(basename "$image")"
/bin/mv "$image" "$dest" 2>/dev/null
exit 0
