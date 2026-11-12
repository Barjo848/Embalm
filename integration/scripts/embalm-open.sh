#!/bin/bash
# Quick Action "Mummify": decrypt the selected file(s). Files are recognised by
# content, so renamed or re-downloaded files work. The original name is restored.
set -u
APP_SUPPORT="$HOME/Library/Application Support/Embalm"
EMBALM_BIN="$APP_SUPPORT/embalm"
TITLE="Mummify"

notify() { /usr/bin/osascript - "$TITLE" "$1" >/dev/null 2>&1 <<'AS'
on run argv
    display notification (item 2 of argv) with title (item 1 of argv)
end run
AS
}
alert() { /usr/bin/osascript - "$TITLE" "$1" >/dev/null 2>&1 <<'AS'
on run argv
    display dialog (item 2 of argv) buttons {"OK"} default button 1 with title (item 1 of argv) with icon caution
end run
AS
}
ask_password() { /usr/bin/osascript - "$TITLE" "$1" 2>/dev/null <<'AS'
on run argv
    set r to display dialog (item 2 of argv) default answer "" with hidden answer with title (item 1 of argv) buttons {"Cancel", "Open"} default button "Open"
    return text returned of r
end run
AS
}

[ -x "$EMBALM_BIN" ] || { alert "The Embalm engine is not installed. Run the setup again."; exit 1; }

files=()
if [ "$#" -gt 0 ]; then files=("$@"); else
    while IFS= read -r line; do [ -n "$line" ] && files+=("$line"); done
fi
[ "${#files[@]}" -gt 0 ] || { alert "No file was selected."; exit 1; }

for f in "${files[@]}"; do
    name=$(basename "$f")
    [ -d "$f" ] && { alert "“$name” is a folder."; continue; }

    # Check the file before asking for a password, so a damaged or unrelated
    # file never costs an attempt.
    if ! info=$("$EMBALM_BIN" info "$f" 2>&1); then
        alert "“$name” is not an Embalm file."; continue
    fi
    case "$info" in
        *"intact:             NO"*)
            alert "“$name” is damaged or incomplete, probably from the transfer. No password attempt was used. Send it again."; continue;;
        *"destroyed:          yes"*)
            alert "“$name” already self-destructed. Nothing can recover it."; continue;;
    esac

    pw=$(ask_password "Enter the password to Mummify “$name”:") || { notify "Cancelled."; continue; }
    out=$(printf '%s\n' "$pw" | "$EMBALM_BIN" open "$f" --password-stdin --porcelain 2>&1)
    code=$?
    pw=""
    case "$code" in
        0)  notify "Mummified “$name” as “$(basename "$(printf '%s' "$out" | tail -n1)")”.";;
        11) alert "⚠️ ${out#embalm: }";;
        *)  alert "${out#embalm: }";;
    esac
done
