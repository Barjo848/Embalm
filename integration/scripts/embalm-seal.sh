#!/bin/bash
# Quick Action "Embalm": encrypt the selected file(s).
# Dialog text is passed to osascript as arguments, never spliced into its source.
set -u
APP_SUPPORT="$HOME/Library/Application Support/Embalm"
EMBALM_BIN="$APP_SUPPORT/embalm"
TITLE="Embalm"

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
    set r to display dialog (item 2 of argv) default answer "" with hidden answer with title (item 1 of argv) buttons {"Cancel", "Continue"} default button "Continue"
    return text returned of r
end run
AS
}
confirm_weak() { /usr/bin/osascript - "$TITLE" 2>/dev/null <<'AS'
on run argv
    return button returned of (display dialog "That password is short, so it is easier to guess. A long passphrase of four or more words is much stronger." buttons {"Choose another", "Use it anyway"} default button "Choose another" with title (item 1 of argv) with icon caution)
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
    if [ -d "$f" ]; then alert "“$name” is a folder. Compress it to a zip first."; continue; fi

    while :; do
        pw=$(ask_password "Enter a password to Embalm “$name”:") || { notify "Cancelled."; continue 2; }
        [ -n "$pw" ] || { alert "The password must not be empty."; continue; }
        pw2=$(ask_password "Re-enter the password to confirm:") || { notify "Cancelled."; continue 2; }
        [ "$pw" = "$pw2" ] || { alert "The passwords did not match. Try again."; continue; }
        if [ "${#pw}" -lt 12 ]; then
            [ "$(confirm_weak)" = "Use it anyway" ] || continue
        fi
        break
    done

    # The password travels on stdin only; it never appears in a process list.
    if out=$(printf '%s\n' "$pw" | "$EMBALM_BIN" seal "$f" --password-stdin --porcelain 2>&1); then
        notify "Embalmed “$name” as “$(basename "$(printf '%s' "$out" | tail -n1)")”."
    else
        alert "Could not embalm “$name”: ${out#embalm: }"
    fi
    pw=""; pw2=""
done
