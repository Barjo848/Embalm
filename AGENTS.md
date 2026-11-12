# Embalm: notes for coding agents

Embalm encrypts a file so only a password opens it; two wrong passwords in a row destroy
it. macOS, Apple Silicon, Swift (command line tools are enough, no Xcode). Read README.md
for the design and format.

## Commands

```bash
swift run embalm-selftest            # 54 checks; run after any change to Sources/EmbalmCore
swift build -c release --product embalm
bash release/fetch-fonts.sh <dir>    # optional: fonts are not in the repo (system faces otherwise)
bash release/build-release.sh --repro   # anonymized package in dist/ (about 2 minutes)
bash release/build-dmg.sh               # dist/Embalm.dmg: installer for sharing (no commercial font)
```

## Layout

`Sources/EmbalmCore` engine, format, password generator. `Sources/EmbalmGUI` AppKit app.
`Sources/embalm-cli` developer tool (not shipped). `release/` packaging, setup script,
entitlements. `app/icon-gen.swift` icons.

Keep one path: everything a user does goes through the app. The Finder Quick Actions only
run `open -b com.embalm.Embalm "$@"`; do not add scripts or helpers beside the app.

## Rules that matter

- **Crypto changes** need a matching test in `SelfCheck.swift`. Old v1/v2/v3 files must keep
  opening (fixtures in `LegacyFixtures.swift`). New files are v4 (`EmbalmV4.swift`): every
  single-password file carries two slots and the 64 KiB decoy region whether or not a duress
  password was set. Never make either conditional; that would reveal who uses one. Never store anything about the plaintext in
  the clear. Do not hand-roll primitives.
- **Release builds are anonymous.** No names, paths, hostnames or tool/model names in
  anything shipped. `release/private-scan.py` is the gate and must never be shipped; it must not
  contain names itself (those go in the untracked `release/private-scan.local`).
  `release/setup.sh` uses only stock macOS tools (no nm, otool, strings).
- **Fonts** (`release/fonts`) are gitignored. Never commit them, and never share a package
  built with Courier Code in it (commercial face). A build without fonts uses system faces.
- **Design:** the GUI follows the Atlas look described in README.md and encoded in
  `Sources/EmbalmGUI/AtlasKit.swift`. Lengths are scale-1 values multiplied by k = side / 333. Do not mix in other designs.
- **App is sandboxed** with only user-selected read-write. A file opened via Open With is
  writable but its folder is not, so output goes through a save panel.
- **The GUI cannot be unit tested.** Build a dev bundle, launch it, drive it with System
  Events, and capture with `screencapture -l <window id>`.
- Do not commit `dist/`, `.build/`, or any `.emb` / `.embalm` file. New files are `.emb`; `.embalm` (1.0 and 1.1) must keep working.
