# Embalm: notes for coding agents

Embalm encrypts a file so only a password opens it; two wrong passwords in a row destroy
it. macOS, Apple Silicon, Swift (command line tools are enough, no Xcode). Read README.md
for the design and format.

## Commands

```bash
swift run embalm-selftest            # 36 checks; run after any change to Sources/EmbalmCore
swift build -c release --product embalm
bash release/fetch-fonts.sh <dir>    # optional: fonts are not in the repo (system faces otherwise)
bash release/build-release.sh --repro   # anonymized package in dist/ (about 2 minutes)
```

## Layout

`Sources/EmbalmCore` engine and format. `Sources/EmbalmGUI` AppKit app. `Sources/embalm-cli`
helper tool. `release/` packaging, setup script, entitlements. `app/icon-gen.swift` icons.

## Rules that matter

- **Crypto changes** need a matching test in `SelfCheck.swift`. Old v1/v2 files must keep
  opening (fixtures in `LegacyFixtures.swift`). Never store anything about the plaintext in
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
- Do not commit `dist/`, `.build/`, or any `.embalm` file.
