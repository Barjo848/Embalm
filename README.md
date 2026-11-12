# Embalm

Encrypt a file so only your password opens it, with a tripwire that destroys the
file after two wrong passwords in a row. Everything runs locally; the app is
sandboxed and has no network permission.

- **Embalm**: right-click any file, pick a password (typed twice, or generated for
  you) and get an encrypted `.emb` file.
- **Mummify**: the reverse, from a right-click on any `.emb` file. The original file comes back byte for byte, with its
  original name, even if the `.emb` file was renamed in transit.
- **Self-destruct**: two consecutive wrong passwords overwrite the key and the
  data. Afterwards not even the correct password opens it.
- **Optional extras**: a duress password that opens a decoy and destroys the real
  key, files that need several people's passwords, and a separate key file.

The tripwire protects the copy it fires on. Someone who copies the file first can
guess against the copy, so the password and Argon2id remain the real protection
(see [what this does and does not protect against](#what-this-does-and-does-not-protect-against)).

Requires macOS 12 or later on Apple Silicon. The Swift command line tools are
enough to build it; Xcode is not needed.

## Layout

| Path | Purpose |
|------|---------|
| `Sources/EmbalmCore` | Engine, container format, password generator, built-in self-check suite |
| `Sources/EmbalmGUI` | AppKit app (drop zone, generator, menus, save-panel flow) |
| `Sources/embalm-cli` | Developer tool, not installed: `embalm seal / open / info / selfcheck` |
| `Sources/embalm-selftest` | Dev runner for the same suite the app ships with |
| `release/` | Anonymized release build, setup and assessment |
| `app/icon-gen.swift` | Draws the app and document icons |

## One app, two right-click actions

Everything runs in the app. Setup adds two Finder Quick Actions, and each is a
single line that opens the selected files in Embalm:

- **Embalm** is offered for every file.
- **Mummify** is offered for files ending in `.emb`.

The app looks at a file's contents, not its name, to decide what to do. Finder can
only offer actions by file type, so Embalm also appears on `.emb` files, and an
embalmed file that lost its extension shows only Embalm; either way the app sees
what the file is and mummifies it.

Files made by earlier versions end in `.embalm`; they keep their icon, their
Mummify action and open exactly as before.

## Password generator

Generate, beside the password box, makes a password from the system's secure random
source: 3 to 10 words from the EFF large word list (optionally capitalized, with a
digit after each word), or 12 to 64 random characters (optionally with symbols).
The window states the exact strength in bits. Using a password fills in both boxes
and copies it to the clipboard, flagged so clipboard managers that honour the
convention do not keep it.

## The window

A perfect square: 333 points by default, 777 from View, Large Window (remembered).
Every length is a scale-1 value multiplied by side / 333, so one design serves both.
The look is called Atlas: square corners, paper canvas, white panes with 1px
borders, grey chiselled controls, black selection, amber only for keyboard focus,
Heros and Courier Code type, and a 25 pt black bar under the system window buttons.
Settings (⌘,) and Instructions (Help) are menus; Help also runs the self-check.
The icons are drawn as 1-bit pixel art by `app/icon-gen.swift`.

The typefaces are not in this repository. Without them the app builds and runs
with Helvetica and the system monospace. TeX Gyre Heros is free under the GUST Font
License; Courier Code is a commercial Bitstream face, so bundle it only under your
own licence and do not share a package that contains it. To use them, run
`bash release/fetch-fonts.sh <folder holding the three font files>`.

## Develop

```bash
swift run embalm-selftest          # 54 checks: known answers, round trips, tampering, old files, duress, quorum, key files, generator
swift build -c release
```

## Install

Download `Embalm.dmg` from the [latest release](https://github.com/Barjo848/Embalm/releases/latest),
open it and double-click **Install Embalm**. The standard macOS installer
shows the licence, asks whether to install for all users or only for you, lets you
leave out the Finder right-click actions, and shows progress. When it has closed,
Embalm offers to move the disk image to the Trash.

The app is signed ad hoc, with no Developer ID, so a copy downloaded from the
internet is stopped by Gatekeeper the first time: open System Settings, Privacy &
Security, and choose Open Anyway.

To remove it: delete `Embalm.app` from Applications, and `Embalm.workflow` and
`Mummify.workflow` from `/Library/Services` (or `~/Library/Services` if you installed
only for yourself).

Build the disk image with `bash release/build-dmg.sh`. It uses the shareable build,
which bundles only the freely licensed typeface.

## Build the release package

```bash
bash release/build-release.sh --repro
```

Produces `dist/Embalm-Setup.zip` and `dist/RELEASE-INFO.txt` (fingerprints and the
single command to run on the target Mac). The build:

- bundles the typefaces if `release/fonts` holds all three, and otherwise uses
  system faces,
- compiles from a clean tree with source paths remapped and debug data dropped,
- removes toolchain traces from the binaries and strips them,
- signs ad hoc with the hardened runtime and the sandbox entitlements only,
- normalizes permissions, attributes and timestamps, and writes a SHA-256 manifest,
- scans every byte of the result for names, paths, hosts and tool identifiers
  (`release/private-scan.py`, which stays on the build machine) and stops if
  anything is found. It takes the builder's identity from the machine and from
  git; list anything else in an untracked `release/private-scan.local`, one
  literal per line,
- with `--repro`, builds twice and checks the zips are byte-identical.

On the target Mac, `setup.sh` verifies the package against the manifest, installs
the app and the two Quick Actions, then runs an assessment: signature and
permissions, an audit of the program files, a live test inside the sandbox
(attempts a network connection and a read of the user's folders, expecting the
operating system to refuse both), the cryptographic self-check, and advice about
the Mac itself. It prints `PRIVACY CHECK: PASSED` or `FAILED`.

## Extra protection (off by default)

Three options in Settings, each off until switched on:

- **Duress password.** A second password that opens a small decoy file (up to 65 KB)
  and, without any sign, overwrites the slot holding the real key. Afterwards the real
  password is simply wrong.
- **Several passwords.** 2 of 2, 2 of 3 or 3 of 5: each holder chooses a password and
  the file opens only when enough of them are entered. Not combinable with duress.
- **Separate key file.** The key block is written to a small `.embkey` file. The
  embalmed file alone has no salt and no wrapped key, so it cannot be used to guess
  passwords, and deleting the key file kills every copy of it.

## Container format (v4)

Envelope encryption. A random 256-bit key encrypts the data in 1 MiB chunks with
AES-256-GCM. Chunk nonces include an index and a final-chunk flag, so chunks cannot
be reordered, dropped or truncated. Passwords are stretched with Argon2id (512 MiB,
4 passes, 4 lanes by default) and unwrap that key from a slot. The header is
checksummed and every slot authenticates it, so the KDF settings, attempt limit,
lengths and password layout cannot be altered undetected.

The encrypted data holds the original file name and is padded (Padmé, with a 4 KiB
floor) so the container size reveals only a rough size class. No hash or other
property of the plaintext is stored in the clear.

```
Key block                                    Body
0   6   "EMBALM" ("EMBKEY" in a key file)    decoy region, 65,552 bytes, always present
6   1   version = 4                          payload: chunks of ciphertext + 16-byte tag
7   1   kind = 2
8   1   kdf id                               Stub at the start of a body file whose key
9   4   kdf parameters                       block is in a key file (36 bytes): magic,
13  1   max failures                         version, kind = 3, file id, payload length,
14  1   failure count (the only mutable byte)  CRC-32
15  1   flags (bit 0: key block is detached)
16  16  salt
32  16  file id
48  7   payload nonce prefix
55  7   decoy nonce prefix
62  1   chunk size (log2)
63  1   passwords needed
64  1   passwords issued
65  1   slot count
66  8   payload length
74  4   CRC-32 of bytes 0..73 (byte 14 zeroed)
78  ..  slots, 61 bytes each: nonce | AES-256-GCM(role, 32-byte key) | tag
```

- **One password:** two slots in random order. One wraps the data key. The other wraps
  the decoy key if there is a duress password, and is random bytes if not; the decoy
  region is likewise a sealed decoy or random bytes. Every single-password file
  therefore has the same size and layout, and nothing in it shows whether a duress
  password exists. The cost is 64 KiB per file.
- **Several passwords:** one slot per holder, wrapping a random holder secret under
  that holder's password, then one slot per qualifying group of holders, wrapping the
  data key under HKDF-SHA256 of the group's secrets. Only standard primitives are
  used; there is no secret-sharing arithmetic to get wrong.
- All slots share one salt, so each password entered costs one Argon2id run.

Files written by earlier versions (v1 to v3) still open.

## What this does and does not protect against

- The password is the real protection. Use a long passphrase.
- The attempt limit protects one copy of a file. Someone who copies a `.emb`
  file first can guess against the copy, so strong passwords and Argon2id are what
  stand in their way.
- The counter lives in the file (or its key file) and can be edited by someone with it.
- The duress password destroys the key in the copy it is used on, not in other copies.
  The file does not show whether one was set, but anyone who knows Embalm knows it is
  possible, so it buys doubt, not proof.
- A separate key file moves the weak point: whoever holds both files is back to
  guessing the password.
- On flash storage, overwriting does not guarantee physical erasure. The guarantee
  is cryptographic: the wrapped key exists nowhere else.
- Container size is hidden to a size class, not exactly. File names are hidden.
- Recovered files are ordinary files: Spotlight, Quick Look, backups and iCloud
  treat them like any other.
- A forgotten password cannot be recovered.

## License

MIT. See [LICENSE](LICENSE). Argon2 comes from
[Argon2Swift](https://github.com/tmthecoder/Argon2Swift), which vendors the PHC
reference implementation; both carry their own licences. The word list in
`Sources/EmbalmCore/Wordlist.swift` is the EFF Large Wordlist for Passphrases,
used under CC BY 3.0 US, with eight words removed.
