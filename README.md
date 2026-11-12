# Embalm

Encrypt a file so only your password opens it, with a tripwire that destroys the
file after two wrong passwords in a row. Everything runs locally; the app is
sandboxed and has no network permission.

- **Embalm**: pick a password (typed twice) and get an encrypted `.embalm` file.
- **Mummify**: the reverse. The original file comes back byte for byte, with its
  original name, even if the `.embalm` file was renamed in transit.
- **Self-destruct**: two consecutive wrong passwords overwrite the key and the
  data. Afterwards not even the correct password opens it.

The tripwire protects the copy it fires on. Someone who copies the file first can
guess against the copy, so the password and Argon2id remain the real protection
(see [what this does and does not protect against](#what-this-does-and-does-not-protect-against)).

Requires macOS 12 or later on Apple Silicon. The Swift command line tools are
enough to build it; Xcode is not needed.

## Layout

| Path | Purpose |
|------|---------|
| `Sources/EmbalmCore` | Engine, container format, built-in self-check suite |
| `Sources/EmbalmGUI` | AppKit app (drop zone, menus, Open With, save-panel flow) |
| `Sources/embalm-cli` | `embalm seal / open / info / selfcheck` |
| `Sources/embalm-selftest` | Dev runner for the same suite the app ships with |
| `integration/` | Finder Quick Actions for a development Mac |
| `release/` | Anonymized release build, setup and assessment for another Mac |
| `app/icon-gen.swift` | Draws the app and document icons |

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
swift run embalm-selftest          # 36 checks: known answers, round trips, tampering, old files
swift build -c release
```

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
the app, helper tool and Quick Actions, then runs an assessment: signature and
permissions, an audit of the program files, a live test inside the sandbox
(attempts a network connection and a read of the user's folders, expecting the
operating system to refuse both), the cryptographic self-check, and advice about
the Mac itself. It prints `PRIVACY CHECK: PASSED` or `FAILED`.

## Container format (v3)

Envelope encryption. A random 256-bit key encrypts the data in 1 MiB chunks with
AES-256-GCM. That key is wrapped under a key derived from the password with
Argon2id (512 MiB, 4 passes, 4 lanes by default). The header is checksummed, and
the wrap authenticates the header fields, so the KDF settings, attempt limit and
chunk size cannot be altered undetected. Chunk nonces include an index and a
final-chunk flag, so chunks cannot be reordered, dropped or truncated.

The encrypted data holds the original file name and is padded (Padmé, with a 4 KiB
floor) so the container size reveals only a rough size class. No hash or other
property of the plaintext is stored in the clear. Older v1 and v2 files still open.

```
0   6   "EMBALM"            94   7   nonce prefix
6   1   version = 3         101  1   chunk size (log2)
7   1   cipher = 2          102  4   reserved
8   1   kdf id              106  4   CRC-32 of bytes 0..105 (byte 14 zeroed)
9   4   kdf parameters      110  8   payload length
13  1   max failures        118  ..  payload: chunks of ciphertext + 16-byte tag
14  1   failure count (the only mutable byte)
15  1   salt length
16  16  salt
32  12  wrap nonce
44  2   wrapped key length
46  48  wrapped key
```

## What this does and does not protect against

- The password is the real protection. Use a long passphrase.
- The attempt limit protects one copy of a file. Someone who copies a `.embalm`
  file first can guess against the copy, so strong passwords and Argon2id are what
  stand in their way.
- The counter lives in the file and can be edited by someone with the file.
- On flash storage, overwriting does not guarantee physical erasure. The guarantee
  is cryptographic: the wrapped key exists nowhere else.
- Container size is hidden to a size class, not exactly. File names are hidden.
- Recovered files are ordinary files: Spotlight, Quick Look, backups and iCloud
  treat them like any other.
- A forgotten password cannot be recovered.

## License

MIT. See [LICENSE](LICENSE). Argon2 comes from
[Argon2Swift](https://github.com/tmthecoder/Argon2Swift), which vendors the PHC
reference implementation; both carry their own licences.
