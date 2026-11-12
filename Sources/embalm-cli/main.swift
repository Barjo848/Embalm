import Foundation
import EmbalmCore

// embalm: command-line interface to the Embalm engine.
//
//   embalm seal <file>  [--out PATH] [--password-stdin] [--kdf argon2id|pbkdf2]
//                       [--iterations N] [--no-padding] [--no-name] [--no-verify]
//                       [--force] [--porcelain]
//   embalm open <file>  [--out PATH] [--password-stdin] [--force] [--porcelain]
//   embalm info <file>
//   embalm selfcheck
//
// Passwords are read from the terminal with no echo, or from stdin with
// --password-stdin. They are never accepted as command-line arguments.

// Never leave a core dump (it could contain key material).
var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
setrlimit(RLIMIT_CORE, &noCore)

enum Exit: Int32 {
    case ok = 0, other = 1
    case wrongPassword = 10, destroyed = 11, integrity = 12, damaged = 13, readOnly = 14
    case usage = 64, notEmbalm = 65, noInput = 66, exists = 73, io = 74
}

func fail(_ message: String, _ code: Exit) -> Never {
    FileHandle.standardError.write(Data(("embalm: " + message + "\n").utf8))
    exit(code.rawValue)
}

func exitCode(for error: EmbalmError) -> Exit {
    switch error {
    case .notAnEmbalmFile, .unsupportedVersion, .corruptHeader: return .notEmbalm
    case .damaged: return .damaged
    case .wrongPassword: return .wrongPassword
    case .destroyed, .alreadyDestroyed: return .destroyed
    case .integrityCheckFailed: return .integrity
    case .readOnlySource: return .readOnly
    case .io: return .io
    case .keyFileNeeded, .keyFileMismatch, .notAKeyFile, .morePasswordsNeeded, .passwordAlreadyGiven,
         .decoyTooLarge, .invalidOptions: return .usage
    }
}

struct Options {
    var input: URL
    var output: URL?
    var passwordStdin = false
    var kdf = "argon2id"
    var iterations: UInt32 = KDF.defaultIterations
    var padding = true, storeName = true, verify = true
    var force = false, porcelain = false
    var keyFile: URL?
}

func parseOptions(_ args: [String], _ command: String) -> Options {
    var positional: [String] = []
    var o = Options(input: URL(fileURLWithPath: "/"))
    var i = 0
    func value(_ flag: String) -> String {
        i += 1
        guard i < args.count else { fail("\(flag) needs a value", .usage) }
        return args[i]
    }
    while i < args.count {
        let a = args[i]
        switch a {
        case "--out", "-o": o.output = URL(fileURLWithPath: value(a))
        case "--password-stdin": o.passwordStdin = true
        case "--key-file": o.keyFile = URL(fileURLWithPath: value(a))
        case "--force", "-f": o.force = true
        case "--porcelain": o.porcelain = true
        case "--no-padding": o.padding = false
        case "--no-name": o.storeName = false
        case "--no-verify": o.verify = false
        case "--kdf":
            let v = value(a)
            guard v == "argon2id" || v == "pbkdf2" else { fail("--kdf must be argon2id or pbkdf2", .usage) }
            o.kdf = v
        case "--iterations":
            guard let n = UInt32(value(a)), n >= 100_000 else { fail("--iterations needs an integer >= 100000", .usage) }
            o.iterations = n
        default:
            if a.hasPrefix("-") { fail("unknown option \(a)", .usage) }
            positional.append(a)
        }
        i += 1
    }
    guard positional.count == 1 else { fail("\(command) expects exactly one file", .usage) }
    o.input = URL(fileURLWithPath: positional[0])
    return o
}

func password(_ o: Options, confirming: Bool) -> String {
    if o.passwordStdin {
        let text = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let pw = lines.first ?? ""
        if confirming, lines.count > 1, !lines[1].isEmpty, lines[1] != pw { fail("passwords did not match", .usage) }
        if pw.isEmpty { fail("the password must not be empty", .usage) }
        return pw
    }
    guard isatty(fileno(stdin)) != 0 else { fail("no terminal for password entry; use --password-stdin", .usage) }
    func ask(_ prompt: String) -> String {
        guard let c = getpass(prompt) else { fail("could not read the password", .io) }
        return String(cString: c)
    }
    let pw = ask("Password: ")
    if pw.isEmpty { fail("the password must not be empty", .usage) }
    if confirming, ask("Confirm password: ") != pw { fail("passwords did not match", .usage) }
    return pw
}

func requireExistingFile(_ url: URL) {
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else { fail("no such file: \(url.path)", .noInput) }
    if isDir.boolValue { fail("\(url.lastPathComponent) is a folder; zip it first", .usage) }
}

func runSeal(_ args: [String]) {
    let o = parseOptions(args, "seal")
    requireExistingFile(o.input)
    let dir = o.input.deletingLastPathComponent()
    let output = o.output ?? EmbalmEngine.uniqueURL(directory: dir, name: o.input.lastPathComponent + "." + EmbalmEngine.fileExtension)
    if o.output != nil, FileManager.default.fileExists(atPath: output.path), !o.force {
        fail("\(output.lastPathComponent) already exists (use --force to overwrite)", .exists)
    }
    let pw = password(o, confirming: true)
    let choice: KDFChoice = o.kdf == "pbkdf2" ? .pbkdf2(iterations: o.iterations) : .defaultArgon2id
    do {
        try EmbalmEngine.embalm(input: o.input, output: output, password: pw, kdf: choice,
                                padding: o.padding, storeName: o.storeName, verify: o.verify)
        print(o.porcelain ? output.path : "Embalmed \(o.input.lastPathComponent) -> \(output.lastPathComponent)")
    } catch let e as EmbalmError {
        fail(e.description, exitCode(for: e))
    } catch { fail(error.localizedDescription, .other) }
}

func runOpen(_ args: [String]) {
    let o = parseOptions(args, "open")
    requireExistingFile(o.input)
    guard EmbalmEngine.isEmbalmFile(at: o.input) else { fail("\(o.input.lastPathComponent) is not an Embalm file", .notEmbalm) }
    if let out = o.output, FileManager.default.fileExists(atPath: out.path), !o.force {
        fail("\(out.lastPathComponent) already exists (use --force to overwrite)", .exists)
    }
    do {
        // A file that needs several passwords takes them one per line (or prompt).
        let session = try EmbalmEngine.beginOpen(input: o.input, keyFile: o.keyFile)
        defer { session.close() }
        var lines: [String] = []
        if o.passwordStdin {
            lines = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
                .split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        }
        var found: EmbalmEngine.OpenedContainer?
        while found == nil {
            let pw: String
            if o.passwordStdin {
                guard !lines.isEmpty else { fail("\(session.threshold - session.accepted) more password(s) needed", .usage) }
                pw = lines.removeFirst()
            } else {
                pw = password(o, confirming: false)
            }
            found = try session.offer(password: pw)
            if found == nil, !o.passwordStdin {
                FileHandle.standardError.write(Data("Accepted. \(session.threshold - session.accepted) more needed.\n".utf8))
            }
        }
        guard let opened = found else { fail("could not open", .other) }
        defer { opened.close() }
        let output = o.output ?? EmbalmEngine.uniqueURL(
            directory: o.input.deletingLastPathComponent(),
            name: EmbalmEngine.suggestedOutputName(opened: opened, inputName: o.input.lastPathComponent))
        try opened.write(to: output, overwrite: o.force)
        print(o.porcelain ? output.path : "Mummified \(o.input.lastPathComponent) -> \(output.lastPathComponent)")
    } catch let e as EmbalmError {
        fail(e.description, exitCode(for: e))
    } catch { fail(error.localizedDescription, .other) }
}

func runInfo(_ args: [String]) {
    let o = parseOptions(args, "info")
    requireExistingFile(o.input)
    do {
        let s = try EmbalmEngine.inspect(input: o.input, keyFile: o.keyFile)
        print("Embalm container: \(o.input.lastPathComponent)")
        if s.needsKeyFile {
            print("  format version:     \(s.formatVersion)")
            print("  key file:           needed (pass --key-file PATH); nothing more can be read without it")
            return
        }
        if s.holders > 1 { print("  passwords needed:   \(s.threshold) of \(s.holders)") }
        print("  format version:     \(s.formatVersion)")
        print("  key derivation:     \(s.kdfName)")
        print("  file size:          \(s.fileSize) bytes")
        print("  intact:             \(s.structurallyIntact ? "yes" : "NO - \(s.problem ?? "damaged")")")
        print("  failed attempts:    \(s.failureCount) of \(s.maxFailures)")
        print("  remaining attempts: \(s.remainingAttempts)")
        print("  destroyed:          \(s.isDestroyed ? "yes" : "no")")
        if s.exposesLegacyFingerprint {
            print("  note:               legacy v1 file; it exposes a plaintext fingerprint. Open and re-embalm it to upgrade.")
        }
    } catch let e as EmbalmError {
        fail(e.description, exitCode(for: e))
    } catch { fail(error.localizedDescription, .other) }
}

func runSelfCheck() {
    var group = "", total = 0, bad = 0
    let ok = SelfCheck.runCrypto { r in
        if r.group != group { group = r.group; print("[\(group)]") }
        total += 1; if !r.passed { bad += 1 }
        print("  \(r.passed ? "[ OK ]" : "[FAIL]") \(r.name)\(r.detail.isEmpty ? "" : " (\(r.detail))")")
    }
    print("\n\(total - bad)/\(total) checks passed")
    exit(ok ? 0 : 1)
}

func usage() -> Never {
    print("""
    Embalm: encrypt a file so only your password can open it.

    USAGE:
      embalm seal <file>  [--out PATH] [--password-stdin] [--kdf argon2id|pbkdf2]
                          [--iterations N] [--no-padding] [--no-name] [--no-verify]
                          [--force] [--porcelain]
      embalm open <file>  [--out PATH] [--key-file PATH] [--password-stdin] [--force] [--porcelain]
      embalm info <file>  [--key-file PATH]
      embalm selfcheck

    NOTES:
      * Duress passwords, several passwords and key files are set up in the app.
        This tool opens such files: several passwords are asked for one at a time.
      * Files are recognised by their content, so a renamed or re-downloaded
        .emb file still opens, and its original name is restored.
      * Existing files are never overwritten unless you pass --force.
      * Two wrong passwords in a row destroy the file permanently.
      * Passwords come from the terminal (no echo) or stdin, never from arguments.
    """)
    exit(Exit.usage.rawValue)
}

let argv = Array(CommandLine.arguments.dropFirst())
guard let command = argv.first else { usage() }
let rest = Array(argv.dropFirst())
switch command {
case "seal", "embalm": runSeal(rest)
case "open", "mummify": runOpen(rest)
case "info": runInfo(rest)
case "selfcheck": runSelfCheck()
case "-h", "--help", "help": usage()
default: fail("unknown command \(command)", .usage)
}
