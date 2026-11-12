import Foundation
import CryptoKit

public struct CheckResult {
    public let group: String
    public let name: String
    public let passed: Bool
    public let detail: String

    public init(group: String, name: String, passed: Bool, detail: String) {
        self.group = group; self.name = name; self.passed = passed; self.detail = detail
    }
}

/// Built-in verification of the cryptography and file handling. The same suite
/// runs in development, in the CLI and inside the shipped app, so what was
/// tested at build time is exactly what runs on the target Mac.
public enum SelfCheck {

    private struct Fail: Error { let message: String }

    private static func expect(_ condition: Bool, _ message: String) throws {
        if !condition { throw Fail(message: message) }
    }
    private static func expectError(_ expected: EmbalmError, _ body: () throws -> Void) throws {
        do { try body() } catch let e as EmbalmError {
            if e == expected { return }
            throw Fail(message: "expected \(expected), got \(e)")
        }
        throw Fail(message: "expected \(expected), but nothing was thrown")
    }
    private static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private static let fastArgon = KDFChoice.argon2id(timeCost: 1, memoryLog2KiB: 10, parallelism: 1)
    private static let fastPBKDF = KDFChoice.pbkdf2(iterations: 1000)

    /// Runs every check, reporting each as it finishes. Returns true if all passed.
    @discardableResult
    public static func runCrypto(report: (CheckResult) -> Void) -> Bool {
        var allPassed = true
        func run(_ group: String, _ name: String, _ body: () throws -> String?) {
            let r: CheckResult
            do { r = CheckResult(group: group, name: name, passed: true, detail: try body() ?? "") }
            catch let f as Fail { r = CheckResult(group: group, name: name, passed: false, detail: f.message) }
            catch { r = CheckResult(group: group, name: name, passed: false, detail: "\(error)") }
            if !r.passed { allPassed = false }
            report(r)
        }

        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("embalm-check-\(UUID().uuidString)")
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }

        func put(_ data: Data, _ name: String) throws -> URL {
            let u = dir.appendingPathComponent(name)
            try data.write(to: u)
            return u
        }
        func seal(_ data: Data, name: String = "payload.bin", password: String = "pw",
                  kdf: KDFChoice = fastArgon, padding: Bool = true) throws -> URL {
            let sub = dir.appendingPathComponent(UUID().uuidString)
            try fm.createDirectory(at: sub, withIntermediateDirectories: true)
            let input = sub.appendingPathComponent(name)
            try data.write(to: input)
            let out = sub.appendingPathComponent("sealed.embalm")
            try EmbalmEngine.embalm(input: input, output: out, password: password, kdf: kdf, padding: padding)
            return out
        }
        func open(_ container: URL, _ password: String = "pw") throws -> Data {
            let out = container.deletingLastPathComponent().appendingPathComponent("out-\(UUID().uuidString)")
            try EmbalmEngine.mummify(input: container, output: out, password: password)
            return try Data(contentsOf: out)
        }
        func mutate(_ url: URL, _ change: (inout [UInt8]) -> Void) throws {
            var bytes = [UInt8](try Data(contentsOf: url))
            change(&bytes)
            try Data(bytes).write(to: url)
        }
        func failures(_ url: URL) throws -> Int { try EmbalmEngine.inspect(input: url).failureCount }

        let C = EmbalmEngine.chunkSize

        // MARK: known answers
        run("Known answers", "AES-256-GCM matches the published test vector") {
            let key = SymmetricKey(data: Data(count: 32))
            let box = try AES.GCM.seal(Data(count: 16), using: key, nonce: AES.GCM.Nonce(data: Data(count: 12)))
            try expect(hex(box.ciphertext) == "cea7403d4d606b6e074ec5d3baf39d18", "ciphertext mismatch")
            try expect(hex(box.tag) == "d0d1c8a799996bf0265b98b5d48ab919", "tag mismatch")
            return nil
        }
        run("Known answers", "PBKDF2-HMAC-SHA256 matches RFC 7914") {
            let k = KDF.pbkdf2(password: "passwd", salt: Data("salt".utf8), iterations: 1)
            try expect(hex(k) == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", "derived key mismatch")
            return nil
        }
        run("Known answers", "Argon2id matches the reference implementation vector") {
            let k = try KDFChoice.argon2id(timeCost: 2, memoryLog2KiB: 16, parallelism: 1)
                .deriveKey(password: "password", salt: Data("somesalt".utf8), normalize: false)
            try expect(hex(k) == "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", "derived key mismatch")
            return nil
        }
        run("Known answers", "CRC-32 matches the standard check value") {
            try expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF43926, "checksum mismatch")
            return nil
        }
        run("Known answers", "Length padding never shrinks and stays within 12.5%") {
            var last: UInt64 = 0
            for l in stride(from: UInt64(12), to: 5_000_000, by: 997) {
                let p = Padding.padme(l)
                try expect(p >= l, "padme shrank \(l)")
                try expect(l < 64 || Double(p) <= Double(l) * 1.125 + 1, "padme overhead too large at \(l)")
                try expect(p >= last, "padme not monotonic at \(l)")
                last = p
            }
            return nil
        }

        // MARK: round trips
        run("Round trip", "Files of many sizes come back byte-for-byte identical") {
            let sizes = [0, 1, 11, 4083, 4084, 100_000, C - 40, C - 13, C - 12, C - 11, C, C + 1,
                         2 * C - 5, 3 * C + 777]
            for padding in [true, false] {
                for n in sizes {
                    let original = RandomBytes.makeData(n)
                    let c = try seal(original, padding: padding)
                    let recovered = try open(c)
                    try expect(recovered == original, "size \(n) padding \(padding) differs")
                    try expect(Data(SHA256.hash(data: recovered)) == Data(SHA256.hash(data: original)), "digest differs at \(n)")
                }
            }
            return "\(sizes.count * 2) cases, including chunk boundaries"
        }
        run("Round trip", "A multi-chunk file recovers exactly after real chunking") {
            let original = RandomBytes.makeData(5 * C / 2 + 123)
            let c = try seal(original)
            let st = try EmbalmEngine.inspect(input: c)
            try expect(st.formatVersion == 3 && st.structurallyIntact, "bad status")
            try expect(try open(c) == original, "differs")
            return "\(st.fileSize) bytes on disk"
        }
        run("Round trip", "PBKDF2 containers also round trip") {
            let original = RandomBytes.makeData(5000)
            try expect(try open(try seal(original, kdf: fastPBKDF)) == original, "differs")
            return nil
        }
        run("Round trip", "The container does not contain the plaintext or its SHA-256") {
            let original = Data(repeating: 0x41, count: 20_000) + RandomBytes.makeData(500)
            let raw = try Data(contentsOf: try seal(original))
            try expect(raw.range(of: Data(SHA256.hash(data: original))) == nil, "digest found")
            try expect(raw.range(of: Data(repeating: 0x41, count: 64)) == nil, "plaintext found")
            return nil
        }

        // MARK: metadata
        run("Metadata", "The original file name is restored from inside the encrypted data") {
            let c = try seal(RandomBytes.makeData(900), name: "Quarterly Report.zip")
            let opened = try EmbalmEngine.unlock(input: c, password: "pw")
            defer { opened.close() }
            try expect(opened.originalName == "Quarterly Report.zip", "name was \(opened.originalName ?? "nil")")
            try expect(opened.dataSize == 900, "size was \(opened.dataSize)")
            let raw = try Data(contentsOf: c)
            try expect(raw.range(of: Data("Quarterly".utf8)) == nil, "name visible in the container")
            return nil
        }
        run("Metadata", "Files of similar size produce containers of identical size") {
            let a = try Data(contentsOf: try seal(RandomBytes.makeData(100))).count
            let b = try Data(contentsOf: try seal(RandomBytes.makeData(3000))).count
            try expect(a == b, "\(a) vs \(b)")
            return "\(a) bytes"
        }
        run("Metadata", "Hostile file names are reduced to a safe single name") {
            try expect(EmbalmEngine.sanitizedFilename("../../etc/passwd") == "passwd", "traversal")
            try expect(EmbalmEngine.sanitizedFilename("a\\b\\c.txt") == "c.txt", "backslash")
            try expect(EmbalmEngine.sanitizedFilename("..") == nil, "dotdot")
            try expect(EmbalmEngine.sanitizedFilename("  ") == nil, "blank")
            try expect(EmbalmEngine.sanitizedFilename("x\u{0}y\u{7}z.txt") == "xyz.txt", "control characters")
            try expect(EmbalmEngine.sanitizedFilename(String(repeating: "a", count: 300)) == nil, "too long")
            return nil
        }
        run("Metadata", "Existing files are never overwritten by default naming") {
            _ = try put(Data("x".utf8), "dup.txt")
            let u = EmbalmEngine.uniqueURL(directory: dir, name: "dup.txt")
            try expect(u.lastPathComponent == "dup (1).txt", "got \(u.lastPathComponent)")
            return nil
        }
        run("Metadata", "Embalm files are recognised by content, not by name") {
            let c = try seal(RandomBytes.makeData(50))
            let renamed = dir.appendingPathComponent("holiday photos.zip.txt")
            try fm.copyItem(at: c, to: renamed)
            try expect(EmbalmEngine.isEmbalmFile(at: renamed), "not recognised")
            let plain = try put(Data("PK\u{3}\u{4}...".utf8), "plain.zip")
            try expect(!EmbalmEngine.isEmbalmFile(at: plain), "false positive")
            return nil
        }
        run("Metadata", "A renamed container still opens and restores its name") {
            let c = try seal(RandomBytes.makeData(70), name: "notes.txt")
            let renamed = c.deletingLastPathComponent().appendingPathComponent("attachment (2).bin")
            try fm.moveItem(at: c, to: renamed)
            let opened = try EmbalmEngine.unlock(input: renamed, password: "pw")
            defer { opened.close() }
            try expect(EmbalmEngine.suggestedOutputName(opened: opened, inputName: "attachment (2).bin") == "notes.txt", "name lost")
            return nil
        }

        // MARK: passwords
        run("Passwords", "The same typed password works whatever keyboard composed it") {
            let c = try seal(Data("unicode".utf8), password: "caf\u{E9}")
            _ = try open(c, "cafe\u{301}")
            return nil
        }
        run("Passwords", "An empty or different password is rejected") {
            let c = try seal(Data("x".utf8))
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(c, "") }
            return nil
        }

        // MARK: self-destruct
        run("Self-destruct", "One wrong password leaves the file recoverable") {
            let original = RandomBytes.makeData(3000)
            let c = try seal(original)
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(c, "WRONG") }
            try expect(try failures(c) == 1, "counter not saved")
            try expect(try open(c) == original, "no longer opens")
            return nil
        }
        run("Self-destruct", "A correct password resets the count, so only consecutive misses count") {
            let c = try seal(RandomBytes.makeData(100))
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(c, "WRONG") }
            _ = try open(c)
            try expect(try failures(c) == 0, "not reset")
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(c, "WRONG") }
            return nil
        }
        run("Self-destruct", "Two wrong passwords in a row destroy the file for good") {
            let original = RandomBytes.makeData(3 * C / 2)
            let c = try seal(original)
            let before = [UInt8](try Data(contentsOf: c))
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(c, "WRONG1") }
            try expectError(.destroyed) { _ = try open(c, "WRONG2") }
            try expectError(.alreadyDestroyed) { _ = try open(c, "pw") }
            let after = [UInt8](try Data(contentsOf: c))
            try expect(after.count == before.count, "size changed")
            let keyRegion = EmbalmFormat.offWrappedDEK..<(EmbalmFormat.offWrappedDEK + 48)
            try expect(Array(after[keyRegion]) != Array(before[keyRegion]), "key not overwritten")
            let payloadStart = EmbalmFormat.v3HeaderLength
            let same = zip(before[payloadStart...], after[payloadStart...]).filter { $0 == $1 }.count
            try expect(Double(same) < Double(before.count - payloadStart) * 0.02, "payload not overwritten")
            return nil
        }
        run("Self-destruct", "A damaged or truncated file never uses up an attempt") {
            let c = try seal(RandomBytes.makeData(5000))
            try mutate(c) { $0.removeLast() }
            try expect(try failures(c) == 0, "inspect changed state")
            do { _ = try open(c) } catch let e as EmbalmError {
                if case .damaged = e { } else { throw Fail(message: "got \(e)") }
            }
            try expect(try failures(c) == 0, "counter moved on a damaged file")
            return nil
        }
        run("Self-destruct", "Files on read-only storage are refused, not silently unprotected") {
            if getuid() == 0 { return "skipped (running as root)" }
            let c = try seal(RandomBytes.makeData(100))
            try fm.setAttributes([.posixPermissions: 0o444], ofItemAtPath: c.path)
            defer { try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: c.path) }
            try expectError(.readOnlySource) { _ = try open(c) }
            return nil
        }

        // MARK: tampering and transit damage
        run("Tampering", "A changed byte in a later chunk is caught and no output is kept") {
            let c = try seal(RandomBytes.makeData(5 * C / 2))
            try mutate(c) { $0[EmbalmFormat.v3HeaderLength + (C + 16) + 100] ^= 0x01 }
            let opened = try EmbalmEngine.unlock(input: c, password: "pw")
            defer { opened.close() }
            let out = dir.appendingPathComponent("tamper-out")
            try expectError(.integrityCheckFailed) { try opened.write(to: out) }
            try expect(!fm.fileExists(atPath: out.path), "partial output left behind")
            return nil
        }
        run("Tampering", "A changed byte in the first chunk is caught") {
            let c = try seal(RandomBytes.makeData(5000))
            try mutate(c) { $0[EmbalmFormat.v3HeaderLength + 20] ^= 0x80 }
            try expectError(.integrityCheckFailed) { _ = try open(c) }
            return nil
        }
        run("Tampering", "Swapped chunks are caught") {
            let c = try seal(RandomBytes.makeData(5 * C / 2))
            try mutate(c) { b in
                let s = EmbalmFormat.v3HeaderLength, u = C + 16
                let first = Array(b[s..<(s + u)]), second = Array(b[(s + u)..<(s + 2 * u)])
                b.replaceSubrange(s..<(s + u), with: second)
                b.replaceSubrange((s + u)..<(s + 2 * u), with: first)
            }
            try expectError(.integrityCheckFailed) { _ = try open(c) }
            return nil
        }
        run("Tampering", "Cutting off the last chunk and fixing the length is caught") {
            let c = try seal(RandomBytes.makeData(5 * C / 2))
            try mutate(c) { b in
                let u = C + 16
                let payload = b.count - EmbalmFormat.v3HeaderLength
                let n = (payload + u - 1) / u
                let lastLen = payload - (n - 1) * u
                b.removeLast(lastLen)
                var d = Data(); d.appendBigEndian(UInt64(payload - lastLen))
                b.replaceSubrange(EmbalmFormat.v3OffPayloadLen..<(EmbalmFormat.v3OffPayloadLen + 8), with: d)
            }
            try expectError(.integrityCheckFailed) { _ = try open(c) }
            return nil
        }
        run("Tampering", "Extra bytes appended to the file are reported as damage") {
            let c = try seal(RandomBytes.makeData(500))
            try mutate(c) { $0.append(0) }
            do { _ = try open(c) } catch let e as EmbalmError { if case .damaged = e { return nil }; throw Fail(message: "got \(e)") }
            throw Fail(message: "no error")
        }
        run("Tampering", "Header damage in transit is reported as damage, not a wrong password") {
            let c = try seal(RandomBytes.makeData(500))
            try mutate(c) { $0[EmbalmFormat.offSalt + 3] ^= 0x10 }
            do { _ = try open(c) } catch let e as EmbalmError { if case .damaged = e { return nil }; throw Fail(message: "got \(e)") }
            throw Fail(message: "no error")
        }
        run("Tampering", "A forged header with a fixed checksum still cannot be opened") {
            let c = try seal(RandomBytes.makeData(500))
            try mutate(c) { b in
                b[EmbalmFormat.offMaxFailures] = 99
                var masked = Array(b[0..<106]); masked[EmbalmFormat.offFailureCount] = 0
                var d = Data(); d.appendBigEndian(CRC32.checksum(masked))
                b.replaceSubrange(EmbalmFormat.v3OffCRC..<(EmbalmFormat.v3OffCRC + 4), with: d)
            }
            do { _ = try open(c) } catch let e as EmbalmError { if case .wrongPassword = e { return nil }; throw Fail(message: "got \(e)") }
            throw Fail(message: "the forged file opened")
        }
        run("Tampering", "Folders and non-files are refused") {
            let out = dir.appendingPathComponent("folder.embalm")
            do { try EmbalmEngine.embalm(input: dir, output: out, password: "pw", kdf: fastArgon) }
            catch is EmbalmError { return nil }
            throw Fail(message: "a folder was accepted")
        }
        run("Tampering", "A hostile header cannot demand absurd memory") {
            do { _ = try KDFChoice(kdfId: 2, paramWord: (3 << 24) | (31 << 16) | (4 << 8)) }
            catch is EmbalmError { return nil }
            throw Fail(message: "2 TiB request was accepted")
        }

        // MARK: older files
        for fixture in LegacyFixtures.all {
            run("Older files", "\(fixture.name) still opens") {
                guard let data = Data(base64Encoded: fixture.base64) else { throw Fail(message: "bad fixture") }
                let u = try put(data, "legacy-\(UUID().uuidString).embalm")
                let recovered = try open(u, "fixture-pass")
                try expect(String(decoding: recovered, as: UTF8.self) == fixture.plaintext, "content differs")
                return nil
            }
        }
        run("Older files", "Legacy files that expose a fingerprint are flagged") {
            guard let data = Data(base64Encoded: LegacyFixtures.all[0].base64) else { throw Fail(message: "bad fixture") }
            let u = try put(data, "legacy-flag.embalm")
            try expect(try EmbalmEngine.inspect(input: u).exposesLegacyFingerprint, "not flagged")
            return nil
        }

        // MARK: production settings
        run("Production settings", "Default Argon2id settings seal and open a file") {
            let t0 = Date()
            let original = RandomBytes.makeData(4096)
            let c = try seal(original, kdf: .defaultArgon2id)
            let t1 = Date()
            let recovered = try open(c)
            let t2 = Date()
            try expect(recovered == original, "differs")
            let name = try EmbalmEngine.inspect(input: c).kdfName
            return String(format: "%@; seal %.1fs, open %.1fs", name, t1.timeIntervalSince(t0), t2.timeIntervalSince(t1))
        }
        return allPassed
    }
}
