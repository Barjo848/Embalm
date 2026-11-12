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
            let out = sub.appendingPathComponent("sealed.emb")
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
        typealias V4 = EmbalmFormat.V4

        /// A fresh folder holding `data` as `name`, for tests that set their own options.
        func source(_ data: Data, _ name: String = "secret.txt") throws -> (dir: URL, input: URL, out: URL) {
            let sub = dir.appendingPathComponent(UUID().uuidString)
            try fm.createDirectory(at: sub, withIntermediateDirectories: true)
            let input = sub.appendingPathComponent(name)
            try data.write(to: input)
            return (sub, input, sub.appendingPathComponent(name + ".emb"))
        }
        func contents(_ o: EmbalmEngine.OpenedContainer) throws -> Data {
            defer { o.close() }
            let out = dir.appendingPathComponent("out-\(UUID().uuidString)")
            try o.write(to: out)
            return try Data(contentsOf: out)
        }

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
            try expect(st.formatVersion == 4 && st.structurallyIntact, "bad status")
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
            let keyRegion = V4.headLength..<V4.plainDecoyOffset
            let unchanged = zip(before[keyRegion], after[keyRegion]).filter { $0 == $1 }.count
            try expect(unchanged < 12, "key slots not overwritten")
            let payloadStart = V4.plainDecoyOffset
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
            try mutate(c) { $0[V4.plainPayloadOffset + (C + 16) + 100] ^= 0x01 }
            let opened = try EmbalmEngine.unlock(input: c, password: "pw")
            defer { opened.close() }
            let out = dir.appendingPathComponent("tamper-out")
            try expectError(.integrityCheckFailed) { try opened.write(to: out) }
            try expect(!fm.fileExists(atPath: out.path), "partial output left behind")
            return nil
        }
        run("Tampering", "A changed byte in the first chunk is caught") {
            let c = try seal(RandomBytes.makeData(5000))
            try mutate(c) { $0[V4.plainPayloadOffset + 20] ^= 0x80 }
            try expectError(.integrityCheckFailed) { _ = try open(c) }
            return nil
        }
        run("Tampering", "Swapped chunks are caught") {
            let c = try seal(RandomBytes.makeData(5 * C / 2))
            try mutate(c) { b in
                let s = V4.plainPayloadOffset, u = C + 16
                let first = Array(b[s..<(s + u)]), second = Array(b[(s + u)..<(s + 2 * u)])
                b.replaceSubrange(s..<(s + u), with: second)
                b.replaceSubrange((s + u)..<(s + 2 * u), with: first)
            }
            try expectError(.integrityCheckFailed) { _ = try open(c) }
            return nil
        }
        run("Tampering", "Cutting off the last chunk is caught, even with the length and checksum fixed") {
            let c = try seal(RandomBytes.makeData(5 * C / 2))
            var lastLen = 0, payload = 0
            try mutate(c) { b in
                let u = C + 16
                payload = b.count - V4.plainPayloadOffset
                lastLen = payload - ((payload + u - 1) / u - 1) * u
                b.removeLast(lastLen)
            }
            do { _ = try open(c); throw Fail(message: "a cut file opened") }
            catch let e as EmbalmError { guard case .damaged = e else { throw Fail(message: "got \(e)") } }
            try expect(try failures(c) == 0, "an attempt was used")
            // The length is authenticated, so a forged one cannot unwrap the key.
            try mutate(c) { b in
                var d = Data(); d.appendBigEndian(UInt64(payload - lastLen))
                b.replaceSubrange(V4.offPayloadLen..<(V4.offPayloadLen + 8), with: d)
                var masked = Array(b[0..<V4.offCRC]); masked[EmbalmFormat.offFailureCount] = 0
                var crc = Data(); crc.appendBigEndian(CRC32.checksum(masked))
                b.replaceSubrange(V4.offCRC..<(V4.offCRC + 4), with: crc)
            }
            do { _ = try open(c) } catch let e as EmbalmError { if case .wrongPassword = e { return nil }; throw Fail(message: "got \(e)") }
            throw Fail(message: "the forged file opened")
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
                var masked = Array(b[0..<V4.offCRC]); masked[EmbalmFormat.offFailureCount] = 0
                var d = Data(); d.appendBigEndian(CRC32.checksum(masked))
                b.replaceSubrange(V4.offCRC..<(V4.offCRC + 4), with: d)
            }
            do { _ = try open(c) } catch let e as EmbalmError { if case .wrongPassword = e { return nil }; throw Fail(message: "got \(e)") }
            throw Fail(message: "the forged file opened")
        }
        run("Tampering", "Folders and non-files are refused") {
            let out = dir.appendingPathComponent("folder.emb")
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
        run("Older files", "The tripwire still destroys a v3 file") {
            guard let fixture = LegacyFixtures.all.last, let data = Data(base64Encoded: fixture.base64) else { throw Fail(message: "bad fixture") }
            let u = try put(data, "legacy-tripwire.embalm")
            try expect(try EmbalmEngine.inspect(input: u).formatVersion == 3, "not a v3 fixture")
            try expectError(.wrongPassword(remaining: 1)) { _ = try open(u, "WRONG1") }
            try expectError(.destroyed) { _ = try open(u, "WRONG2") }
            try expectError(.alreadyDestroyed) { _ = try open(u, "fixture-pass") }
            return nil
        }
        run("Older files", "Legacy files that expose a fingerprint are flagged") {
            guard let data = Data(base64Encoded: LegacyFixtures.all[0].base64) else { throw Fail(message: "bad fixture") }
            let u = try put(data, "legacy-flag.embalm")
            try expect(try EmbalmEngine.inspect(input: u).exposesLegacyFingerprint, "not flagged")
            return nil
        }

        run("Metadata", "New files end in .emb, and both .emb and the older .embalm are stripped on the way back") {
            try expect(EmbalmEngine.fileExtension == "emb", "extension changed")
            let input = try put(Data("x".utf8), "report.pdf")
            let out = dir.appendingPathComponent("nameless.emb")
            try EmbalmEngine.embalm(input: input, output: out, password: "pw", kdf: fastArgon, storeName: false)
            let o = try EmbalmEngine.unlock(input: out, password: "pw")
            defer { o.close() }
            try expect(o.originalName == nil, "a name was stored")
            for (given, wanted) in [("report.pdf.emb", "report.pdf"), ("report.pdf.EMB", "report.pdf"),
                                    ("report.pdf.embalm", "report.pdf"), ("report.bin", "report.bin.mummified")] {
                let got = EmbalmEngine.suggestedOutputName(opened: o, inputName: given)
                try expect(got == wanted, "\(given) gave \(got)")
            }
            return nil
        }

        // MARK: duress password
        run("Duress password", "The real password opens the file and the duress password opens the decoy") {
            let real = RandomBytes.makeData(9000), fake = Data("nothing to see here".utf8)
            let s = try source(real, "accounts.xlsx")
            let decoy = try put(fake, "shopping list.txt")
            try EmbalmEngine.embalm(input: s.input, output: s.out, password: "pw", kdf: fastArgon,
                                    duress: .init(password: "duress", decoy: decoy))
            let a = try EmbalmEngine.unlock(input: s.out, password: "pw")
            try expect(a.originalName == "accounts.xlsx", "real name lost")
            try expect(try contents(a) == real, "real content differs")
            let b = try EmbalmEngine.unlock(input: s.out, password: "duress")
            try expect(b.originalName == "shopping list.txt", "decoy name lost")
            try expect(try contents(b) == fake, "decoy content differs")
            return nil
        }
        run("Duress password", "Using it destroys the real key for good, and the decoy keeps opening") {
            let s = try source(RandomBytes.makeData(500))
            let decoy = try put(Data("decoy".utf8), "decoy-a.txt")
            try EmbalmEngine.embalm(input: s.input, output: s.out, password: "pw", kdf: fastArgon,
                                    duress: .init(password: "duress", decoy: decoy))
            let before = [UInt8](try Data(contentsOf: s.out))
            _ = try contents(try EmbalmEngine.unlock(input: s.out, password: "duress"))
            let after = [UInt8](try Data(contentsOf: s.out))
            try expectError(.wrongPassword(remaining: 1)) { _ = try EmbalmEngine.unlock(input: s.out, password: "pw") }
            try expect(try contents(try EmbalmEngine.unlock(input: s.out, password: "duress")) == Data("decoy".utf8), "decoy stopped opening")
            // Only one key slot changed; nothing else in the file was touched.
            let changed = before.indices.filter { before[$0] != after[$0] }
            guard let lo = changed.first, let hi = changed.last else { throw Fail(message: "nothing was destroyed") }
            let slot = (lo - V4.headLength) / V4.slotLength
            try expect(lo >= V4.headLength && hi < V4.plainDecoyOffset && (hi - V4.headLength) / V4.slotLength == slot, "more than one slot changed")
            try expect(changed.count > 40, "the slot was not overwritten")
            return nil
        }
        run("Duress password", "A file with a duress password has the same size and layout as one without") {
            let data = RandomBytes.makeData(700)
            let a = try source(data), b = try source(data)
            let decoy = try put(RandomBytes.makeData(40_000), "decoy-b.bin")
            try EmbalmEngine.embalm(input: a.input, output: a.out, password: "pw", kdf: fastArgon)
            try EmbalmEngine.embalm(input: b.input, output: b.out, password: "pw", kdf: fastArgon,
                                    duress: .init(password: "duress", decoy: decoy))
            let x = [UInt8](try Data(contentsOf: a.out)), y = [UInt8](try Data(contentsOf: b.out))
            try expect(x.count == y.count, "\(x.count) vs \(y.count) bytes")
            // Everything in the clear that is not random per file is identical.
            for r in [0..<EmbalmFormat.offSalt, V4.offChunkLog2..<V4.offCRC] {
                try expect(Array(x[r]) == Array(y[r]), "the headers differ at \(r)")
            }
            return "\(x.count) bytes each"
        }
        run("Duress password", "Bad duress settings are refused before anything is written") {
            let s = try source(Data("x".utf8))
            let small = try put(Data("d".utf8), "decoy-c.txt")
            let big = try put(Data(count: EmbalmEngine.maxDecoyBytes + 1), "decoy-big.bin")
            try expectError(.decoyTooLarge) {
                try EmbalmEngine.embalm(input: s.input, output: s.out, password: "pw", kdf: fastArgon, duress: .init(password: "duress", decoy: big))
            }
            do {
                try EmbalmEngine.embalm(input: s.input, output: s.out, password: "caf\u{E9}", kdf: fastArgon,
                                        duress: .init(password: "cafe\u{301}", decoy: small))
                throw Fail(message: "the same password was accepted twice")
            } catch let e as EmbalmError { guard case .invalidOptions = e else { throw Fail(message: "got \(e)") } }
            try expect(!fm.fileExists(atPath: s.out.path), "a file was left behind")
            return nil
        }

        // MARK: several passwords
        run("Several passwords", "With 2 of 3, every pair opens the file, in either order, and one alone does not") {
            let data = RandomBytes.makeData(4000)
            let s = try source(data)
            let pws = ["alpha", "bravo", "charlie"]
            try EmbalmEngine.embalm(input: s.input, output: s.out, passwords: pws, threshold: 2, kdf: fastArgon)
            let st = try EmbalmEngine.inspect(input: s.out)
            try expect(st.threshold == 2 && st.holders == 3, "layout reported as \(st.threshold) of \(st.holders)")
            for (i, j) in [(0, 1), (1, 0), (0, 2), (2, 1)] {
                let session = try EmbalmEngine.beginOpen(input: s.out)
                try expect(try session.offer(password: pws[i]) == nil, "one password opened the file")
                guard let o = try session.offer(password: pws[j]) else { throw Fail(message: "two passwords were not enough") }
                try expect(try contents(o) == data, "content differs")
            }
            try expectError(.morePasswordsNeeded(1)) { _ = try EmbalmEngine.unlock(input: s.out, password: "alpha") }
            try expect(try failures(s.out) == 0, "a right password used an attempt")
            return nil
        }
        run("Several passwords", "2 of 2 and 3 of 5 work, and too few of five do not") {
            let data = RandomBytes.makeData(100)
            let a = try source(data)
            try EmbalmEngine.embalm(input: a.input, output: a.out, passwords: ["one", "two"], threshold: 2, kdf: fastArgon)
            let sa = try EmbalmEngine.beginOpen(input: a.out)
            _ = try sa.offer(password: "two")
            guard let oa = try sa.offer(password: "one") else { throw Fail(message: "2 of 2 did not open") }
            try expect(try contents(oa) == data, "content differs")
            let b = try source(data)
            let five = ["p1", "p2", "p3", "p4", "p5"]
            try EmbalmEngine.embalm(input: b.input, output: b.out, passwords: five, threshold: 3, kdf: fastArgon)
            let sb = try EmbalmEngine.beginOpen(input: b.out)
            try expect(try sb.offer(password: "p5") == nil && sb.offer(password: "p2") == nil, "two of five opened it")
            guard let ob = try sb.offer(password: "p4") else { throw Fail(message: "3 of 5 did not open") }
            try expect(try contents(ob) == data, "content differs")
            return nil
        }
        run("Several passwords", "A repeated password is not counted twice, and wrong ones still trip the wire") {
            let s = try source(RandomBytes.makeData(100))
            try EmbalmEngine.embalm(input: s.input, output: s.out, passwords: ["alpha", "bravo", "charlie"], threshold: 2, kdf: fastArgon)
            let session = try EmbalmEngine.beginOpen(input: s.out)
            _ = try session.offer(password: "alpha")
            try expectError(.passwordAlreadyGiven) { _ = try session.offer(password: "alpha") }
            try expect(session.accepted == 1, "counted twice")
            try expectError(.wrongPassword(remaining: 1)) { _ = try session.offer(password: "WRONG1") }
            try expectError(.destroyed) { _ = try session.offer(password: "WRONG2") }
            session.close()
            try expectError(.alreadyDestroyed) { _ = try EmbalmEngine.unlock(input: s.out, password: "bravo") }
            return nil
        }
        run("Several passwords", "Repeated passwords, or a duress password as well, are refused") {
            let s = try source(Data("x".utf8))
            let decoy = try put(Data("d".utf8), "decoy-d.txt")
            for attempt in 0..<2 {
                do {
                    if attempt == 0 {
                        try EmbalmEngine.embalm(input: s.input, output: s.out, passwords: ["same", "same"], threshold: 2, kdf: fastArgon)
                    } else {
                        try EmbalmEngine.embalm(input: s.input, output: s.out, passwords: ["a", "b"], threshold: 2, kdf: fastArgon,
                                                duress: .init(password: "c", decoy: decoy))
                    }
                    throw Fail(message: "case \(attempt) was accepted")
                } catch let e as EmbalmError { guard case .invalidOptions = e else { throw Fail(message: "got \(e)") } }
            }
            return nil
        }

        // MARK: key file
        run("Key file", "The embalmed file is useless without its key file, and opens with it") {
            let data = RandomBytes.makeData(3 * C / 2)
            let s = try source(data, "plans.pdf")
            let key = s.dir.appendingPathComponent("plans.embkey")
            try EmbalmEngine.embalm(input: s.input, output: s.out, password: "pw", kdf: fastArgon, keyFile: key)
            try expect(EmbalmEngine.isEmbalmFile(at: s.out) && EmbalmEngine.isKeyFile(at: key), "files not recognised")
            try expect(!EmbalmEngine.isKeyFile(at: s.out) && !EmbalmEngine.isEmbalmFile(at: key), "files confused")
            try expect(try EmbalmEngine.inspect(input: s.out).needsKeyFile, "the need for a key file was not reported")
            try expectError(.keyFileNeeded) { _ = try EmbalmEngine.unlock(input: s.out, password: "pw") }
            // The salt and every key slot are in the key file only.
            let body = try Data(contentsOf: s.out), keyBytes = try Data(contentsOf: key)
            try expect(body.range(of: keyBytes.subdata(in: EmbalmFormat.offSalt..<(EmbalmFormat.offSalt + 16))) == nil, "salt found in the embalmed file")
            try expect(body.range(of: keyBytes.subdata(in: V4.headLength..<(V4.headLength + 24))) == nil, "a key slot was found in the embalmed file")
            let o = try EmbalmEngine.unlock(input: s.out, password: "pw", keyFile: key)
            try expect(o.originalName == "plans.pdf", "name lost")
            try expect(try contents(o) == data, "content differs")
            return "key file is \(keyBytes.count) bytes"
        }
        run("Key file", "Another file's key file is refused without using an attempt") {
            let a = try source(RandomBytes.makeData(50)), b = try source(RandomBytes.makeData(50))
            let ka = a.dir.appendingPathComponent("a.embkey"), kb = b.dir.appendingPathComponent("b.embkey")
            try EmbalmEngine.embalm(input: a.input, output: a.out, password: "pw", kdf: fastArgon, keyFile: ka)
            try EmbalmEngine.embalm(input: b.input, output: b.out, password: "pw", kdf: fastArgon, keyFile: kb)
            try expectError(.keyFileMismatch) { _ = try EmbalmEngine.unlock(input: a.out, password: "pw", keyFile: kb) }
            try expectError(.notAKeyFile) { _ = try EmbalmEngine.unlock(input: a.out, password: "pw", keyFile: b.out) }
            try expect(try EmbalmEngine.inspect(input: a.out, keyFile: ka).failureCount == 0, "an attempt was used")
            _ = try contents(try EmbalmEngine.unlock(input: a.out, password: "pw", keyFile: ka))
            return nil
        }
        run("Key file", "The tripwire counts in the key file and destroys both files") {
            let s = try source(RandomBytes.makeData(2000))
            let key = s.dir.appendingPathComponent("k.embkey")
            try EmbalmEngine.embalm(input: s.input, output: s.out, password: "pw", kdf: fastArgon, keyFile: key)
            let bodyBefore = [UInt8](try Data(contentsOf: s.out)), keyBefore = [UInt8](try Data(contentsOf: key))
            try expectError(.wrongPassword(remaining: 1)) { _ = try EmbalmEngine.unlock(input: s.out, password: "WRONG1", keyFile: key) }
            try expect(try EmbalmEngine.inspect(input: s.out, keyFile: key).failureCount == 1, "counter not saved in the key file")
            try expect([UInt8](try Data(contentsOf: s.out)) == bodyBefore, "the embalmed file changed on a first miss")
            try expectError(.destroyed) { _ = try EmbalmEngine.unlock(input: s.out, password: "WRONG2", keyFile: key) }
            try expectError(.alreadyDestroyed) { _ = try EmbalmEngine.unlock(input: s.out, password: "pw", keyFile: key) }
            let bodyAfter = [UInt8](try Data(contentsOf: s.out)), keyAfter = [UInt8](try Data(contentsOf: key))
            let slots = V4.headLength..<keyBefore.count
            try expect(zip(keyBefore[slots], keyAfter[slots]).filter { $0 == $1 }.count < 12, "key slots not overwritten")
            let data = V4.stubLength..<bodyBefore.count
            try expect(Double(zip(bodyBefore[data], bodyAfter[data]).filter { $0 == $1 }.count) < Double(data.count) * 0.02, "data not overwritten")
            return nil
        }
        run("Key file", "A key file works together with a duress password and with several passwords") {
            let data = RandomBytes.makeData(300)
            let a = try source(data)
            let ka = a.dir.appendingPathComponent("a.embkey")
            let decoy = try put(Data("decoy".utf8), "decoy-e.txt")
            try EmbalmEngine.embalm(input: a.input, output: a.out, password: "pw", kdf: fastArgon,
                                    duress: .init(password: "duress", decoy: decoy), keyFile: ka)
            try expect(try contents(try EmbalmEngine.unlock(input: a.out, password: "duress", keyFile: ka)) == Data("decoy".utf8), "decoy differs")
            try expectError(.wrongPassword(remaining: 1)) { _ = try EmbalmEngine.unlock(input: a.out, password: "pw", keyFile: ka) }
            let b = try source(data)
            let kb = b.dir.appendingPathComponent("b.embkey")
            try EmbalmEngine.embalm(input: b.input, output: b.out, passwords: ["x1", "x2", "x3"], threshold: 2, kdf: fastArgon, keyFile: kb)
            let session = try EmbalmEngine.beginOpen(input: b.out, keyFile: kb)
            _ = try session.offer(password: "x3")
            guard let o = try session.offer(password: "x1") else { throw Fail(message: "did not open") }
            try expect(try contents(o) == data, "content differs")
            return nil
        }

        // MARK: password generator
        run("Password generator", "The word list is complete, lowercase and free of duplicates") {
            let w = Wordlist.words
            try expect(w.count == 7768, "count is \(w.count)")
            try expect(Set(w).count == w.count, "duplicates")
            try expect(w.allSatisfy { $0.count >= 3 && $0.allSatisfy { c in c >= "a" && c <= "z" } }, "unexpected characters")
            return "\(w.count) words"
        }
        run("Password generator", "Memorable passwords have the words, capitals and digits asked for") {
            let words = Set(Wordlist.words)
            for n in PasswordGenerator.wordRange {
                for (caps, nums) in [(false, false), (true, false), (false, true), (true, true)] {
                    let g = PasswordGenerator.memorable(words: n, capitalize: caps, numbers: nums)
                    let parts = g.password.split(separator: "-").map(String.init)
                    try expect(parts.count == n, "\(parts.count) parts for \(n) words")
                    for p in parts {
                        var word = p
                        if nums {
                            try expect(word.last?.isNumber == true, "no digit")
                            word.removeLast()
                        }
                        try expect((word.first?.isUppercase == true) == caps, "capitalisation")
                        try expect(words.contains(word.lowercased()), "not from the list")
                    }
                    let expected = Double(n) * (log2(7768.0) + (nums ? log2(10.0) : 0))
                    try expect(abs(g.bits - expected) < 1e-9, "strength misreported")
                }
            }
            return nil
        }
        run("Password generator", "Random passwords have the length and characters asked for") {
            let plain = Set(PasswordGenerator.alphanumerics), all = plain.union(PasswordGenerator.symbols)
            for n in [12, 13, 24, 63, 64] {
                let a = PasswordGenerator.random(length: n, symbols: false)
                let b = PasswordGenerator.random(length: n, symbols: true)
                try expect(a.password.count == n && b.password.count == n, "wrong length")
                try expect(a.password.allSatisfy(plain.contains), "symbol where none was asked for")
                try expect(b.password.allSatisfy(all.contains), "character outside the alphabet")
                try expect(abs(b.bits - Double(n) * log2(70)) < 1e-9, "strength misreported")
            }
            try expect(all.count == 70, "alphabet has repeats")
            // 2,000 characters from 70: every character should turn up, and no two runs match.
            let long = (0..<32).map { _ in PasswordGenerator.random(length: 64, symbols: true).password }
            try expect(Set(long.joined()).count == 70, "some characters never appear")
            try expect(Set(long).count == long.count, "repeated output")
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
