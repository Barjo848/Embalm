import Foundation
import CryptoKit

/// ## v4 (current)
///
/// A v4 container is a key block followed by a body. The key block holds
/// everything needed to turn passwords into the data key; the body holds only
/// ciphertext. They are normally one file. With a detached key file the key
/// block is its own small file and the body file starts with a 36-byte stub.
///
/// ```
/// Key block                              Body
/// 0   6   "EMBALM" ("EMBKEY" if detached)  decoy region: 65,552 bytes, always present
/// 6   1   version = 4                      payload: chunks of ciphertext + 16-byte tag
/// 7   1   kind = 2
/// 8   1   kdf id                         Stub (only in a body file without its key block)
/// 9   4   kdf parameters                 0   6   "EMBALM"
/// 13  1   max failures                   6   1   version = 4
/// 14  1   failure count (mutable)        7   1   kind = 3
/// 15  1   flags (bit 0: detached)        8   16  file id
/// 16  16  salt                           24  8   payload length
/// 32  16  file id                        32  4   CRC-32 of bytes 0..31
/// 48  7   payload nonce prefix
/// 55  7   decoy nonce prefix
/// 62  1   chunk size (log2)
/// 63  1   passwords needed (k)
/// 64  1   passwords issued (n)
/// 65  1   slot count
/// 66  8   payload length
/// 74  4   CRC-32 of bytes 0..73 (byte 14 zeroed)
/// 78  ..  slots, 61 bytes each: nonce 12 | ciphertext 33 | tag 16
/// ```
///
/// Every slot wraps `role | 32-byte key` with AES-256-GCM, authenticating bytes
/// 0..73 of the key block (byte 14 zeroed). One KDF run per password serves
/// every slot, because all slots share the salt.
///
/// * One password (n = 1): two slots in random order. One wraps the data key.
///   The other wraps the decoy key if a duress password was set, and is random
///   bytes if not. The decoy region is a sealed 64 KiB decoy or random bytes.
///   Nothing in the file shows which, so no file reveals whether it has a
///   duress password.
/// * Several passwords (n > 1): n holder slots, each wrapping a random holder
///   secret under that holder's password, then one slot for every group of k
///   holders, wrapping the data key under HKDF-SHA256 of that group's secrets.
///   Only standard primitives are used; there is no secret-sharing arithmetic.
extension EmbalmFormat {
    enum V4 {
        static let version: UInt8 = 4
        static let keyMagic: [UInt8] = Array("EMBKEY".utf8)
        static let kindWhole: UInt8 = 2
        static let kindBody: UInt8 = 3
        static let offKind = 7
        static let offFlags = 15
        static let offFileId = 32
        static let offMainPrefix = 48
        static let offDecoyPrefix = 55
        static let offChunkLog2 = 62
        static let offThreshold = 63
        static let offHolders = 64
        static let offSlotCount = 65
        static let offPayloadLen = 66
        static let offCRC = 74
        static let headLength = 78
        static let slotLength = 12 + 33 + 16
        static let decoyLog2: UInt8 = 16
        static let decoyRegion = (1 << 16) + 16
        static let stubLength = 36
        static let maxHolders = 5
        static let roleData: UInt8 = 0
        static let roleDecoy: UInt8 = 1
        static let roleHolder: UInt8 = 2
        /// Where the payload starts in an ordinary one-file, one-password container.
        static let plainDecoyOffset = headLength + 2 * slotLength
        static let plainPayloadOffset = plainDecoyOffset + decoyRegion
    }
}

private typealias V4 = EmbalmFormat.V4

/// Every group of `k` indices out of `0..<n`, in a fixed order.
func combinations(_ n: Int, _ k: Int) -> [[Int]] {
    guard k > 0 else { return [[]] }
    guard n >= k else { return [] }
    var out: [[Int]] = []
    func go(_ start: Int, _ picked: [Int]) {
        if picked.count == k { out.append(picked); return }
        if start >= n { return }
        for i in start..<n { go(i + 1, picked + [i]) }
    }
    go(0, [])
    return out
}

struct V4KeyBlock {
    let head: [UInt8]
    let kdf: KDFChoice
    let maxFailures: UInt8
    var failureCount: UInt8
    let detached: Bool
    let salt: Data, fileId: Data, mainPrefix: Data, decoyPrefix: Data
    let chunkLog2: UInt8
    let threshold: Int, holders: Int, slotCount: Int
    let payloadLen: UInt64

    var length: Int { V4.headLength + slotCount * V4.slotLength }
    /// How many slots a single password can open directly.
    var personalSlots: Int { holders == 1 ? 2 : holders }
    var aad: Data {
        var a = Array(head[0..<V4.offCRC]); a[EmbalmFormat.offFailureCount] = 0
        return Data(a)
    }

    static func slots(threshold k: Int, holders n: Int) -> Int { n == 1 ? 2 : n + combinations(n, k).count }

    static func parse(_ b: [UInt8], keyFile: Bool) throws -> V4KeyBlock {
        guard b.count >= 6, Array(b[0..<6]) == (keyFile ? V4.keyMagic : EmbalmFormat.magic) else {
            throw keyFile ? EmbalmError.notAKeyFile : EmbalmError.notAnEmbalmFile
        }
        guard b.count >= V4.headLength else { throw EmbalmError.damaged("header is cut short") }
        guard b[EmbalmFormat.offVersion] == V4.version else { throw EmbalmError.unsupportedVersion(b[EmbalmFormat.offVersion]) }
        var masked = Array(b[0..<V4.offCRC]); masked[EmbalmFormat.offFailureCount] = 0
        guard CRC32.checksum(masked) == UInt32(bigEndian: b, at: V4.offCRC) else {
            throw EmbalmError.damaged("header checksum mismatch")
        }
        guard b[V4.offKind] == V4.kindWhole else { throw EmbalmError.corruptHeader("unknown kind") }
        let k = Int(b[V4.offThreshold]), n = Int(b[V4.offHolders]), s = Int(b[V4.offSlotCount])
        guard (1...V4.maxHolders).contains(n), (1...n).contains(k), s == slots(threshold: k, holders: n) else {
            throw EmbalmError.corruptHeader("invalid password layout")
        }
        let detached = b[V4.offFlags] & 1 == 1
        guard detached == keyFile else { throw EmbalmError.corruptHeader("key block in the wrong kind of file") }
        return V4KeyBlock(
            head: Array(b[0..<V4.headLength]),
            kdf: try KDFChoice(kdfId: b[EmbalmFormat.offKdfId], paramWord: UInt32(bigEndian: b, at: EmbalmFormat.offKdfParams)),
            maxFailures: b[EmbalmFormat.offMaxFailures], failureCount: b[EmbalmFormat.offFailureCount],
            detached: detached,
            salt: Data(b[EmbalmFormat.offSalt..<(EmbalmFormat.offSalt + 16)]),
            fileId: Data(b[V4.offFileId..<(V4.offFileId + 16)]),
            mainPrefix: Data(b[V4.offMainPrefix..<(V4.offMainPrefix + 7)]),
            decoyPrefix: Data(b[V4.offDecoyPrefix..<(V4.offDecoyPrefix + 7)]),
            chunkLog2: b[V4.offChunkLog2], threshold: k, holders: n, slotCount: s,
            payloadLen: UInt64(bigEndian: b, at: V4.offPayloadLen))
    }

    static func build(magic: [UInt8], kdf: KDFChoice, maxFailures: UInt8, detached: Bool, salt: Data,
                      fileId: Data, mainPrefix: Data, decoyPrefix: Data, threshold: Int, holders: Int,
                      payloadLen: UInt64) -> [UInt8] {
        var h = Data(capacity: V4.headLength)
        h.append(contentsOf: magic)
        h.append(V4.version); h.append(V4.kindWhole)
        h.append(kdf.kdfId); h.appendBigEndian(kdf.paramWord)
        h.append(maxFailures); h.append(0); h.append(detached ? 1 : 0)
        h.append(salt); h.append(fileId); h.append(mainPrefix); h.append(decoyPrefix)
        h.append(EmbalmFormat.defaultChunkLog2)
        h.append(UInt8(threshold)); h.append(UInt8(holders))
        h.append(UInt8(slots(threshold: threshold, holders: holders)))
        h.appendBigEndian(payloadLen)
        precondition(h.count == V4.offCRC)
        h.appendBigEndian(CRC32.checksum([UInt8](h)))
        return [UInt8](h)
    }
}

/// The open file or files of one v4 container.
final class V4Files {
    let key: FileHandle
    let body: FileHandle
    let bodyWritable: Bool
    var block: V4KeyBlock
    let bodyOffset: UInt64
    let problem: String?
    let size: UInt64

    init(key: FileHandle, body: FileHandle, bodyWritable: Bool, block: V4KeyBlock, bodyOffset: UInt64,
         problem: String?, size: UInt64) {
        self.key = key; self.body = body; self.bodyWritable = bodyWritable; self.block = block
        self.bodyOffset = bodyOffset; self.problem = problem; self.size = size
    }
    var shared: Bool { key === body }
    var decoyOffset: UInt64 { bodyOffset }
    var payloadOffset: UInt64 { bodyOffset + UInt64(V4.decoyRegion) }
    func slotOffset(_ i: Int) -> UInt64 { UInt64(V4.headLength + i * V4.slotLength) }
    func closeAll() { try? key.close(); if !shared { try? body.close() } }
}

extension EmbalmEngine {

    /// The largest decoy file a duress password can reveal.
    public static let maxDecoyBytes = 65_000
    /// The most passwords one file can be split between.
    public static let maxHolders = V4.maxHolders

    /// What a duress password does: it opens `decoy` and, without saying so,
    /// destroys the key to the real file.
    public struct Duress {
        public let password: String
        public let decoy: URL
        public init(password: String, decoy: URL) { self.password = password; self.decoy = decoy }
    }

    /// True if the file is an Embalm key file (the detached half of a container).
    public static func isKeyFile(at url: URL) -> Bool {
        guard let h = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? h.close() }
        guard let d = try? h.read(upToCount: 6) else { return false }
        return [UInt8](d) == V4.keyMagic
    }

    static func formatVersion(of url: URL) -> UInt8? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        guard let d = try? h.read(upToCount: 7), d.count == 7, Array(d.prefix(6)) == EmbalmFormat.magic else { return nil }
        return d[d.startIndex + 6]
    }

    // MARK: - Opening the files

    private static func openHandle(_ url: URL, update: Bool) throws -> (FileHandle, Bool) {
        if update, let h = try? FileHandle(forUpdating: url) { return (h, true) }
        if let h = try? FileHandle(forReadingFrom: url) { return (h, false) }
        throw EmbalmError.io("cannot open \(url.lastPathComponent)")
    }

    private static func geometryProblem(payloadLen: UInt64, chunkLog2: UInt8) -> String? {
        guard (10...24).contains(chunkLog2) else { return "invalid chunk size" }
        let unit = UInt64(1 << Int(chunkLog2)) + 16
        let n = (payloadLen + unit - 1) / unit
        let last = payloadLen &- (n &- 1) &* unit
        if n == 0 || n > UInt64(UInt32.max) || last < 17 || last > unit { return "invalid payload length" }
        return nil
    }

    /// Opens a v4 container. With `update`, the file holding the key block must
    /// be writable, because the attempt count lives there.
    static func openV4(input: URL, keyFile: URL?, update: Bool) throws -> V4Files {
        let (h, writable) = try openHandle(input, update: update)
        var keep = false
        defer { if !keep { try? h.close() } }
        let size = try h.seekToEnd()
        try h.seek(toOffset: 0)
        let first = [UInt8](try h.read(upToCount: Int(min(size, UInt64(V4.headLength)))) ?? Data())
        guard first.count >= 8, Array(first[0..<6]) == EmbalmFormat.magic else { throw EmbalmError.notAnEmbalmFile }

        if first[V4.offKind] == V4.kindBody {
            guard first.count >= V4.stubLength else { throw EmbalmError.damaged("header is cut short") }
            guard CRC32.checksum(Array(first[0..<32])) == UInt32(bigEndian: first, at: 32) else {
                throw EmbalmError.damaged("header checksum mismatch")
            }
            guard let keyURL = keyFile else { throw EmbalmError.keyFileNeeded }
            let (kh, keyWritable) = try openHandle(keyURL, update: update)
            var keepKey = false
            defer { if !keepKey { try? kh.close() } }
            let keySize = try kh.seekToEnd()
            try kh.seek(toOffset: 0)
            let block = try V4KeyBlock.parse([UInt8](try kh.read(upToCount: V4.headLength) ?? Data()), keyFile: true)
            guard block.fileId == Data(first[8..<24]) else { throw EmbalmError.keyFileMismatch }
            if update && !keyWritable { throw EmbalmError.readOnlySource }
            let expected = UInt64(V4.stubLength + V4.decoyRegion) + block.payloadLen
            var problem = geometryProblem(payloadLen: block.payloadLen, chunkLog2: block.chunkLog2)
            if keySize != UInt64(block.length) { problem = "the key file should be \(block.length) bytes but is \(keySize)" }
            else if UInt64(bigEndian: first, at: 24) != block.payloadLen { problem = "the two files disagree about the length" }
            else if size != expected { problem = "expected \(expected) bytes but found \(size)" }
            _ = flock(kh.fileDescriptor, LOCK_EX | LOCK_NB)
            keep = true; keepKey = true
            return V4Files(key: kh, body: h, bodyWritable: writable, block: block,
                           bodyOffset: UInt64(V4.stubLength), problem: problem, size: size)
        }

        let block = try V4KeyBlock.parse(first, keyFile: false)
        if update && !writable { throw EmbalmError.readOnlySource }
        let expected = UInt64(block.length + V4.decoyRegion) + block.payloadLen
        var problem = geometryProblem(payloadLen: block.payloadLen, chunkLog2: block.chunkLog2)
        if size != expected { problem = "expected \(expected) bytes but found \(size)" }
        _ = flock(h.fileDescriptor, LOCK_EX | LOCK_NB)
        keep = true
        return V4Files(key: h, body: h, bodyWritable: writable, block: block,
                       bodyOffset: UInt64(block.length), problem: problem, size: size)
    }

    static func inspectV4(input: URL, keyFile: URL?) throws -> Status {
        let f: V4Files
        do { f = try openV4(input: input, keyFile: keyFile, update: false) }
        catch EmbalmError.keyFileNeeded {
            let size = (try? FileManager.default.attributesOfItem(atPath: input.path)[.size] as? UInt64) ?? nil
            return Status(formatVersion: Int(V4.version), failureCount: 0, maxFailures: 1, kdfName: "unknown",
                          fileSize: size ?? 0, structurallyIntact: true, problem: nil,
                          exposesLegacyFingerprint: false, needsKeyFile: true)
        }
        defer { f.closeAll() }
        let destroyed = f.block.failureCount >= f.block.maxFailures
        return Status(formatVersion: Int(V4.version), failureCount: Int(f.block.failureCount),
                      maxFailures: Int(f.block.maxFailures), kdfName: f.block.kdf.displayName, fileSize: f.size,
                      structurallyIntact: destroyed || f.problem == nil, problem: destroyed ? nil : f.problem,
                      exposesLegacyFingerprint: false, needsKeyFile: false,
                      threshold: f.block.threshold, holders: f.block.holders)
    }

    // MARK: - Slots

    private static func sealSlot(role: UInt8, key: Data, under kek: SymmetricKey, aad: Data) throws -> Data {
        let nonce = RandomBytes.makeData(EmbalmFormat.nonceLength)
        let box = try AES.GCM.seal(Data([role]) + key, using: kek, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
        return nonce + box.ciphertext + box.tag
    }

    /// The role and key inside slot `i`, or nil if `kek` does not open it.
    private static func openSlot(_ f: V4Files, _ i: Int, _ kek: SymmetricKey) throws -> (role: UInt8, key: Data)? {
        try f.key.seek(toOffset: f.slotOffset(i))
        let raw = try readExactly(f.key, V4.slotLength)
        guard let box = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: raw.prefix(12)),
                                               ciphertext: raw.dropFirst(12).prefix(33), tag: raw.suffix(16)),
              let plain = try? AES.GCM.open(box, using: kek, authenticating: f.block.aad), plain.count == 33
        else { return nil }
        return (plain[plain.startIndex], Data(plain.dropFirst()))
    }

    /// The key that a particular group of holders shares.
    private static func groupKey(_ secrets: [Int: Data], fileId: Data) -> SymmetricKey {
        let members = secrets.keys.sorted()
        var material = Data()
        for i in members { material.append(secrets[i]!) }
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: material), salt: fileId,
                                      info: Data("Embalm v4 group".utf8) + Data(members.map { UInt8($0) }),
                                      outputByteCount: 32)
    }

    private static func innerHead(name: String, dataLen: UInt64) -> Data {
        let nameBytes = Array(name.utf8)
        var d = Data([1, 0])
        d.appendBigEndian(UInt16(nameBytes.count))
        d.append(contentsOf: nameBytes)
        d.appendBigEndian(dataLen)
        return d
    }

    private static func normal(_ password: String) -> String { password.precomposedStringWithCompatibilityMapping }

    // MARK: - Embalm (encrypt)

    /// Embalm with one password.
    public static func embalm(
        input: URL, output: URL, password: String,
        kdf: KDFChoice = .defaultArgon2id, maxFailures: UInt8 = 2,
        padding: Bool = true, storeName: Bool = true, verify: Bool = true,
        duress: Duress? = nil, keyFile: URL? = nil,
        progress: ((Double) -> Void)? = nil
    ) throws {
        try embalm(input: input, output: output, passwords: [password], threshold: 1, kdf: kdf,
                   maxFailures: maxFailures, padding: padding, storeName: storeName, verify: verify,
                   duress: duress, keyFile: keyFile, progress: progress)
    }

    /// Embalm a file.
    ///
    /// - `passwords`: one password, or up to five for different holders, of whom
    ///   any `threshold` must give theirs to open the file.
    /// - `duress`: a second password that opens a decoy and destroys the real key.
    ///   Only for a single-password file.
    /// - `keyFile`: if given, the key block is written there instead of into
    ///   `output`, and both files are then needed to open it.
    public static func embalm(
        input: URL, output: URL, passwords: [String], threshold: Int,
        kdf: KDFChoice = .defaultArgon2id, maxFailures: UInt8 = 2,
        padding: Bool = true, storeName: Bool = true, verify: Bool = true,
        duress: Duress? = nil, keyFile: URL? = nil,
        progress: ((Double) -> Void)? = nil
    ) throws {
        let holders = passwords.count
        guard (1...V4.maxHolders).contains(holders), (1...holders).contains(threshold) else {
            throw EmbalmError.invalidOptions("Choose between 1 and \(V4.maxHolders) passwords, and need no more of them than there are.")
        }
        guard !passwords.contains(where: { $0.isEmpty }) else { throw EmbalmError.invalidOptions("A password must not be empty.") }
        guard Set(passwords.map(normal)).count == holders else {
            throw EmbalmError.invalidOptions("Each holder needs a different password.")
        }
        if let d = duress {
            guard holders == 1 else { throw EmbalmError.invalidOptions("A duress password cannot be combined with several passwords.") }
            guard !d.password.isEmpty, normal(d.password) != normal(passwords[0]) else {
                throw EmbalmError.invalidOptions("The duress password must be different from the real password.")
            }
        }
        let paths = [input, output, keyFile, duress?.decoy].compactMap { $0?.standardizedFileURL.path }
        guard Set(paths).count == paths.count else { throw EmbalmError.io("the same file was chosen twice") }

        let inHandle: FileHandle
        do { inHandle = try FileHandle(forReadingFrom: input) }
        catch { throw EmbalmError.io("cannot read \(input.lastPathComponent)") }
        defer { try? inHandle.close() }
        var st = stat()
        guard fstat(inHandle.fileDescriptor, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
            throw EmbalmError.io("\(input.lastPathComponent) is not a regular file (zip a folder first)")
        }
        let dataLen = UInt64(st.st_size)

        let name = storeName ? (sanitizedFilename(input.lastPathComponent) ?? "") : ""
        let head = innerHead(name: name, dataLen: dataLen)
        let innerLen = UInt64(head.count) + dataLen
        let padded = padding ? Padding.paddedLength(innerLen) : innerLen
        let C = UInt64(chunkSize)
        let n = (padded + C - 1) / C
        let payloadLen = padded + 16 * n

        // Keys and the key block.
        let dek = SymmetricKey(size: .bits256)
        let dekData = dek.withUnsafeBytes { Data($0) }
        let salt = RandomBytes.makeData(EmbalmFormat.saltLength)
        let fileId = RandomBytes.makeData(16)
        let mainPrefix = RandomBytes.makeData(EmbalmFormat.noncePrefixLength)
        let decoyPrefix = RandomBytes.makeData(EmbalmFormat.noncePrefixLength)
        let detached = keyFile != nil
        let blockHead = V4KeyBlock.build(
            magic: detached ? V4.keyMagic : EmbalmFormat.magic, kdf: kdf, maxFailures: maxFailures,
            detached: detached, salt: salt, fileId: fileId, mainPrefix: mainPrefix, decoyPrefix: decoyPrefix,
            threshold: threshold, holders: holders, payloadLen: payloadLen)
        var aadBytes = Array(blockHead[0..<V4.offCRC]); aadBytes[EmbalmFormat.offFailureCount] = 0
        let aad = Data(aadBytes)
        func kek(_ password: String) throws -> SymmetricKey {
            SymmetricKey(data: try kdf.deriveKey(password: password, salt: salt, normalize: true))
        }

        var slots: [Data] = []
        var decoyRegion = RandomBytes.makeData(V4.decoyRegion)
        if holders == 1 {
            let real = try sealSlot(role: V4.roleData, key: dekData, under: try kek(passwords[0]), aad: aad)
            var other = RandomBytes.makeData(V4.slotLength)
            if let d = duress {
                let values = try d.decoy.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard values.isRegularFile == true else { throw EmbalmError.io("the decoy is not a regular file") }
                guard (values.fileSize ?? Int.max) <= maxDecoyBytes else { throw EmbalmError.decoyTooLarge }
                let decoyData: Data
                do { decoyData = try Data(contentsOf: d.decoy) } catch { throw EmbalmError.io("cannot read the decoy") }
                guard decoyData.count <= maxDecoyBytes else { throw EmbalmError.decoyTooLarge }
                let decoyName = storeName ? (sanitizedFilename(d.decoy.lastPathComponent) ?? "") : ""
                var plain = innerHead(name: decoyName, dataLen: UInt64(decoyData.count)) + decoyData
                plain.append(Data(count: (1 << Int(V4.decoyLog2)) - plain.count))
                let decoyKey = SymmetricKey(size: .bits256)
                let box = try AES.GCM.seal(plain, using: decoyKey, nonce: chunkNonce(prefix: decoyPrefix, index: 0, final: true))
                decoyRegion = box.ciphertext + box.tag
                other = try sealSlot(role: V4.roleDecoy, key: decoyKey.withUnsafeBytes { Data($0) },
                                     under: try kek(d.password), aad: aad)
            }
            slots = Bool.random() ? [real, other] : [other, real]
        } else {
            var secrets: [Int: Data] = [:]
            for (i, pw) in passwords.enumerated() {
                let secret = RandomBytes.makeData(32)
                secrets[i] = secret
                slots.append(try sealSlot(role: V4.roleHolder, key: secret, under: try kek(pw), aad: aad))
            }
            for group in combinations(holders, threshold) {
                let members = secrets.filter { group.contains($0.key) }
                slots.append(try sealSlot(role: V4.roleData, key: dekData, under: groupKey(members, fileId: fileId), aad: aad))
            }
        }
        var keyBlock = Data(blockHead)
        slots.forEach { keyBlock.append($0) }

        // Write. Anything left half-made is removed.
        func create(_ url: URL) throws -> FileHandle {
            guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]),
                  let h = try? FileHandle(forWritingTo: url) else {
                throw EmbalmError.io("cannot create \(url.lastPathComponent)")
            }
            return h
        }
        var finished = false
        var made: [URL] = []
        defer { if !finished { made.forEach { try? FileManager.default.removeItem(at: $0) } } }

        made.append(output)
        let out = try create(output)
        defer { try? out.close() }
        let payloadOffset: UInt64
        if let keyURL = keyFile {
            made.append(keyURL)
            let kh = try create(keyURL)
            defer { try? kh.close() }
            try kh.write(contentsOf: keyBlock)
            SecureErase.fullSync(kh)
            var stub = Data(EmbalmFormat.magic)
            stub.append(V4.version); stub.append(V4.kindBody)
            stub.append(fileId); stub.appendBigEndian(payloadLen)
            stub.appendBigEndian(CRC32.checksum([UInt8](stub)))
            try out.write(contentsOf: stub)
            payloadOffset = UInt64(V4.stubLength + V4.decoyRegion)
        } else {
            try out.write(contentsOf: keyBlock)
            payloadOffset = UInt64(keyBlock.count + V4.decoyRegion)
        }
        try out.write(contentsOf: decoyRegion)

        var sha = SHA256()
        var consumed: UInt64 = 0
        var headPos = 0
        for i in 0..<Int(n) {
            let want = Int(min(C, padded - UInt64(i) * C))
            var buf = Data(capacity: want)
            if headPos < head.count {
                let take = min(head.count - headPos, want)
                buf.append(head[(head.startIndex + headPos)..<(head.startIndex + headPos + take)])
                headPos += take
            }
            if buf.count < want && consumed < dataLen {
                let need = Int(min(UInt64(want - buf.count), dataLen - consumed))
                let piece = try readExactly(inHandle, need)
                sha.update(data: piece)
                consumed += UInt64(piece.count)
                buf.append(piece)
            }
            if buf.count < want { buf.append(Data(count: want - buf.count)) }
            let box = try AES.GCM.seal(buf, using: dek, nonce: chunkNonce(prefix: mainPrefix, index: UInt32(i), final: i == Int(n) - 1))
            try out.write(contentsOf: box.ciphertext + box.tag)
            progress?(verify ? 0.5 * Double(i + 1) / Double(n) : Double(i + 1) / Double(n))
        }
        guard consumed == dataLen else { throw EmbalmError.io("\(input.lastPathComponent) changed while it was being embalmed") }
        SecureErase.fullSync(out)

        // Read the result back the way it will be opened, and compare, so a bad
        // disk or a bug cannot produce a file that fails to open later.
        if verify {
            let expected = Data(sha.finalize())
            let f: V4Files
            do { f = try openV4(input: output, keyFile: keyFile, update: false) } catch { throw EmbalmError.integrityCheckFailed }
            defer { f.closeAll() }
            guard f.problem == nil, f.payloadOffset == payloadOffset, f.block.fileId == fileId else {
                throw EmbalmError.integrityCheckFailed
            }
            let stream = try V3Stream(handle: f.body, offset: f.payloadOffset, payloadLen: f.block.payloadLen,
                                      prefix: f.block.mainPrefix, chunkLog2: f.block.chunkLog2, dek: dek)
            var check = SHA256()
            let first = try stream.decryptChunk(0)
            let inner = try parseInner(first, totalPlain: stream.totalPlain)
            guard inner.dataLen == dataLen, inner.name == (name.isEmpty ? nil : name) else { throw EmbalmError.integrityCheckFailed }
            let firstData = first.subdata(in: inner.headEnd..<min(first.count, inner.headEnd + Int(min(inner.dataLen, UInt64(first.count - inner.headEnd)))))
            check.update(data: firstData)
            var remaining = dataLen - UInt64(firstData.count)
            for i in 1..<max(1, stream.n) {
                let c = try stream.decryptChunk(i)
                let take = Int(min(remaining, UInt64(c.count)))
                if take > 0 { check.update(data: c.prefix(take)) }
                remaining -= UInt64(take)
                progress?(0.5 + 0.5 * Double(i + 1) / Double(n))
            }
            guard remaining == 0, Data(check.finalize()) == expected else { throw EmbalmError.integrityCheckFailed }
            // Every password must open its slot.
            for pw in passwords + (duress.map { [$0.password] } ?? []) {
                let k = try kek(pw)
                guard try (0..<f.block.personalSlots).contains(where: { try openSlot(f, $0, k) != nil }) else {
                    throw EmbalmError.integrityCheckFailed
                }
            }
        }
        progress?(1)
        finished = true
    }

    // MARK: - Mummify (decrypt)

    /// One opening of a container. A file that needs several passwords takes
    /// them one at a time through `offer`.
    public final class OpenSession {
        public let threshold: Int
        public let holders: Int
        /// Passwords accepted so far in this opening.
        public var accepted: Int { secrets.count }

        private let legacy: URL?
        private var files: V4Files?
        private var secrets: [Int: Data] = [:]

        init(legacy: URL) { self.legacy = legacy; files = nil; threshold = 1; holders = 1 }
        init(files: V4Files) {
            legacy = nil; self.files = files
            threshold = files.block.threshold; holders = files.block.holders
        }
        deinit { close() }

        public func close() { files?.closeAll(); files = nil; secrets = [:] }

        /// Give one password. Returns the opened container, or nil if the password
        /// was right and more are needed. A wrong password is counted on disk and,
        /// on the last allowed miss, destroys the container.
        public func offer(password: String) throws -> OpenedContainer? {
            if let url = legacy { return try EmbalmEngine.legacyUnlock(input: url, password: password) }
            guard let f = files else { throw EmbalmError.io("this opening has ended") }
            if f.block.failureCount >= f.block.maxFailures { throw EmbalmError.alreadyDestroyed }
            if let problem = f.problem { throw EmbalmError.damaged(problem) }

            let kek = SymmetricKey(data: try f.block.kdf.deriveKey(password: password, salt: f.block.salt, normalize: true))
            var hit: (index: Int, role: UInt8, key: Data)?
            for i in 0..<f.block.personalSlots {
                if let s = try EmbalmEngine.openSlot(f, i, kek) { hit = (i, s.role, s.key); break }
            }
            guard let found = hit else { throw try registerFailure(f) }

            switch (found.role, f.block.holders == 1) {
            case (V4.roleData, true):
                try resetCount(f)
                return try open(f, offset: f.payloadOffset, payloadLen: f.block.payloadLen, prefix: f.block.mainPrefix,
                                chunkLog2: f.block.chunkLog2, key: found.key)
            case (V4.roleDecoy, true):
                // Duress: the slot holding the real key becomes random bytes, exactly
                // what an unused slot looks like. Then the decoy opens as any file would.
                try SecureErase.overwrite(f.key, offset: f.slotOffset(1 - found.index), length: UInt64(V4.slotLength))
                try resetCount(f)
                return try open(f, offset: f.decoyOffset, payloadLen: UInt64(V4.decoyRegion), prefix: f.block.decoyPrefix,
                                chunkLog2: V4.decoyLog2, key: found.key)
            case (V4.roleHolder, false):
                if secrets[found.index] != nil { throw EmbalmError.passwordAlreadyGiven }
                secrets[found.index] = found.key
                if secrets.count < threshold { return nil }
                let group = EmbalmEngine.groupKey(secrets, fileId: f.block.fileId)
                for j in f.block.holders..<f.block.slotCount {
                    if let s = try EmbalmEngine.openSlot(f, j, group), s.role == V4.roleData {
                        try resetCount(f)
                        return try open(f, offset: f.payloadOffset, payloadLen: f.block.payloadLen,
                                        prefix: f.block.mainPrefix, chunkLog2: f.block.chunkLog2, key: s.key)
                    }
                }
                throw EmbalmError.integrityCheckFailed
            default:
                throw EmbalmError.integrityCheckFailed
            }
        }

        private func resetCount(_ f: V4Files) throws {
            guard f.block.failureCount != 0 else { return }
            try EmbalmEngine.writeByte(f.key, EmbalmFormat.offFailureCount, 0)
            f.block.failureCount = 0
        }

        /// Hands the body file to the opened container and ends this session.
        private func open(_ f: V4Files, offset: UInt64, payloadLen: UInt64, prefix: Data, chunkLog2: UInt8,
                          key: Data) throws -> OpenedContainer {
            let stream = try V3Stream(handle: f.body, offset: offset, payloadLen: payloadLen, prefix: prefix,
                                      chunkLog2: chunkLog2, dek: SymmetricKey(data: key))
            let first = try stream.decryptChunk(0)
            let inner = try EmbalmEngine.parseInner(first, totalPlain: stream.totalPlain)
            let take = Int(min(inner.dataLen, UInt64(first.count - inner.headEnd)))
            let firstData = first.subdata(in: inner.headEnd..<(inner.headEnd + take))
            if !f.shared { try? f.key.close() }
            files = nil; secrets = [:]
            return OpenedContainer(version: Int(V4.version), name: inner.name, dataSize: inner.dataLen,
                                   source: .stream(stream, firstData: firstData))
        }

        /// Record a wrong password. Returns the error to throw.
        private func registerFailure(_ f: V4Files) throws -> EmbalmError {
            let newCount = f.block.failureCount + 1
            if newCount >= f.block.maxFailures {
                // Destroy every slot (the only copies of the keys), then the data.
                try SecureErase.overwrite(f.key, offset: f.slotOffset(0), length: UInt64(f.block.slotCount * V4.slotLength))
                if f.bodyWritable {
                    try SecureErase.overwrite(f.body, offset: f.bodyOffset, length: UInt64(V4.decoyRegion) + f.block.payloadLen)
                }
                try EmbalmEngine.writeByte(f.key, EmbalmFormat.offFailureCount, f.block.maxFailures)
                f.block.failureCount = f.block.maxFailures
                secrets = [:]
                return .destroyed
            }
            try EmbalmEngine.writeByte(f.key, EmbalmFormat.offFailureCount, newCount)
            f.block.failureCount = newCount
            return .wrongPassword(remaining: Int(f.block.maxFailures - newCount))
        }
    }

    /// Step 1 of mummifying: open the file (and its key file, if it has one)
    /// ready to take passwords. Nothing is written until `OpenedContainer.write`.
    public static func beginOpen(input: URL, keyFile: URL? = nil) throws -> OpenSession {
        guard let version = formatVersion(of: input) else {
            if FileManager.default.isReadableFile(atPath: input.path) { throw EmbalmError.notAnEmbalmFile }
            throw EmbalmError.io("cannot open \(input.lastPathComponent)")
        }
        if version != V4.version { return OpenSession(legacy: input) }
        return OpenSession(files: try openV4(input: input, keyFile: keyFile, update: true))
    }

    /// Open a container that needs a single password.
    public static func unlock(input: URL, password: String, keyFile: URL? = nil) throws -> OpenedContainer {
        let session = try beginOpen(input: input, keyFile: keyFile)
        defer { session.close() }
        guard let opened = try session.offer(password: password) else {
            throw EmbalmError.morePasswordsNeeded(session.threshold - session.accepted)
        }
        return opened
    }
}
