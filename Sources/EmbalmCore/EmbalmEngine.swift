import Foundation
import CryptoKit

/// The Embalm engine: embalm (encrypt) and mummify (decrypt), with a
/// self-destruct tripwire.
///
/// Fidelity: AES-GCM authenticates every chunk, so a successful mummify returns
/// exactly the bytes that were sealed. Embalming also re-reads its own output and
/// compares a SHA-256 of the data before reporting success (the digest is never
/// stored in the file).
public enum EmbalmEngine {

    public static let chunkSize = 1 << Int(EmbalmFormat.defaultChunkLog2)

    /// The extension given to new embalmed files. Files are recognised by content,
    /// so the name is a convenience for Finder, never a requirement.
    public static let fileExtension = "emb"
    /// Extensions used by earlier versions, still treated as embalmed files.
    public static let legacyExtensions = ["embalm"]

    // MARK: - Status

    public struct Status {
        public let formatVersion: Int
        public let failureCount: Int
        public let maxFailures: Int
        public let kdfName: String
        public let fileSize: UInt64
        /// False when the file looks incomplete or damaged (checked without a password).
        public let structurallyIntact: Bool
        public let problem: String?
        public let exposesLegacyFingerprint: Bool
        /// True for a file whose key block lives in a separate key file that has
        /// not been supplied yet. The attempt counts are unknown until it is.
        public var needsKeyFile = false
        /// How many different passwords are needed, out of how many issued.
        public var threshold = 1
        public var holders = 1
        public var remainingAttempts: Int { max(0, maxFailures - failureCount) }
        public var isDestroyed: Bool { failureCount >= maxFailures }
    }

    /// True if the file starts with the Embalm magic, whatever it is called.
    public static func isEmbalmFile(at url: URL) -> Bool {
        guard let h = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? h.close() }
        guard let d = try? h.read(upToCount: 6) else { return false }
        return [UInt8](d) == EmbalmFormat.magic
    }

    /// Read a container's state without a password and without using an attempt.
    public static func inspect(input: URL, keyFile: URL? = nil) throws -> Status {
        if formatVersion(of: input) == EmbalmFormat.V4.version { return try inspectV4(input: input, keyFile: keyFile) }
        let h: FileHandle
        do { h = try FileHandle(forReadingFrom: input) }
        catch { throw EmbalmError.io("cannot read \(input.lastPathComponent)") }
        defer { try? h.close() }
        let size = try h.seekToEnd()
        try h.seek(toOffset: 0)
        let head = try h.read(upToCount: Int(min(size, UInt64(EmbalmFormat.maxHeaderLength)))) ?? Data()
        let header = try EmbalmHeader.parse(head)
        let problem = structureProblem(header, fileSize: size)
        let kdfName = (try? KDFChoice(kdfId: header.kdfId, paramWord: header.kdfParamWord))?.displayName ?? "unknown"
        return Status(
            formatVersion: Int(header.version),
            failureCount: Int(header.failureCount),
            maxFailures: Int(header.maxFailures),
            kdfName: kdfName, fileSize: size,
            structurallyIntact: problem == nil, problem: problem,
            exposesLegacyFingerprint: header.legacySHA256 != nil)
    }

    private static func structureProblem(_ header: EmbalmHeader, fileSize: UInt64) -> String? {
        if header.failureCount >= header.maxFailures { return nil }   // destroyed: reported separately
        let end = UInt64(header.payloadOffset) &+ header.payloadLen
        if header.isChunked {
            if !header.crcOK { return "header checksum mismatch" }
            if fileSize != end { return "expected \(end) bytes but found \(fileSize)" }
            guard (10...24).contains(header.chunkLog2) else { return "invalid chunk size" }
            let unit = UInt64(1 << Int(header.chunkLog2)) + 16
            let n = (header.payloadLen + unit - 1) / unit
            let last = header.payloadLen &- (n &- 1) &* unit
            if n == 0 || n > UInt64(UInt32.max) || last < 17 || last > unit { return "invalid payload length" }
        } else if fileSize < end {
            return "expected \(end) bytes but found \(fileSize)"
        }
        return nil
    }

    // MARK: - Names

    /// A safe single file name from untrusted text, or nil.
    public static func sanitizedFilename(_ raw: String) -> String? {
        var s = raw.replacingOccurrences(of: "\\", with: "/")
        if let last = s.split(separator: "/", omittingEmptySubsequences: true).last { s = String(last) }
        s = String(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7F })
        s = s.trimmingCharacters(in: .whitespaces)
        if s.isEmpty || s == "." || s == ".." || s.utf8.count > 255 { return nil }
        return s
    }

    /// `name`, or `name (1)`, `name (2)`... in `directory`, never overwriting.
    public static func uniqueURL(directory: URL, name: String) -> URL {
        let fm = FileManager.default
        var candidate = directory.appendingPathComponent(name)
        if !fm.fileExists(atPath: candidate.path) { return candidate }
        let ext = (name as NSString).pathExtension
        let stem = (name as NSString).deletingPathExtension
        var i = 1
        repeat {
            let n = ext.isEmpty ? "\(stem) (\(i))" : "\(stem) (\(i)).\(ext)"
            candidate = directory.appendingPathComponent(n)
            i += 1
        } while fm.fileExists(atPath: candidate.path)
        return candidate
    }

    // MARK: - Mummify (decrypt)

    /// Opens a v1 to v3 container. A wrong password updates the on-disk attempt
    /// counter and, on the last allowed miss, shreds the container.
    static func legacyUnlock(input: URL, password: String) throws -> OpenedContainer {
        let handle: FileHandle
        do { handle = try FileHandle(forUpdating: input) }
        catch {
            if FileManager.default.isReadableFile(atPath: input.path) { throw EmbalmError.readOnlySource }
            throw EmbalmError.io("cannot open \(input.lastPathComponent)")
        }
        var transferred = false
        defer { if !transferred { try? handle.close() } }
        _ = flock(handle.fileDescriptor, LOCK_EX | LOCK_NB)   // best effort; some volumes lack locks

        let fileSize = try handle.seekToEnd()
        try handle.seek(toOffset: 0)
        let head = try handle.read(upToCount: Int(min(fileSize, UInt64(EmbalmFormat.maxHeaderLength)))) ?? Data()
        let header = try EmbalmHeader.parse(head)

        if header.failureCount >= header.maxFailures { throw EmbalmError.alreadyDestroyed }
        if let problem = structureProblem(header, fileSize: fileSize) { throw EmbalmError.damaged(problem) }

        let choice = try KDFChoice(kdfId: header.kdfId, paramWord: header.kdfParamWord)
        let kek = SymmetricKey(data: try choice.deriveKey(
            password: password, salt: header.salt, normalize: header.version >= 3))

        let dekData: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: header.wrapNonce),
                ciphertext: header.wrappedDEK.prefix(EmbalmFormat.dekLength),
                tag: header.wrappedDEK.suffix(EmbalmFormat.gcmTagLength))
            dekData = header.isChunked
                ? try AES.GCM.open(box, using: kek, authenticating: header.wrapAAD)
                : try AES.GCM.open(box, using: kek)
        } catch {
            throw try registerFailure(handle: handle, header: header)
        }

        if header.failureCount != 0 { try? writeByte(handle, EmbalmFormat.offFailureCount, 0) }
        let dek = SymmetricKey(data: dekData)

        if header.isChunked {
            let stream = try V3Stream(handle: handle, header: header, dek: dek)
            let first = try stream.decryptChunk(0)
            let inner = try parseInner(first, totalPlain: stream.totalPlain)
            let take = Int(min(inner.dataLen, UInt64(first.count - inner.headEnd)))
            let firstData = first.subdata(in: inner.headEnd..<(inner.headEnd + take))
            transferred = true
            return OpenedContainer(version: Int(header.version), name: inner.name, dataSize: inner.dataLen,
                                   source: .stream(stream, firstData: firstData))
        }

        // Legacy v1/v2: single-shot payload, read whole.
        try handle.seek(toOffset: UInt64(header.payloadOffset))
        let payload = try readExactly(handle, Int(header.payloadLen))
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: header.payloadNonce),
                ciphertext: payload.prefix(payload.count - 16), tag: payload.suffix(16))
            plaintext = try AES.GCM.open(box, using: dek)
        } catch { throw EmbalmError.integrityCheckFailed }
        if let digest = header.legacySHA256, Data(SHA256.hash(data: plaintext)) != digest {
            throw EmbalmError.integrityCheckFailed
        }
        return OpenedContainer(version: Int(header.version), name: nil, dataSize: UInt64(plaintext.count),
                               source: .legacy(plaintext))
    }

    /// Unlock and write in one step to an explicit path.
    public static func mummify(input: URL, output: URL, password: String, keyFile: URL? = nil,
                               overwrite: Bool = false, progress: ((Double) -> Void)? = nil) throws {
        let opened = try unlock(input: input, password: password, keyFile: keyFile)
        defer { opened.close() }
        try opened.write(to: output, overwrite: overwrite, progress: progress)
    }

    /// Where a mummified file should go by default: the embedded name if there is
    /// one, otherwise the container's name without `.emb` (or the older `.embalm`).
    public static func suggestedOutputName(opened: OpenedContainer, inputName: String) -> String {
        if let n = opened.originalName { return n }
        if ([fileExtension] + legacyExtensions).contains((inputName as NSString).pathExtension.lowercased()) {
            let stem = (inputName as NSString).deletingPathExtension
            if !stem.isEmpty { return stem }
        }
        return inputName + ".mummified"
    }

    // MARK: - Internals

    static func chunkNonce(prefix: Data, index: UInt32, final: Bool) throws -> AES.GCM.Nonce {
        var b = [UInt8](prefix)
        b.append(UInt8(truncatingIfNeeded: index >> 24))
        b.append(UInt8(truncatingIfNeeded: index >> 16))
        b.append(UInt8(truncatingIfNeeded: index >> 8))
        b.append(UInt8(truncatingIfNeeded: index))
        b.append(final ? 1 : 0)
        return try AES.GCM.Nonce(data: b)
    }

    static func readExactly(_ h: FileHandle, _ count: Int) throws -> Data {
        var out = Data(capacity: count)
        while out.count < count {
            guard let piece = try h.read(upToCount: count - out.count), !piece.isEmpty else {
                throw EmbalmError.damaged("the file ends early")
            }
            out.append(piece)
        }
        return out
    }

    static func parseInner(_ chunk0: Data, totalPlain: UInt64) throws
        -> (name: String?, dataLen: UInt64, headEnd: Int) {
        let b = [UInt8](chunk0)
        guard b.count >= 12, b[0] == 1 else { throw EmbalmError.integrityCheckFailed }
        let nameLen = (Int(b[2]) << 8) | Int(b[3])
        let headEnd = 12 + nameLen
        guard b.count >= headEnd, totalPlain >= UInt64(headEnd) else { throw EmbalmError.integrityCheckFailed }
        let dataLen = UInt64(bigEndian: b, at: 4 + nameLen)
        guard dataLen <= totalPlain - UInt64(headEnd) else { throw EmbalmError.integrityCheckFailed }
        let name = nameLen == 0 ? nil : sanitizedFilename(String(decoding: b[4..<(4 + nameLen)], as: UTF8.self))
        return (name, dataLen, headEnd)
    }

    static func writeByte(_ h: FileHandle, _ offset: Int, _ value: UInt8) throws {
        try h.seek(toOffset: UInt64(offset))
        try h.write(contentsOf: Data([value]))
        SecureErase.fullSync(h)
    }

    /// Record a wrong password. Returns the error to throw.
    private static func registerFailure(handle: FileHandle, header: EmbalmHeader) throws -> EmbalmError {
        let newCount = header.failureCount + 1
        if newCount >= header.maxFailures {
            try shred(handle: handle, header: header)
            return .destroyed
        }
        try writeByte(handle, EmbalmFormat.offFailureCount, newCount)
        return .wrongPassword(remaining: Int(header.maxFailures - newCount))
    }

    /// Overwrite the wrapped key (the only copy of the DEK) and the payload, then
    /// mark the container destroyed.
    private static func shred(handle: FileHandle, header: EmbalmHeader) throws {
        try SecureErase.overwrite(handle, offset: UInt64(EmbalmFormat.offWrappedDEK),
                                  length: UInt64(EmbalmFormat.wrappedDEKLength))
        try SecureErase.overwrite(handle, offset: UInt64(header.payloadOffset), length: header.payloadLen)
        try writeByte(handle, EmbalmFormat.offFailureCount, header.maxFailures)
    }

    /// Geometry and decryption of a chunked payload (v3 and later).
    struct V3Stream {
        let handle: FileHandle
        let offset: UInt64
        let prefix: Data
        let dek: SymmetricKey
        let n: Int
        let unit: Int            // ciphertext bytes in a full chunk
        let lastLen: Int         // ciphertext bytes in the final chunk
        let totalPlain: UInt64

        init(handle: FileHandle, header: EmbalmHeader, dek: SymmetricKey) throws {
            try self.init(handle: handle, offset: UInt64(header.payloadOffset), payloadLen: header.payloadLen,
                          prefix: header.noncePrefix, chunkLog2: header.chunkLog2, dek: dek)
        }

        init(handle: FileHandle, offset: UInt64, payloadLen: UInt64, prefix: Data, chunkLog2: UInt8,
             dek: SymmetricKey) throws {
            guard (10...24).contains(chunkLog2) else { throw EmbalmError.damaged("invalid chunk size") }
            let unit = (1 << Int(chunkLog2)) + 16
            let n = (payloadLen + UInt64(unit) - 1) / UInt64(unit)
            let last = payloadLen &- (n &- 1) &* UInt64(unit)
            guard n >= 1, n <= UInt64(UInt32.max), last >= 17, last <= UInt64(unit) else {
                throw EmbalmError.damaged("invalid payload length")
            }
            self.handle = handle; self.offset = offset; self.prefix = prefix; self.dek = dek
            self.n = Int(n); self.unit = unit; self.lastLen = Int(last)
            self.totalPlain = payloadLen - 16 * n
        }

        func decryptChunk(_ i: Int) throws -> Data {
            let isLast = i == n - 1
            let len = isLast ? lastLen : unit
            try handle.seek(toOffset: offset + UInt64(i) * UInt64(unit))
            let raw = try EmbalmEngine.readExactly(handle, len)
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: EmbalmEngine.chunkNonce(prefix: prefix, index: UInt32(i), final: isLast),
                    ciphertext: raw.prefix(len - 16), tag: raw.suffix(16))
                return try AES.GCM.open(box, using: dek)
            } catch { throw EmbalmError.integrityCheckFailed }
        }
    }

    // MARK: - Opened container

    /// A container whose password has been accepted.
    public final class OpenedContainer {
        enum Source {
            case legacy(Data)
            case stream(V3Stream, firstData: Data)
        }
        /// The original file name, restored from inside the encrypted data (v3 and later).
        public let originalName: String?
        public let dataSize: UInt64
        public let formatVersion: Int
        private let source: Source
        private var closed = false

        init(version: Int, name: String?, dataSize: UInt64, source: Source) {
            self.formatVersion = version; self.originalName = name
            self.dataSize = dataSize; self.source = source
        }
        deinit { close() }

        public func close() {
            guard !closed else { return }
            closed = true
            if case .stream(let s, _) = source { try? s.handle.close() }
        }

        /// Write the recovered file. On any failure the partial output is deleted.
        public func write(to output: URL, overwrite: Bool = false,
                          progress: ((Double) -> Void)? = nil) throws {
            if !overwrite && FileManager.default.fileExists(atPath: output.path) {
                throw EmbalmError.io("\(output.lastPathComponent) already exists")
            }
            guard FileManager.default.createFile(atPath: output.path, contents: nil,
                                                 attributes: [.posixPermissions: 0o600]) else {
                throw EmbalmError.io("cannot create \(output.lastPathComponent)")
            }
            let out: FileHandle
            do { out = try FileHandle(forWritingTo: output) }
            catch { try? FileManager.default.removeItem(at: output); throw EmbalmError.io("cannot write \(output.lastPathComponent)") }
            var ok = false
            defer { try? out.close(); if !ok { try? FileManager.default.removeItem(at: output) } }

            switch source {
            case .legacy(let data):
                try out.write(contentsOf: data)
            case .stream(let s, let firstData):
                try out.write(contentsOf: firstData)
                var remaining = dataSize - UInt64(firstData.count)
                progress?(1.0 / Double(s.n))
                for i in 1..<max(1, s.n) {
                    let c = try s.decryptChunk(i)
                    let take = Int(min(remaining, UInt64(c.count)))
                    if take > 0 { try out.write(contentsOf: c.prefix(take)) }
                    remaining -= UInt64(take)
                    progress?(Double(i + 1) / Double(s.n))
                }
                guard remaining == 0 else { throw EmbalmError.integrityCheckFailed }
            }
            SecureErase.fullSync(out)
            ok = true
        }
    }
}
