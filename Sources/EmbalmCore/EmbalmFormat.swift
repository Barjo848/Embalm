import Foundation

/// On-disk layout of an Embalm container.
///
/// Envelope encryption: a random 256-bit Data Encryption Key (DEK) encrypts the
/// payload; the DEK is wrapped under a key derived from the password. Destroying
/// the wrapped DEK makes the payload unrecoverable, which gives the
/// self-destruct its teeth. All integers are big-endian.
///
/// ## v3 (current)
/// ```
/// off  len  field
/// 0    6    magic "EMBALM"
/// 6    1    version = 3
/// 7    1    cipherId = 2 (AES-256-GCM, chunked)
/// 8    1    kdfId (1 PBKDF2, 2 Argon2id)
/// 9    4    kdf parameter word
/// 13   1    maxFailures
/// 14   1    failureCount       <- the only mutable byte
/// 15   1    saltLen = 16
/// 16   16   salt
/// 32   12   wrapNonce
/// 44   2    wrapLen = 48
/// 46   48   wrappedDEK         <- overwritten on shred
/// 94   7    noncePrefix
/// 101  1    chunkLog2 (20 = 1 MiB chunks)
/// 102  4    reserved (0)
/// 106  4    CRC-32 of bytes 0..105 with byte 14 zeroed
/// 110  8    payloadLen
/// 118  ..   payload: chunks of (ciphertext || 16-byte tag)
/// ```
/// The wrap authenticates bytes 0..45 (byte 14 zeroed) and 94..105 as AAD, so
/// tampering with the KDF settings, limits or chunk geometry breaks unwrapping.
/// Each chunk uses nonce `prefix(7) || index(4) || finalFlag(1)`, so chunks
/// cannot be reordered, dropped or truncated undetected.
///
/// The payload plaintext is an inner envelope, padded with zeros (Padmé):
/// `u8 version=1 | u8 flags | u16 nameLen | name | u64 dataLen | data | padding`.
/// The original file name lives only inside the encrypted data.
///
/// ## v2 and v1 (read-only)
/// Single-shot AES-GCM payloads. v1 also stored the plaintext SHA-256 in the
/// clear, which leaked the content fingerprint; v2 removed it. Both still open.
enum EmbalmFormat {
    static let magic: [UInt8] = Array("EMBALM".utf8)
    static let currentVersion: UInt8 = 3
    static let cipherAESGCM: UInt8 = 1
    static let cipherAESGCMStream: UInt8 = 2
    static let kdfPBKDF2SHA256: UInt8 = 1
    static let kdfArgon2id: UInt8 = 2

    static let saltLength = 16
    static let nonceLength = 12
    static let dekLength = 32
    static let gcmTagLength = 16
    static let wrappedDEKLength = dekLength + gcmTagLength   // 48
    static let sha256Length = 32
    static let noncePrefixLength = 7
    static let defaultChunkLog2: UInt8 = 20

    // Shared preamble offsets.
    static let offVersion = 6
    static let offCipherId = 7
    static let offKdfId = 8
    static let offKdfParams = 9
    static let offMaxFailures = 13
    static let offFailureCount = 14
    static let offSaltLen = 15
    static let offSalt = 16
    static let offWrapNonce = 32
    static let offWrapLen = 44
    static let offWrappedDEK = 46
    static let offTail = 94

    // v3
    static let v3OffNoncePrefix = 94
    static let v3OffChunkLog2 = 101
    static let v3OffCRC = 106
    static let v3OffPayloadLen = 110
    static let v3HeaderLength = 118

    // v2
    static let v2OffPayloadLen = 106
    static let v2HeaderLength = 114

    // v1
    static let v1OffSHA256 = 114
    static let v1OffPayloadLen = 146
    static let v1HeaderLength = 154

    /// Enough bytes to parse any version's header.
    static let maxHeaderLength = 154
}

struct EmbalmHeader {
    var version: UInt8
    var kdfId: UInt8
    var kdfParamWord: UInt32
    var maxFailures: UInt8
    var failureCount: UInt8
    var salt: Data
    var wrapNonce: Data
    var wrappedDEK: Data
    var payloadNonce: Data        // v1/v2 single-shot nonce
    var noncePrefix: Data         // v3
    var chunkLog2: UInt8          // v3
    var payloadLen: UInt64
    var payloadOffset: Int
    var legacyPlaintextSize: UInt64
    var legacySHA256: Data?
    var crcOK: Bool
    var wrapAAD: Data             // v3 only; empty otherwise

    var isChunked: Bool { version >= 3 }

    /// Build the two fixed parts of a v3 header: bytes 0..45 and 94..105.
    static func v3Parts(kdfId: UInt8, paramWord: UInt32, maxFailures: UInt8,
                        salt: Data, wrapNonce: Data, noncePrefix: Data,
                        chunkLog2: UInt8) -> (head: Data, tail: Data) {
        var h = Data(capacity: 46)
        h.append(contentsOf: EmbalmFormat.magic)
        h.append(EmbalmFormat.currentVersion)
        h.append(EmbalmFormat.cipherAESGCMStream)
        h.append(kdfId)
        h.appendBigEndian(paramWord)
        h.append(maxFailures)
        h.append(0)                                   // failureCount
        h.append(UInt8(EmbalmFormat.saltLength))
        h.append(salt)
        h.append(wrapNonce)
        h.appendBigEndian(UInt16(EmbalmFormat.wrappedDEKLength))
        precondition(h.count == 46)
        var t = Data(capacity: 12)
        t.append(noncePrefix)
        t.append(chunkLog2)
        t.append(contentsOf: [0, 0, 0, 0])
        precondition(t.count == 12)
        return (h, t)
    }

    static func parse(_ data: Data) throws -> EmbalmHeader {
        guard data.count >= EmbalmFormat.offTail else { throw EmbalmError.notAnEmbalmFile }
        let b = [UInt8](data)
        guard Array(b[0..<6]) == EmbalmFormat.magic else { throw EmbalmError.notAnEmbalmFile }
        let version = b[EmbalmFormat.offVersion]
        guard version >= 1 && version <= EmbalmFormat.currentVersion else {
            throw EmbalmError.unsupportedVersion(version)
        }
        let cipher = b[EmbalmFormat.offCipherId]
        guard cipher == (version >= 3 ? EmbalmFormat.cipherAESGCMStream : EmbalmFormat.cipherAESGCM) else {
            throw EmbalmError.corruptHeader("unknown cipher id")
        }
        let kdfId = b[EmbalmFormat.offKdfId]
        guard kdfId == EmbalmFormat.kdfPBKDF2SHA256 || kdfId == EmbalmFormat.kdfArgon2id else {
            throw EmbalmError.corruptHeader("unknown KDF id")
        }
        guard Int(b[EmbalmFormat.offSaltLen]) == EmbalmFormat.saltLength else {
            throw EmbalmError.corruptHeader("unexpected salt length")
        }
        guard Int(UInt16(bigEndian: b, at: EmbalmFormat.offWrapLen)) == EmbalmFormat.wrappedDEKLength else {
            throw EmbalmError.corruptHeader("unexpected wrapped-key length")
        }
        let salt = Data(b[EmbalmFormat.offSalt..<(EmbalmFormat.offSalt + EmbalmFormat.saltLength)])
        let wrapNonce = Data(b[EmbalmFormat.offWrapNonce..<(EmbalmFormat.offWrapNonce + EmbalmFormat.nonceLength)])

        var h = EmbalmHeader(
            version: version, kdfId: kdfId,
            kdfParamWord: UInt32(bigEndian: b, at: EmbalmFormat.offKdfParams),
            maxFailures: b[EmbalmFormat.offMaxFailures],
            failureCount: b[EmbalmFormat.offFailureCount],
            salt: salt, wrapNonce: wrapNonce, wrappedDEK: Data(),
            payloadNonce: Data(), noncePrefix: Data(), chunkLog2: 0,
            payloadLen: 0, payloadOffset: 0, legacyPlaintextSize: 0,
            legacySHA256: nil, crcOK: true, wrapAAD: Data())

        func needs(_ n: Int, _ why: String) throws {
            guard b.count >= n else { throw EmbalmError.damaged("header is cut short") }
        }

        switch version {
        case 3:
            try needs(EmbalmFormat.v3HeaderLength, "v3")
            h.wrappedDEK = Data(b[EmbalmFormat.offWrappedDEK..<(EmbalmFormat.offWrappedDEK + 48)])
            h.noncePrefix = Data(b[94..<101])
            h.chunkLog2 = b[EmbalmFormat.v3OffChunkLog2]
            h.payloadLen = UInt64(bigEndian: b, at: EmbalmFormat.v3OffPayloadLen)
            h.payloadOffset = EmbalmFormat.v3HeaderLength
            var masked = Array(b[0..<106]); masked[EmbalmFormat.offFailureCount] = 0
            h.crcOK = CRC32.checksum(masked) == UInt32(bigEndian: b, at: EmbalmFormat.v3OffCRC)
            var aad = Array(b[0..<46]); aad[EmbalmFormat.offFailureCount] = 0
            aad += b[94..<106]
            h.wrapAAD = Data(aad)
        case 2:
            try needs(EmbalmFormat.v2HeaderLength, "v2")
            h.wrappedDEK = Data(b[EmbalmFormat.offWrappedDEK..<(EmbalmFormat.offWrappedDEK + 48)])
            h.payloadNonce = Data(b[94..<106])
            h.payloadLen = UInt64(bigEndian: b, at: EmbalmFormat.v2OffPayloadLen)
            h.payloadOffset = EmbalmFormat.v2HeaderLength
        default:
            try needs(EmbalmFormat.v1HeaderLength, "v1")
            h.wrappedDEK = Data(b[EmbalmFormat.offWrappedDEK..<(EmbalmFormat.offWrappedDEK + 48)])
            h.payloadNonce = Data(b[94..<106])
            h.legacySHA256 = Data(b[EmbalmFormat.v1OffSHA256..<(EmbalmFormat.v1OffSHA256 + 32)])
            h.payloadLen = UInt64(bigEndian: b, at: EmbalmFormat.v1OffPayloadLen)
            h.payloadOffset = EmbalmFormat.v1HeaderLength
        }
        if !h.isChunked {
            h.legacyPlaintextSize = h.payloadLen >= 16 ? h.payloadLen - 16 : 0
        }
        return h
    }
}

// MARK: - Big-endian helpers

extension Data {
    mutating func appendBigEndian(_ v: UInt16) { Swift.withUnsafeBytes(of: v.bigEndian) { append(contentsOf: $0) } }
    mutating func appendBigEndian(_ v: UInt32) { Swift.withUnsafeBytes(of: v.bigEndian) { append(contentsOf: $0) } }
    mutating func appendBigEndian(_ v: UInt64) { Swift.withUnsafeBytes(of: v.bigEndian) { append(contentsOf: $0) } }
}
extension UInt16 {
    init(bigEndian b: [UInt8], at o: Int) { self = (UInt16(b[o]) << 8) | UInt16(b[o + 1]) }
}
extension UInt32 {
    init(bigEndian b: [UInt8], at o: Int) { var v: UInt32 = 0; for i in 0..<4 { v = (v << 8) | UInt32(b[o + i]) }; self = v }
}
extension UInt64 {
    init(bigEndian b: [UInt8], at o: Int) { var v: UInt64 = 0; for i in 0..<8 { v = (v << 8) | UInt64(b[o + i]) }; self = v }
}
