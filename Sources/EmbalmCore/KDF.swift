import Foundation
import CommonCrypto
import Argon2Swift

/// A password-based key-derivation choice and how it is stored in the header.
///
/// The header holds a 1-byte `kdfId` and a 4-byte parameter word:
///   * PBKDF2 (kdfId 1): the word is the iteration count.
///   * Argon2id (kdfId 2): the word packs `[timeCost, log2(memory KiB), lanes, 0]`.
/// Every file records the exact parameters it was made with.
public enum KDFChoice: Equatable {
    case pbkdf2(iterations: UInt32)
    case argon2id(timeCost: UInt8, memoryLog2KiB: UInt8, parallelism: UInt8)

    /// Legacy option, kept for old files and as a fallback.
    public static let defaultPBKDF2 = KDFChoice.pbkdf2(iterations: 600_000)
    /// Default: Argon2id with 512 MiB of memory, 4 passes and 4 lanes. Every guess
    /// an attacker makes must find 512 MiB of memory, which is what makes
    /// cracking on GPUs and custom hardware expensive.
    public static let defaultArgon2id = KDFChoice.argon2id(timeCost: 4, memoryLog2KiB: 19, parallelism: 4)

    var kdfId: UInt8 {
        switch self {
        case .pbkdf2:   return EmbalmFormat.kdfPBKDF2SHA256
        case .argon2id: return EmbalmFormat.kdfArgon2id
        }
    }

    var paramWord: UInt32 {
        switch self {
        case .pbkdf2(let it): return it
        case .argon2id(let t, let m, let p):
            return (UInt32(t) << 24) | (UInt32(m) << 16) | (UInt32(p) << 8)
        }
    }

    /// Rebuild a choice from a header. Bounds are enforced so a hostile file
    /// cannot demand absurd memory (cap: 1 GiB) or time.
    init(kdfId: UInt8, paramWord: UInt32) throws {
        switch kdfId {
        case EmbalmFormat.kdfPBKDF2SHA256:
            guard paramWord >= 1, paramWord <= 100_000_000 else {
                throw EmbalmError.corruptHeader("invalid PBKDF2 parameters")
            }
            self = .pbkdf2(iterations: paramWord)
        case EmbalmFormat.kdfArgon2id:
            let t = UInt8((paramWord >> 24) & 0xFF)
            let m = UInt8((paramWord >> 16) & 0xFF)
            let p = UInt8((paramWord >> 8) & 0xFF)
            guard t >= 1, t <= 32, p >= 1, p <= 16, m >= 3, m <= 20, (1 << Int(m)) >= 8 * Int(p) else {
                throw EmbalmError.corruptHeader("invalid Argon2 parameters")
            }
            self = .argon2id(timeCost: t, memoryLog2KiB: m, parallelism: p)
        default:
            throw EmbalmError.corruptHeader("unknown KDF id \(kdfId)")
        }
    }

    public var displayName: String {
        switch self {
        case .pbkdf2(let it):
            return "PBKDF2-HMAC-SHA256 (\(it) iterations)"
        case .argon2id(let t, let m, let p):
            let kib = 1 << Int(m)
            let mem = kib >= 1024 ? "\(kib / 1024) MiB" : "\(kib) KiB"
            return "Argon2id (\(mem), \(t) passes, \(p) lane\(p == 1 ? "" : "s"))"
        }
    }

    /// Derive a 32-byte key. `normalize` applies Unicode NFKC to the password so
    /// the same typed password works whatever keyboard composed it. New (v3)
    /// files normalize; older files were made from raw bytes and must not.
    func deriveKey(password: String, salt: Data, normalize: Bool) throws -> Data {
        let pw = normalize ? password.precomposedStringWithCompatibilityMapping : password
        switch self {
        case .pbkdf2(let iterations):
            return KDF.pbkdf2(password: pw, salt: salt, iterations: iterations)
        case .argon2id(let t, let m, let p):
            do {
                let result = try Argon2Swift.hashPasswordBytes(
                    password: Data(pw.utf8),
                    salt: Salt(bytes: salt),
                    iterations: Int(t),
                    memory: 1 << Int(m),
                    parallelism: Int(p),
                    length: EmbalmFormat.dekLength,
                    type: .id)
                return result.hashData()
            } catch {
                throw EmbalmError.io("Argon2id derivation failed")
            }
        }
    }
}

public enum KDF {
    public static let defaultIterations: UInt32 = 600_000

    /// PBKDF2-HMAC-SHA256 via CommonCrypto (ships with the OS).
    static func pbkdf2(password: String, salt: Data, iterations: UInt32) -> Data {
        let passwordBytes = Array(password.utf8)
        var derived = [UInt8](repeating: 0, count: EmbalmFormat.dekLength)
        let saltBytes = [UInt8](salt)
        let status = saltBytes.withUnsafeBufferPointer { saltPtr in
            passwordBytes.withUnsafeBufferPointer { passPtr in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passPtr.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: Int8.self) },
                    passwordBytes.count,
                    saltPtr.baseAddress, saltBytes.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations, &derived, derived.count)
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 derivation failed")
        return Data(derived)
    }
}
