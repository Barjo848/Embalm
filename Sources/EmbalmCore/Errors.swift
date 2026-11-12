import Foundation

/// Errors surfaced by the Embalm engine.
public enum EmbalmError: Error, Equatable {
    /// Not an Embalm container (bad magic / too short).
    case notAnEmbalmFile
    /// Written by a newer, incompatible format version.
    case unsupportedVersion(UInt8)
    /// Header is structurally invalid.
    case corruptHeader(String)
    /// The file is incomplete or damaged (typically in transit). No password
    /// attempt was used.
    case damaged(String)
    /// Wrong password. `remaining` attempts are left before self-destruct.
    case wrongPassword(remaining: Int)
    /// The final wrong attempt was just made; the container has been shredded.
    case destroyed
    /// The container was shredded earlier.
    case alreadyDestroyed
    /// Password was right, but the data failed authentication (damaged file).
    case integrityCheckFailed
    /// The container sits on read-only storage, so the attempt limit could not
    /// be enforced. Copy it somewhere writable first.
    case readOnlySource
    /// Filesystem trouble.
    case io(String)
}

extension EmbalmError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .notAnEmbalmFile:
            return "This is not an Embalm file."
        case .unsupportedVersion(let v):
            return "This file uses format version \(v), which this version of Embalm cannot open. Update Embalm."
        case .corruptHeader(let why):
            return "The Embalm file is corrupt: \(why)."
        case .damaged(let why):
            return "This file is damaged or incomplete (\(why)). It was probably corrupted in transit. No password attempt was used. Send it again."
        case .wrongPassword(let remaining):
            return remaining <= 0
                ? "Wrong password. This was the final attempt."
                : "Wrong password. \(remaining) attempt(s) remaining before this file self-destructs."
        case .destroyed:
            return "Wrong password entered too many times. The file has self-destructed and cannot be recovered."
        case .alreadyDestroyed:
            return "This file already self-destructed on an earlier attempt. Nothing remains to recover."
        case .integrityCheckFailed:
            return "The password was correct, but the data is damaged and failed its integrity check. Send the file again."
        case .readOnlySource:
            return "This file is on read-only storage, so the attempt limit cannot be enforced. Copy it to your Mac first, then open the copy."
        case .io(let msg):
            return "Filesystem error: \(msg)."
        }
    }
}
