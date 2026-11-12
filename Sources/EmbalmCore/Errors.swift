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
    /// This file's key block is in a separate key file, which was not supplied.
    case keyFileNeeded
    /// The key file supplied belongs to a different embalmed file.
    case keyFileMismatch
    /// The file offered as a key file is not one.
    case notAKeyFile
    /// The password was right, and this many more different passwords are needed.
    case morePasswordsNeeded(Int)
    /// This person's password was already accepted for this opening.
    case passwordAlreadyGiven
    /// The decoy file is larger than the space every file reserves for one.
    case decoyTooLarge
    /// The options chosen for embalming cannot be combined or are incomplete.
    case invalidOptions(String)
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
        case .keyFileNeeded:
            return "This file was embalmed with a separate key file. Choose its key file to continue."
        case .keyFileMismatch:
            return "That key file belongs to a different embalmed file. No password attempt was used."
        case .notAKeyFile:
            return "That is not an Embalm key file."
        case .morePasswordsNeeded(let n):
            return "Password accepted. \(n) more password\(n == 1 ? " is" : "s are") needed from other holders."
        case .passwordAlreadyGiven:
            return "That password was already accepted. A different holder's password is needed. No attempt was used."
        case .decoyTooLarge:
            return "The decoy file is too large. It must be \(EmbalmEngine.maxDecoyBytes / 1000) KB or smaller."
        case .invalidOptions(let why):
            return why
        }
    }
}
