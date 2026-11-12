import Foundation

/// Best-effort secure erasure of bytes already on disk.
///
/// Honesty note: on flash storage, overwriting logical bytes does not guarantee
/// the physical blocks are erased (wear levelling, APFS snapshots, backups).
/// Embalm does not rely on physical erasure. Its guarantee is cryptographic:
/// shredding destroys the wrapped key, which exists nowhere else.
enum SecureErase {
    /// Overwrite `length` bytes at `offset` with random data, in 1 MiB steps so
    /// memory use stays flat for large files, then flush to the device.
    static func overwrite(_ handle: FileHandle, offset: UInt64, length: UInt64) throws {
        guard length > 0 else { return }
        let step: UInt64 = 1 << 20
        var done: UInt64 = 0
        try handle.seek(toOffset: offset)
        while done < length {
            let n = Int(min(step, length - done))
            try handle.write(contentsOf: RandomBytes.makeData(n))
            done += UInt64(n)
        }
        fullSync(handle)
    }

    /// Ask the OS to flush all the way to the device where possible.
    static func fullSync(_ handle: FileHandle) {
        let fd = handle.fileDescriptor
        if fcntl(fd, F_FULLFSYNC) == -1 { fsync(fd) }
    }
}
