import Foundation

/// Length padding, so the container size reveals only a rough size class.
///
/// Uses Padmé (Nikitin et al., 2019): the padded length leaks only O(log log n)
/// bits and costs at most about 12% overhead on large files. Every file also
/// gets a floor, so all small files look the same size.
enum Padding {
    static let minimumPaddedLength: UInt64 = 4096

    static func padme(_ length: UInt64) -> UInt64 {
        guard length > 2 else { return length }
        let e = UInt64(63 - length.leadingZeroBitCount)       // floor(log2 L)
        let s = UInt64(63 - e.leadingZeroBitCount) + 1        // floor(log2 e) + 1
        let lastBits = e - s
        let mask: UInt64 = (1 << lastBits) - 1
        return (length + mask) & ~mask
    }

    static func paddedLength(_ length: UInt64) -> UInt64 {
        max(padme(length), minimumPaddedLength)
    }
}

/// CRC-32 (IEEE). Used only to tell accidental damage in transit apart from a
/// wrong password. It is not a security mechanism.
enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
        return c
    }
    static func checksum(_ bytes: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        for b in bytes { c = table[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFFFFFF
    }
}
