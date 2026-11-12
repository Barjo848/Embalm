import Foundation

/// Generates passwords from the system's cryptographic random source. Every
/// choice is uniform and independent, so the stated strength is exact.
public enum PasswordGenerator {
    public struct Generated {
        public let password: String
        /// Bits of randomness: log2 of the number of equally likely passwords.
        public let bits: Double
    }

    public static let wordRange = 3...10
    public static let lengthRange = 12...64
    public static let symbols = Array("!@#$%^&*")
    static let alphanumerics = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    /// Words joined by hyphens, like Dealmaker7-Elated2-Obscurity5.
    public static func memorable(words count: Int, capitalize: Bool, numbers: Bool) -> Generated {
        var rng = SystemRandomNumberGenerator()
        let n = min(max(count, wordRange.lowerBound), wordRange.upperBound)
        let list = Wordlist.words
        let parts: [String] = (0..<n).map { _ in
            var w = list[Int.random(in: 0..<list.count, using: &rng)]
            if capitalize { w = w.prefix(1).uppercased() + w.dropFirst() }
            if numbers { w += String(Int.random(in: 0...9, using: &rng)) }
            return w
        }
        let perWord = log2(Double(list.count)) + (numbers ? log2(10) : 0)
        return Generated(password: parts.joined(separator: "-"), bits: Double(n) * perWord)
    }

    /// Letters and digits, with eight common symbols if asked.
    public static func random(length: Int, symbols useSymbols: Bool) -> Generated {
        var rng = SystemRandomNumberGenerator()
        let n = min(max(length, lengthRange.lowerBound), lengthRange.upperBound)
        let alphabet = alphanumerics + (useSymbols ? symbols : [])
        let chars = (0..<n).map { _ in alphabet[Int.random(in: 0..<alphabet.count, using: &rng)] }
        return Generated(password: String(chars), bits: Double(n) * log2(Double(alphabet.count)))
    }
}
