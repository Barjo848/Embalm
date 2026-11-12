import Foundation
import EmbalmCore

/// User settings. They live in this app's private container and never leave the Mac.
enum Prefs {
    private static let d = UserDefaults.standard

    static func register() {
        d.register(defaults: ["maxFailures": 2, "strongKDF": false, "padding": true,
                              "storeName": true, "verify": true, "reveal": true, "largeWindow": false,
                              "genRandom": false, "genWords": 5, "genLength": 24,
                              "genCapitalize": true, "genNumbers": true, "genSymbols": true,
                              "duress": false, "quorum": false, "quorumPreset": 1, "keyFile": false])
    }

    /// Wrong passwords in a row before a newly embalmed file destroys itself.
    static var maxFailures: Int {
        get { let v = d.integer(forKey: "maxFailures"); return [2, 3, 5].contains(v) ? v : 2 }
        set { d.set(newValue, forKey: "maxFailures") }
    }
    static var strongKDF: Bool { get { d.bool(forKey: "strongKDF") } set { d.set(newValue, forKey: "strongKDF") } }
    static var padding: Bool { get { d.bool(forKey: "padding") } set { d.set(newValue, forKey: "padding") } }
    static var storeName: Bool { get { d.bool(forKey: "storeName") } set { d.set(newValue, forKey: "storeName") } }
    static var verify: Bool { get { d.bool(forKey: "verify") } set { d.set(newValue, forKey: "verify") } }
    static var reveal: Bool { get { d.bool(forKey: "reveal") } set { d.set(newValue, forKey: "reveal") } }
    static var largeWindow: Bool { get { d.bool(forKey: "largeWindow") } set { d.set(newValue, forKey: "largeWindow") } }

    // The password generator remembers its options, never a password.
    static var genRandom: Bool { get { d.bool(forKey: "genRandom") } set { d.set(newValue, forKey: "genRandom") } }
    static var genWords: Int { get { d.integer(forKey: "genWords") } set { d.set(newValue, forKey: "genWords") } }
    static var genLength: Int { get { d.integer(forKey: "genLength") } set { d.set(newValue, forKey: "genLength") } }
    static var genCapitalize: Bool { get { d.bool(forKey: "genCapitalize") } set { d.set(newValue, forKey: "genCapitalize") } }
    static var genNumbers: Bool { get { d.bool(forKey: "genNumbers") } set { d.set(newValue, forKey: "genNumbers") } }
    static var genSymbols: Bool { get { d.bool(forKey: "genSymbols") } set { d.set(newValue, forKey: "genSymbols") } }

    // Extra protection. All three are off unless switched on in Settings.
    static var duress: Bool { get { d.bool(forKey: "duress") } set { d.set(newValue, forKey: "duress") } }
    static var quorum: Bool { get { d.bool(forKey: "quorum") } set { d.set(newValue, forKey: "quorum") } }
    static var keyFile: Bool { get { d.bool(forKey: "keyFile") } set { d.set(newValue, forKey: "keyFile") } }
    /// Passwords needed and passwords issued, for each choice offered in Settings.
    static let quorumPresets: [(threshold: Int, holders: Int)] = [(2, 2), (2, 3), (3, 5)]
    static var quorumPreset: Int {
        get { min(max(d.integer(forKey: "quorumPreset"), 0), quorumPresets.count - 1) }
        set { d.set(newValue, forKey: "quorumPreset") }
    }

    /// Standard: 512 MiB, 4 passes. Maximum: 1 GiB, 4 passes (the format's ceiling).
    static var kdf: KDFChoice {
        strongKDF ? .argon2id(timeCost: 4, memoryLog2KiB: 20, parallelism: 4) : .defaultArgon2id
    }
}
