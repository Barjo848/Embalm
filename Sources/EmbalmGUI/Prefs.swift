import Foundation
import EmbalmCore

/// User settings. They live in this app's private container and never leave the Mac.
enum Prefs {
    private static let d = UserDefaults.standard

    static func register() {
        d.register(defaults: ["maxFailures": 2, "strongKDF": false, "padding": true,
                              "storeName": true, "verify": true, "reveal": true, "largeWindow": false])
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

    /// Standard: 512 MiB, 4 passes. Maximum: 1 GiB, 4 passes (the format's ceiling).
    static var kdf: KDFChoice {
        strongKDF ? .argon2id(timeCost: 4, memoryLog2KiB: 20, parallelism: 4) : .defaultArgon2id
    }
}
