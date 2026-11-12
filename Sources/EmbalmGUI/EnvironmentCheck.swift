import Foundation
import Darwin
import AppKit
import Security
import EmbalmCore

/// Runtime proof of what this process can and cannot do. Run with --self-check.
/// Inside the sandbox the operating system itself blocks network access and
/// access to the rest of the user's files. These checks try to do both.
enum EnvironmentCheck {

    @discardableResult
    static func run(report: (CheckResult) -> Void) -> Bool {
        var ok = true
        func record(_ name: String, _ pass: Bool, _ detail: String) {
            if !pass { ok = false }
            report(CheckResult(group: "This app's sandbox", name: name, passed: pass, detail: detail))
        }

        // 1. The sandbox is active.
        let sandboxed = ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
        record("The macOS App Sandbox is active for this process", sandboxed,
               sandboxed ? "container \(ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] ?? "")"
                         : "not sandboxed")

        // 2. Entitlements granted to the running process.
        func entitlement(_ key: String) -> Bool {
            guard let task = SecTaskCreateFromSelf(nil),
                  let v = SecTaskCopyValueForEntitlement(task, key as CFString, nil) else { return false }
            return (v as? Bool) ?? true
        }
        let net = ["com.apple.security.network.client", "com.apple.security.network.server"].filter(entitlement)
        record("No network entitlement was granted", net.isEmpty,
               net.isEmpty ? "no client or server access" : "granted: \(net.joined(separator: ", "))")

        // 3. Try to reach the network. Port 9 on loopback has no listener, so an
        //    unsandboxed process would see "connection refused"; the sandbox
        //    refuses the attempt itself. No packet leaves this Mac either way.
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var blockedBySandbox = false
        var detail = "could not create a socket"
        if fd >= 0 {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(9).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            let r = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            let e = errno
            close(fd)
            blockedBySandbox = (r == -1 && e == EPERM)
            detail = blockedBySandbox ? "the operating system refused the connection (EPERM)"
                                      : "connect returned \(r), errno \(e): NOT blocked"
        } else if errno == EPERM || errno == EACCES {
            blockedBySandbox = true
            detail = "the operating system refused to create a socket"
        }
        record("An attempted network connection is blocked by the operating system", blockedBySandbox, detail)

        // 4. Try to read the user's real folders.
        let home = getpwuid(getuid()).flatMap { String(cString: $0.pointee.pw_dir) } ?? "/var/empty"
        var readable: [String] = []
        for sub in ["Desktop", "Documents", "Downloads", ".ssh", "Library/Messages", "Library/Mail", "Library/Safari"] {
            if let d = opendir(home + "/" + sub) { closedir(d); readable.append(sub) }
        }
        record("The app cannot read your Desktop, Documents, Downloads or keys", readable.isEmpty,
               readable.isEmpty ? "all refused" : "readable: \(readable.joined(separator: ", "))")

        // 5. Typefaces. If this build bundles them, each must load by name (a system
        //    fallback is then a failure). A build without them uses system faces.
        if Atlas.fontsBundled {
            let missing = [Atlas.heros, Atlas.herosBold, Atlas.mono].filter { NSFont(name: $0, size: 12) == nil }
            report(CheckResult(group: "This app's sandbox", name: "The three bundled typefaces load by name",
                               passed: missing.isEmpty, detail: missing.isEmpty ? "Heros, Heros Bold, Courier Code" : "missing: \(missing.joined(separator: ", "))"))
            if !missing.isEmpty { ok = false }
        } else {
            report(CheckResult(group: "This app's sandbox", name: "Typefaces: none bundled, system faces in use",
                               passed: true, detail: "Helvetica and the system monospace"))
        }

        // 6. It can still work in its own private space.
        let probe = FileManager.default.temporaryDirectory.appendingPathComponent("probe-\(UUID().uuidString)")
        let canWrite = (try? Data("ok".utf8).write(to: probe)) != nil
        try? FileManager.default.removeItem(at: probe)
        record("The app can still use its own private temporary space", canWrite, "")
        return ok
    }
}
