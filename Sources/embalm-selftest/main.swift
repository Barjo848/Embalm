import Foundation
import EmbalmCore

// Development test runner. Runs the same suite that ships inside the app.
var count = 0, failed = 0
var group = ""
let ok = SelfCheck.runCrypto { r in
    if r.group != group { group = r.group; print("[\(group)]") }
    count += 1
    if !r.passed { failed += 1 }
    print("  \(r.passed ? "ok  " : "FAIL") - \(r.name)\(r.detail.isEmpty ? "" : "  (\(r.detail))")")
}
print("\n\(count - failed)/\(count) checks passed")
print(ok ? "SELF-TEST PASSED" : "SELF-TEST FAILED")
exit(ok ? 0 : 1)
