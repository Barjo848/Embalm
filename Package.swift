// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Embalm",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(name: "EmbalmCore", targets: ["EmbalmCore"]),
        .executable(name: "embalm", targets: ["embalm-cli"]),
        .executable(name: "embalm-selftest", targets: ["embalm-selftest"]),
        .executable(name: "EmbalmGUI", targets: ["EmbalmGUI"]),
    ],
    dependencies: [
        // Argon2id (memory-hard KDF). Vendors the PHC reference C implementation,
        // so there is no system-library dependency. Pinned to an exact revision:
        // review the diff before moving it.
        .package(url: "https://github.com/tmthecoder/Argon2Swift.git", revision: "53543623fefe68461b7eeea03d7f96677c2fd76d"),
    ],
    targets: [
        .target(
            name: "EmbalmCore",
            dependencies: [
                .product(name: "Argon2Swift", package: "Argon2Swift"),
            ]
        ),
        .executableTarget(
            name: "embalm-cli",
            dependencies: ["EmbalmCore"]
        ),
        // The AppKit app. release/build-release.sh copies the product into Embalm.app.
        .executableTarget(
            name: "EmbalmGUI",
            dependencies: ["EmbalmCore"]
        ),
        // Self-test runner. XCTest is not available with the Command Line Tools
        // (only with full Xcode), so the engine's verification is an ordinary
        // executable you can run with `swift run embalm-selftest`.
        .executableTarget(
            name: "embalm-selftest",
            dependencies: ["EmbalmCore"]
        ),
    ]
)
