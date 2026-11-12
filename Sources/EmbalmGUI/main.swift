import AppKit
import EmbalmCore

// Never leave a core dump (it could contain key material).
var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
setrlimit(RLIMIT_CORE, &noCore)

// Command line modes, used by the setup assessment: no window is created.
let arguments = CommandLine.arguments
Atlas.registerFonts()
if arguments.contains("--version") {
    print("Embalm 1.0.0")
    exit(0)
}
if arguments.contains("--self-check") {
    var group = "", total = 0, failed = 0
    func show(_ r: CheckResult) {
        if r.group != group { group = r.group; print("[\(group)]") }
        total += 1; if !r.passed { failed += 1 }
        print("  \(r.passed ? "[ OK ]" : "[FAIL]") \(r.name)\(r.detail.isEmpty ? "" : " (\(r.detail))")")
    }
    let envOK = EnvironmentCheck.run(report: show)
    let cryptoOK = SelfCheck.runCrypto(report: show)
    print("\n\(total - failed)/\(total) checks passed")
    print(envOK && cryptoOK ? "SELF-CHECK PASSED" : "SELF-CHECK FAILED")
    exit(envOK && cryptoOK ? 0 : 1)
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuItemValidation {
    var controller: MainController?
    private var settings: SettingsWindowController?
    private var instructions: InfoWindowController?
    private var report: InfoWindowController?
    private var pending: [URL] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        Prefs.register()
        UserDefaults.standard.register(defaults: ["NSQuitAlwaysKeepsWindows": false])
        NSApp.mainMenu = buildMainMenu(delegate: self)
        let c = MainController()
        controller = c
        c.window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if !pending.isEmpty { c.accept(pending); pending = [] }
        #if EMBALM_PROBE
        // Development-only: open the secondary windows for visual checks.
        if arguments.contains("--open-settings") { showSettings(nil) }
        if arguments.contains("--open-instructions") { showInstructions(nil) }
        if arguments.contains("--open-selfcheck") { runSelfCheck(nil) }
        #endif
    }

    // Double-click, "Open With", dragging onto the Dock icon.
    func application(_ application: NSApplication, open urls: [URL]) {
        #if EMBALM_PROBE
        // Development-only: records what the sandbox allows for files handed over by
        // Launch Services. Compiled out of every release build.
        var out: [String] = []
        for u in urls {
            out.append("url: \(u.lastPathComponent)")
            do {
                let h = try FileHandle(forUpdating: u)
                try h.seek(toOffset: 0)
                let d = try h.read(upToCount: 6)
                out.append("update-open: ok, magic=\(String(decoding: d ?? Data(), as: UTF8.self))")
                try h.close()
            } catch { out.append("update-open: FAILED \(error)") }
        }
        try? out.joined(separator: "\n").write(
            to: FileManager.default.temporaryDirectory.appendingPathComponent("probe.txt"),
            atomically: true, encoding: .utf8)
        #endif
        if let c = controller { c.accept(urls) } else { pending += urls }
    }

    @objc func openDocument(_ sender: Any?) { controller?.chooseFiles() }

    @objc func toggleLargeWindow(_ sender: Any?) {
        Prefs.largeWindow.toggle()
        controller?.applySize(large: Prefs.largeWindow, animate: true)
    }

    @objc func showSettings(_ sender: Any?) {
        if settings == nil { settings = SettingsWindowController() }
        settings?.show()
    }

    @objc func showInstructions(_ sender: Any?) {
        if instructions == nil {
            instructions = InfoWindowController(title: "Instructions", size: NSSize(width: 460, height: 560),
                                                content: HelpText.instructions())
        }
        instructions?.show()
    }

    @objc func runSelfCheck(_ sender: Any?) {
        let w = InfoWindowController(title: "Self-Check", size: NSSize(width: 520, height: 560),
                                     content: Atlas.attributed("Running checks…\n", Atlas.T.inspectorParagraph, color: Atlas.C.dark, k: 1))
        report = w
        w.show()
        DispatchQueue.global(qos: .userInitiated).async {
            var rows: [CheckResult] = []
            let envOK = EnvironmentCheck.run { rows.append($0) }
            let cryptoOK = SelfCheck.runCrypto { rows.append($0) }
            let text = HelpText.selfCheck(rows, passed: envOK && cryptoOK)
            DispatchQueue.main.async { w.setContent(text) }
        }
    }

    func validateMenuItem(_ item: NSMenuItem) -> Bool {
        if item.action == #selector(toggleLargeWindow(_:)) { item.state = Prefs.largeWindow ? .on : .off }
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
