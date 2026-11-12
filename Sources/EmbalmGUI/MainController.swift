import AppKit
import EmbalmCore

/// The main window: a perfect square (333 pt, or 777 pt from the View menu) in the
/// Atlas design. Every length is a scale-1 value multiplied by k = side / 333.
final class MainController: NSObject, NSTextFieldDelegate {
    enum Mode { case none, embalm, mummify, finished }

    let window: NSWindow
    private let root = AtlasRootView()
    private let titleBar = TitleBarView()
    private let pane = PaneView(frame: .zero)
    private let paneTitle = AtlasLabel()
    private let paneSub = AtlasLabel()
    private let passwordField = FieldView()
    private let confirmField = FieldView()
    private let strengthLabel = AtlasLabel()
    private let progressBar = HatchProgressView()
    private let actionButton = AtlasButton()
    private let statusLabel = AtlasLabel()
    private let footerRule = RuleView()
    private let footerLabel = AtlasLabel()

    private var mode: Mode = .none
    private var current: URL?
    private var queue: [URL] = []
    private var busy = false
    private var status: EmbalmEngine.Status?
    private var doneName = ""
    private var message = ""
    private var messageColor = Atlas.C.dark
    private var opened: EmbalmEngine.OpenedContainer?
    private var revealURL: URL?

    private static let baseSide: CGFloat = 333
    private static let largeSide: CGFloat = 777

    override init() {
        window = AtlasWindowFactory.make(size: NSSize(width: Self.baseSide, height: Self.baseSide))
        super.init()
        window.contentView = root
        root.onLayout = { [weak self] in self?.layoutAll() }

        titleBar.version = "v1.0.0"
        [titleBar, pane, passwordField, confirmField, strengthLabel, progressBar, actionButton,
         statusLabel, footerRule, footerLabel].forEach { root.addSubview($0) }
        pane.addSubview(paneTitle); pane.addSubview(paneSub)

        pane.onClick = { [weak self] in self?.chooseFiles() }
        pane.onDrop = { [weak self] urls in self?.accept(urls) }
        passwordField.placeholder = "Password"
        confirmField.placeholder = "Confirm password"
        passwordField.field.delegate = self
        confirmField.field.delegate = self
        actionButton.kind = .primary
        actionButton.keyEquivalent = "\r"
        actionButton.target = self; actionButton.action = #selector(performAction)
        actionButton.setAccessibilityLabel("Embalm or Mummify")
        footerRule.color = Atlas.C.line
        footerLabel.text = "AES-256-GCM · Argon2id · stays on this Mac"
        footerLabel.style = Atlas.T.inspectorNote; footerLabel.color = Atlas.C.dark
        footerLabel.lineBreak = .byTruncatingTail

        message = Self.hint; messageColor = Atlas.C.dark
        applySize(large: Prefs.largeWindow, animate: false)
        refresh()
    }

    private static let hint = "Embalm: drop any file, then choose a password.\nMummify: drop an embalmed file and enter its password.\nHelp, Embalm Instructions explains the rest."

    // MARK: size

    /// Square windows only. 777 shrinks to fit a small screen, staying square.
    func applySize(large: Bool, animate: Bool) {
        var side = large ? Self.largeSide : Self.baseSide
        if let vis = (window.screen ?? NSScreen.main)?.visibleFrame { side = min(side, floor(min(vis.width, vis.height) - 8)) }
        var f = window.frame
        let top = f.maxY
        f.size = NSSize(width: side, height: side)
        f.origin.y = max(((window.screen ?? NSScreen.main)?.visibleFrame.minY ?? 0), top - side)
        window.setFrame(f, display: true, animate: animate)
        root.needsLayout = true
        layoutAll()
    }

    // MARK: layout (all lengths scale with k)

    private func layoutAll() {
        let W = root.bounds.width, H = root.bounds.height
        guard W > 0 else { return }
        let k = W / Self.baseSide
        let P = Atlas.S.mainPadding * k, cw = W - 2 * P
        let pad = Atlas.S.focusPad * k

        titleBar.k = k
        titleBar.frame = NSRect(x: 0, y: 0, width: W, height: Atlas.S.titlebar * k)

        let footerH = 26 * k
        footerRule.frame = NSRect(x: P, y: H - footerH, width: cw, height: 2 * k)
        footerLabel.k = k; footerLabel.refresh()
        footerLabel.frame = NSRect(x: P, y: H - footerH + 8 * k, width: cw, height: 15 * k)

        var y = (Atlas.S.titlebar + 14) * k
        let hasFile = mode != .none
        let paneH = (hasFile ? 78 : 150) * k
        pane.k = k
        pane.frame = NSRect(x: P, y: y, width: cw, height: paneH)
        let ix = 11 * k, iw = cw - 22 * k, strip = pane.stripHeight
        paneTitle.k = k; paneTitle.style = Atlas.T.rowTitle; paneTitle.color = Atlas.C.ink
        paneTitle.lineBreak = .byTruncatingMiddle; paneTitle.refresh()
        paneTitle.frame = NSRect(x: ix, y: strip + 9 * k, width: iw, height: 20 * k)
        paneSub.k = k; paneSub.style = Atlas.T.rowSummary; paneSub.color = Atlas.C.dark; paneSub.refresh()
        let subH = min(paneH - strip - 9 * k - 20 * k - 6 * k, paneSub.height(forWidth: iw))
        paneSub.frame = NSRect(x: ix, y: strip + 32 * k, width: iw, height: max(0, subH))
        y += paneH + 10 * k

        let showFields = (mode == .embalm || mode == .mummify)
        let fh = 28 * k + 2 * pad
        passwordField.k = k
        passwordField.isHidden = !showFields
        passwordField.frame = NSRect(x: P - pad, y: y - pad, width: cw + 2 * pad, height: fh)
        if showFields { y += 28 * k + 6 * k }
        confirmField.k = k
        confirmField.isHidden = mode != .embalm
        confirmField.frame = NSRect(x: P - pad, y: y - pad, width: cw + 2 * pad, height: fh)
        if mode == .embalm { y += 28 * k + 4 * k }
        strengthLabel.k = k; strengthLabel.style = Atlas.T.status; strengthLabel.isHidden = mode != .embalm
        strengthLabel.refresh()
        strengthLabel.frame = NSRect(x: P, y: y, width: cw, height: 13 * k)
        if mode == .embalm { y += 13 * k + 8 * k } else if showFields { y += 2 * k }

        let showButton = showFields || (mode == .finished && !queue.isEmpty)
        actionButton.k = k
        actionButton.isHidden = !showButton
        actionButton.frame = NSRect(x: P - pad, y: y - pad, width: cw + 2 * pad, height: 30 * k + 2 * pad)
        if showButton { y += 30 * k + 8 * k }

        progressBar.k = k
        progressBar.isHidden = !busy
        progressBar.frame = NSRect(x: P, y: y, width: cw, height: 12 * k)
        if busy { y += 12 * k + 6 * k }
        statusLabel.k = k; statusLabel.style = Atlas.T.status; statusLabel.color = messageColor
        statusLabel.refresh()
        let avail = H - footerH - 6 * k - y
        statusLabel.frame = NSRect(x: P, y: y, width: cw, height: max(0, min(avail, statusLabel.height(forWidth: cw))))
        statusLabel.isHidden = message.isEmpty
    }

    // MARK: state -> content

    private func refresh() {
        let sizeText = current.flatMap { fileSize($0) } ?? ""
        switch mode {
        case .none:
            pane.heading = "NO FILE"
            paneTitle.text = "Drop a file here"
            paneSub.text = "or click to choose one.\n\nEmbalmed files from email, a drive or a USB stick open the same way."
        case .embalm:
            pane.heading = busy ? "WORKING" : "FILE · READY TO EMBALM"
            paneTitle.text = current?.lastPathComponent ?? ""
            paneSub.text = sizeText.isEmpty ? "" : sizeText
        case .mummify:
            pane.heading = busy ? "WORKING" : "EMBALMED FILE · READY TO MUMMIFY"
            paneTitle.text = current?.lastPathComponent ?? ""
            paneSub.text = sizeText
        case .finished:
            pane.heading = "DONE"
            paneTitle.text = doneName
            paneSub.text = "Saved."
        }
        actionButton.title = mode == .embalm ? "Embalm" : (mode == .mummify ? "Mummify" : "Next file (\(queue.count) waiting)")
        let usable = mode == .mummify ? (status.map { !$0.isDestroyed && $0.structurallyIntact } ?? false) : true
        actionButton.isEnabled = !busy && usable
        passwordField.field.isEnabled = !busy && usable
        confirmField.field.isEnabled = !busy
        passwordField.alphaValue = passwordField.field.isEnabled ? 1 : 0.5     // derived: disabled is 50%
        confirmField.alphaValue = confirmField.field.isEnabled ? 1 : 0.5
        passwordField.needsDisplay = true
        let s = passwordStrength(passwordField.field.stringValue)
        strengthLabel.text = s.text; strengthLabel.color = s.color
        statusLabel.text = message
        pane.needsDisplay = true
        root.needsLayout = true
        layoutAll()
        pane.resetCursorRects()
    }

    private func fileSize(_ url: URL) -> String {
        guard let n = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize else { return "" }
        return ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }

    private func say(_ text: String, _ color: NSColor) {
        message = text; messageColor = color
        statusLabel.text = text; statusLabel.color = color
        layoutAll()
    }

    // MARK: opening files

    func accept(_ urls: [URL]) {
        guard !busy else { say("Please wait until the current file is finished.", Atlas.C.state); return }
        let files = urls.filter { url in
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) && !isDir.boolValue
        }
        if files.isEmpty {
            say("Folders can't be embalmed directly. Compress the folder to a zip first.", Atlas.C.state)
            return
        }
        queue = Array(files.dropFirst())
        load(files[0])
        window.makeKeyAndOrderFront(nil)
    }

    private func load(_ url: URL) {
        current = url; revealURL = nil
        passwordField.field.stringValue = ""; confirmField.field.stringValue = ""
        status = nil
        let more = queue.isEmpty ? "" : " \(queue.count) more waiting."
        if EmbalmEngine.isEmbalmFile(at: url) {
            mode = .mummify
            do {
                let s = try EmbalmEngine.inspect(input: url)
                status = s
                message = containerMessage(s) + more
                messageColor = containerColor(s)
            } catch {
                mode = .none; current = nil
                message = (error as? EmbalmError)?.description ?? "This file can't be read."
                messageColor = Atlas.C.error
            }
        } else {
            mode = .embalm
            message = "Choose a password. Nobody can recover this file without it." + more
            messageColor = Atlas.C.dark
        }
        refresh()
        window.makeFirstResponder(passwordField.field)
    }

    private func containerMessage(_ s: EmbalmEngine.Status) -> String {
        if s.isDestroyed { return "This file has self-destructed. Nothing can recover it." }
        if !s.structurallyIntact {
            return "This file is damaged or incomplete (\(s.problem ?? "unknown")). Ask for it to be sent again. No attempt is used."
        }
        var t = s.remainingAttempts <= 1
            ? "Intact. One wrong password will destroy this file for good."
            : "Intact. \(s.remainingAttempts) wrong passwords in a row will destroy it."
        if s.exposesLegacyFingerprint { t += " Older format: embalm the result again to upgrade." }
        return t
    }
    private func containerColor(_ s: EmbalmEngine.Status) -> NSColor {
        (s.isDestroyed || !s.structurallyIntact || s.remainingAttempts <= 1) ? Atlas.C.error : Atlas.C.state
    }

    @objc func chooseFiles() {
        guard !busy else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = true
        panel.message = "Choose a file to Embalm, or an embalmed file to Mummify."
        panel.beginSheetModal(for: window) { [weak self] r in if r == .OK { self?.accept(panel.urls) } }
    }

    @objc private func performAction() {
        guard !busy else { return }
        switch mode {
        case .embalm: startEmbalm()
        case .mummify: startMummify()
        case .finished: if !queue.isEmpty { load(queue.removeFirst()) }
        case .none: break
        }
    }

    func controlTextDidChange(_ obj: Notification) {
        if mode == .embalm {
            let p = passwordField.field.stringValue, c = confirmField.field.stringValue
            if !c.isEmpty && p != c { say("The passwords don't match yet.", Atlas.C.state) }
            else if message == "The passwords don't match yet." { say("", Atlas.C.dark) }
        }
        let s = passwordStrength(passwordField.field.stringValue)
        strengthLabel.text = s.text; strengthLabel.color = s.color
        layoutAll()
    }

    // MARK: embalm

    private func startEmbalm() {
        guard let input = current else { return }
        let pw = passwordField.field.stringValue
        guard !pw.isEmpty else { say("The password must not be empty.", Atlas.C.error); return }
        guard pw == confirmField.field.stringValue else { say("The two passwords don't match.", Atlas.C.error); return }
        if pw.count < 12 {
            let a = NSAlert()
            a.messageText = "That password is short"
            a.informativeText = "A short password is easier to guess. A passphrase of four or more random words is much stronger. Nobody, including this app, can recover a file if the password is lost."
            a.addButton(withTitle: "Choose another"); a.addButton(withTitle: "Use it anyway")
            a.alertStyle = .warning
            if a.runModal() != .alertSecondButtonReturn { return }
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = input.lastPathComponent + ".embalm"
        panel.directoryURL = input.deletingLastPathComponent()
        panel.message = "Choose where to save the embalmed file."
        panel.canCreateDirectories = true; panel.isExtensionHidden = false
        panel.beginSheetModal(for: window) { [weak self] r in
            guard let self = self else { return }
            guard r == .OK, let out = panel.url else { self.say("Cancelled. Nothing was written.", Atlas.C.dark); return }
            self.runEmbalm(input: input, output: out, password: pw)
        }
    }

    private func runEmbalm(input: URL, output: URL, password: String) {
        busy = true; say(Prefs.verify ? "Embalming, then reading it back to check…" : "Embalming…", Atlas.C.dark)
        progressBar.value = 0; refresh()
        let kdf = Prefs.kdf, maxF = UInt8(Prefs.maxFailures)
        let padding = Prefs.padding, name = Prefs.storeName, verify = Prefs.verify
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try EmbalmEngine.embalm(input: input, output: output, password: password, kdf: kdf,
                                        maxFailures: maxF, padding: padding, storeName: name, verify: verify) { self?.setProgress($0) }
                DispatchQueue.main.async { self?.finish("Embalmed and checked: \(output.lastPathComponent)", output) }
            } catch { DispatchQueue.main.async { self?.fail(error) } }
        }
    }

    // MARK: mummify

    private func startMummify() {
        guard let input = current else { return }
        let pw = passwordField.field.stringValue
        guard !pw.isEmpty else { say("Enter the password.", Atlas.C.error); return }
        unlock(input: input, password: pw, allowRegrant: true)
    }

    private func unlock(input: URL, password: String, allowRegrant: Bool) {
        busy = true; say("Checking the password…", Atlas.C.dark); progressBar.value = 0; refresh()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let o = try EmbalmEngine.unlock(input: input, password: password)
                DispatchQueue.main.async { self?.chooseDestination(for: o, input: input) }
            } catch EmbalmError.readOnlySource where allowRegrant {
                DispatchQueue.main.async { self?.requestWriteAccess(input: input) { self?.unlock(input: input, password: password, allowRegrant: false) } }
            } catch { DispatchQueue.main.async { self?.fail(error) } }
        }
    }

    /// In the sandbox a handed-over file can be readable yet not writable. The
    /// attempt limit needs write access, so the user is asked to grant it.
    private func requestWriteAccess(input: URL, retry: @escaping () -> Void) {
        busy = false; refresh()
        let a = NSAlert()
        a.messageText = "Embalm needs permission to update this file"
        a.informativeText = "To enforce the wrong-password limit, Embalm must be able to modify the file. Choose it again to allow that. If it is on read-only storage, copy it to your Mac first."
        a.addButton(withTitle: "Choose file…"); a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { say("Cancelled. No attempt was used.", Atlas.C.dark); return }
        let p = NSOpenPanel()
        p.directoryURL = input.deletingLastPathComponent()
        p.canChooseFiles = true; p.canChooseDirectories = false; p.allowsMultipleSelection = false
        p.message = "Select “\(input.lastPathComponent)” to allow access."
        if p.runModal() == .OK, let chosen = p.url, chosen.standardizedFileURL.path == input.standardizedFileURL.path { retry() }
        else { say(EmbalmError.readOnlySource.description, Atlas.C.error) }
    }

    private func chooseDestination(for container: EmbalmEngine.OpenedContainer, input: URL) {
        busy = false; refresh()
        opened = container
        let panel = NSSavePanel()
        panel.nameFieldStringValue = EmbalmEngine.suggestedOutputName(opened: container, inputName: input.lastPathComponent)
        panel.directoryURL = input.deletingLastPathComponent()
        panel.message = "Password accepted. Choose where to save the recovered file."
        panel.canCreateDirectories = true; panel.isExtensionHidden = false
        panel.beginSheetModal(for: window) { [weak self] r in
            guard let self = self else { return }
            guard r == .OK, let out = panel.url else {
                container.close(); self.opened = nil
                self.passwordField.field.stringValue = ""
                self.say("Cancelled. Nothing was written. Your password was correct.", Atlas.C.dark)
                self.refresh(); return
            }
            self.runWrite(container, to: out)
        }
    }

    private func runWrite(_ container: EmbalmEngine.OpenedContainer, to output: URL) {
        busy = true; say("Mummifying…", Atlas.C.dark); progressBar.value = 0; refresh()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try container.write(to: output, overwrite: true) { self?.setProgress($0) }
                container.close()
                DispatchQueue.main.async { self?.opened = nil; self?.finish("Mummified: \(output.lastPathComponent)", output) }
            } catch {
                container.close()
                DispatchQueue.main.async { self?.opened = nil; self?.fail(error) }
            }
        }
    }

    // MARK: results

    private func setProgress(_ f: Double) {
        DispatchQueue.main.async { [weak self] in self?.progressBar.value = f }
    }

    private func finish(_ text: String, _ output: URL) {
        busy = false
        passwordField.field.stringValue = ""; confirmField.field.stringValue = ""
        mode = .finished; doneName = output.lastPathComponent; revealURL = output
        message = text; messageColor = Atlas.C.success
        refresh()
        if Prefs.reveal { NSWorkspace.shared.activateFileViewerSelecting([output]) }
    }

    private func fail(_ error: Error) {
        busy = false
        passwordField.field.stringValue = ""
        if mode == .embalm { confirmField.field.stringValue = "" }
        message = (error as? EmbalmError)?.description ?? error.localizedDescription
        messageColor = Atlas.C.error
        if mode == .mummify, let url = current { status = try? EmbalmEngine.inspect(input: url) }
        refresh()
        window.makeFirstResponder(passwordField.field)
    }
}
