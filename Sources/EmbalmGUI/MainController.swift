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
    private let generateButton = AtlasButton()
    private var generator: GeneratorWindowController?
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

    // Embalming: what Settings asked for when the file was loaded, and how far along we are.
    private var holders = 1, threshold = 1
    private var wantsDuress = false, wantsKeyFile = false
    private var collected: [String] = []
    private var duressStep = false
    private var decoy: URL?
    // Mummifying: the key file if the container has one, and a part-finished opening.
    private var keyFile: URL?
    private var spareKeys: [URL] = []
    private var session: EmbalmEngine.OpenSession?
    private var needsKey: Bool { mode == .mummify && (status?.needsKeyFile ?? false) }

    private static let baseSide: CGFloat = 333
    private static let largeSide: CGFloat = 777

    override init() {
        window = AtlasWindowFactory.make(size: NSSize(width: Self.baseSide, height: Self.baseSide))
        super.init()
        window.contentView = root
        root.onLayout = { [weak self] in self?.layoutAll() }

        titleBar.version = "v1.3.0"
        [titleBar, pane, passwordField, generateButton, confirmField, strengthLabel, progressBar, actionButton,
         statusLabel, footerRule, footerLabel].forEach { root.addSubview($0) }
        pane.addSubview(paneTitle); pane.addSubview(paneSub)

        pane.onClick = { [weak self] in
            guard let self = self else { return }
            if self.mode == .embalm && self.duressStep { self.chooseDecoy() } else { self.chooseFiles() }
        }
        pane.onDrop = { [weak self] urls in
            guard let self = self else { return }
            if self.mode == .embalm && self.duressStep, let first = urls.first { self.setDecoy(first) } else { self.accept(urls) }
        }
        passwordField.placeholder = "Password"
        confirmField.placeholder = "Confirm password"
        passwordField.field.delegate = self
        confirmField.field.delegate = self
        generateButton.title = "Generate"
        generateButton.target = self; generateButton.action = #selector(showGenerator)
        generateButton.setAccessibilityLabel("Generate a password")
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

    private static let hint = "Embalm: drop any file, then choose or generate a password.\nMummify: drop an embalmed file and enter its password.\nHelp, Embalm Instructions explains the rest."

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
        // While embalming, a Generate button shares the password row.
        let gw = mode == .embalm ? 78 * k : 0, gap = mode == .embalm ? 6 * k : 0
        passwordField.frame = NSRect(x: P - pad, y: y - pad, width: cw - gw - gap + 2 * pad, height: fh)
        generateButton.k = k
        generateButton.isHidden = mode != .embalm
        generateButton.frame = NSRect(x: P + cw - gw - pad, y: y - pad, width: gw + 2 * pad, height: fh)
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
        case .embalm where duressStep:
            pane.heading = busy ? "WORKING" : "DURESS PASSWORD · OPTIONAL"
            paneTitle.text = decoy?.lastPathComponent ?? "Click to choose a decoy file"
            paneSub.text = decoy.map { fileSize($0) } ?? "Shown instead of the real file. ≤ \(EmbalmEngine.maxDecoyBytes / 1000) KB"
        case .embalm:
            pane.heading = busy ? "WORKING" : (holders > 1
                ? "PASSWORD \(min(collected.count + 1, holders)) OF \(holders) · ANY \(threshold) OPEN IT" : "FILE · READY TO EMBALM")
            paneTitle.text = current?.lastPathComponent ?? ""
            paneSub.text = sizeText.isEmpty ? "" : sizeText
        case .mummify:
            let k = status?.threshold ?? 1
            pane.heading = busy ? "WORKING" : (needsKey ? "EMBALMED FILE · NEEDS ITS KEY FILE"
                : (k > 1 ? "NEEDS \(k) OF \(status?.holders ?? k) PASSWORDS · \(session?.accepted ?? 0) GIVEN" : "EMBALMED FILE · READY TO MUMMIFY"))
            paneTitle.text = current?.lastPathComponent ?? ""
            paneSub.text = sizeText
        case .finished:
            pane.heading = "DONE"
            paneTitle.text = doneName
            paneSub.text = "Saved."
        }
        let lastStep = duressStep || (collected.count + 1 >= holders && !wantsDuress)
        actionButton.title = mode == .embalm ? (lastStep ? "Embalm" : "Next")
            : (mode == .mummify ? (needsKey ? "Choose key file…" : "Mummify") : "Next file (\(queue.count) waiting)")
        let usable = mode == .mummify ? (needsKey || (status.map { !$0.isDestroyed && $0.structurallyIntact } ?? false)) : true
        actionButton.isEnabled = !busy && usable
        passwordField.field.isEnabled = !busy && usable && !needsKey
        passwordField.placeholder = duressStep ? "Duress password" : "Password"
        confirmField.placeholder = duressStep ? "Confirm duress password" : "Confirm password"
        confirmField.field.isEnabled = !busy
        generateButton.isEnabled = !busy
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
        // Key files are never embalmed or opened on their own: they go with their embalmed file.
        let keys = files.filter { EmbalmEngine.isKeyFile(at: $0) }
        let others = files.filter { !keys.contains($0) }
        if needsKey, others.isEmpty, let key = keys.first { useKeyFile(key); window.makeKeyAndOrderFront(nil); return }
        guard let first = others.first else {
            say("This is a key file. Open the embalmed file it belongs to, and Embalm will ask for this.", Atlas.C.state)
            return
        }
        spareKeys = keys
        queue = Array(others.dropFirst())
        load(first)
        window.makeKeyAndOrderFront(nil)
    }

    private func load(_ url: URL) {
        current = url; revealURL = nil
        passwordField.field.stringValue = ""; confirmField.field.stringValue = ""
        status = nil
        collected = []; duressStep = false; decoy = nil; keyFile = nil
        session?.close(); session = nil
        let more = queue.isEmpty ? "" : " \(queue.count) more waiting."
        if EmbalmEngine.isEmbalmFile(at: url) {
            mode = .mummify
            do {
                var s = try EmbalmEngine.inspect(input: url)
                // A key file handed over together with this file is used without asking.
                if s.needsKeyFile {
                    for key in spareKeys {
                        if let paired = try? EmbalmEngine.inspect(input: url, keyFile: key) { s = paired; keyFile = key; break }
                    }
                }
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
            let preset = Prefs.quorumPresets[Prefs.quorumPreset]
            holders = Prefs.quorum ? preset.holders : 1
            threshold = Prefs.quorum ? preset.threshold : 1
            wantsDuress = Prefs.duress && holders == 1
            wantsKeyFile = Prefs.keyFile
            message = (holders > 1
                ? "Holder 1 of \(holders): choose a password. Any \(threshold) of the \(holders) will open this file."
                : "Choose a password. Nobody can recover this file without it.") + more
            messageColor = Atlas.C.dark
        }
        refresh()
        window.makeFirstResponder(needsKey ? actionButton : passwordField.field)
    }

    // MARK: key file and decoy

    @objc private func chooseKeyFile() {
        guard needsKey, !busy, let input = current else { return }
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = false; p.allowsMultipleSelection = false
        p.message = "Choose the key file for “\(input.lastPathComponent)”."
        p.beginSheetModal(for: window) { [weak self] r in if r == .OK, let u = p.url { self?.useKeyFile(u) } }
    }

    private func useKeyFile(_ key: URL) {
        guard let input = current else { return }
        do {
            let s = try EmbalmEngine.inspect(input: input, keyFile: key)
            keyFile = key; status = s
            message = containerMessage(s); messageColor = containerColor(s)
        } catch {
            message = (error as? EmbalmError)?.description ?? "That key file can't be read."
            messageColor = Atlas.C.error
        }
        refresh()
        window.makeFirstResponder(needsKey ? actionButton : passwordField.field)
    }

    private func chooseDecoy() {
        guard !busy else { return }
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = false; p.allowsMultipleSelection = false
        p.message = "Choose a harmless file for the duress password to open (up to \(EmbalmEngine.maxDecoyBytes / 1000) KB)."
        p.beginSheetModal(for: window) { [weak self] r in if r == .OK, let u = p.url { self?.setDecoy(u) } }
    }

    private func setDecoy(_ url: URL) {
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]))
        guard size?.isRegularFile == true, let n = size?.fileSize else { say("The decoy must be a file.", Atlas.C.error); return }
        guard n <= EmbalmEngine.maxDecoyBytes else { say(EmbalmError.decoyTooLarge.description, Atlas.C.error); return }
        guard url.standardizedFileURL != current?.standardizedFileURL else { say("The decoy must be a different file.", Atlas.C.error); return }
        decoy = url
        message = "Decoy chosen. Now type the duress password twice."; messageColor = Atlas.C.dark
        refresh()
        window.makeFirstResponder(passwordField.field)
    }

    private func containerMessage(_ s: EmbalmEngine.Status) -> String {
        if s.isDestroyed { return "This file has self-destructed. Nothing can recover it." }
        if !s.structurallyIntact {
            return "This file is damaged or incomplete (\(s.problem ?? "unknown")). Ask for it to be sent again. No attempt is used."
        }
        if s.needsKeyFile { return "This file was embalmed with a separate key file. Choose it to continue." }
        var t = s.remainingAttempts <= 1
            ? "Intact. One wrong password will destroy this file for good."
            : "Intact. \(s.remainingAttempts) wrong passwords in a row will destroy it."
        if s.threshold > 1 { t = "Needs \(s.threshold) of its \(s.holders) passwords, entered one after another. " + t }
        if s.exposesLegacyFingerprint { t += " Older format: embalm the result again to upgrade." }
        return t
    }
    private func containerColor(_ s: EmbalmEngine.Status) -> NSColor {
        s.needsKeyFile ? Atlas.C.state
            : ((s.isDestroyed || !s.structurallyIntact || s.remainingAttempts <= 1) ? Atlas.C.error : Atlas.C.state)
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
        case .embalm: advanceEmbalm()
        case .mummify: if needsKey { chooseKeyFile() } else { startMummify() }
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

    // MARK: password generator

    @objc private func showGenerator() {
        guard mode == .embalm, !busy else { return }
        if generator == nil {
            let g = GeneratorWindowController()
            g.onUse = { [weak self] pw in self?.useGenerated(pw) }
            generator = g
        }
        generator?.show(over: window)
    }

    /// Fills both boxes and copies the password, marked so that clipboard
    /// managers which honour the convention do not keep it in their history.
    private func useGenerated(_ pw: String) {
        guard mode == .embalm, !busy else { return }
        passwordField.field.stringValue = pw; confirmField.field.stringValue = pw
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(pw, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        message = "Password filled in and copied. Paste it into your password manager now: nothing can recover this file without it."
        messageColor = Atlas.C.state
        refresh()
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(actionButton)
    }

    // MARK: embalm

    /// One press of the button while embalming: take this password and move to the
    /// next holder, to the duress step, or to saving.
    private func advanceEmbalm() {
        guard let input = current else { return }
        let pw = passwordField.field.stringValue, confirm = confirmField.field.stringValue
        if duressStep {
            if pw.isEmpty && confirm.isEmpty { startSave(input: input, duress: nil); return }
            guard pw == confirm else { say("The two duress passwords don't match.", Atlas.C.error); return }
            guard pw != collected.first else { say("The duress password must be different from the real password.", Atlas.C.error); return }
            guard let d = decoy else { say("Choose a decoy file first: click the box above.", Atlas.C.error); return }
            startSave(input: input, duress: EmbalmEngine.Duress(password: pw, decoy: d))
            return
        }
        guard !pw.isEmpty else { say("The password must not be empty.", Atlas.C.error); return }
        guard pw == confirm else { say("The two passwords don't match.", Atlas.C.error); return }
        guard !collected.contains(pw) else { say("Each holder needs a different password.", Atlas.C.error); return }
        if pw.count < 12 {
            let a = NSAlert()
            a.messageText = "That password is short"
            a.informativeText = "A short password is easier to guess. A passphrase of four or more random words is much stronger. Nobody, including this app, can recover a file if the password is lost."
            a.addButton(withTitle: "Choose another"); a.addButton(withTitle: "Use it anyway")
            a.alertStyle = .warning
            if a.runModal() != .alertSecondButtonReturn { return }
        }
        collected.append(pw)
        passwordField.field.stringValue = ""; confirmField.field.stringValue = ""
        if collected.count < holders {
            message = "Saved. Holder \(collected.count + 1) of \(holders): choose a different password, unseen by the others."
            messageColor = Atlas.C.dark
        } else if wantsDuress {
            duressStep = true
            message = "A second password that opens a decoy and quietly destroys the real key. Leave both boxes empty to skip it for this file."
            messageColor = Atlas.C.dark
        } else {
            startSave(input: input, duress: nil); return
        }
        refresh()
        window.makeFirstResponder(passwordField.field)
    }

    /// Back to the first password, after a cancel or a failure.
    private func restartEmbalm(_ text: String, _ color: NSColor) {
        collected = []; duressStep = false
        passwordField.field.stringValue = ""; confirmField.field.stringValue = ""
        message = text; messageColor = color
        refresh()
        window.makeFirstResponder(passwordField.field)
    }

    private func startSave(input: URL, duress: EmbalmEngine.Duress?) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = input.lastPathComponent + "." + EmbalmEngine.fileExtension
        panel.directoryURL = input.deletingLastPathComponent()
        panel.message = "Choose where to save the embalmed file."
        panel.canCreateDirectories = true; panel.isExtensionHidden = false
        panel.beginSheetModal(for: window) { [weak self] r in
            guard let self = self else { return }
            guard r == .OK, let out = panel.url else {
                self.restartEmbalm("Cancelled. Nothing was written. Enter the password again to retry.", Atlas.C.dark); return
            }
            guard self.wantsKeyFile else { self.runEmbalm(input: input, output: out, duress: duress, keyFile: nil); return }
            // The sandbox lets the app write only where the user points, so the key file gets its own panel.
            DispatchQueue.main.async {
                let kp = NSSavePanel()
                kp.nameFieldStringValue = input.lastPathComponent + ".embkey"
                kp.message = "Now choose where to save the key file. Keep it somewhere different from the embalmed file."
                kp.canCreateDirectories = true; kp.isExtensionHidden = false
                kp.beginSheetModal(for: self.window) { r in
                    guard r == .OK, let key = kp.url, key.standardizedFileURL != out.standardizedFileURL else {
                        self.restartEmbalm("Cancelled. Nothing was written. Enter the password again to retry.", Atlas.C.dark); return
                    }
                    self.runEmbalm(input: input, output: out, duress: duress, keyFile: key)
                }
            }
        }
    }

    private func runEmbalm(input: URL, output: URL, duress: EmbalmEngine.Duress?, keyFile: URL?) {
        busy = true; say(Prefs.verify ? "Embalming, then reading it back to check…" : "Embalming…", Atlas.C.dark)
        progressBar.value = 0; refresh()
        let kdf = Prefs.kdf, maxF = UInt8(Prefs.maxFailures)
        let padding = Prefs.padding, name = Prefs.storeName, verify = Prefs.verify
        let passwords = collected, needed = threshold
        collected = []
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try EmbalmEngine.embalm(input: input, output: output, passwords: passwords, threshold: needed, kdf: kdf,
                                        maxFailures: maxF, padding: padding, storeName: name, verify: verify,
                                        duress: duress, keyFile: keyFile) { self?.setProgress($0) }
                let extra = keyFile.map { " Key file: \($0.lastPathComponent). Send the two by different routes." } ?? ""
                DispatchQueue.main.async { self?.finish("Embalmed and checked: \(output.lastPathComponent)." + extra, output) }
            } catch { DispatchQueue.main.async { self?.fail(error) } }
        }
    }

    // MARK: mummify

    private func startMummify() {
        guard let input = current else { return }
        let pw = passwordField.field.stringValue
        guard !pw.isEmpty else { say("Enter the password.", Atlas.C.error); return }
        offer(input: input, password: pw, allowRegrant: true)
    }

    /// Gives one password to the opening in progress, starting one if needed. A file
    /// that needs several keeps the same opening until enough have been accepted.
    private func offer(input: URL, password: String, allowRegrant: Bool) {
        busy = true; say("Checking the password…", Atlas.C.dark); progressBar.value = 0; refresh()
        let key = keyFile, existing = session
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let s: EmbalmEngine.OpenSession
            do { s = try existing ?? EmbalmEngine.beginOpen(input: input, keyFile: key) }
            catch EmbalmError.readOnlySource where allowRegrant {
                DispatchQueue.main.async { self?.requestWriteAccess(input: input) { self?.offer(input: input, password: password, allowRegrant: false) } }
                return
            } catch { DispatchQueue.main.async { self?.fail(error) }; return }
            do {
                if let opened = try s.offer(password: password) {
                    DispatchQueue.main.async { self?.session = nil; self?.chooseDestination(for: opened, input: input) }
                } else {
                    DispatchQueue.main.async { self?.session = s; self?.acceptedOne(s) }
                }
            } catch {
                DispatchQueue.main.async {
                    // Keep earlier holders' passwords unless the file is gone.
                    let gone = (error as? EmbalmError) == .destroyed || (error as? EmbalmError) == .alreadyDestroyed
                    if s.accepted > 0 && !gone { self?.session = s } else { s.close(); self?.session = nil }
                    self?.fail(error)
                }
            }
        }
    }

    private func acceptedOne(_ s: EmbalmEngine.OpenSession) {
        busy = false
        passwordField.field.stringValue = ""
        message = "Password \(s.accepted) of \(s.threshold) accepted. Now a different holder enters theirs."
        messageColor = Atlas.C.success
        refresh()
        window.makeFirstResponder(passwordField.field)
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
        collected = []; duressStep = false; decoy = nil
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
        if mode == .mummify, let url = current { status = (try? EmbalmEngine.inspect(input: url, keyFile: keyFile)) ?? status }
        if mode == .embalm { collected = []; duressStep = false }
        refresh()
        window.makeFirstResponder(passwordField.field)
    }
}

#if EMBALM_PROBE
// Development-only: lets the off-screen renderer walk through the password steps.
extension MainController {
    func probeEnter(_ password: String) {
        passwordField.field.stringValue = password; confirmField.field.stringValue = password
        performAction()
    }
}
#endif
