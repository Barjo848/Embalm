import AppKit
import EmbalmCore

/// A read-only text window in the Atlas style: used for the instructions and the self-check report.
final class InfoWindowController: NSObject {
    let window: NSWindow
    private let scroll = NSScrollView()
    private let textView = NSTextView()
    private let bar = TitleBarView()
    private let root = AtlasRootView()

    init(title: String, size: NSSize, content: NSAttributedString) {
        window = AtlasWindowFactory.make(size: size, resizable: true)
        super.init()
        window.minSize = NSSize(width: 340, height: 260)
        window.contentView = root
        bar.title = title; bar.version = "v1.3.0"
        textView.isEditable = false; textView.isSelectable = true
        textView.drawsBackground = true; textView.backgroundColor = Atlas.C.paper
        textView.textContainerInset = NSSize(width: 22, height: 14)
        textView.isVerticallyResizable = true; textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = true; scroll.backgroundColor = Atlas.C.paper
        root.addSubview(scroll); root.addSubview(bar)
        root.onLayout = { [weak self] in
            guard let self = self else { return }
            let w = self.root.bounds.width, h = self.root.bounds.height
            self.bar.frame = NSRect(x: 0, y: 0, width: w, height: Atlas.S.titlebar)
            self.scroll.frame = NSRect(x: 0, y: Atlas.S.titlebar, width: w, height: h - Atlas.S.titlebar)
        }
        setContent(content)
    }

    func setContent(_ s: NSAttributedString) {
        textView.textStorage?.setAttributedString(s)
        textView.scrollToBeginningOfDocument(nil)
    }
    func show() { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
}

enum HelpText {
    private static func head(_ s: String, into out: NSMutableAttributedString, first: Bool = false) {
        out.append(Atlas.attributed((first ? "" : "\n") + s + "\n", Atlas.T.inspectorBlockTitle, color: Atlas.C.dark, k: 1))
    }
    private static func body(_ s: String, into out: NSMutableAttributedString) {
        out.append(Atlas.attributed(s + "\n", Atlas.T.inspectorParagraph, color: Atlas.C.ink, k: 1))
    }

    static func instructions() -> NSAttributedString {
        let o = NSMutableAttributedString()
        o.append(Atlas.attributed("Instructions\n", Atlas.Style(Atlas.herosBold, 26, tracking: -0.78, lineHeight: 30), color: Atlas.C.ink, k: 1))
        body("Embalm encrypts a file so that only your password can open it. Everything happens on this Mac. The app has no network access at all.", into: o)

        head("Embalm a file", into: o)
        body("Right-click any file in Finder and choose Quick Actions, Embalm. Or drop the file on the window, or choose File, Open. Type a password twice, or press Generate to have one made for you. Choose where to save. You get a new file ending in .emb; the original is not changed. To embalm a folder, compress it to a zip first.", into: o)

        head("Mummify: open an embalmed file", into: o)
        body("Right-click the .emb file and choose Quick Actions, Mummify. Or double-click it, or drop it on the window. Type the password and choose where to save. The file comes back exactly as it was, with its original name. Embalm recognises its files by their contents, so a file renamed by an email program or a download still opens.", into: o)

        head("Self-destruct", into: o)
        body("Two wrong passwords in a row destroy the file for good. After that nothing can open it, not even the right password. A correct password resets the count. A damaged or incomplete file never uses up an attempt. You can change the limit in Settings; it applies to files embalmed afterwards.", into: o)

        head("Sending embalmed files", into: o)
        body("By email, a USB stick or a shared folder: all work. Send the password by a different route than the file. If a file arrives damaged or cut short, Embalm says so before asking for a password; ask for it again. A file on read-only storage must be copied to this Mac first, because the attempt limit has to be written into the file.", into: o)

        head("Passwords", into: o)
        body("Use a long passphrase, four or more unrelated words. Length matters far more than symbols. There is no way to recover a forgotten password, by design.\n\nGenerate makes one for you from this Mac's secure random source: memorable (random words, like Dealmaker7-Elated2-Obscurity5) or random characters. Choose the length; the window shows how strong the result is. Using it fills in both boxes and copies it, so paste it into your password manager before you carry on.", into: o)

        head("Extra protection (off until you turn it on in Settings)", into: o)
        body("Duress password. While embalming you are asked for a second password and a small harmless file, the decoy. If someone forces you to open the file, give the duress password: the decoy opens as if it were the real thing, and the key to the real file is destroyed without any sign. Every file Embalm makes has the same size and layout whether or not it has a duress password, so the file itself does not give you away. It protects the copy it is used on, like the wrong-password limit, and someone who knows Embalm knows a duress password is possible.", into: o)
        body("Several passwords. The file gets 2, 3 or 5 passwords, each chosen by a different person, and opens only when enough of them (2 of 2, 2 of 3 or 3 of 5) are entered one after another. No single holder can open it, and with 2 of 3 or 3 of 5 it survives a holder losing theirs. It cannot be combined with a duress password.", into: o)
        body("Separate key file. Embalming makes two files: the embalmed file and a small key file ending in .embkey. Both, and the password, are needed. Send them by different routes. A copy of the embalmed file alone is useless for guessing passwords, and deleting the key file kills every copy of the embalmed file. To open, choose the embalmed file and Embalm asks for the key file, or select both at once.", into: o)

        head("What stays private", into: o)
        body("The file's name and exact size are hidden inside it; only a rough size class shows. Nothing is sent anywhere, and nothing about your files is recorded by Embalm. Recovered files are ordinary files: Spotlight, Quick Look, backups and iCloud treat them like any other, so choose where you save them with that in mind.", into: o)

        head("Window size and keys", into: o)
        body("View, Large Window switches between 333 and 777 points square.\n⌘O open a file     ⌘, settings\n⌘L large window    ⌘? these instructions", into: o)

        head("Checking the installation", into: o)
        body("Help, Run Self-Check tests the cryptography and shows that this app is sandboxed, cannot reach the network and cannot read your other folders.", into: o)
        return o
    }

    static func selfCheck(_ lines: [CheckResult], passed: Bool) -> NSAttributedString {
        let o = NSMutableAttributedString()
        o.append(Atlas.attributed(passed ? "Self-check passed\n" : "Self-check FAILED\n",
                                  Atlas.Style(Atlas.herosBold, 22, tracking: -0.6, lineHeight: 26),
                                  color: passed ? Atlas.C.success : Atlas.C.error, k: 1))
        var group = ""
        for r in lines {
            if r.group != group {
                group = r.group
                o.append(Atlas.attributed("\n" + r.group + "\n", Atlas.T.inspectorBlockTitle, color: Atlas.C.dark, k: 1))
            }
            let mark = r.passed ? "[ OK ]" : "[FAIL]"
            o.append(Atlas.attributed("\(mark) \(r.name)\(r.detail.isEmpty ? "" : " (\(r.detail))")\n",
                                      Atlas.T.inspectorNote, color: r.passed ? Atlas.C.ink : Atlas.C.error, k: 1))
        }
        return o
    }
}
