import AppKit
import EmbalmCore

/// Settings, in the Atlas inspector style: blocks separated by a 1px #aaa rule, each with
/// an uppercase mono title. Segmented controls and checkboxes are derived (Atlas defines
/// neither): the segmented control uses the view-switch treatment, the checkbox the
/// stepper mark.
final class SettingsWindowController: NSObject {
    let window: NSWindow
    private let root = FlippedView()
    private let width: CGFloat = 400
    private var y: CGFloat = 0
    private let attempts = AtlasSegmented()
    private let strength = AtlasSegmented()
    private var boxes: [AtlasCheckbox] = []
    private let attemptValues = [2, 3, 5]
    private let quorum = AtlasSegmented()

    override init() {
        window = AtlasWindowFactory.make(size: NSSize(width: 400, height: 520))
        super.init()
        window.contentView = root
        build()
        window.setFrame(NSRect(x: 0, y: 0, width: width, height: y + 24), display: false)
        window.center()
    }

    private func add(_ v: NSView, _ f: NSRect) { v.frame = f; root.addSubview(v) }
    private let P: CGFloat = 22
    private var W: CGFloat { width - 44 }

    private func bar() {
        let b = TitleBarView(); b.title = "Settings"; b.version = "v1.3.0"
        add(b, NSRect(x: 0, y: 0, width: width, height: Atlas.S.titlebar))
        y = Atlas.S.titlebar + 18
    }
    private func rule() {
        let r = RuleView(); r.color = Atlas.C.mid
        add(r, NSRect(x: P, y: y, width: W, height: 1)); y += 14
    }
    private func title(_ t: String) {
        let l = AtlasLabel(); l.style = Atlas.T.inspectorBlockTitle; l.color = Atlas.C.dark; l.text = t
        add(l, NSRect(x: P, y: y, width: W, height: 15)); y += 22
    }
    private func para(_ t: String) {
        let l = AtlasLabel(); l.style = Atlas.T.inspectorParagraph; l.color = Atlas.C.g444; l.text = t
        let h = l.height(forWidth: W)
        add(l, NSRect(x: P, y: y, width: W, height: h)); y += h + 8
    }
    private func checkbox(_ t: String, _ on: Bool, tag: Int) {
        let c = AtlasCheckbox(); c.title = t; c.isChecked = on; c.tag = tag
        c.target = self; c.action = #selector(toggled(_:))
        add(c, NSRect(x: P - 5, y: y, width: W + 10, height: 24)); boxes.append(c); y += 26
    }

    private func build() {
        bar()
        title("Self-destruct after")
        attempts.segments = ["2 wrong", "3 wrong", "5 wrong"]
        attempts.selected = attemptValues.firstIndex(of: Prefs.maxFailures) ?? 0
        attempts.target = self; attempts.action = #selector(attemptsChanged)
        add(attempts, NSRect(x: P, y: y, width: W, height: 30)); y += 38
        para("Wrong passwords in a row before a file destroys itself. This applies to files you embalm from now on; files already embalmed keep their own limit.")
        y += 6; rule()

        title("Key strength")
        strength.segments = ["Standard", "Maximum"]
        strength.selected = Prefs.strongKDF ? 1 : 0
        strength.target = self; strength.action = #selector(strengthChanged)
        add(strength, NSRect(x: P, y: y, width: W, height: 30)); y += 38
        para("Standard needs 512 MiB of memory for every password guess. Maximum needs 1 GiB and takes a little longer to open files. Either is very strong with a long passphrase.")
        y += 6; rule()

        title("When embalming")
        checkbox("Hide the file's size", Prefs.padding, tag: 0)
        checkbox("Keep the original name inside the file", Prefs.storeName, tag: 1)
        checkbox("Read the result back to check it", Prefs.verify, tag: 2)
        y += 8; rule()

        title("Extra protection")
        checkbox("Duress password with a decoy file", Prefs.duress, tag: 4)
        checkbox("Several passwords, held by different people", Prefs.quorum, tag: 5)
        quorum.segments = Prefs.quorumPresets.map { "\($0.threshold) of \($0.holders)" }
        quorum.selected = Prefs.quorumPreset
        quorum.target = self; quorum.action = #selector(quorumChanged)
        add(quorum, NSRect(x: P + 22, y: y + 2, width: W - 22, height: 26)); y += 34
        checkbox("Separate key file", Prefs.keyFile, tag: 6)
        para("All off unless you turn them on. They apply to files you embalm from then on. Help, Embalm Instructions explains each.")
        y += 6; rule()

        title("When finished")
        checkbox("Show the new file in Finder", Prefs.reveal, tag: 3)
        y += 10

        let note = AtlasLabel(); note.style = Atlas.T.inspectorNote; note.color = Atlas.C.g444
        note.text = "Kept on this Mac only. The right-click actions in Finder open this app, so they use these settings too."
        let nh = note.height(forWidth: W - 2 * 4) + 22
        let strip = FlippedView(); strip.wantsLayer = true
        strip.layer?.backgroundColor = Atlas.C.note.cgColor
        add(strip, NSRect(x: 0, y: y, width: width, height: nh))
        let top = RuleView(); top.color = Atlas.C.mid; add(top, NSRect(x: 0, y: y, width: width, height: 1))
        add(note, NSRect(x: P, y: y + 11, width: W, height: nh - 22))
        y += nh - 24 + 0
    }

    @objc private func attemptsChanged() { Prefs.maxFailures = attemptValues[attempts.selected] }
    @objc private func strengthChanged() { Prefs.strongKDF = strength.selected == 1 }
    @objc private func quorumChanged() { Prefs.quorumPreset = quorum.selected }
    @objc private func toggled(_ sender: AtlasCheckbox) {
        switch sender.tag {
        case 0: Prefs.padding = sender.isChecked
        case 1: Prefs.storeName = sender.isChecked
        case 2: Prefs.verify = sender.isChecked
        case 3: Prefs.reveal = sender.isChecked
        case 4, 5:
            // A duress password and several passwords cannot be combined: one switches the other off.
            if sender.tag == 4 { Prefs.duress = sender.isChecked } else { Prefs.quorum = sender.isChecked }
            if sender.isChecked {
                if sender.tag == 4 { Prefs.quorum = false } else { Prefs.duress = false }
                boxes.first { $0.tag == (sender.tag == 4 ? 5 : 4) }?.isChecked = false
            }
        default: Prefs.keyFile = sender.isChecked
        }
    }

    func show() { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
}
