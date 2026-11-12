import AppKit
import EmbalmCore

/// The password generator: memorable words or random characters, a length, and
/// two options. It shows the password and exactly how strong it is.
final class GeneratorWindowController: NSObject {
    let window: NSWindow
    var onUse: ((String) -> Void)?

    private let root = FlippedView()
    private let width: CGFloat = 400
    private let P: CGFloat = 22
    private var W: CGFloat { width - 44 }
    private let output = AtlasLabel()
    private let strength = AtlasLabel()
    private let kind = AtlasSegmented()
    private let amount = AtlasLabel()
    private let slider = AtlasSlider()
    private let first = AtlasCheckbox()
    private let second = AtlasCheckbox()
    private let again = AtlasButton()
    private let use = AtlasButton()
    private var current = ""

    override init() {
        window = AtlasWindowFactory.make(size: NSSize(width: 400, height: 420))
        super.init()
        window.contentView = root
        let height = build()
        window.setFrame(NSRect(x: 0, y: 0, width: width, height: height), display: false)
    }

    private func add(_ v: NSView, _ f: NSRect) { v.frame = f; root.addSubview(v) }
    private func title(_ t: String, at y: CGFloat) {
        let l = AtlasLabel(); l.style = Atlas.T.inspectorBlockTitle; l.color = Atlas.C.dark; l.text = t
        add(l, NSRect(x: P, y: y, width: W, height: 15))
    }

    private func build() -> CGFloat {
        let bar = TitleBarView(); bar.title = "Generate Password"; bar.version = "v1.3.0"
        add(bar, NSRect(x: 0, y: 0, width: width, height: Atlas.S.titlebar))
        var y = Atlas.S.titlebar + 18

        title("Password", at: y); y += 22
        add(BoxView(), NSRect(x: P, y: y, width: W, height: 66))
        output.style = Atlas.Style(Atlas.mono, 13, lineHeight: 17); output.lineBreak = .byCharWrapping
        output.isSelectable = true
        add(output, NSRect(x: P + 9, y: y + 7, width: W - 18, height: 52)); y += 66 + 6
        strength.style = Atlas.T.status
        add(strength, NSRect(x: P, y: y, width: W, height: 13)); y += 13 + 14

        let r1 = RuleView(); add(r1, NSRect(x: P, y: y, width: W, height: 1)); y += 14
        title("Type", at: y); y += 22
        kind.segments = ["Memorable", "Random"]
        kind.selected = Prefs.genRandom ? 1 : 0
        kind.target = self; kind.action = #selector(kindChanged)
        add(kind, NSRect(x: P, y: y, width: W, height: 30)); y += 30 + 16

        amount.style = Atlas.T.inspectorParagraph
        add(amount, NSRect(x: P, y: y + 2, width: 104, height: 20))
        slider.target = self; slider.action = #selector(sliderChanged)
        add(slider, NSRect(x: P + 108, y: y, width: W - 108, height: 24)); y += 24 + 10
        for box in [first, second] {
            box.target = self; box.action = #selector(optionChanged(_:))
            add(box, NSRect(x: P - 5, y: y, width: W + 10, height: 24)); y += 26
        }
        y += 10

        let pad = Atlas.S.focusPad, half = (W - 8) / 2
        again.title = "Regenerate"
        again.target = self; again.action = #selector(regenerate)
        add(again, NSRect(x: P - pad, y: y - pad, width: half + 2 * pad, height: 30 + 2 * pad))
        use.title = "Use and copy"; use.kind = .primary; use.keyEquivalent = "\r"
        use.target = self; use.action = #selector(usePassword)
        add(use, NSRect(x: P + half + 8 - pad, y: y - pad, width: half + 2 * pad, height: 30 + 2 * pad))
        y += 30 + 18

        let note = AtlasLabel(); note.style = Atlas.T.inspectorNote; note.color = Atlas.C.g444
        note.text = "Made on this Mac from its secure random source. Using it fills in both password boxes and copies it. Keep it in a password manager: nothing can recover the file without it."
        let nh = note.height(forWidth: W) + 22
        let strip = FlippedView(); strip.wantsLayer = true
        strip.layer?.backgroundColor = Atlas.C.note.cgColor
        add(strip, NSRect(x: 0, y: y, width: width, height: nh))
        let top = RuleView(); add(top, NSRect(x: 0, y: y, width: width, height: 1))
        add(note, NSRect(x: P, y: y + 11, width: W, height: nh - 22))
        return y + nh
    }

    /// Shows the controls for the chosen type with its remembered options.
    private func configure() {
        let random = Prefs.genRandom
        slider.range = random ? PasswordGenerator.lengthRange : PasswordGenerator.wordRange
        slider.value = random ? Prefs.genLength : Prefs.genWords
        first.title = random ? "Special characters (!&*)" : "Capitalize"
        first.isChecked = random ? Prefs.genSymbols : Prefs.genCapitalize
        second.title = "Include numbers"
        second.isChecked = Prefs.genNumbers
        second.isHidden = random
        first.needsDisplay = true
    }

    @objc private func regenerate() {
        let g = Prefs.genRandom
            ? PasswordGenerator.random(length: slider.value, symbols: Prefs.genSymbols)
            : PasswordGenerator.memorable(words: slider.value, capitalize: Prefs.genCapitalize, numbers: Prefs.genNumbers)
        current = g.password
        output.text = g.password
        amount.text = Prefs.genRandom ? "\(slider.value) characters" : "\(slider.value) words"
        // With Argon2id each guess costs about a second and 512 MiB, so these are cautious.
        let (word, color) = g.bits < 45 ? ("Weak", Atlas.C.error) : (g.bits < 60 ? ("Fair", Atlas.C.state) : ("Strong", Atlas.C.success))
        strength.color = color
        strength.text = "\(word): \(Int(g.bits)) bits of randomness."
    }

    @objc private func kindChanged() { Prefs.genRandom = kind.selected == 1; configure(); regenerate() }
    @objc private func sliderChanged() {
        if Prefs.genRandom { Prefs.genLength = slider.value } else { Prefs.genWords = slider.value }
        regenerate()
    }
    @objc private func optionChanged(_ sender: AtlasCheckbox) {
        if sender === second { Prefs.genNumbers = sender.isChecked }
        else if Prefs.genRandom { Prefs.genSymbols = sender.isChecked }
        else { Prefs.genCapitalize = sender.isChecked }
        regenerate()
    }

    @objc private func usePassword() {
        let pw = current
        forget()
        window.orderOut(nil)
        onUse?(pw)
    }
    private func forget() { current = ""; output.text = "" }

    func prepare() {
        kind.selected = Prefs.genRandom ? 1 : 0
        configure(); regenerate()
    }

    /// A fresh password every time the window opens.
    func show(over parent: NSWindow) {
        prepare()
        let p = parent.frame
        window.setFrameTopLeftPoint(NSPoint(x: p.midX - width / 2, y: p.maxY - 30))
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(use)
    }
}
