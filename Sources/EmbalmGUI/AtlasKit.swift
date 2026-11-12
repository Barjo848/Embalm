import AppKit
import CoreText

// Atlas design tokens for AppKit. Values come from the Atlas 0.1.0-draft token
// set (Swift tokens); nothing here is invented. Lengths are points at scale 1;
// every view multiplies them by its window scale `k` (1 at 333, 7/3 at 777).

enum Atlas {
    static func rgb(_ hex: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }

    enum C {
        static let ink = Atlas.rgb(0x000000)        // body text, title bar, selection
        static let line = Atlas.rgb(0x111111)       // hard rules, borders
        static let dark = Atlas.rgb(0x555555)       // secondary text, bevel shadow
        static let mid = Atlas.rgb(0xAAAAAA)        // control faces, soft rules
        static let white = Atlas.rgb(0xFFFFFF)      // information surfaces, bevel light
        static let paper = Atlas.rgb(0xFAF7EF)      // reading canvas
        static let amber = Atlas.rgb(0xD68B22)      // focus outline only
        static let hover = Atlas.rgb(0xF6F0E3)      // hovered row
        static let note = Atlas.rgb(0xEEEEEE)       // note strip
        static let g777 = Atlas.rgb(0x777777)
        static let g444 = Atlas.rgb(0x444444)
        static let gCCC = Atlas.rgb(0xCCCCCC)       // secondary text on black
        static let error = Atlas.rgb(0x8A2200)
        static let success = Atlas.rgb(0x16542C)
        static let state = Atlas.rgb(0x735012)      // state text
    }

    enum S {   // sizes at scale 1
        static let hairline: CGFloat = 1
        static let rule: CGFloat = 2
        static let bevel: CGFloat = 2
        static let focusWidth: CGFloat = 3
        static let focusOffset: CGFloat = 2
        static let titlebar: CGFloat = 25
        static let buttonMinHeight: CGFloat = 28
        static let mainPadding: CGFloat = 22
        static let focusPad: CGFloat = 5     // room outside a control for its focus outline
    }

    static let heros = "TeXGyreHeros-Regular"
    static let herosBold = "TeXGyreHeros-Bold"
    static let mono = "CourierCode-Roman"

    struct Style {
        let font: String, size: CGFloat, bold: Bool, tracking: CGFloat, lineHeight: CGFloat?, upper: Bool
        init(_ font: String, _ size: CGFloat, bold: Bool = false, tracking: CGFloat = 0,
             lineHeight: CGFloat? = nil, upper: Bool = false) {
            self.font = font; self.size = size; self.bold = bold; self.tracking = tracking
            self.lineHeight = lineHeight; self.upper = upper
        }
    }

    enum T {   // text styles (names as in the Atlas tokens)
        static let body = Style(heros, 14)
        static let button = Style(heros, 14)
        static let titlebar = Style(heros, 13, tracking: 0.13)
        static let titlebarVersion = Style(mono, 10, tracking: 1)
        static let label = Style(mono, 11, tracking: 0.66)
        static let eyebrow = Style(mono, 11, bold: true, tracking: 0.66)
        static let inspectorHead = Style(mono, 12)
        static let inspectorParagraph = Style(heros, 13, lineHeight: 18.85)
        static let inspectorNote = Style(mono, 11, lineHeight: 15.4)
        static let inspectorBlockTitle = Style(mono, 11, tracking: 0.88, upper: true)
        static let rowTitle = Style(herosBold, 15)
        static let rowSummary = Style(mono, 11, lineHeight: 14.3)
        static let stateTag = Style(mono, 10, upper: true)
        static let sectionTitle = Style(herosBold, 19, tracking: -0.38)
        static let status = Style(mono, 10, lineHeight: 13)       // inline status message
        static let field = Style(mono, 12)                         // text field input
    }

    // MARK: fonts

    private(set) static var fontsLoaded = false

    private static let fontFiles = [(heros, "TeXGyreHeros-Regular.otf"), (herosBold, "TeXGyreHeros-Bold.otf"),
                                    (mono, "CourierCode-Roman.ttf")]

    /// The faces this build carries. The typefaces are not in the repository: a build
    /// from a plain checkout has none, and a build meant for sharing leaves out the
    /// commercial one. Whatever is missing falls back to a system face.
    static var bundledFaces: [String] {
        guard let dir = Bundle.main.resourceURL?.appendingPathComponent("Fonts") else { return [] }
        return fontFiles.filter { FileManager.default.fileExists(atPath: dir.appendingPathComponent($0.1).path) }.map { $0.0 }
    }

    /// Registers the three bundled faces and confirms each resolves by name.
    /// When they are bundled, a system fallback is a failed implementation, so
    /// callers can check `fontsLoaded` and the self-check reports it.
    @discardableResult
    static func registerFonts() -> Bool {
        if let dir = Bundle.main.resourceURL?.appendingPathComponent("Fonts") {
            for (_, f) in fontFiles {
                CTFontManagerRegisterFontsForURL(dir.appendingPathComponent(f) as CFURL, .process, nil)
            }
        }
        fontsLoaded = [heros, herosBold, mono].allSatisfy { NSFont(name: $0, size: 12) != nil }
        return fontsLoaded
    }

    static func font(_ name: String, _ size: CGFloat) -> NSFont {
        if let f = NSFont(name: name, size: size) { return f }
        switch name {
        case mono: return NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
        case herosBold: return NSFont(name: "Helvetica-Bold", size: size) ?? NSFont.boldSystemFont(ofSize: size)
        default: return NSFont(name: "Helvetica", size: size) ?? NSFont.systemFont(ofSize: size)
        }
    }

    static func attributed(_ text: String, _ s: Style, color: NSColor, k: CGFloat,
                           align: NSTextAlignment = .left,
                           lineBreak: NSLineBreakMode = .byWordWrapping) -> NSAttributedString {
        let p = NSMutableParagraphStyle()
        p.alignment = align
        p.lineBreakMode = lineBreak
        if let lh = s.lineHeight { p.minimumLineHeight = lh * k; p.maximumLineHeight = lh * k }
        var a: [NSAttributedString.Key: Any] = [
            .font: font(s.font, s.size * k), .foregroundColor: color,
            .paragraphStyle: p, .kern: s.tracking * k]
        if s.bold { a[.strokeWidth] = -2.5; a[.strokeColor] = color }   // Courier Code has no bold file
        return NSAttributedString(string: s.upper ? text.uppercased() : text, attributes: a)
    }

    static func height(_ text: String, _ s: Style, k: CGFloat, width: CGFloat) -> CGFloat {
        let a = attributed(text, s, color: C.ink, k: k)
        return ceil(a.boundingRect(with: NSSize(width: width, height: .greatestFiniteMagnitude),
                                   options: [.usesLineFragmentOrigin, .usesFontLeading]).height)
    }

    // MARK: pattern (recipe atlas.pattern.hatch-complete: 135deg, black 2px, white 2px)

    static func drawHatch(in rect: NSRect, k: CGFloat) {
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect: rect).addClip()
        C.white.setFill(); rect.fill()
        C.ink.setStroke()
        let p = NSBezierPath()
        p.lineWidth = 2 * k
        let step = 4 * k * 2.0.squareRoot()
        var x = rect.minX - rect.height
        while x < rect.maxX + rect.height {
            p.move(to: NSPoint(x: x, y: rect.minY))
            p.line(to: NSPoint(x: x + rect.height, y: rect.maxY))
            x += step
        }
        p.stroke()
        NSGraphicsContext.restoreGraphicsState()
    }

    /// The 3pt amber focus outline, offset outside `rect`.
    static func drawFocusRing(around rect: NSRect, k: CGFloat, offset: CGFloat = S.focusOffset) {
        let w = S.focusWidth * k, o = offset * k
        let r = rect.insetBy(dx: -(o + w / 2), dy: -(o + w / 2))
        let p = NSBezierPath(rect: r)
        p.lineWidth = w
        C.amber.setStroke()
        p.stroke()
    }
}

class FlippedView: NSView { override var isFlipped: Bool { true } }

// MARK: - Label

final class AtlasLabel: NSTextField {
    var style = Atlas.T.body
    var color = Atlas.C.ink
    var k: CGFloat = 1
    var align: NSTextAlignment = .left
    var lineBreak: NSLineBreakMode = .byWordWrapping

    init() {
        super.init(frame: .zero)
        isEditable = false; isSelectable = false; isBordered = false; drawsBackground = false
        usesSingleLineMode = false
        cell?.wraps = true
        cell?.isScrollable = false
        maximumNumberOfLines = 0
    }
    required init?(coder: NSCoder) { fatalError() }

    var text: String = "" { didSet { refresh() } }
    func refresh() {
        attributedStringValue = Atlas.attributed(text, style, color: color, k: k, align: align, lineBreak: lineBreak)
    }
    /// Height needed at this width, measured the way the field itself lays text out
    /// (including its inner padding), so wrapped text is never clipped.
    func height(forWidth w: CGFloat) -> CGFloat {
        refresh()
        guard let c = cell else { return Atlas.height(text, style, k: k, width: w) }
        return ceil(c.cellSize(forBounds: NSRect(x: 0, y: 0, width: w, height: 10_000)).height)
    }
}

// MARK: - Title bar (25pt black bar; the system window buttons sit on top of it)

final class TitleBarView: FlippedView {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    var title = "Embalm" { didSet { needsDisplay = true } }
    var version = "v1.3.0" { didSet { needsDisplay = true } }

    override func draw(_ dirtyRect: NSRect) {
        Atlas.C.ink.setFill(); bounds.fill()
        let t = Atlas.attributed(title, Atlas.T.titlebar, color: Atlas.C.white, k: k)
        let ts = t.size()
        t.draw(at: NSPoint(x: 78 * k, y: (bounds.height - ts.height) / 2))
        let v = Atlas.attributed(version.uppercased(), Atlas.T.titlebarVersion, color: Atlas.C.gCCC, k: k)
        let vs = v.size()
        v.draw(at: NSPoint(x: bounds.width - vs.width - 13 * k, y: (bounds.height - vs.height) / 2))
    }
}

// MARK: - Pane (white surface, 1px #111 border, optional black heading strip)

final class PaneView: FlippedView {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    var heading = "" { didSet { needsDisplay = true } }
    var highlighted = false { didSet { needsDisplay = true } }
    var onClick: (() -> Void)?
    var onDrop: (([URL]) -> Void)?
    var stripHeight: CGFloat { 22 * k }

    override init(frame: NSRect) {
        super.init(frame: frame)
        registerForDraggedTypes([.fileURL])
    }
    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        (highlighted ? Atlas.C.hover : Atlas.C.white).setFill(); bounds.fill()
        if !heading.isEmpty {
            Atlas.C.ink.setFill()
            NSRect(x: 0, y: 0, width: bounds.width, height: stripHeight).fill()
            let t = Atlas.attributed(heading, Atlas.T.inspectorHead, color: Atlas.C.white, k: k, lineBreak: .byTruncatingTail)
            let ts = t.size()
            t.draw(in: NSRect(x: 11 * k, y: (stripHeight - ts.height) / 2, width: bounds.width - 22 * k, height: ts.height))
        }
        // 1px hard border (2px while a drag is over it: derived state)
        let bw = (highlighted ? 2 : 1) * k
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: bounds.insetBy(dx: bw / 2, dy: bw / 2)); b.lineWidth = bw; b.stroke()
    }

    override func mouseDown(with event: NSEvent) { onClick?() }
    override func resetCursorRects() { if onClick != nil { addCursorRect(bounds, cursor: .pointingHand) } }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation { highlighted = true; return .copy }
    override func draggingExited(_ sender: NSDraggingInfo?) { highlighted = false }
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        highlighted = false
        let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self],
                                                         options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        guard !urls.isEmpty else { return false }
        onDrop?(urls)
        return true
    }
}

// MARK: - Button (real NSButton; chiselled, or primary black)

final class AtlasButton: NSButton {
    enum Kind { case push, primary }
    var kind: Kind = .push { didSet { needsDisplay = true } }
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    private var showRing = false

    override init(frame: NSRect) {
        super.init(frame: frame)
        isBordered = false
        setButtonType(.momentaryPushIn)
        focusRingType = .none
    }
    required init?(coder: NSCoder) { fatalError() }

    override var acceptsFirstResponder: Bool { isEnabled }
    override func becomeFirstResponder() -> Bool {
        showRing = NSApp.currentEvent?.type != .leftMouseDown
        needsDisplay = true
        return super.becomeFirstResponder()
    }
    override func resignFirstResponder() -> Bool { showRing = false; needsDisplay = true; return super.resignFirstResponder() }
    override func mouseDown(with event: NSEvent) { showRing = false; super.mouseDown(with: event) }
    override func resetCursorRects() { if isEnabled { addCursorRect(bounds, cursor: .pointingHand) } }

    /// The visible rectangle, inside the room left for the focus outline.
    var face: NSRect { bounds.insetBy(dx: Atlas.S.focusPad * k, dy: Atlas.S.focusPad * k) }

    override func draw(_ dirtyRect: NSRect) {
        let r = face
        let pressed = isHighlighted
        let bev = Atlas.S.bevel * k, hair = k
        NSGraphicsContext.saveGraphicsState()
        if !isEnabled { NSGraphicsContext.current?.cgContext.setAlpha(0.5) }   // derived: disabled is 50%
        switch kind {
        case .push:
            Atlas.C.mid.setFill(); r.fill()
            // inset bands: light on top/left, shadow on bottom/right; swapped when pressed (derived)
            let (tl, br) = pressed ? (Atlas.C.dark, Atlas.C.white) : (Atlas.C.white, Atlas.C.dark)
            tl.setFill()
            NSRect(x: r.minX + hair, y: r.minY + hair, width: r.width - 2 * hair, height: bev).fill()
            NSRect(x: r.minX + hair, y: r.minY + hair, width: bev, height: r.height - 2 * hair).fill()
            br.setFill()
            NSRect(x: r.minX + hair, y: r.maxY - hair - bev, width: r.width - 2 * hair, height: bev).fill()
            NSRect(x: r.maxX - hair - bev, y: r.minY + hair, width: bev, height: r.height - 2 * hair).fill()
        case .primary:
            Atlas.C.ink.setFill(); r.fill()
            if pressed {   // derived: a pressed primary shows an inset band on its top and left
                Atlas.C.dark.setFill()
                NSRect(x: r.minX + hair, y: r.minY + hair, width: r.width - 2 * hair, height: bev).fill()
                NSRect(x: r.minX + hair, y: r.minY + hair, width: bev, height: r.height - 2 * hair).fill()
            }
        }
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: r.insetBy(dx: hair / 2, dy: hair / 2)); b.lineWidth = hair; b.stroke()
        let color = kind == .primary ? Atlas.C.white : Atlas.C.ink
        let t = Atlas.attributed(title, Atlas.T.button, color: color, k: k, align: .center, lineBreak: .byTruncatingTail)
        let ts = t.size()
        let nudge = pressed ? hair : 0
        t.draw(in: NSRect(x: r.minX + 6 * k + nudge, y: r.midY - ts.height / 2 + nudge, width: r.width - 12 * k, height: ts.height))
        NSGraphicsContext.restoreGraphicsState()
        if showRing && isEnabled { Atlas.drawFocusRing(around: r, k: k) }
    }
}

// MARK: - Password field (white, 1px #aaa border, mono 12, amber focus outline offset 1px)

final class AtlasSecureField: NSSecureTextField {
    var onFocusChange: ((Bool) -> Void)?
    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder(); if ok { onFocusChange?(true) }; return ok
    }
    override func resignFirstResponder() -> Bool {
        let ok = super.resignFirstResponder(); if ok { onFocusChange?(false) }; return ok
    }
}

final class FieldView: FlippedView {
    let field = AtlasSecureField()
    var k: CGFloat = 1 { didSet { restyle() } }
    var placeholder = "" { didSet { restyle() } }
    private var focused = false { didSet { needsDisplay = true } }

    init() {
        super.init(frame: .zero)
        field.isBordered = false; field.drawsBackground = false; field.focusRingType = .none
        field.onFocusChange = { [weak self] f in self?.focused = f }
        addSubview(field)
    }
    required init?(coder: NSCoder) { fatalError() }

    var face: NSRect { bounds.insetBy(dx: Atlas.S.focusPad * k, dy: Atlas.S.focusPad * k) }

    func restyle() {
        field.font = Atlas.font(Atlas.mono, Atlas.T.field.size * k)
        field.textColor = Atlas.C.ink
        field.placeholderAttributedString = NSAttributedString(
            string: placeholder, attributes: [.font: Atlas.font(Atlas.mono, 12 * k), .foregroundColor: Atlas.C.g777])
        needsLayout = true; needsDisplay = true
    }
    override func layout() {
        super.layout()
        let f = face
        let h = ceil(Atlas.font(Atlas.mono, 12 * k).boundingRectForFont.height)
        field.frame = NSRect(x: f.minX + 9 * k, y: f.minY + (f.height - h) / 2, width: f.width - 18 * k, height: h)
    }
    override func draw(_ dirtyRect: NSRect) {
        let f = face
        Atlas.C.white.setFill(); f.fill()
        Atlas.C.mid.setStroke()
        let b = NSBezierPath(rect: f.insetBy(dx: k / 2, dy: k / 2)); b.lineWidth = k; b.stroke()
        if focused && field.isEnabled { Atlas.drawFocusRing(around: f, k: k, offset: 1) }
    }
    override func mouseDown(with event: NSEvent) { window?.makeFirstResponder(field) }
}

// MARK: - Progress (derived: a bar whose completed part uses the "complete" hatch)

final class HatchProgressView: FlippedView {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    var value: Double = 0 { didSet { needsDisplay = true } }
    override func draw(_ dirtyRect: NSRect) {
        Atlas.C.white.setFill(); bounds.fill()
        let inner = bounds.insetBy(dx: k, dy: k)
        let w = inner.width * CGFloat(max(0, min(1, value)))
        if w > 0 { Atlas.drawHatch(in: NSRect(x: inner.minX, y: inner.minY, width: w, height: inner.height), k: k) }
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: bounds.insetBy(dx: k / 2, dy: k / 2)); b.lineWidth = k; b.stroke()
    }
}

/// A 1px #aaa rule, or the 2px #111 rule for the footer.
final class RuleView: FlippedView {
    var color = Atlas.C.mid { didSet { needsDisplay = true } }
    override func draw(_ dirtyRect: NSRect) { color.setFill(); bounds.fill() }
}

// MARK: - Checkbox and segmented control (derived: Atlas defines neither)

final class AtlasCheckbox: NSButton {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    private var showRing = false
    override init(frame: NSRect) {
        super.init(frame: frame)
        isBordered = false; setButtonType(.toggle); focusRingType = .none
    }
    required init?(coder: NSCoder) { fatalError() }
    var isChecked: Bool { get { state == .on } set { state = newValue ? .on : .off } }
    override var acceptsFirstResponder: Bool { isEnabled }
    override func becomeFirstResponder() -> Bool { showRing = NSApp.currentEvent?.type != .leftMouseDown; needsDisplay = true; return super.becomeFirstResponder() }
    override func resignFirstResponder() -> Bool { showRing = false; needsDisplay = true; return super.resignFirstResponder() }
    override func mouseDown(with event: NSEvent) { showRing = false; super.mouseDown(with: event) }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }

    override func draw(_ dirtyRect: NSRect) {
        let box = NSRect(x: 5 * k, y: (bounds.height - 13 * k) / 2, width: 13 * k, height: 13 * k)
        (isChecked ? Atlas.C.ink : Atlas.C.white).setFill(); box.fill()      // stepper-mark treatment
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: box.insetBy(dx: k / 2, dy: k / 2)); b.lineWidth = k; b.stroke()
        let t = Atlas.attributed(title, Atlas.T.inspectorParagraph, color: Atlas.C.ink, k: k)
        let ts = t.size()
        t.draw(in: NSRect(x: box.maxX + 9 * k, y: (bounds.height - ts.height) / 2, width: bounds.width - box.maxX - 12 * k, height: ts.height + 2))
        if showRing { Atlas.drawFocusRing(around: box, k: k) }
    }
}

final class AtlasSegmented: NSControl {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    var segments: [String] = [] { didSet { needsDisplay = true } }
    var selected = 0 { didSet { needsDisplay = true } }
    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        let n = max(1, segments.count)
        let w = bounds.width / CGFloat(n)
        for (i, s) in segments.enumerated() {
            let r = NSRect(x: CGFloat(i) * w, y: 0, width: w, height: bounds.height)
            (i == selected ? Atlas.C.ink : Atlas.C.mid).setFill(); r.fill()
            let t = Atlas.attributed(s, Atlas.T.button, color: i == selected ? Atlas.C.white : Atlas.C.ink, k: k, align: .center)
            let ts = t.size()
            t.draw(in: NSRect(x: r.minX, y: r.midY - ts.height / 2, width: r.width, height: ts.height))
            if i > 0 { Atlas.C.line.setFill(); NSRect(x: r.minX, y: 0, width: k, height: bounds.height).fill() }
        }
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: bounds.insetBy(dx: k / 2, dy: k / 2)); b.lineWidth = k; b.stroke()
    }
    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        let i = min(segments.count - 1, max(0, Int(p.x / (bounds.width / CGFloat(max(1, segments.count))))))
        selected = i
        sendAction(action, to: target)
    }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .radioGroup }
    override func accessibilityValue() -> Any? { segments.indices.contains(selected) ? segments[selected] : nil }
}

// MARK: - Slider and plain box (derived: Atlas defines neither)

/// A whole-number slider: a 2px rule, black up to a black thumb.
final class AtlasSlider: NSControl {
    var k: CGFloat = 1 { didSet { needsDisplay = true } }
    var range: ClosedRange<Int> = 0...1 { didSet { value = min(max(value, range.lowerBound), range.upperBound) } }
    var value = 0 { didSet { needsDisplay = true } }
    private var focused = false { didSet { needsDisplay = true } }
    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }
    override func becomeFirstResponder() -> Bool { focused = NSApp.currentEvent?.type != .leftMouseDown; return true }
    override func resignFirstResponder() -> Bool { focused = false; return true }

    private var thumbWidth: CGFloat { 12 * k }
    private var track: NSRect { NSRect(x: thumbWidth / 2, y: bounds.midY - k, width: bounds.width - thumbWidth, height: 2 * k) }
    private var thumb: NSRect {
        let f = CGFloat(value - range.lowerBound) / CGFloat(max(1, range.upperBound - range.lowerBound))
        return NSRect(x: track.minX + f * track.width - thumbWidth / 2, y: bounds.midY - 9 * k, width: thumbWidth, height: 18 * k)
    }

    override func draw(_ dirtyRect: NSRect) {
        let t = track, th = thumb
        Atlas.C.mid.setFill(); t.fill()
        Atlas.C.ink.setFill()
        NSRect(x: t.minX, y: t.minY, width: th.midX - t.minX, height: t.height).fill()
        th.fill()
        if focused { Atlas.drawFocusRing(around: th, k: k) }
    }
    private func track(_ event: NSEvent) {
        let x = convert(event.locationInWindow, from: nil).x
        let f = max(0, min(1, (x - track.minX) / max(1, track.width)))
        change(to: range.lowerBound + Int((f * CGFloat(range.upperBound - range.lowerBound)).rounded()))
    }
    private func change(to v: Int) {
        let c = min(max(v, range.lowerBound), range.upperBound)
        guard c != value else { return }
        value = c
        sendAction(action, to: target)
    }
    override func mouseDown(with event: NSEvent) { window?.makeFirstResponder(self); track(event) }
    override func mouseDragged(with event: NSEvent) { track(event) }
    override func keyDown(with event: NSEvent) {
        switch event.keyCode {
        case 123, 125: change(to: value - 1)     // left, down
        case 124, 126: change(to: value + 1)     // right, up
        default: super.keyDown(with: event)
        }
    }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .slider }
    override func accessibilityValue() -> Any? { value }
}

/// A white surface with the 1px hard border.
final class BoxView: FlippedView {
    override func draw(_ dirtyRect: NSRect) {
        Atlas.C.white.setFill(); bounds.fill()
        Atlas.C.line.setStroke()
        let b = NSBezierPath(rect: bounds.insetBy(dx: 0.5, dy: 0.5)); b.lineWidth = 1; b.stroke()
    }
}

// MARK: - Password guidance

func passwordStrength(_ pw: String) -> (text: String, color: NSColor) {
    let len = pw.count
    if len == 0 { return ("", Atlas.C.dark) }
    var classes = 0
    if pw.rangeOfCharacter(from: .lowercaseLetters) != nil { classes += 1 }
    if pw.rangeOfCharacter(from: .uppercaseLetters) != nil { classes += 1 }
    if pw.rangeOfCharacter(from: .decimalDigits) != nil { classes += 1 }
    if pw.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil { classes += 1 }
    if len < 8 { return ("Very weak: easy to guess.", Atlas.C.error) }
    if len < 12 { return ("Weak: use 12 or more characters.", Atlas.C.state) }
    if len < 16 && classes < 3 { return ("Fair: add length or variety.", Atlas.C.state) }
    if len >= 20 || (len >= 16 && classes >= 3) { return ("Strong.", Atlas.C.success) }
    return ("Good.", Atlas.C.success)
}
