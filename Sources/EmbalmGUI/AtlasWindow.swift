import AppKit

final class AtlasRootView: FlippedView {
    var onLayout: (() -> Void)?
    override func layout() { super.layout(); onLayout?() }
}

enum AtlasWindowFactory {
    /// A window whose content runs under a transparent title bar, so Atlas's own
    /// 25pt black bar is drawn at the top while the system's working close,
    /// minimise and zoom buttons stay on it (Atlas ADR-0004 default).
    static func make(size: NSSize, resizable: Bool = false) -> NSWindow {
        var mask: NSWindow.StyleMask = [.titled, .closable, .miniaturizable, .fullSizeContentView]
        if resizable { mask.insert(.resizable) }
        let w = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: mask,
                         backing: .buffered, defer: false)
        w.titlebarAppearsTransparent = true
        w.titleVisibility = .hidden
        w.isReleasedWhenClosed = false
        w.isRestorable = false                       // never remember what was open
        w.backgroundColor = Atlas.C.paper
        w.appearance = NSAppearance(named: .aqua)    // Atlas has no approved dark mode
        w.setFrame(NSRect(origin: .zero, size: size), display: false)
        w.center()
        return w
    }
}
