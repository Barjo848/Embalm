import AppKit

/// A real menu bar. Without an Edit menu, Cut/Copy/Paste do nothing in text fields,
/// so passwords could not be pasted.
func buildMainMenu(delegate: AppDelegate) -> NSMenu {
    let main = NSMenu()
    @discardableResult
    func add(_ title: String, to menu: NSMenu, _ action: Selector?, _ key: String = "",
             target: AnyObject? = nil, mods: NSEvent.ModifierFlags = .command) -> NSMenuItem {
        let item = menu.addItem(withTitle: title, action: action, keyEquivalent: key)
        item.keyEquivalentModifierMask = mods
        item.target = target
        return item
    }
    func submenu(_ title: String) -> NSMenu {
        let item = NSMenuItem(); main.addItem(item)
        let m = NSMenu(title: title); item.submenu = m
        return m
    }

    let app = submenu("Embalm")
    add("About Embalm", to: app, #selector(NSApplication.orderFrontStandardAboutPanel(_:)))
    app.addItem(.separator())
    add("Settings…", to: app, #selector(AppDelegate.showSettings(_:)), ",", target: delegate)
    app.addItem(.separator())
    add("Hide Embalm", to: app, #selector(NSApplication.hide(_:)), "h")
    add("Hide Others", to: app, #selector(NSApplication.hideOtherApplications(_:)), "h", mods: [.command, .option])
    add("Show All", to: app, #selector(NSApplication.unhideAllApplications(_:)))
    app.addItem(.separator())
    add("Quit Embalm", to: app, #selector(NSApplication.terminate(_:)), "q")

    let file = submenu("File")
    add("Open…", to: file, #selector(AppDelegate.openDocument(_:)), "o", target: delegate)
    file.addItem(.separator())
    add("Close", to: file, #selector(NSWindow.performClose(_:)), "w")

    let edit = submenu("Edit")
    add("Undo", to: edit, Selector(("undo:")), "z")
    add("Redo", to: edit, Selector(("redo:")), "z", mods: [.command, .shift])
    edit.addItem(.separator())
    add("Cut", to: edit, #selector(NSText.cut(_:)), "x")
    add("Copy", to: edit, #selector(NSText.copy(_:)), "c")
    add("Paste", to: edit, #selector(NSText.paste(_:)), "v")
    add("Select All", to: edit, #selector(NSText.selectAll(_:)), "a")

    let view = submenu("View")
    add("Large Window (777 × 777)", to: view, #selector(AppDelegate.toggleLargeWindow(_:)), "l", target: delegate)

    let window = submenu("Window")
    add("Minimize", to: window, #selector(NSWindow.performMiniaturize(_:)), "m")
    NSApp.windowsMenu = window

    let help = submenu("Help")
    add("Embalm Instructions", to: help, #selector(AppDelegate.showInstructions(_:)), "?", target: delegate)
    help.addItem(.separator())
    add("Run Self-Check…", to: help, #selector(AppDelegate.runSelfCheck(_:)), target: delegate)
    NSApp.helpMenu = help

    return main
}
