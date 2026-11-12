import AppKit

// Renders Embalm's icons as 1-bit-style pixel art in the manner of early Macintosh
// icons: hard black outline, white face, dithered shading lit from the upper left,
// a checkered cast shadow and one amber accent.
//
//   icon-gen <out.png> [size] [app|doc]
//
// "app" is the application icon (a grey tile); "doc" is the icon for embalmed files.

let args = CommandLine.arguments
let outPath = args.count > 1 ? args[1] : "icon.png"
let side = Int(args.count > 2 ? args[2] : "1024") ?? 1024
let isDoc = args.count > 3 && args[3] == "doc"

let N = 64                       // the art lives on a 64 x 64 grid
enum Px: UInt8 { case clear, black, white, tile, amber, dark }

var grid = [[Px]](repeating: [Px](repeating: .clear, count: N), count: N)
func put(_ x: Int, _ y: Int, _ p: Px) { if x >= 0, y >= 0, x < N, y < N { grid[y][x] = p } }

// MARK: ankh geometry (design space is 64 x 64; scaled about (cx, cy) on the grid)

func inBody(_ u: Double, _ v: Double) -> Bool {
    let dx = (u - 32) / 13.2, dy = (v - 21) / 16.2
    let outer = dx * dx + dy * dy <= 1
    let ix = (u - 32) / 6.7, iy = (v - 21) / 9.5
    let ring = outer && (ix * ix + iy * iy > 1)
    let bar = (u >= 10 && u < 54 && v >= 37 && v < 43) || ((u >= 10 && u < 13 || u >= 51 && u < 54) && v >= 36 && v < 44)
    let stem = u >= 29 && u < 35 && v >= 37 && v < 60
    return ring || bar || stem
}
func inKey(_ u: Double, _ v: Double) -> Bool {
    let round = (u - 32) * (u - 32) + (v - 17.8) * (v - 17.8) <= 3.3 * 3.3
    let hw = 2.7 - (v - 20) * 0.1
    return round || (v >= 20 && v < 27.6 && abs(u - 32) <= hw)
}

func mask(scale: Double, cx: Double, cy: Double, _ f: (Double, Double) -> Bool) -> [[Bool]] {
    var m = [[Bool]](repeating: [Bool](repeating: false, count: N), count: N)
    for y in 0..<N { for x in 0..<N {
        m[y][x] = f(32 + (Double(x) + 0.5 - cx) / scale, 32 + (Double(y) + 0.5 - cy) / scale)
    } }
    return m
}
func shifted(_ m: [[Bool]], _ dx: Int, _ dy: Int) -> [[Bool]] {
    var o = m
    for y in 0..<N { for x in 0..<N {
        let sx = x - dx, sy = y - dy
        o[y][x] = (sx >= 0 && sy >= 0 && sx < N && sy < N) ? m[sy][sx] : false
    } }
    return o
}
func get(_ m: [[Bool]], _ x: Int, _ y: Int) -> Bool { x >= 0 && y >= 0 && x < N && y < N && m[y][x] }
func isEdge(_ m: [[Bool]], _ x: Int, _ y: Int) -> Bool {
    m[y][x] && !(get(m, x - 1, y) && get(m, x + 1, y) && get(m, x, y - 1) && get(m, x, y + 1))
}
func blur(_ m: [[Bool]], radius r: Int, passes: Int) -> [[Double]] {
    var f = m.map { $0.map { $0 ? 1.0 : 0.0 } }
    for _ in 0..<passes {
        var g = f
        for y in 0..<N { for x in 0..<N {
            var s = 0.0, c = 0.0
            for j in -r...r { for i in -r...r {
                let xx = x + i, yy = y + j
                s += (xx >= 0 && yy >= 0 && xx < N && yy < N) ? f[yy][xx] : 0; c += 1
            } }
            g[y][x] = s / c
        } }
        f = g
    }
    return f
}
func checker(_ x: Int, _ y: Int) -> Bool { (x + y) % 2 == 0 }

// MARK: draw

/// Lower-right chiselling: pixels next to a lower-right outline get a 50% dither, then a
/// 25% dither one pixel further in. Everything else stays white.
func chisel(_ m: [[Bool]], edge: [[Bool]], x: Int, y: Int) -> Px {
    func e(_ dx: Int, _ dy: Int) -> Bool { get(edge, x + dx, y + dy) }
    if e(1, 0) || e(0, 1) || e(1, 1) { return checker(x, y) ? .black : .white }
    return .white
}
func edges(_ m: [[Bool]]) -> [[Bool]] {
    var o = m
    for y in 0..<N { for x in 0..<N { o[y][x] = isEdge(m, x, y) } }
    return o
}

if !isDoc {
    let body = mask(scale: 1, cx: 32, cy: 32, inBody)
    let key = mask(scale: 1, cx: 32, cy: 32, inKey)
    let edge = edges(body)
    let shadow = shifted(body, 3, 3)
    for y in 0..<N { for x in 0..<N where shadow[y][x] && !body[y][x] { put(x, y, .dark) } }
    for y in 0..<N { for x in 0..<N where body[y][x] { put(x, y, edge[y][x] ? .black : chisel(body, edge: edge, x: x, y: y)) } }
    let kedge = edges(key)
    for y in 0..<N { for x in 0..<N where key[y][x] { put(x, y, kedge[y][x] ? .black : .amber) } }
} else {
    // A page with a folded corner, and a small ankh.
    let l = 12, r = 51, t = 3, b = 60, fold = 12
    var page = [[Bool]](repeating: [Bool](repeating: false, count: N), count: N)
    for y in t..<b { for x in l..<r {
        let cutAway = x >= r - fold && y < t + fold && (x - (r - fold)) > (y - t)
        page[y][x] = !cutAway
    } }
    let edge = edges(page)
    let shadow = shifted(page, 3, 3)
    for y in 0..<N { for x in 0..<N where shadow[y][x] && !page[y][x] { put(x, y, .dark) } }
    for y in 0..<N { for x in 0..<N where page[y][x] { put(x, y, edge[y][x] ? .black : chisel(page, edge: edge, x: x, y: y)) } }
    // the folded flap: shaded, with a black fold line along its two inner sides
    for y in t..<(t + fold) { for x in (r - fold)..<r where (x - (r - fold)) <= (y - t) && !edge[y][x] {
        put(x, y, (x + y) % 2 == 0 ? .black : .white)
    } }
    for i in 0..<fold { put(r - fold, t + i, .black); put(r - fold + i, t + fold - 1, .black) }
    // the ankh, drawn black with an amber keyhole
    let body = mask(scale: 0.64, cx: 31.5, cy: 33.5, inBody)
    let key = mask(scale: 0.64, cx: 31.5, cy: 33.5, inKey)
    for y in 0..<N { for x in 0..<N where body[y][x] { put(x, y, .black) } }
    for y in 0..<N { for x in 0..<N where key[y][x] { put(x, y, .amber) } }
}

// MARK: render

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side, bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext
func col(_ hex: UInt32) -> CGColor {
    CGColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}
let S = Double(side)

if !isDoc {
    // macOS-style tile: Atlas grey with a light upper-left rim and a dark lower-right rim.
    let inset = S * 0.098
    let rect = CGRect(x: inset, y: inset, width: S - 2 * inset, height: S - 2 * inset)
    let path = CGPath(roundedRect: rect, cornerWidth: S * 0.2237, cornerHeight: S * 0.2237, transform: nil)
    ctx.saveGState()
    ctx.addPath(path); ctx.clip()
    ctx.setFillColor(col(0xAAAAAA)); ctx.fill(rect)
    let g = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                       colors: [col(0xC6C6C6), col(0xAAAAAA), col(0x8E8E8E)] as CFArray, locations: [0, 0.5, 1])!
    ctx.drawLinearGradient(g, start: CGPoint(x: rect.minX, y: rect.maxY), end: CGPoint(x: rect.maxX, y: rect.minY), options: [])
    ctx.restoreGState()
    ctx.setStrokeColor(col(0x111111)); ctx.setLineWidth(S * 0.004)
    ctx.addPath(path); ctx.strokePath()
}

let art = S * (768.0 / 1024.0), ox = (S - art) / 2, c = art / Double(N)
ctx.setShouldAntialias(false)
for y in 0..<N { for x in 0..<N {
    let p = grid[y][x]
    if p == .clear { continue }
    switch p {
    case .black: ctx.setFillColor(col(0x000000))
    case .white: ctx.setFillColor(col(0xFFFFFF))
    case .tile:  ctx.setFillColor(col(0xAAAAAA))
    case .amber: ctx.setFillColor(col(0xD68B22))
    case .dark:  ctx.setFillColor(col(0x555555))
    case .clear: continue
    }
    // CoreGraphics' origin is bottom-left; the grid's is top-left.
    ctx.fill(CGRect(x: (ox + Double(x) * c).rounded(), y: (S - ox - Double(y + 1) * c).rounded(),
                    width: c.rounded(.up), height: c.rounded(.up)))
} }
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: outPath))
