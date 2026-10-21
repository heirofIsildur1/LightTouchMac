// FitCheck: proof, read off the firmware itself at prepare time, that a guest-side piece fits the firmware it is
// injected into. Every check returns a Fit: fits with the proof, or does
// not fit with why. "Could not tell" is never a fit. No per-build tables: only symbols, strings and structure.
//
//   let fw = FitCheck.Firmware(volume: systemVolume, arch: "armv7")       // any VolumeFiles, or root: a folder
//   let f = FitCheck.loads("it_agent", Data(contentsOf: helper), on: fw)   // f.fits, f.proof
//
// The recipes record every Fit in the lock ("fit"); a piece that does not fit fails the prepare, or, where the
// piece is optional, is left out with a warning event.

import BinaryParsing
import Foundation

public enum FitCheck {
    public struct Fit: Sendable, Equatable {
        public var piece: String, fits: Bool, proof: String
        public init(_ piece: String, fits: Bool, _ proof: String) {
            self.piece = piece
            self.fits = fits
            self.proof = proof
        }
        public var object: [String: Any] { ["piece": piece, "fits": fits, "proof": proof] }
        /// The warning event's text: the misfit and what the preparer did about it.
        public func warning(_ outcome: String) -> String {
            "\(piece) does not fit this firmware (\(outcome)): \(proof)"
        }
    }

    /// The prepare's record of every check (the lock's "fit"). A required piece that does not fit throws; an
    /// optional one is recorded and warned about, and the caller leaves it out.
    public final class Log: @unchecked Sendable {
        public private(set) var fits: [Fit] = []
        let warn: (String) -> Void
        public init(warn: @escaping (String) -> Void = { _ in }) { self.warn = warn }

        /// `outcome`: what the preparer does with an optional piece that does not fit ("left out", "kept: ...").
        @discardableResult
        public func check(_ f: Fit, required: Bool, outcome: String = "left out") throws -> Bool {
            fits.append(f)
            if f.fits { return true }
            if required {
                throw FirmwareError(.unsupported, "\(f.piece) does not fit this firmware: \(f.proof)", piece: f.piece)
            }
            warn(f.warning(outcome))
            return false
        }
        /// One optional piece that goes wherever it fits (it_msmquiet: whichever job raises the notice): every place is
        /// recorded, and only when it fits none is each misfit warned about. Returns the places' fits.
        @discardableResult
        public func checkAny(_ places: [Fit], outcome: String = "left out") -> [Bool] {
            fits += places
            if !places.contains(where: \.fits) { places.forEach { warn($0.warning(outcome)) } }
            return places.map(\.fits)
        }
        /// A piece the preparer did not install, recorded as such (nothing proven, so not a fit; no warning).
        public func notInstalled(_ piece: String, _ why: String) {
            fits.append(Fit(piece, fits: false, "not installed (\(why))"))
        }
        public var object: [[String: Any]] { fits.map(\.object) }
    }

    /// The pristine firmware as the checks read it: the system volume (symlinks resolved inside it, never on the
    /// host), its dyld shared cache, and the decrypted kernelcache when the recipe has one.
    public final class Firmware {
        public let volume: any VolumeFiles, arch: String, kernelcache: Data?
        public init(volume: any VolumeFiles, arch: String, kernelcache: Data? = nil) {
            self.volume = volume
            self.arch = arch
            self.kernelcache = kernelcache
        }

        /// The firmware in a folder on the host (a mounted volume, an extracted tree).
        public convenience init(root: URL, arch: String, kernelcache: Data? = nil) {
            self.init(volume: MountedVolume(root: root), arch: arch, kernelcache: kernelcache)
        }

        public lazy var cache: DyldSharedCache? = data(SystemEdits.dyldCache(arch)).flatMap {
            try? DyldSharedCache(data: $0)
        }

        /// `rel` (volume-relative, with or without a leading "/") with every symlink followed inside the volume;
        /// nil when it is not there.
        public func resolve(_ rel: String) -> String? {
            let (path, exists) = follow(rel)
            return exists ? path : nil
        }

        /// (the path with symlinks followed, whether it exists).
        func follow(_ rel: String) -> (String, Bool) {
            var parts = rel.split(separator: "/").map(String.init)
            var out: [String] = []
            var hops = 0
            while !parts.isEmpty {
                let p = parts.removeFirst()
                if p == "." { continue }
                if p == ".." {
                    _ = out.popLast()
                    continue
                }
                let here = (out + [p]).joined(separator: "/")
                if volume.isSymlink(here), let dest = try? volume.destinationOfSymlink(at: here) {
                    hops += 1
                    guard hops < 32 else { return (rel, false) }
                    if dest.hasPrefix("/") { out = [] }
                    parts = dest.split(separator: "/").map(String.init) + parts
                    continue
                }
                out.append(p)
            }
            let path = out.joined(separator: "/")
            return (path, volume.exists(path))
        }

        public func data(_ rel: String) -> Data? { resolve(rel).flatMap { try? volume.contents(at: $0) } }

        /// The property list at `rel`, symlinks followed, or nil.
        public func plist(_ rel: String) -> NSDictionary? { resolve(rel).flatMap { volume.plist(at: $0) } }

        /// The names in the folder at `rel`, sorted; none when it is not there.
        public func names(_ rel: String) -> [String] {
            (resolve(rel).flatMap { try? volume.contentsOfDirectory(at: $0) } ?? []).sorted()
        }

        /// Does the file at `rel` contain `bytes`?
        public func file(_ rel: String, contains bytes: Data) -> Bool { data(rel)?.range(of: bytes) != nil }

        /// Which of the firmware's own executables carries each dyld-required load command (LC_REQ_DYLD set):
        /// a command this firmware's dyld is known to take, by precedent.
        public lazy var precedent: [UInt32: String] = {
            var out: [UInt32: String] = [:]
            for rel in Self.precedentBinaries {
                guard let d = data(rel), let m = MachO32.slice(d, arch: arch)?.image else { continue }
                for c in m.commands where c.cmd & MachO32.reqDyld != 0 && out[c.cmd] == nil {
                    out[c.cmd] = (rel as NSString).lastPathComponent
                }
            }
            return out
        }()
        static let precedentBinaries = [
            "sbin/launchd", "System/Library/CoreServices/SpringBoard.app/SpringBoard", "usr/libexec/lockdownd"
        ]

        private var exportMemo: [String: Set<String>?] = [:]

        /// The symbols the image installed as `install` exports (its re-exports' included); nil when this firmware
        /// has no such image (on disk or in the shared cache).
        public func exports(_ install: String) -> Set<String>? {
            if let hit = exportMemo[install] { return hit }
            exportMemo[install] = .some(nil)  // a re-export cycle ends here
            let found = loadExports(install)
            exportMemo[install] = .some(found)
            return found
        }

        private var linkMemo: [String: [String]] = [:]

        /// The images `install` links (weak ones included); [] when it is not on this firmware.
        public func links(_ install: String) -> [String] {
            if let hit = linkMemo[install] { return hit }
            var out: [String] = []
            let (followed, onDisk) = follow(install)
            if let cache, let img = cache.image(install) ?? cache.image("/" + followed) {
                // An image whose load commands don't read links nothing.
                do {
                    try cache.loadCommands(img) { cmd, off, b in
                        if MachO32.linkCommands.contains(cmd) {
                            out.append(try b.latin1(off + Int(try b.u32le(off + 8))))
                        }
                    }
                } catch { out = [] }
            } else if onDisk, let d = data(followed), let m = MachO32.slice(d, arch: arch)?.image {
                out = m.dylibs().map(\.name)
            }
            linkMemo[install] = out
            return out
        }

        /// Every image a process of `executable` has loaded before anything is inserted: it and its links, transitively.
        public func loaded(_ executable: String) -> [String] {
            var seen = ["/" + executable.drop { $0 == "/" }]
            var queue = seen
            while let next = queue.popLast() {
                for l in links(next) where !seen.contains(l) {
                    seen.append(l)
                    queue.append(l)
                }
            }
            return seen
        }

        private var importMemo: [String: Set<String>?] = [:]

        /// The undefined external symbols (prebound ones included: 2.x/3.0) the image installed as `install` imports;
        /// nil when this firmware has no such image.
        public func imports(_ install: String) -> Set<String>? {
            if let hit = importMemo[install] { return hit }
            let (followed, onDisk) = follow(install)
            var found: Set<String>?
            if let cache, let img = cache.image(install) ?? cache.image("/" + followed) {
                var out = Set<String>()
                // An image whose symbol table doesn't read is not there to import from.
                let read: Void? = try? cache.forEachSymbol(in: img) { s in
                    if MachO32.isImport(s.type) { out.insert(s.name) }
                    return true
                }
                found = read.map { out }
            } else if onDisk, let d = data(followed), let m = MachO32.slice(d, arch: arch)?.image {
                found = FitCheck.imports(m)
            }
            importMemo[install] = .some(found)
            return found
        }

        private func loadExports(_ install: String) -> Set<String>? {
            let (followed, onDisk) = follow(install)
            if let cache, let img = cache.image(install) ?? cache.image("/" + followed) {
                var out = Set<String>()
                var reexports: [String] = []
                // An image whose symbols or load commands don't read exports nothing.
                do {
                    try cache.forEachSymbol(in: img) { s in
                        if MachO32.isExport(s.type) { out.insert(s.name) }
                        return true
                    }
                    try cache.loadCommands(img) { cmd, off, b in
                        if cmd == MachO32.lcReexportDylib {
                            reexports.append(try b.latin1(off + Int(try b.u32le(off + 8))))
                        }
                        // a cache image's export trie offset is a cache file offset
                        if cmd == MachO32.lcDyldInfo || cmd == MachO32.lcDyldInfoOnly {
                            out.formUnion(
                                MachO32.trieReexports(
                                    b,
                                    at: Int(try b.u32le(off + 40)),
                                    size: Int(try b.u32le(off + 44))
                                )
                            )
                        }
                    }
                } catch { return nil }
                for r in reexports { out.formUnion(exports(r) ?? []) }
                return out
            }
            guard onDisk, let d = data(followed), let m = MachO32.slice(d, arch: arch)?.image else { return nil }
            var out = Set(m.symbols().filter { MachO32.isExport($0.type) }.map(\.name))
            for r in m.reexported() { out.formUnion(exports(r) ?? []) }
            if let info = m.commands.first(where: { $0.cmd == MachO32.lcDyldInfo || $0.cmd == MachO32.lcDyldInfoOnly }),
                let at = try? m.u32(info.off + 40), let size = try? m.u32(info.off + 44)
            {
                m.b.withUnsafeBytes { b in out.formUnion(MachO32.trieReexports(b, at: Int(at), size: Int(size))) }
            }
            return out
        }
    }

    /// Is `d` a Mach-O (thin 32-bit or fat)?
    static func isMachO(_ d: Data) -> Bool {
        guard d.count >= 4 else { return false }
        let m = d.prefix(4)
        return m.elementsEqual([0xCE, 0xFA, 0xED, 0xFE]) || m.elementsEqual([0xCA, 0xFE, 0xBA, 0xBE])
    }

    /// The stock executable whose launchd job inserts `dylib` (DYLD_INSERT_LIBRARIES), as the volume's jobs say now.
    static func host(of dylib: String, on fw: Firmware) -> String? {
        for n in fw.names(SystemEdits.daemons) where n.hasSuffix(".plist") {
            guard let d = fw.plist(SystemEdits.daemons + "/" + n),
                let inserted = (d["EnvironmentVariables"] as? [String: Any])?["DYLD_INSERT_LIBRARIES"] as? String,
                inserted.split(separator: ":").contains(Substring(dylib))
            else { continue }
            return (d["ProgramArguments"] as? [String])?.first ?? d["Program"] as? String
        }
        return nil
    }

    /// ARM subtypes the recipes' archs name.
    static let subtype: [String: Int32] = ["armv6": 6, "armv7": 9]

    /// Does the guest Mach-O `bin` (thin or fat) load on this firmware? Proven, not assumed: a slice this board's
    /// CPU runs; every dyld-required load command one the firmware's own executables carry (so its dyld takes it);
    /// every non-weak linked image present (on disk or in the shared cache); every non-weak imported symbol
    /// exported by the image it binds to (two-level) or by one of the linked images (flat).
    /// `host`: the stock executable a dylib is inserted into (DYLD_INSERT_LIBRARIES); its loaded images answer the
    /// dylib's flat and dynamic-lookup imports, and its own exports the executable-ordinal ones.
    public static func loads(_ piece: String, _ bin: Data, on fw: Firmware, host: String? = nil) -> Fit {
        guard let (m, sliceArch) = MachO32.slice(bin, arch: fw.arch) else {
            return Fit(piece, fits: false, "no \(fw.arch) slice this CPU runs (not a 32-bit ARM Mach-O for this board)")
        }
        var why: [String] = []
        let required = m.commands.map(\.cmd).filter { $0 & MachO32.reqDyld != 0 }
        let unknown = Set(required.filter { fw.precedent[$0] == nil })
        if !unknown.isEmpty {
            why.append(
                "load command \(unknown.sorted().map { hex($0) }.joined(separator: ", ")) is in none of this firmware's own executables (its dyld refuses what it does not know)"
            )
        }
        let linked = m.dylibs()
        var exports: [[String]?] = []  // by ordinal - 1
        var lost: [String] = []
        for l in linked {
            let e = fw.exports(l.name)
            exports.append(e.map { _ in [l.name] })
            if e == nil, !l.weak { lost.append(l.name) }
        }
        if !lost.isEmpty { why.append("links \(lost.joined(separator: ", ")), which this firmware does not have") }
        var missing: [String] = []
        var resolved = 0
        let twoLevel = m.flags & 0x80 != 0
        for s in m.symbols() where s.type & 0xE0 == 0 && s.type & 0x01 != 0 && s.type & 0x0E == 0 && !s.name.isEmpty {
            if s.desc & 0x40 != 0 { continue }  // N_WEAK_REF: dyld leaves it NULL
            let ordinal = Int(s.desc >> 8)
            let candidates: [String]
            if twoLevel && ordinal >= 1 && ordinal <= linked.count {
                candidates = [linked[ordinal - 1].name]
            } else if twoLevel && ordinal == 0 {
                continue
            }  // SELF_LIBRARY
            else if twoLevel && ordinal == 0xFF {
                candidates = host.map { ["/" + $0.drop { $0 == "/" }] } ?? []
            }  // EXECUTABLE_ORDINAL
            else {
                candidates = linked.map(\.name) + (host.map(fw.loaded) ?? [])
            }  // flat namespace, or DYNAMIC_LOOKUP
            if candidates.contains(where: { fw.exports($0)?.contains(s.name) == true }) {
                resolved += 1
            } else {
                missing.append(s.name)
            }
        }
        if !missing.isEmpty {
            why.append(
                "imports \(missing.prefix(6).joined(separator: ", "))\(missing.count > 6 ? " (+\(missing.count - 6))" : "") that no linked image of this firmware exports"
            )
        }
        if !why.isEmpty { return Fit(piece, fits: false, why.joined(separator: "; ")) }
        // every one has a precedent: an unknown command returned above
        let cmds = Set(required).sorted().compactMap { c in fw.precedent[c].map { "\(hex(c)) as \($0)" } }
        return Fit(
            piece,
            fits: true,
            "\(sliceArch) slice\(host.map { " in " + ($0 as NSString).lastPathComponent } ?? ""); \(cmds.isEmpty ? "no dyld-required load commands" : "load commands " + cmds.joined(separator: ", ")); "
                + "\(linked.count) linked images present; \(resolved) imports resolved"
        )
    }
}

/// Just enough of a 32-bit little-endian Mach-O for the fit checks: load commands, linked images, nlist.
struct MachO32 {
    static let reqDyld: UInt32 = 0x8000_0000
    static let lcLoadDylib: UInt32 = 0xC, lcLoadWeakDylib: UInt32 = 0x8000_0018, lcReexportDylib: UInt32 = 0x8000_001F
    static let lcLoadUpwardDylib: UInt32 = 0x8000_0023, lcSubUmbrella: UInt32 = 0x13, lcSubLibrary: UInt32 = 0x15
    static let linkCommands: Set<UInt32> = [lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib]
    static let lcDyldInfo: UInt32 = 0x22, lcDyldInfoOnly: UInt32 = 0x8000_0022

    /// The names an export trie re-exports one by one (EXPORT_SYMBOL_FLAGS_REEXPORT). iOS 6 moved NSObject to libobjc
    /// and left CoreFoundation re-exporting _OBJC_CLASS_$_NSObject this way, with no nlist entry, so images that
    /// bind NSObject to CoreFoundation (built against an older SDK) still load.
    static func trieReexports(_ b: UnsafeRawBufferPointer, at start: Int, size: Int) -> [String] {
        guard start > 0, size > 0, start + size <= b.count else { return [] }
        let end = start + size
        func uleb(_ p: inout Int) -> Int? {
            var r = 0
            var shift = 0
            while p < end, shift < 63 {
                let x = b[p]
                p += 1
                r |= Int(x & 0x7F) << shift
                shift += 7
                if x < 0x80 { return r }
            }
            return nil
        }
        var out: [String] = []
        var stack: [(Int, [UInt8])] = [(0, [])]
        var seen = Set<Int>()
        while let (node, prefix) = stack.popLast() {
            guard seen.insert(node).inserted else { continue }  // a malformed trie cannot loop
            var p = start + node
            guard p < end, let info = uleb(&p) else { continue }
            if info > 0 {
                var q = p
                if let flags = uleb(&q), flags & 0x8 != 0 { out.append(String(decoding: prefix, as: UTF8.self)) }
            }
            p += info
            guard p < end else { continue }
            let children = Int(b[p])
            p += 1
            for _ in 0..<children {
                guard let nul = b[p..<end].firstIndex(of: 0) else { break }
                let label = Array(b[p..<nul])
                p = nul + 1
                guard let child = uleb(&p) else { break }
                stack.append((child, prefix + label))
            }
        }
        return out
    }

    let b: [UInt8]
    let filetype: UInt32, flags: UInt32
    let commands: [(cmd: UInt32, off: Int)]

    init?(_ b: [UInt8]) {
        // mach_header: magic, cputype (ARM), cpusubtype, filetype, ncmds, sizeofcmds, flags; then the load commands
        let header = try? b.withParserSpan { s -> (UInt32, UInt32, [(UInt32, Int)])? in
            guard try UInt32(parsingLittleEndian: &s) == 0xFEED_FACE, try UInt32(parsingLittleEndian: &s) == 12 else {
                return nil
            }
            try s.seek(toRelativeOffset: 4)
            let filetype = try UInt32(parsingLittleEndian: &s)
            let ncmds = try UInt32(parsingLittleEndian: &s)
            try s.seek(toRelativeOffset: 4)
            let flags = try UInt32(parsingLittleEndian: &s)
            var cmds: [(UInt32, Int)] = []
            var off = s.startPosition
            for _ in 0..<ncmds {
                var c = try s.seeking(toAbsoluteOffset: off)
                cmds.append((try UInt32(parsingLittleEndian: &c), off))
                let size = Int(try UInt32(parsingLittleEndian: &c))
                guard size >= 8 else { return nil }
                off += size
            }
            return (filetype, flags, cmds)
        }
        guard let (filetype, flags, commands) = header else { return nil }
        self.b = b
        self.filetype = filetype
        self.flags = flags
        self.commands = commands
    }

    /// The little-endian word at `o`, or the readers' error past the image.
    func u32(_ o: Int) throws -> UInt32 { try b.withParserSpan { s throws(ParsingError) in try s.le32(at: o) } }

    /// The slice a CPU of `arch` runs: the exact subtype, else (armv7) an armv6 or ARM_ALL one.
    static func slice(_ d: Data, arch: String) -> (image: MachO32, arch: String)? {
        let b = [UInt8](d)
        let want = FitCheck.subtype[arch] ?? -1
        var slices: [(Int32, [UInt8])] = []
        if b.count >= 8, be32(b, 0) == 0xCAFE_BABE {
            for i in 0..<Int(be32(b, 4)) {
                let o = 8 + 20 * i
                guard o + 20 <= b.count, be32(b, o) == 12 else { continue }
                let off = Int(be32(b, o + 8))
                let size = Int(be32(b, o + 12))
                guard off + size <= b.count else { continue }
                slices.append((Int32(bitPattern: be32(b, o + 4)), Array(b[off..<off + size])))
            }
        } else if b.count >= 12, le32(b, 4) == 12 {
            slices.append((Int32(bitPattern: le32(b, 8)), b))
        }
        let runnable = arch == "armv7" ? [want, 6, 0] : [want, 0]
        for s in runnable {
            if let hit = slices.first(where: { $0.0 == s }), let m = MachO32(hit.1) {
                return (m, s == 9 ? "armv7" : s == 6 ? "armv6" : "arm")
            }
        }
        return nil
    }

    /// A defined external symbol: N_EXT and a defined type (N_ABS, N_SECT, N_INDR), not N_UNDF nor N_PBUD (a prebound
    /// 1.x/2.x image's imports are N_PBUD, 0xC: counting them made every name a prebound framework imports its export).
    static func isExport(_ type: UInt8) -> Bool {
        type & 0xE0 == 0 && type & 0x01 != 0 && type & 0x0E != 0 && type & 0x0E != 0x0C
    }
    /// N_UNDF, or N_PBUD (a prebound import: 2.x and 3.0 executables).
    static func isImport(_ type: UInt8) -> Bool {
        type & 0xE0 == 0 && type & 0x01 != 0 && (type & 0x0E == 0 || type & 0x0E == 0x0C)
    }

    func name(_ off: Int) -> String {
        guard let name = try? u32(off + 8), off + Int(name) < b.count else { return "" }
        let start = off + Int(name)
        let end = b[start...].firstIndex(of: 0) ?? b.count
        return String(decoding: b[start..<end], as: UTF8.self)
    }

    /// Linked images in ordinal order.
    func dylibs() -> [(name: String, weak: Bool)] {
        commands.filter { Self.linkCommands.contains($0.cmd) }
            .map { (name($0.off), $0.cmd == Self.lcLoadWeakDylib) }
    }

    /// Images whose symbols this one exports as its own: LC_REEXPORT_DYLIB, and the old umbrella form
    /// (LC_SUB_UMBRELLA / LC_SUB_LIBRARY naming one of its linked images).
    func reexported() -> [String] {
        var out = commands.filter { $0.cmd == Self.lcReexportDylib }.map { name($0.off) }
        let subs = Set(
            commands.filter { $0.cmd == Self.lcSubUmbrella || $0.cmd == Self.lcSubLibrary }.map { name($0.off) }
        )
        if !subs.isEmpty {
            for d in dylibs() {
                let leaf = (d.name as NSString).lastPathComponent
                let stem = String(leaf.prefix { $0 != "." })
                if subs.contains(leaf) || subs.contains(stem) { out.append(d.name) }
            }
        }
        return out
    }

    func symbols() -> [(name: String, type: UInt8, desc: UInt16)] {
        // LC_SYMTAB: symoff, nsyms, stroff
        guard let st = commands.first(where: { $0.cmd == 2 }),
            let (symoff, nsyms, stroff) = try? (Int(u32(st.off + 8)), Int(u32(st.off + 12)), Int(u32(st.off + 16)))
        else { return [] }
        var out: [(String, UInt8, UInt16)] = []
        for i in 0..<nsyms {
            let e = symoff + 12 * i
            guard e + 12 <= b.count else { break }
            let s = stroff + Int(le32(b, e))
            guard s < b.count else { continue }
            let end = b[s...].firstIndex(of: 0) ?? b.count
            out.append(
                (String(decoding: b[s..<end], as: UTF8.self), b[e + 4], UInt16(b[e + 6]) | UInt16(b[e + 7]) << 8)
            )
        }
        return out
    }
}
