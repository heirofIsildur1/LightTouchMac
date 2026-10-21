import FirmwareSchema
import Foundation
import ReleaseChecks
import SessionKit

/// The repository this was built from.
let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../..")
    .standardized
let home = FileManager.default.homeDirectoryForCurrentUser

/// Ends a run that couldn't be judged with its verdict line: exit 2 for a refused or stale input (the default), 3 for
/// the infrastructure (a build, a tool that won't start).
func die(_ message: String, code: Int32 = 2) -> Never {
    print("FAIL sessions: \(message) -")
    exit(code)
}

/// The emulator slot this run boots in (EmulatorSlot), held until it exits; a run this one starts shares it.
nonisolated(unsafe) private var emulatorSlot: Int32 = -1
func takeEmulatorSlot() {
    guard emulatorSlot < 0, ProcessInfo.processInfo.environment["LTM_EMULATOR_SLOT_HELD"] == nil else { return }
    emulatorSlot =
        EmulatorSlot.wait {
            print("waiting for an emulator slot (\(EmulatorSlot.count) in use, \(EmulatorSlot.directory.path))")
            fflush(stdout)
        }.fd
    setenv("LTM_EMULATOR_SLOT_HELD", "1", 1)
}

/// The pinned checkout `name` (build-support/sources.json "path"; QEMU_IOS_DIR / USBMUXD_SOURCE_DIR override it).
func checkout(_ name: String) -> URL {
    let env = ["qemu-ios": "QEMU_IOS_DIR", "usbmuxd": "USBMUXD_SOURCE_DIR"][name] ?? ""
    if let override = ProcessInfo.processInfo.environment[env] { return URL(fileURLWithPath: override) }
    let pins =
        (try? JSONSerialization.jsonObject(
            with: Data(contentsOf: repository.appendingPathComponent("build-support/sources.json"))
        )) as? [String: Any]
    let path = (pins?[name] as? [String: Any])?["path"] as? String ?? ""
    return URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
}

/// scripts/vendor's directory for the current pins (`scripts/vendor-check --print`), nil if there is none.
func vendorDirectory() -> URL? {
    let path = output("/bin/bash", [repository.appendingPathComponent("scripts/vendor-check").path, "--print"])
        .trimmingCharacters(in: .whitespacesAndNewlines)
    return path.isEmpty ? nil : URL(fileURLWithPath: path)
}

/// A copy of `helper` re-signed ad hoc with its own entitlements and `options` (the impostor the rendezvous refuses, the
/// socket-observed helper): in a folder laid out as the bundle's, Contents/MacOS beside a link to its Frameworks, so a
/// release helper finds its emulator, and under its own signing identifier, so a sandboxed copy has its own container.
func helperCopy(_ helper: URL, named name: String, in work: URL, options: [String]) -> URL {
    let fm = FileManager.default
    let contents = work.appendingPathComponent("helper-\(name)/Contents")
    let copy = contents.appendingPathComponent("MacOS/LightTouchDevice")
    try? fm.removeItem(at: contents.deletingLastPathComponent())
    try? fm.createDirectory(at: copy.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? fm.copyItem(at: helper, to: copy)
    let frameworks = helper.deletingLastPathComponent().appendingPathComponent("../Frameworks").standardizedFileURL
    if fm.fileExists(atPath: frameworks.path) {
        try? fm.createSymbolicLink(at: contents.appendingPathComponent("Frameworks"), withDestinationURL: frameworks)
    }
    let entitlements = work.appendingPathComponent("helper-\(name).entitlements")
    try? output("/usr/bin/codesign", ["-d", "--entitlements", "-", "--xml", helper.path]).write(
        to: entitlements,
        atomically: true,
        encoding: .utf8
    )
    let identifier = "gold.samhenri.LightTouchMac.LightTouchDevice-\(name)"
    guard
        run(
            "/usr/bin/codesign",
            ["-f", "-s", "-", "-i", identifier] + options + ["--entitlements", entitlements.path, copy.path]
        ) == 0
    else { die("could not sign the helper copy \(copy.path)") }
    return copy
}

/// The executables and resources a run boots with: a built app's (`--app`), or a Debug build of the helper, the
/// services worker and firmwarekit with scripts/vendor's dylib, usbmuxd, SecureROMs and guest package.
struct Tools {
    var helper: URL, services: URL, firmwarekit: URL
    var dylib: URL, usbmuxd: URL, files: URL
    /// The unpacked guest archive: guest-tools/armv6.itpack, armv7.itpack, it_agent, …
    var guest: URL
    /// The signing requirement the driver pins the helper to (nil: the helper's own designated requirement).
    var requirement: String?

    static let teamRequirement = #"anchor apple generic and certificate leaf[subject.OU] = "SM75355Y6R""#

    static func resolve(_ args: Inputs, work: URL) -> Tools {
        takeEmulatorSlot()
        let fm = FileManager.default
        let tools: Tools
        if let app = args.app {
            let contents = app.appendingPathComponent("Contents")
            tools = Tools(
                helper: contents.appendingPathComponent("MacOS/LightTouchDevice"),
                services: contents.appendingPathComponent("MacOS/LightTouchServices"),
                firmwarekit: contents.appendingPathComponent("MacOS/firmwarekit"),
                dylib: contents.appendingPathComponent("Frameworks/libqemu-arm.dylib"),
                usbmuxd: contents.appendingPathComponent("MacOS/usbmuxd"),
                files: contents.appendingPathComponent("Resources/Device"),
                guest: unpack(contents.appendingPathComponent("Resources/Guest/guest.aar"), into: work),
                requirement: args.requirement
            )
        } else {
            guard let vendor = vendorDirectory() else {
                die("no vendor directory for the current pins: run scripts/vendor (about 15 minutes), or pass --app")
            }
            let built = build(work: work)
            tools = Tools(
                helper: built.appendingPathComponent("LightTouchDevice"),
                services: built.appendingPathComponent("LightTouchServices"),
                firmwarekit: built.appendingPathComponent("firmwarekit"),
                dylib: vendor.appendingPathComponent("Frameworks/libqemu-arm.dylib"),
                usbmuxd: vendor.appendingPathComponent("MacOS/usbmuxd"),
                files: vendor.appendingPathComponent("Resources/Device"),
                guest: unpack(vendor.appendingPathComponent("Resources/Guest/guest.aar"), into: work),
                requirement: args.requirement ?? teamRequirement
            )
        }
        var t = tools
        if let dylib = args.dylib { t.dylib = dylib }
        if let usbmuxd = args.usbmuxd { t.usbmuxd = usbmuxd }
        for (what, url) in [
            ("helper", t.helper), ("services worker", t.services), ("firmwarekit", t.firmwarekit),
            ("usbmuxd", t.usbmuxd)
        ] where !fm.isExecutableFile(atPath: url.path) {
            die("no \(what) at \(url.path)")
        }
        if !fm.fileExists(atPath: t.dylib.path) { die("no emulator dylib at \(t.dylib.path)") }
        return t
    }

    /// LightTouchDevice, LightTouchServices and firmwarekit, Debug, signed by the project's team (the helper sandboxed
    /// with LTM_HELPER_SANDBOX=YES); the build is cached under .build/sessions-xcode.
    static func build(work: URL) -> URL {
        let symroot = repository.appendingPathComponent(".build/sessions-xcode")
        let log = work.appendingPathComponent("xcodebuild.log")
        print("building the helper, services worker and firmwarekit (log \(log.path))")
        let status = run(
            "/usr/bin/xcodebuild",
            [
                "-project", repository.appendingPathComponent("LightTouchMac.xcodeproj").path,
                "-target", "LightTouchDevice", "-target", "LightTouchServices", "-target", "firmwarekit",
                "-configuration", "Debug", "SYMROOT=\(symroot.path)", "OBJROOT=\(symroot.path)/obj",
                // the helper under the App Sandbox when the environment asks (Configuration/Shared.xcconfig)
                "LTM_HELPER_SANDBOX=\(ProcessInfo.processInfo.environment["LTM_HELPER_SANDBOX"] ?? "NO")",
                "COMPILER_INDEX_STORE_ENABLE=NO", "build"
            ],
            log: log
        )
        if status != 0 { die("xcodebuild failed; see \(log.path)", code: 3) }
        return symroot.appendingPathComponent("Debug")
    }

    /// Resources/Guest/guest.aar unpacked into the run's directory.
    static func unpack(_ archive: URL, into work: URL) -> URL {
        let dir = work.appendingPathComponent("guest")
        if FileManager.default.fileExists(atPath: dir.appendingPathComponent("guest-tools").path) { return dir }
        guard FileManager.default.fileExists(atPath: archive.path),
            run(
                "/usr/bin/aa",
                ["extract", "-i", archive.path, "-d", dir.path],
                log: work.appendingPathComponent("aa.log")
            ) == 0
        else { die("could not unpack \(archive.path)", code: 3) }
        return dir
    }
}

/// Run a tool to completion, output to `log` (appended) or discarded.
@discardableResult
func run(_ tool: String, _ arguments: [String], log: URL? = nil, environment: [String: String]? = nil) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = arguments
    if let environment { p.environment = environment }
    if let log {
        if !FileManager.default.fileExists(atPath: log.path) {
            FileManager.default.createFile(atPath: log.path, contents: nil)
        }
        let h = try? FileHandle(forWritingTo: log)
        h?.seekToEndOfFile()
        p.standardOutput = h
        p.standardError = h
    } else {
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
    }
    p.standardInput = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return -1 }
    p.waitUntilExit()
    return p.terminationStatus
}

/// A tool's standard output (empty if it could not run).
func output(_ tool: String, _ arguments: [String]) -> String {
    (try? Shell.run([tool] + arguments))?.output ?? ""
}

/// A prepared base: its lock and what the driver calls its board.
struct Base {
    let url: URL
    let lock: [String: Any]
    var board: String { lock["board"] as? String ?? "" }
    var build: String { lock["build"] as? String ?? "" }
    var version: String { lock["product_version"] as? String ?? "" }
    var major: Int { Int(version.split(separator: ".").first ?? "") ?? 0 }
    var entryID: String { ((lock["entry"] as? [String: Any])?["id"] as? String) ?? "\(board)-\(build)" }
    /// session-driver's device name for the board.
    var driverBoard: String {
        [
            "n72ap": "ipod", "k48ap": "ipad", "n45ap": "ipod1g", "m68ap": "iphone2g", "n81ap": "ipod4g",
            "n90ap": "iphone4",
            "n18ap": "ipod3g", "n88ap": "iphone3gs"
        ][board] ?? board
    }
    var productType: String {
        [
            "n72ap": "iPod2,1", "k48ap": "iPad1,1", "n45ap": "iPod1,1", "m68ap": "iPhone1,1", "n81ap": "iPod4,1",
            "n90ap": "iPhone3,1", "n18ap": "iPod3,1", "n88ap": "iPhone2,1"
        ][board] ?? ""
    }
    /// The kboot boards boot as the iPad does (an armv7 offer); the rest take the armv6 package.
    var armv7: Bool { ["k48ap", "n81ap", "n90ap", "n18ap", "n88ap"].contains(board) }
    var firstGeneration: Bool { ["n45ap", "m68ap"].contains(board) }
    /// The layout has a data partition (fstab mounts it on /private/var).
    var dataVolume: Bool {
        (((lock["entry"] as? [String: Any])?["content"] as? [String: Any])?["recipe"] as? [String: Any])?["data_size"]
            as? String == "partition"
    }

    /// Prints how the base was prepared, and refuses one this tree would prepare differently unless --allow-stale:
    /// a check on an older base chases what the tree has already fixed.
    init(_ path: String, _ inputs: Inputs) { self.init(path, allowStale: inputs.allowStale) }

    init(_ path: String, allowStale: Bool) {
        url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardized
        guard let data = try? Data(contentsOf: url.appendingPathComponent("device.lock.json")),
            let lock = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            die("\(url.path) is not a prepared base (no device.lock.json)")
        }
        self.lock = lock
        let verdict = PreparationChanges.verdict(lock: lock, catalog: catalogEntries)
        print("base \(url.path) (\(verdict.stale.isEmpty ? "fresh" : "stale")): \(verdict.fingerprint)")
        // Where it was prepared otherwise than its catalog row: a deliberate variant or drift, not stale either way.
        for variant in (try? LockedPreparation.plan(lock: lock, catalog: catalogEntries))?.variants ?? [] {
            print("  as prepared, not the catalog row's: \(variant)")
        }
        fflush(stdout)
        guard !verdict.stale.isEmpty else { return }
        let reasons = verdict.stale.map { "  - \($0)" }.joined(separator: "\n")
        guard allowStale else {
            die(
                """
                \(url.path) is stale: this tree prepares \(entryID) differently.
                \(reasons)
                Prepare it again from this tree as it was prepared (checked with sessions single, then swapped in):
                  sessions reprepare \(url.path)
                or pass --allow-stale to boot it anyway.
                """
            )
        }
        print(reasons)
    }
}

/// The catalog's entries in this tree.
let catalogEntries: [FirmwareWire.Entry] = {
    struct Catalog: Decodable { let entries: [FirmwareWire.Entry] }
    let url = repository.appendingPathComponent("LightTouchMac/Resources/firmware-catalog.json")
    do { return try JSONDecoder().decode(Catalog.self, from: Data(contentsOf: url)).entries } catch {
        die("can't read the catalog at \(url.path): \(error)")
    }
}()
