import Foundation
import LightTouchCore
import SessionKit

/// The drivers built beside this executable.
let binDirectory = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()

/// Every pid the drivers report starting (helpers, usbmuxds), killed if still alive when a run ends; never a lookup by name.
func killLeftovers(_ events: Events, pidFile: URL? = nil) {
    var pids = Set(
        events.all.filter { ["hello", "booted", "usbmuxd", "connected", "hold"].contains($0.string("event") ?? "") }
            .compactMap { $0.int("pid") ?? $0.int("helperPid") }
    )
    if let pidFile, let text = try? String(contentsOf: pidFile, encoding: .utf8) {
        pids.formUnion(text.split(whereSeparator: \.isNewline).compactMap { Int($0) })
    }
    for pid in pids where pid > 0 && kill(pid_t(pid), 0) == 0 {
        kill(pid_t(pid), SIGKILL)
        print("  (killed leftover \(pid))")
    }
}

/// A started driver process writing JSON lines to `out`.
final class DriverProcess {
    let process = Process()
    let out: URL

    init(_ tool: String, _ arguments: [String], out: URL, environment: [String: String] = [:]) {
        self.out = out
        FileManager.default.createFile(atPath: out.path, contents: nil)
        process.executableURL = binDirectory.appendingPathComponent(tool)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
        let h = FileHandle(forWritingAtPath: out.path)
        process.standardOutput = h
        process.standardError = h
        process.standardInput = FileHandle.nullDevice
        do { try process.run() } catch { die("could not start \(tool): \(error)") }
    }

    var pid: pid_t { process.processIdentifier }
    var events: Events { Events(jsonLines: (try? String(contentsOf: out, encoding: .utf8)) ?? "") }

    /// Its exit status, or nil once `seconds` pass (then it is killed).
    @discardableResult
    func wait(_ seconds: Double) -> Int32? {
        let deadline = Date().addingTimeInterval(seconds)
        while process.isRunning, Date() < deadline { usleep(100_000) }
        if process.isRunning {
            kill(pid, SIGKILL)
            process.waitUntilExit()
            return nil
        }
        return process.terminationStatus
    }

    /// The first event named `name`, waiting up to `seconds` while the driver runs.
    func waitFor(_ name: String, _ seconds: Double) -> Event? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let e = events.find(name).first { return e }
            if !process.isRunning { break }
            usleep(200_000)
        }
        return events.find(name).first
    }
}

/// session-driver with `config` (written to work/config.json): its events and exit status. Leftover processes it
/// started are killed.
func sessionDriver(_ config: [String: Any], work: URL, timeout: Double, environment: [String: String] = [:]) -> (
    Events, Int32?
) {
    let file = work.appendingPathComponent("config.json")
    do {
        try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]).write(to: file)
    } catch { die("config: \(error)") }
    let d = DriverProcess(
        "session-driver",
        [file.path],
        out: work.appendingPathComponent("driver.jsonl"),
        environment: environment
    )
    let status = d.wait(timeout + 10)
    let events = d.events
    killLeftovers(events, pidFile: work.appendingPathComponent("pids"))
    for fail in events.find("fail") { print("  driver: \(fail.string("why") ?? "")") }
    return (events, status)
}

func alive(_ pid: Int) -> Bool { pid > 0 && kill(pid_t(pid), 0) == 0 }

/// Seconds until `pid` is gone, or nil if it outlives `seconds`.
func waitGone(_ pid: Int, _ seconds: Double) -> Double? {
    let t0 = Date()
    while Date().timeIntervalSince(t0) < seconds {
        if !alive(pid) { return Date().timeIntervalSince(t0) }
        usleep(100_000)
    }
    return nil
}

/// The temporary work directory `finish` deletes when the run passes: none with --work or --keep.
nonisolated(unsafe) var disposableWork: URL?

/// A fresh work directory: `--work`, or a temporary one.
func workDirectory(_ args: Inputs, _ name: String) -> URL {
    let work =
        args.work
        ?? FileManager.default.temporaryDirectory
        .appendingPathComponent("ltm-\(name)-\(UUID().uuidString.prefix(8))")
    if args.work == nil, !args.keep { disposableWork = work }
    try? FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
    print("work: \(work.path)")
    return work
}

/// The user's real app.log, which no run may write (the drivers' app code logs under LTM_STATE_DIR, the run's own).
let realAppLog = URL(fileURLWithPath: getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? "/Users")
    .appendingPathComponent("Library/Logs/gold.samhenri.LightTouchMac/app.log")

func finish(_ report: Report, work: URL) -> Never {
    let real = (try? String(contentsOf: realAppLog, encoding: .utf8)) ?? ""
    report.check(!real.contains(work.path), "the run left the real \(realAppLog.path) alone")
    // A base the drivers published under work is locked (uchg) and its NAND read only: removeTree unlocks first.
    let removed = report.allPassed && work == disposableWork && (try? DeviceStateStorage.removeTree(work)) != nil
    print("\n\(report.allPassed ? "PASS" : "FAIL"): \(report.summary)" + (removed ? "" : "; logs in \(work.path)"))
    exit(report.allPassed ? 0 : 1)
}

/// The base fields every session-driver config carries.
func driverConfig(_ tools: Tools, work: URL, ipa: URL? = nil) -> [String: Any] {
    var config: [String: Any] = [
        "helper": tools.helper.path, "firmwarekit": tools.firmwarekit.path, "usbmuxd": tools.usbmuxd.path,
        "ipa": ipa?.path ?? "", "bundleID": ipa.flatMap(ipaBundleID) ?? "com.qemuios.harness", "work": work.path,
        "files": tools.files.path, "ipodBase": "", "ipadBase": "",
    ]
    if let requirement = tools.requirement, !requirement.isEmpty { config["requirement"] = requirement }
    return config
}

/// The IPA's CFBundleIdentifier, from its root app's Info.plist (the app's own archive readers).
func ipaBundleID(_ ipa: URL) -> String? {
    guard let root = IPAMembers.appRoot(ZipMembers.paths(ipa)),
        let data = ZipMembers.data(ipa, root + "Info.plist"),
        let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
    else { return nil }
    return info["CFBundleIdentifier"] as? String
}

/// What the drivers' children read: the dylib the helper loads and the services worker DeviceServices spawns.
func driverEnvironment(_ tools: Tools) -> [String: String] {
    [
        "LTM_QEMU_DYLIB": tools.dylib.path, "LTM_HOST_SERVICE_WORKER": tools.services.path,
        "LTM_STATE_DIR": FileManager.default.temporaryDirectory.appendingPathComponent("ltm-sessions-state").path,
    ]
}

func format(_ value: Double?, _ digits: Int = 1) -> String { String(format: "%.\(digits)f", value ?? -1) }
