// Whether LightTouchDevice runs under the App Sandbox, and what that changes for whoever spawns it. One switch, the
// LTM_HELPER_SANDBOX build setting (Configuration/Shared.xcconfig), signs the helper with
// LightTouchDevice-Sandbox*.entitlements and the app with the app group; at run time the spawner reads the helper's
// own signature, so a process never treats a sandboxed helper as an unsandboxed one or the other way round.
//
// Sandboxed, the helper may look up only Mach services named under its app group (DeviceRendezvous) and reach Unix
// sockets only inside a container: the per-user temporary directory the sockets use otherwise is outside it. So its
// sockets (usbmuxd's guest socket, the web proxy's, the gdbstub's) go in the group's container, in a folder per
// spawning process that the next launch removes once that process is gone (sweepStaleSockets). Unsandboxed, nothing
// changes: the bundle's rendezvous name and the temporary directory.

import Foundation
import Security

public nonisolated enum HelperSandbox {
    /// Short on purpose: the group container's path is in every socket path, which must stay under sun_path's 104
    /// bytes ("/Users/<user>/Library/Group Containers/SM75355Y6R.ltm/" is 48 bytes plus the user name).
    public static let appGroup = "SM75355Y6R.ltm"

    /// The longest socket name, after "<pid>/" (DebugPort's "keybag-XXXXXXXX.sock").
    static let longestName = 20

    nonisolated(unsafe) private static var current: Bool?
    private static let lock = NSLock()

    /// Whether `helper`'s signature asks for the App Sandbox.
    public static func isSandboxed(_ helper: URL) -> Bool {
        var code: SecStaticCode?
        var info: CFDictionary?
        guard SecStaticCodeCreateWithPath(helper as CFURL, [], &code) == errSecSuccess, let code,
            SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSRequirementInformation), &info)
                == errSecSuccess,
            let entitlements = (info as? [String: Any])?[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        else { return false }
        return entitlements["com.apple.security.app-sandbox"] as? Bool == true
    }

    /// Whether this process's helpers run sandboxed: the LightTouchDevice beside this executable (the app's, a
    /// bundled or built firmwarekit's) unless `use(helper:)` named another first.
    public static var enabled: Bool {
        lock.withLock {
            if let current { return current }
            let sibling = Bundle.main.executableURL?.resolvingSymlinksInPath().deletingLastPathComponent()
                .appendingPathComponent("LightTouchDevice")
            let value = sibling.map(isSandboxed) ?? false
            current = value
            return value
        }
    }

    /// The helper this process spawns (the harness's drivers, which aren't beside one), before any socket path.
    public static func use(helper: URL) {
        let value = isSandboxed(helper)
        lock.withLock { current = value }
    }

    /// The app group's container, whether or not it exists yet.
    public static var groupContainer: URL {
        URL(fileURLWithPath: realHome, isDirectory: true).appendingPathComponent(
            "Library/Group Containers/\(appGroup)",
            isDirectory: true
        )
    }

    /// A Unix socket path for `name`: in the temporary directory as "ltm-<name>", or sandboxed in this process's
    /// folder of the group's container.
    public static func socketPath(_ name: String) -> String {
        enabled ? processSocketDirectory + name : NSTemporaryDirectory() + "ltm-" + name
    }

    /// <group container>/<pid>/, owner-only, made once; the container itself made through the system, so it gets
    /// the group's owner. There is no fallback a sandboxed helper could reach, so a failure is said on stderr (the
    /// app's console, firmwarekit's diagnostics) and the boot fails at the socket.
    private static let processSocketDirectory: String = {
        let fm = FileManager.default
        let container = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroup) ?? groupContainer
        let directory = container.appendingPathComponent("\(getpid())", isDirectory: true)
        do {
            try fm.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            FileHandle.standardError.write(
                Data("sandboxed helper: no socket folder \(directory.path): \(error)\n".utf8)
            )
        }
        if !socketsFit(home: realHome) {
            FileHandle.standardError.write(
                Data("sandboxed helper: socket paths under \(directory.path) are too long for a Unix socket\n".utf8)
            )
        }
        return directory.path + "/"
    }()

    /// Whether every socket name fits sun_path in a group container under `home` (one byte left for the NUL).
    static func socketsFit(home: String) -> Bool {
        (home + "/Library/Group Containers/\(appGroup)/99999/").utf8.count + longestName < 104
    }

    /// App launch: the socket folders of processes that are gone (a crash, a kill -9, a force quit), and what they
    /// left in them. A live process's folder is never touched. What it removed, by name.
    @discardableResult public static func sweepStaleSockets(in container: URL = groupContainer) -> [String] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: container.path) else { return [] }
        var removed: [String] = []
        for name in names {
            guard let pid = pid_t(name), pid > 0, pid != getpid(), kill(pid, 0) == -1, errno == ESRCH else { continue }
            if (try? fm.removeItem(at: container.appendingPathComponent(name))) != nil { removed.append(name) }
        }
        return removed
    }

    /// The account's home, not a sandboxed process's container.
    static var realHome: String {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return NSHomeDirectory() }
        return String(cString: dir)
    }
}
