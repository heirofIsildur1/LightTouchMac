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

    /// The process at the other end of a connected Unix socket. Every sandboxed helper can write the whole group
    /// container (one app group), so a socket there can be connected to, or unlinked and bound again, by another
    /// device's helper: an end that knows which process belongs at the other checks it.
    public static func peerPID(_ fd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        return getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0 ? pid : nil
    }

    /// Whether the TCP connection `fd` accepted on 127.0.0.1 was made by this same process: its other end is one of
    /// this process's own sockets (another process can connect to any loopback port, but can't be this one).
    public static func isOwnConnection(_ fd: Int32) -> Bool {
        var local = sockaddr_in()
        var remote = sockaddr_in()
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) == 0 }
        }
        size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let peered = withUnsafeMutablePointer(to: &remote) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &size) == 0 }
        }
        guard named, peered, local.sin_family == sa_family_t(AF_INET) else { return false }
        // the peer's socket here has local port = remote.sin_port and foreign port = local.sin_port
        let want = (local: Int32(UInt16(bigEndian: remote.sin_port)), foreign: Int32(UInt16(bigEndian: local.sin_port)))
        let pid = getpid()
        let count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0) / Int32(MemoryLayout<proc_fdinfo>.size)
        guard count > 0 else { return false }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(count) + 16)
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.size))
        for entry in fds.prefix(Int(bytes) / MemoryLayout<proc_fdinfo>.size)
        where entry.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) && entry.proc_fd != fd {
            var info = socket_fdinfo()
            let size = Int32(MemoryLayout<socket_fdinfo>.size)
            guard proc_pidfdinfo(pid, entry.proc_fd, PROC_PIDFDSOCKETINFO, &info, size) == size,
                info.psi.soi_kind == Int32(SOCKINFO_TCP)
            else { continue }
            let tcp = info.psi.soi_proto.pri_tcp.tcpsi_ini
            if Int32(UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.insi_lport))) == want.local
                && Int32(UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.insi_fport))) == want.foreign
            {
                return true
            }
        }
        return false
    }

    /// The account's home, not a sandboxed process's container.
    static var realHome: String {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return NSHomeDirectory() }
        return String(cString: dir)
    }
}
