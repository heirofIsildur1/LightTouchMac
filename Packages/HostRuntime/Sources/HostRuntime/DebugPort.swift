// The per-device debug port: QEMU's gdbstub on a Unix socket only this user can reach, and the lldb command that
// attaches to it (qemu-ios docs/guest-debug.md: kernel and userland debugging through imgtools/lldb/xnu.py).

import Foundation

public nonisolated enum DebugPort {
    /// QEMU's argv for a gdbstub on the Unix socket `path`. The stub has no authentication, so it is never on TCP:
    /// the socket is in the per-user temporary directory (0700, as usbmuxd's and the web proxy's are), and a socket
    /// takes a connection only from who may write it (its owner).
    public static func arguments(socket path: String) -> [String] {
        ["-gdb", "unix:\(path.replacingOccurrences(of: ",", with: ",,")),server=on,wait=off"]
    }

    /// A fresh socket path for one gdbstub (a Unix socket path stays under 104 bytes).
    public static func socketPath(_ prefix: String = "ltm-gdb") -> String {
        NSTemporaryDirectory() + prefix + "-" + UUID().uuidString.prefix(8) + ".sock"
    }

    /// lldb attached to the stub at `socket`.
    public static func lldbConnect(socket: String) -> String { "process connect unix-connect://\(socket)" }

    /// What to paste into Terminal. KERNELCACHE stays a placeholder: the decrypted kernel lives in the firmware,
    /// not in the device (qemu-ios docs/guest-debug.md lists where each board's comes from).
    public static func lldbCommand(board: String, socket: String) -> String {
        "lldb -o 'target create --arch \(Board(rawValue: board)?.arch ?? "armv7")-apple-ios KERNELCACHE'"
            + " -o '\(lldbConnect(socket: socket))'"
            + " -o 'command script import QEMU_IOS/imgtools/lldb/xnu.py'"
    }
}
