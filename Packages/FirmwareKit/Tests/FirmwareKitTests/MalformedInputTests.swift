import Foundation
import Testing

@testable import FirmwareKit

/// Firmware and guest structures that are cut short, claim lengths and offsets past their data, or nest and loop
/// past any real one: each reader refuses them with an error rather than trapping, reading another structure's bytes
/// or running away.
struct MalformedInputTests {
    // MARK: DeviceTree

    /// A device tree of `depth` nodes, each the only child of the one before.
    static func nestedDeviceTree(depth: Int) -> Data {
        var d = Data()
        for level in 0..<depth {
            d += KBootTests.node([("name", Data("n\0".utf8))]).prefix(4)
            d += DeviceTree.Value.le([level == depth - 1 ? 0 : 1])
            d += KBootTests.prop("name", Data("n\0".utf8))
        }
        return d
    }

    /// iBoot's trees are a few levels deep; one nested past any real one is refused, not walked off the stack.
    @Test func aDeviceTreeNestedPastAnyRealOneIsRefused() throws {
        #expect(try DeviceTree(Self.nestedDeviceTree(depth: 8)).contains("n/n/n/n/n/n/n"))
        #expect(throws: FirmwareError.self) { try DeviceTree(Self.nestedDeviceTree(depth: 200_000)) }
    }

    /// A property whose length runs past the tree, a node claiming more children than follow, and a last property
    /// whose padding is missing.
    @Test func aDeviceTreeCutShortIsRefused() {
        let blob = KBootTests.dtBlob
        var long = blob
        long.replaceSubrange(8 + 32..<8 + 36, with: DeviceTree.Value.le([UInt32(blob.count)]))  // "name"'s length
        var children = blob
        children.replaceSubrange(4..<8, with: DeviceTree.Value.le([99]))
        let unpadded = KBootTests.node([("name", Data("x\0".utf8))]).dropLast(2)
        for bad in [long, children, unpadded, blob.prefix(7), Data()] {
            #expect(throws: FirmwareError.self) { try DeviceTree(bad) }
        }
    }

    // MARK: Mach-O (kernelcaches)

    static let le = DeviceTree.Value.le

    /// A 32-bit ARM Mach-O header for `cmds`, the commands' bytes after it, then `tail`.
    static func machO(ncmds: UInt32, _ cmds: Data, tail: Data = Data()) -> Data {
        le([0xFEED_FACE, 12, 9, 2, ncmds, UInt32(cmds.count), 0]) + cmds + tail
    }

    /// The keybag one-shot's read of the kernelcache's entry, the sandbox patch's and kboot's, over a kernel whose
    /// one command is missing and one whose LC_SEGMENT is only its 8-byte cmd/cmdsize: the first two read the
    /// segment's fields past the end of the file.
    @Test func aKernelcacheCutShortIsRefused() {
        for kernel in [Self.machO(ncmds: 1, Data()), Self.machO(ncmds: 1, Self.le([1, 8]))] {
            #expect(throws: FirmwareError.self) { try N72Keybag.kernelEntry(kernel) }
            #expect(throws: SandboxPatch.Error.self) { try SandboxPatch.locate([UInt8](kernel)) }
            #expect(throws: FirmwareError.self) { try MachO(kernel) }
        }
    }

    /// A segment whose fileoff and filesize add up past 4 GiB: the boot_args version check added them as UInt32s.
    @Test func aSegmentPast4GiBIsNotAnOverflow() throws {
        let seg =
            Self.le([1, 56]) + DeviceTree.name32("__TEXT").prefix(16)
            + Self.le([0x8000_0000, 0x1000, 0x10, 0xFFFF_FFF8, 7, 7, 0, 0])
        let kernel = Self.machO(ncmds: 1, seg, tail: Data("pe_identify_machine: Epoch Mismatch\0".utf8))
        #expect(try MachO(kernel).bootArgsVersion() == 2)
    }

    /// A kernelcache whose segment claims 3.75 GiB: kboot laid out (and zero-filled) an image that size.
    @Test func aKernelcacheLargerThanMemoryIsRefused() {
        var kernel = KBootTests.kernel(at: 0x8000_0000)
        kernel.replaceSubrange(28 + 56 + 28..<28 + 56 + 32, with: Self.le([0xF000_0000]))  // __DATA's vmsize
        #expect(throws: FirmwareError.self) {
            try KBoot.build(kernel: kernel, deviceTree: KBootTests.dtBlob, identity: KBootTests.placeholder)
        }
    }

    /// boot_args read out of guest memory by the keybag one-shot: a topOfKernelData at the top of the address space
    /// and a device tree pointer below the kernel's base are refused, not wrapped.
    @Test func bootArgsThatWouldWrapAreRefused() throws {
        func args(top: UInt32, dtp: UInt32) -> Data {
            var a = Data(count: 0x138)
            a.replaceSubrange(0..<2, with: [1, 0])
            a.replaceSubrange(4..<20, with: Self.le([0x8000_0000, N72Keybag.physBase, 0x0800_0000, top]))
            a.replaceSubrange(0x30..<0x38, with: Self.le([dtp, 0x1000]))
            return a
        }
        let ok = try N72Keybag.ramdiskPlace(
            bootArgs: args(top: 0x0900_0000, dtp: 0x8100_0000), at: 0, base: 0x8000_0000, ramdisk: 0x1000)
        #expect(ok.rdPA == 0x0900_0000 && ok.newTop == 0x0900_4000 && ok.dtPA == 0x0900_0000)
        for bad in [args(top: 0xFFFF_F800, dtp: 0x8100_0000), args(top: 0x0900_0000, dtp: 0x10)] {
            #expect(throws: FirmwareError.self) {
                try N72Keybag.ramdiskPlace(bootArgs: bad, at: 0, base: 0x8000_0000, ramdisk: 0x1000)
            }
        }
        #expect(throws: FirmwareError.self) {
            try N72Keybag.ramdiskPlace(bootArgs: Data(count: 0x20), at: 0, base: 0x8000_0000, ramdisk: 0x1000)
        }
    }

    // MARK: IMG3

    static func word(_ v: Int) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    /// An img3 of `tags` (magic as stored, total, data length, data), its fullSize `full` (default: what they take).
    static func img3(_ tags: [(String, Int, Int, [UInt8])], full: Int? = nil) -> [UInt8] {
        let body = tags.flatMap { Array($0.0.utf8) + word($0.1) + word($0.2) + $0.3 }
        return Array("3gmI".utf8) + word(full ?? 0x14 + body.count) + word(body.count) + word(0) + word(0) + body
    }

    /// A DATA tag whose data length runs past its own total into the next tag: the payload was the DATA bytes and
    /// the KBAG's header after them.
    @Test func anImg3TagWhoseDataRunsIntoTheNextIsRefused() {
        let bad = Self.img3([
            ("ATAD", 28, 32, [UInt8](repeating: 0xDA, count: 16)), ("GABK", 20, 8, [1, 0, 0, 0, 0, 1, 0, 0])
        ])
        #expect(throws: FirmwareError.self) { try IMG3.payload(Data(bad)) }
        #expect(throws: FirmwareError.self) { try IMG3.tags(Data(bad)) }
    }

    /// An img3 cut short (its fullSize past the file) or whose tag claims more than is left.
    @Test func anImg3CutShortIsRefused() {
        let data = [UInt8](repeating: 0xDA, count: 16)
        let cut = Self.img3([("ATAD", 28, 16, data)], full: 0x1000)
        let long = Self.img3([("ATAD", 28, 16, data), ("GABK", 0x1000, 8, [1, 0, 0, 0, 0, 1, 0, 0])])
        for bad in [cut, long] {
            #expect(throws: FirmwareError.self) { try IMG3.tags(Data(bad)) }
            #expect(throws: FirmwareError.self) { try SandboxPatch.rebuildIMG3(Data(bad), data: [1, 2, 3]) }
        }
    }

    /// The K48 iBoot path's DeviceTree img3 with its production KBAG cut short: the KBAG's IV and key were read past
    /// the end of the file.
    @Test func aDeviceTreeImg3WithItsKBAGCutShortIsRefused() {
        let bag = [1, 0, 0, 0, 0, 1, 0, 0] + [UInt8](repeating: 7, count: 8)
        let image = Self.img3([("GABK", 68, 56, bag)], full: 0x14 + 28)
        #expect(throws: FirmwareError.self) {
            try K48IBoot.hostUSBDeviceTree(
                img3: Data(image),
                plaintext: KBootTests.dtBlob,
                gidBlobs: Data(repeating: 7, count: 96)
            )
        }
    }
}
