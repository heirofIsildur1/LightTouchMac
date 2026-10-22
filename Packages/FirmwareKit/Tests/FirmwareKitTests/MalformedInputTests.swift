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
}
