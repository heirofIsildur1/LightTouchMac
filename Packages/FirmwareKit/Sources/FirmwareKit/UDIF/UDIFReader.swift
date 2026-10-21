// UDIFReader: the raw disk of a UDIF disk image (.dmg) without hdiutil. The image ends in a 512-byte "koly" trailer
// naming its XML property list, whose resource-fork "blkx" entries are "mish" block tables: runs of the disk's
// 512-byte sectors, each stored raw, zero-filled, or compressed (zlib or ADC; the IPSW root filesystems are zlib
// and raw). Writes the same bytes as `hdiutil convert -format UDTO`; zero runs are left sparse.
//
//   try UDIFReader.convertToRaw(dmg, to: raw)

import Foundation
import zlib

enum UDIFReader {
    static func convertToRaw(_ src: URL, to out: URL) throws {
        let input = open(src.path, O_RDONLY)
        guard input >= 0 else { throw FirmwareError(.internal, "open \(src.path)") }
        defer { close(input) }
        var st = stat()
        guard fstat(input, &st) == 0, st.st_size >= 512 else {
            throw FirmwareError(.unsupported, "\(src.lastPathComponent): too short")
        }
        func read(_ at: UInt64, _ n: Int) throws -> [UInt8] {
            var b = [UInt8](repeating: 0, count: n)
            guard pread(input, &b, n, off_t(at)) == n else {
                throw FirmwareError(.unsupported, "\(src.lastPathComponent): read past its end at \(at)")
            }
            return b
        }
        let koly = try read(UInt64(st.st_size) - 512, 512)
        guard koly.starts(with: Array("koly".utf8)) else {
            throw FirmwareError(.unsupported, "\(src.lastPathComponent): no UDIF trailer")
        }
        let dataFork = be64(koly, 0x18)
        let sectors = be64(koly, 0x1EC)
        let xml = Data(try read(be64(koly, 0xD8), Int(be64(koly, 0xE0))))
        guard let plist = try PropertyListSerialization.propertyList(from: xml, format: nil) as? [String: Any],
            let blkx = (plist["resource-fork"] as? [String: Any])?["blkx"] as? [[String: Any]]
        else { throw FirmwareError(.unsupported, "\(src.lastPathComponent): no blkx table") }

        guard FileManager.default.createFile(atPath: out.path, contents: nil) else {
            throw FirmwareError(.internal, "cannot create \(out.path)")
        }
        let output = open(out.path, O_WRONLY)
        guard output >= 0 else { throw FirmwareError(.internal, "open \(out.path)") }
        defer { close(output) }
        for entry in blkx {
            guard let m = (entry["Data"] as? Data).map({ [UInt8]($0) }), m.count >= 204,
                m.starts(with: Array("mish".utf8))
            else { throw FirmwareError(.unsupported, "\(src.lastPathComponent): a blkx entry is not a block table") }
            let first = be64(m, 8)
            let base = dataFork + be64(m, 24)
            let count = Int(be32(m, 200))
            guard m.count >= 204 + 40 * count else { throw FirmwareError(.unsupported, "short block table") }
            for i in 0..<count {
                let c = 204 + 40 * i
                let type = be32(m, c)
                let at = (first + be64(m, c + 8)) * 512
                let size = Int(be64(m, c + 16)) * 512
                let stored = { try read(base + be64(m, c + 24), Int(be64(m, c + 32))) }
                let bytes: [UInt8]
                switch type {
                case 0, 2, 0x7FFF_FFFE, 0xFFFF_FFFF: continue  // zero-filled, ignored, comment, end
                case 1: bytes = try stored()
                case 0x8000_0005: bytes = try inflate(try stored(), size, src)
                case 0x8000_0004: bytes = try adc(try stored(), size, src)
                default:
                    throw FirmwareError(.unsupported, "\(src.lastPathComponent): chunk type \(String(type, radix: 16))")
                }
                guard bytes.count == size, pwrite(output, bytes, size, off_t(at)) == size else {
                    throw FirmwareError(.internal, "\(src.lastPathComponent): chunk \(i) at sector \(at / 512)")
                }
            }
        }
        guard ftruncate(output, off_t(sectors * 512)) == 0 else {
            throw FirmwareError(.internal, "truncate \(out.path)")
        }
    }

    static func inflate(_ z: [UInt8], _ size: Int, _ src: URL) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: size)
        var n = uLongf(size)
        guard uncompress(&out, &n, z, uLong(z.count)) == Z_OK, n == size else {
            throw FirmwareError(.unsupported, "\(src.lastPathComponent): bad zlib chunk")
        }
        return out
    }

    /// Apple Data Compression: literal runs (0x80 | n-1), and copies of 3-18 bytes from up to 1 KiB back (two-byte
    /// codes) or 4-67 bytes from up to 64 KiB back (three-byte codes).
    static func adc(_ c: [UInt8], _ size: Int, _ src: URL) throws -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(size)
        var i = 0
        while i < c.count && out.count < size {
            let b = Int(c[i])
            var length: Int
            var distance: Int
            if b & 0x80 != 0 {
                length = (b & 0x7F) + 1
                guard i + 1 + length <= c.count else { break }
                out += c[i + 1..<i + 1 + length]
                i += 1 + length
                continue
            } else if b & 0x40 != 0 {
                guard i + 3 <= c.count else { break }
                length = (b & 0x3F) + 4
                distance = Int(c[i + 1]) << 8 | Int(c[i + 2])
                i += 3
            } else {
                guard i + 2 <= c.count else { break }
                length = (b >> 2 & 0x0F) + 3
                distance = (b & 0x03) << 8 | Int(c[i + 1])
                i += 2
            }
            guard distance < out.count else {
                throw FirmwareError(.unsupported, "\(src.lastPathComponent): bad ADC chunk")
            }
            for _ in 0..<length { out.append(out[out.count - distance - 1]) }
        }
        guard out.count == size else { throw FirmwareError(.unsupported, "\(src.lastPathComponent): short ADC chunk") }
        return out
    }
}
