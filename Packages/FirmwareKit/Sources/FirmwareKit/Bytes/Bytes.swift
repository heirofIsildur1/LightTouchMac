// The byte readers and writers FirmwareKit's formats share: integers at offsets of an image, hex, zlib's CRC-32.
import BinaryParsing
import Foundation
import zlib

func le16(_ b: [UInt8], _ o: Int) -> UInt16 { UInt16(b[o]) | UInt16(b[o + 1]) << 8 }

func le32(_ b: [UInt8], _ o: Int) -> UInt32 {
    UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
}

func be32(_ b: [UInt8], _ o: Int) -> UInt32 {
    UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
}

func be16(_ b: [UInt8], _ o: Int) -> UInt16 { UInt16(b[o]) << 8 | UInt16(b[o + 1]) }
func le64(_ b: [UInt8], _ o: Int) -> UInt64 { UInt64(le32(b, o)) | UInt64(le32(b, o + 4)) << 32 }
func be64(_ b: [UInt8], _ o: Int) -> UInt64 { UInt64(be32(b, o)) << 32 | UInt64(be32(b, o + 4)) }

/// `v`, big-endian (HFS+), at `o`.
func putBE16(_ b: inout [UInt8], _ o: Int, _ v: UInt16) {
    b[o] = UInt8(v >> 8)
    b[o + 1] = UInt8(v & 0xFF)
}

/// `v`, big-endian (HFS+), at `o`.
func putBE32(_ b: inout [UInt8], _ o: Int, _ v: UInt32) {
    for k in 0..<4 { b[o + k] = UInt8(truncatingIfNeeded: v >> (24 - 8 * k)) }
}

/// `v`, big-endian (HFS+), at `o`.
func putBE64(_ b: inout [UInt8], _ o: Int, _ v: UInt64) {
    putBE32(&b, o, UInt32(v >> 32))
    putBE32(&b, o + 4, UInt32(truncatingIfNeeded: v))
}

/// `v`'s low 16 bits, little-endian, at `o`.
func put16(_ b: inout [UInt8], _ o: Int, _ v: Int) {
    b[o] = UInt8(v & 0xFF)
    b[o + 1] = UInt8((v >> 8) & 0xFF)
}

/// `v`, little-endian, at `o`.
func put32(_ b: inout [UInt8], _ o: Int, _ v: UInt32) {
    for k in 0..<4 { b[o + k] = UInt8(truncatingIfNeeded: v >> (8 * k)) }
}

/// zlib's CRC-32 of `b`.
func crc(_ b: ArraySlice<UInt8>) -> UInt32 {
    UInt32(b.withUnsafeBufferPointer { zlib.crc32(0, $0.baseAddress, uInt($0.count)) })
}

extension Sequence<UInt8> {
    /// Lowercase hex, two digits a byte.
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

/// The readers over raw bytes check their bounds and throw: what they read comes from firmware files, and a raw
/// load or subscript checks nothing in a Release build.
extension UnsafeRawBufferPointer {
    /// The `n` bytes at `o`.
    func bytes(_ o: Int, _ n: Int) throws -> UnsafeRawBufferPointer {
        guard o >= 0, n >= 0, o <= count, n <= count - o else {
            throw FirmwareError(.unsupported, "\(n) bytes at \(o) run past the \(count) there are")
        }
        return UnsafeRawBufferPointer(rebasing: self[o..<o + n])
    }
    func field<T: FixedWidthInteger>(_ o: Int, as: T.Type = T.self) throws -> T {
        try bytes(o, MemoryLayout<T>.size).loadUnaligned(as: T.self)
    }
    func byte(_ o: Int) throws -> UInt8 { try field(o) }
    func u16le(_ o: Int) throws -> UInt16 { UInt16(littleEndian: try field(o)) }
    func u32le(_ o: Int) throws -> UInt32 { UInt32(littleEndian: try field(o)) }
    func u64le(_ o: Int) throws -> UInt64 { UInt64(littleEndian: try field(o)) }
}

extension Data {
    /// The little-endian UInt32 at `o` (from the data's start), or the readers' error.
    func u32le(_ o: Int) throws -> UInt32 { try withUnsafeBytes { try $0.u32le(o) } }
}

/// The parsers read firmware files through BinaryParsing's ParserSpan, whose reads check their bounds and throw.
extension ParserSpan {
    /// The integer `o` bytes in, big-endian; the span stays where it is.
    func be16(at o: Int) throws(ParsingError) -> UInt16 {
        var s = try seeking(toRelativeOffset: o)
        return try UInt16(parsingBigEndian: &s)
    }
    func be32(at o: Int) throws(ParsingError) -> UInt32 {
        var s = try seeking(toRelativeOffset: o)
        return try UInt32(parsingBigEndian: &s)
    }
    func le32(at o: Int) throws(ParsingError) -> UInt32 {
        var s = try seeking(toRelativeOffset: o)
        return try UInt32(parsingLittleEndian: &s)
    }
    func byte(at o: Int) throws(ParsingError) -> UInt8 {
        var s = try seeking(toRelativeOffset: o)
        return try UInt8(parsing: &s)
    }
    /// The `n` bytes `o` bytes in.
    func bytes(at o: Int, _ n: Int) throws(ParsingError) -> [UInt8] {
        var s = try seeking(toRelativeOffset: o)
        return try [UInt8](parsing: &s, byteCount: n)
    }
    /// The NUL-terminated string's bytes `o` bytes in: up to the NUL, or to the span's end when there is none.
    func cBytes(at o: Int) throws(ParsingError) -> [UInt8] {
        let s = try seeking(toRelativeOffset: o)
        return s.withUnsafeBytes { Array($0.prefix { $0 != 0 }) }
    }
    /// The NUL-terminated string `o` bytes in, as Latin-1.
    func latin1(at o: Int) throws(ParsingError) -> String {
        String(try cBytes(at: o).map { Character(Unicode.Scalar($0)) })
    }
}

/// `body` over `bytes`, a ParsingError (input cut short or out of range) as FirmwareError's unsupported, naming
/// `what`.
func parsing<T>(
    _ bytes: some ParserSpanProvider,
    _ what: @autoclosure () -> String,
    _ body: (inout ParserSpan) throws -> T
) throws -> T {
    do { return try bytes.withParserSpan(body) } catch let e as ParsingError {
        throw FirmwareError(.unsupported, "\(what()): \(e)")
    }
}
