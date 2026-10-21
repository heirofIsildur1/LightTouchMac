// IMG3: tag parsing and AES-CBC payload decryption, ported from ipad1_fw.py.
//
//   try IMG3.tags(data)["DATA"]                            // (offset, dataLength) per tag, last wins
//   try IMG3.decrypt(data, iv: iv, key: key)               // 3.x+: the final partial block is encrypted
//                                                          //   into the tag's padding (decrypt it whole)
//   try IMG3.decrypt(data, iv: iv, key: key, plainTail: true)  // 2.x: the final partial block is plaintext
//   try AESCBC.crypt(buf, iv: iv, key: key, decrypt: true) // no padding; 16/24/32-byte keys
//   Data(hex: "00ff")
//
// Which tail convention a firmware uses is decided once, on the kernelcache (the one component with a
// checksum): see FirmwareDecryptor.

import Crypto
import Foundation

#if canImport(CommonCrypto)
    import CommonCrypto
#else
    import CryptoExtras
#endif

public enum IMG3 {
    public struct Tag: Equatable, Sendable {
        public var offset: Int
        public var dataLength: Int
    }

    /// Tag magic (as read, e.g. "DATA", "KBAG") -> its header offset and data length.
    public static func tags(_ data: Data) throws -> [String: Tag] {
        let d = [UInt8](data)
        guard d.count >= 0x14, d[0..<4] == [0x33, 0x67, 0x6D, 0x49] else {
            throw FirmwareError(.unsupported, "not an img3")
        }
        let full = Int(d.u32(4))
        var off = 0x14
        var tags: [String: Tag] = [:]
        while off + 12 <= full, off + 12 <= d.count {
            let magic = String(decoding: d[off..<off + 4].reversed(), as: UTF8.self)
            let total = Int(d.u32(off + 4))
            let dlen = Int(d.u32(off + 8))
            if total < 12 { break }
            tags[magic] = Tag(offset: off, dataLength: dlen)
            off += total
        }
        return tags
    }

    /// The DATA payload as stored (an unencrypted img3's plaintext, else the ciphertext).
    public static func payload(_ data: Data) throws -> Data {
        guard let tag = try tags(data)["DATA"] else { throw FirmwareError(.unsupported, "img3 has no DATA tag") }
        let start = data.startIndex + tag.offset + 12
        guard start + tag.dataLength <= data.endIndex else {
            throw FirmwareError(.unsupported, "img3 DATA runs past the file")
        }
        return data[start..<start + tag.dataLength]
    }

    public static func decrypt(_ data: Data, iv: Data, key: Data, plainTail: Bool = false) throws -> Data {
        guard let tag = try tags(data)["DATA"] else { throw FirmwareError(.unsupported, "img3 has no DATA tag") }
        let start = data.startIndex + tag.offset + 12
        let dlen = tag.dataLength
        guard start + dlen <= data.endIndex else { throw FirmwareError(.unsupported, "img3 DATA runs past the file") }
        if plainTail {
            let n = dlen & ~15
            return try AESCBC.crypt(data[start..<start + n], iv: iv, key: key) + data[start + n..<start + dlen]
        }
        let n = (dlen + 15) & ~15
        guard start + n <= data.endIndex else {
            throw FirmwareError(.unsupported, "img3 DATA padding runs past the file")
        }
        return try AESCBC.crypt(data[start..<start + n], iv: iv, key: key).prefix(dlen)
    }
}

/// CommonCrypto where the host has it; elsewhere swift-crypto's CryptoExtras (BoringSSL), which an Apple build leaves
/// out: BoringSSL's error macros put each C source's absolute build path in the binary (__FILE__), which the release
/// check refuses (it would ship the builder's home folder).
public enum AESCBC {
    /// AES-CBC without padding; `buf` must be a multiple of 16 bytes.
    public static func crypt(_ buf: Data, iv: Data, key: Data, decrypt: Bool = true) throws -> Data {
        guard [16, 24, 32].contains(key.count), iv.count == 16, buf.count % 16 == 0 else {
            throw FirmwareError(.unsupported, "AES: key \(key.count) B, iv \(iv.count) B, data \(buf.count) B")
        }
        guard !buf.isEmpty else { return Data() }
        #if canImport(CommonCrypto)
            var out = Data(count: buf.count)
            var moved = 0
            let status = out.withUnsafeMutableBytes { o in
                buf.withUnsafeBytes { i in
                    key.withUnsafeBytes { k in
                        iv.withUnsafeBytes { v in
                            CCCrypt(
                                CCOperation(decrypt ? kCCDecrypt : kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), 0,
                                k.baseAddress, key.count, v.baseAddress, i.baseAddress, buf.count, o.baseAddress,
                                buf.count, &moved)
                        }
                    }
                }
            }
            guard status == kCCSuccess, moved == buf.count else {
                throw FirmwareError(.internal, "CCCrypt failed (\(status))")
            }
            return out
        #else
            let key = SymmetricKey(data: key)
            let iv = try AES._CBC.IV(ivBytes: iv)
            return decrypt
                ? try AES._CBC.decrypt(buf, using: key, iv: iv, noPadding: true)
                : try AES._CBC.encrypt(buf, using: key, iv: iv, noPadding: true)
        #endif
    }
}

extension Data {
    /// Bytes from a hex string (no separators); nil if it isn't hex.
    public init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let b = UInt8(String(decoding: chars[i..<i + 2], as: UTF8.self), radix: 16) else { return nil }
            out.append(b)
        }
        self.init(out)
    }

    /// Bytes from a hex literal written in the source (a key, an IV, a magic value); a malformed literal is a
    /// programmer error.
    init(hexLiteral hex: StaticString) {
        guard let data = Data(hex: "\(hex)") else { preconditionFailure("not a hex literal: \(hex)") }
        self = data
    }
}

extension [UInt8] {
    func u32(_ at: Int) -> UInt32 {
        UInt32(self[at]) | UInt32(self[at + 1]) << 8 | UInt32(self[at + 2]) << 16 | UInt32(self[at + 3]) << 24
    }
}
