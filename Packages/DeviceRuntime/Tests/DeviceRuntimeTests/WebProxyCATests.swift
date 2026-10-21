import Crypto
import Foundation
import Security
import Testing
import X509

@testable import DeviceRuntime

/// WebProxyCA's certificates against the old Security.framework encoder's: the same keys, serials and clock give
/// the same bytes (digests recorded from 8946b383's WebProxyCA with those inputs pinned).
struct WebProxyCATests {
    /// PKCS#8, as the old proxy wrote it (DER.pkcs8 of SecKeyCopyExternalRepresentation).
    private static let caKeyPKCS8 = Self.base64(
        [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDnbnL9EnthI5+Pnsri1Mj4FsPRx+w2QmtM3xi8+4e2C2Mn",
            "alikdt4M+B77cdSfsBzRfHqfYJ1wJsqYg2xG3wmcWr0Z+ZtWjYsnPQBM1KWn+vKQHIcxokFqhTIuGi/EOtQWpVMxkWQMZxxQ",
            "4juWv3dPPZUWs8PYFYiooK/P2cs97aRTuL79xLUWlIyFLAea7A69gOEBBXAuOoG3uYfiJRp+GFIbZQjvGSmYw35dNf81WD7a",
            "++O2O10RfxA6kEiWVCA1vfKwYeqfi+UdjDU5em9+Ul9s0xNFhRudXSjXP+yuwy3+4+GTnKnzbYdBI/eGxjCGArP1OtuqyXHg",
            "rTEBV72vAgMBAAECggEBAMNMkJsB4r5pungPj7T1zhaV13ALn0l2qWf4iL7KII8+ctFLTDyV1vLo2/Ri7gRIMTmTK0Od255O",
            "Df/AQDpac5jPde8albznu3tEXiF3/ceQ3OtCN9Bp1XxXpK4FCTQ2VM47e8ZDpENXLC0RjSm8r6leFZdP4kBSg72RxGvJplq9",
            "uldQQLMoQaGTevHknsckSnt93UEAbvfG0kTEUc1UAcR4LbLbJZO9ctQB7LgdHYpWHtvC853KB+871zRa7QpiUIEAzMCXxlNQ",
            "iCKk46i19ZhB0R8kfaVFarLw4fKR+4P6AEw+YdmcqGGcAeJkfTgY46rIKXANfdIZzflth9fshbECgYEA+RPJ7R7UJOAsv406",
            "H4CseTN9zgW1vHMQl+DrDkYSvCybkXLWvUW0wzSvTags+aNtVKJ96Eqt+4B2szj/ECs8FXiwMut+ycijg0f3NoM5jkhAycjw",
            "HQSIdZGdle12ASLKsR7KcHgfB12rNqX20YVuHeXCR5D7KgxOG8MVIoa7C7cCgYEA7d0btxh1VGmwMtDjdPJKph26I1v5FQGH",
            "OzsDrTy1YhRSVAEwtiik/kkPrtk3HiIi7/OnAF/NGn+ILH6dohlJQIZJvr6J4Rl1L5UY1n0k5ZITMGI6Th/6ZP1xQikPqblt",
            "r17j8gpGDAUyi1hBRaCERmWYZ0fDVcP6N9nWucS2zckCgYAUBH4e+3JLQGT4RA5ex8WUvAmpTBYt/gVgX2gkrocE7oTWLKeL",
            "cJW1dn98Oz7aFUNNIP4DdDUFWG6xuqvtDbx3cUqf3QNEjkZt35PDoso2YCIs1WROwLWC1WAX04y/TJ+DmpjkbxL3UZTYAICU",
            "mCegaX2yqLk2yORiIMyLCM7xgwKBgBW6xERmvJk4insp8A2H8N/aCV4fkdKkcBkuG/jgeeV628aG0U9iySfdvswHVeyvy6dG",
            "B/SVy+Pm0KbX7kiXrMRzQBtnxqrEq5rsMPevOQar4Irj/lWSwEoniQg1PhQQN3/02DgNTjbc5rAqINRehJb1wwV0Xdjg7WPa",
            "x63y1YxZAoGBAMx//wkLxyz5DzU0ib6AVaM/13IukJA6IJDm2HlbyvNua+FvLyej/wlsahI7gHbDu/Q2boGAanSDURzP2VVF",
            "u4OO86yFnAvSb4cFKzPOWofQ5Xi/kpVld5EfLgsQqEFSmNx/DgxTJzuvCOvEZAt2n5lxcxXl5a8kar8H4fbVvcBH",
        ].joined()
    )
    private static let leafKeyPKCS8 = Self.base64(
        [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDH3WR8Jg7lXhhFDnqRghwbjUDA9jUqz5JcVYEBXv+iNXg7",
            "FigTqvprm+KrN6yiWSdkfGa1LobibxrhBslAtA9n6wD3Dxh3QMwl6tifOEVmuPcTmwQ6oCbcxlVNJoLQgMNatsCSgEn+epAo",
            "jOB59VyiYVBOH1oenz+5kbKdxQBNCMql5yA28VBA1n8gaKv8Es52hXJDf48HVXpDV7wCfMv8i2Gvp2JojCqjXuXxGAAylzSZ",
            "gNdsZFVT8vxxOq1M+tR3E/qJ1JhZ4M8dnSqUZMJ1qmiBly+6ZSLodTdfNDHwByJLyhHhgImjPAdYU2RBeC6IFizCb5FNI/68",
            "Ynd4nEQ7AgMBAAECggEBALl+r9lNlTup9gp5oqZTxHSJx9SPbc768ZMCxIWaPtW0nI7yRGXkpSCkgF56gJ348sefcc+sjAGy",
            "Lpc1LioAM+A1yyKBfyqHGDIE4eH8XuU0vBQVJnqm0wrKhLbjDDwplaYmwVn2+TXXWN5ZyalHYR9QBDFNhd2v3XwETmuBQIM9",
            "BBuz7qaJV2eaXIkbaAlwFM8A3qz0ByozNWA3j+VoZ2M7OEqYnENGZ5VaJK+xTU1OibqFDDC0Xc3QOcitwXFgxI6gxhHPHoeV",
            "N/y7h1chBsArZYcYfxqhukyTXzlifn5iVEMep6kZsJgOhdb+qkLoYEG8K18iSTIjRDnnxi2rTvkCgYEA/QbXCBPw1EZn/EAp",
            "UrXO/gl8DrpRMhVXtAIaXGXiDdhQ56J6pwd13TpEwYQvWmR4NOyEQ4lr5DvdaXp/wGz2TW/2buyic7msKa6VtNOR8lLtfO1e",
            "j+at2hYrK8Sc++uOvIomiZlx+kUjvCLB/1x+iEHYzcjY+kRr50X5O06UVx8CgYEAyjahPdU7VyBTD5YvflvcF3DJvqgzgGL3",
            "aIcCW3ZE/UiNTtC2KqOle2SGK1ZC5IfOL3zGnAkvGn0qsyC4FGL9hSP9lcWJUHDMgFq7bpZKxLdmgr6GELkkb4dJIgM0p3Y8",
            "G6RO3FhDcvR908QCICmSWR9aVeH3OPhLYH4q+miGe2UCgYEA5+xoF0Bn47rxP3b0KZr6M0IwUzOWjyie7iFrVjwQ2w3nApqc",
            "gBNHhtMNCLAH03v57tDIXztMCLSSu0cMaC24CbzRjlUahqau1rnvAQNYaFx40KSmo5IW0qq1QXYDSqpceBbNQhzDK1pKaf0W",
            "AuIeHPj2J5GsyKEEosUxsJnTQJMCgYAWkGwDq1SYz0mVdqvMDNINZ4+Lj9dXXzO+XTpdHGBsZvklr1J0hZhEoZ37HgAO4jyW",
            "vfSnmrq/2PG31VHVLIqfnbmBSe6dpEidlgJOP8UOGGz+7+Wj3hT7wPvfKL5qZV4ls3r9SXgVTsTvqXKXRixHd6Er7jAZElPO",
            "66U+FgXTpQKBgEe8SCkEGlaypPruoZPWN6OUnJfwLb+hZL1L9yRo+aA+4B3Iy45hp3hP9gxFjzlbP3eQDlOWQKH64/qL7eiF",
            "R04F7uzmau8BJhrTBdDWWUUyJmQMuZTlLk5VBDhW3sZmOtbpaNVm230SJWAdI7L5r4aZhyRxAfw8qSV3eEffBex1",
        ].joined()
    )
    private static let caKey = key(caKeyPKCS8), leafKey = key(leafKeyPKCS8)
    private static let now = Date(timeIntervalSince1970: 1_790_000_000)
    private static let caSerial = (0..<16).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 0x91) }
    private static let leafSerial = (0..<16).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 3) }
    private static let caDigest = "60c8ec9eda085f61332f0333ec2503f80fd7cdabc35dc6f8085f76a82dedd1fc"

    private static func base64(_ text: String) -> Data {
        guard let data = Data(base64Encoded: text) else { preconditionFailure("the fixture keys are constants") }
        return data
    }

    private static func key(_ pkcs8: Data) -> WebProxyCA.Key {
        guard let key = try? WebProxyCA.Key(derRepresentation: pkcs8) else {
            preconditionFailure("the fixture keys are constants")
        }
        return key
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func caCertificate() throws -> Data {
        let name = try DistinguishedName { CommonName("Light Touch Device Proxy") }
        return try WebProxyCA.certificate(
            key: caKey,
            issuerKey: caKey,
            issuer: name,
            subject: name,
            days: 3650,
            host: nil,
            serial: caSerial,
            now: now
        )
    }

    @Test func theCAMatchesTheOldEncoder() throws {
        #expect(Self.sha256(try Self.caCertificate()) == Self.caDigest)
    }

    @Test(arguments: [
        ("www.apple.com", "51fef170830fc69ecc9ae96963fb78cd9bf8b5ee1e06e13fed3327b4386b5bad"),
        ("10.0.2.2", "a08c18e593e21689f7db799bcfd6fd469ccb9a8168fac1cb49049b37c9967092"),
        ("fe80::1", "728baa44a7785bd43ef93806e1c2db163c592f76aff26ee9b472fedbfa768da0"),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
            "0d801c91f8d6fbbfe905545a92e80f4032da67176fdb6626cd5f01aa4aab7b2e"
        ),
    ])
    func aLeafMatchesTheOldEncoder(host: String, digest: String) throws {
        let issuer = try DistinguishedName { CommonName("Light Touch Device Proxy") }
        let leaf = try WebProxyCA.certificate(
            key: Self.leafKey,
            issuerKey: Self.caKey,
            issuer: issuer,
            subject: DistinguishedName { CommonName(host.utf8.count <= 64 ? host : "Light Touch Device Proxy") },
            days: 7,
            host: host,
            serial: Self.leafSerial,
            now: Self.now
        )
        #expect(Self.sha256(leaf) == digest)
    }

    /// A CONFIG.ca.pem as the old proxy wrote it (PKCS#8 key, then the certificate) loads with the same key, and
    /// its leaves are signed by it as Security.framework checks a signature.
    @Test func anOldCAFileLoadsAndSignsLeaves() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("webproxyca-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let config = dir.appendingPathComponent("web-proxy.plist")
        let caDER = try Self.caCertificate()
        let text =
            "-----BEGIN PRIVATE KEY-----\n" + Self.caKeyPKCS8.base64EncodedString(options: .lineLength64Characters)
            + "\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\n"
            + caDER.base64EncodedString(options: .lineLength64Characters) + "\n-----END CERTIFICATE-----\n"
        #expect(
            FileManager.default.createFile(
                atPath: config.path + ".ca.pem",
                contents: Data(text.utf8),
                attributes: [.posixPermissions: 0o600]
            )
        )
        let ca = try WebProxyCA.prepare(config: config)
        #expect(Self.sha256(ca.certificate) == Self.caDigest)
        #expect(try Data(contentsOf: URL(fileURLWithPath: config.path + ".ca.der")) == caDER)
        #expect(ca.key.pkcs8DERRepresentation == Self.caKeyPKCS8)

        let identity = try ca.identity(for: "www.apple.com", key: Self.leafKey)
        var leafRef: SecCertificate?
        #expect(SecIdentityCopyCertificate(identity, &leafRef) == errSecSuccess)
        let leafDER = try #require(leafRef.map { SecCertificateCopyData($0) as Data })
        let leaf = try Certificate(derEncoded: [UInt8](leafDER))
        #expect(leaf.issuer == ca.subject)
        let caPublic = try #require(SecCertificateCreateWithData(nil, caDER as CFData).flatMap(SecCertificateCopyKey))
        let signature = Data(leaf.signature.rawRepresentation)
        #expect(
            SecKeyVerifySignature(
                caPublic,
                .rsaSignatureMessagePKCS1v15SHA1,
                Data(leaf.tbsCertificateBytes) as CFData,
                signature as CFData,
                nil
            )
        )
    }
}
