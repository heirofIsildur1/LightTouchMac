// The web proxy's per-device certificate authority (the app trusts its public
// certificate in the guest; the helper's WebProxy signs a leaf per HTTPS host
// with it). RSA-2048 keys, SHA-1 signatures (iOS 3's TLS 1.0 stack), through
// swift-crypto and swift-certificates; only the TLS identity the helper serves
// (`identity(for:key:)`) is Security.framework's.
//
// Files beside the routing CONFIG, as the old itwebproxy --init-ca wrote them,
// so a device keeps the CA its guest already trusts: CONFIG.ca.pem (PKCS#8
// private key then the certificate, mode 0600, owner only), CONFIG.ca.der
// (the public certificate), CONFIG.ca.lock (creation lock).

import Crypto
import CryptoExtras
import Foundation
import SwiftASN1
import X509

#if canImport(Security)
    import Security
#endif

nonisolated public struct WebProxyCA: Sendable {
    public typealias Key = _RSA.Signing.PrivateKey
    public let key: Key
    /// The public certificate, DER.
    public let certificate: Data
    /// The certificate's subject: every leaf's issuer.
    let subject: DistinguishedName

    enum Failure: Error {
        case unreadable(String)
        case signing, identity
    }

    /// Loads CONFIG.ca.pem, creating it on first use; (re)writes CONFIG.ca.der.
    public static func prepare(config: URL) throws -> WebProxyCA {
        let lock = open(config.path + ".ca.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard lock >= 0, flock(lock, LOCK_EX) == 0 else { throw Failure.unreadable("lock") }
        defer { close(lock) }
        let pem = URL(fileURLWithPath: config.path + ".ca.pem")
        let ca: WebProxyCA
        if FileManager.default.fileExists(atPath: pem.path) {
            ca = try load(config: config)
        } else {
            let key = try newKey()
            let name = try DistinguishedName { CommonName("Light Touch Device Proxy") }
            let der = try certificate(key: key, issuerKey: key, issuer: name, subject: name, days: 3650, host: nil)
            let text =
                "-----BEGIN PRIVATE KEY-----\n"
                + key.pkcs8DERRepresentation.base64EncodedString(options: .lineLength64Characters)
                + "\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\n"
                + der.base64EncodedString(options: .lineLength64Characters)
                + "\n-----END CERTIFICATE-----\n"
            try save(Data(text.utf8), to: pem, mode: 0o600)
            ca = try load(config: config)
        }
        try save(ca.certificate, to: URL(fileURLWithPath: config.path + ".ca.der"), mode: 0o644)
        return ca
    }

    /// CONFIG.ca.pem, refused unless it is a regular file of this user's that nobody else can read.
    public static func load(config: URL) throws -> WebProxyCA {
        let path = config.path + ".ca.pem"
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw Failure.unreadable(path) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == getuid(), st.st_mode & 0o077 == 0, st.st_mode & S_IFMT == S_IFREG,
            let text = String(data: handle.readDataToEndOfFile(), encoding: .utf8),
            let pkcs8 = pemBlock(text, "PRIVATE KEY"), let key = try? Key(derRepresentation: pkcs8),
            let der = pemBlock(text, "CERTIFICATE"), let certificate = try? Certificate(derEncoded: [UInt8](der)),
            certificate.publicKey == Certificate.PublicKey(key.publicKey)
        else { throw Failure.unreadable(path) }
        return WebProxyCA(key: key, certificate: der, subject: certificate.subject)
    }

    /// A certificate for `host` (a DNS name or an IP literal), valid for a week, under this CA, DER.
    public func leafCertificate(for host: String, key leafKey: Key) throws -> Data {
        try Self.certificate(
            key: leafKey,
            issuerKey: key,
            issuer: subject,
            subject: DistinguishedName { CommonName(host.utf8.count <= 64 ? host : "Light Touch Device Proxy") },
            days: 7,
            host: host
        )
    }

    public static func newKey() throws -> Key { try Key(keySize: .bits2048) }

    // MARK: - Certificates

    static func certificate(
        key: Key,
        issuerKey: Key,
        issuer: DistinguishedName,
        subject: DistinguishedName,
        days: Int,
        host: String?,
        serial: [UInt8] = (0..<16).map { _ in UInt8.random(in: 0...255) },
        now: Date = Date()
    ) throws -> Data {
        var serial = serial
        serial[0] &= 0x7f
        // Valid from 2000, not from today: a dated device (a developer beta pinned inside its release window,
        // recipe rtc_epoch) checks notBefore against its own 2012-2013 clock.
        let validFrom = Date(timeIntervalSince1970: 946_684_800)
        let extensions: Certificate.Extensions
        if let host {
            let ip = [AF_INET, AF_INET6].lazy.compactMap { family -> [UInt8]? in
                var bytes = [UInt8](repeating: 0, count: 16)
                return inet_pton(family, host, &bytes) == 1 ? Array(bytes.prefix(family == AF_INET ? 4 : 16)) : nil
            }.first
            guard host.utf8.count <= 253, !host.isEmpty,
                host.unicodeScalars.allSatisfy({
                    $0.isASCII && (CharacterSet.alphanumerics.contains($0) || ".-:".unicodeScalars.contains($0))
                })
            else { throw Failure.signing }
            extensions = try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true, keyEncipherment: true))
                SubjectAlternativeNames([
                    ip.map { .ipAddress(ASN1OctetString(contentBytes: $0[...])) } ?? .dnsName(host)
                ])
                try ExtendedKeyUsage([.serverAuth])
            }
        } else {
            extensions = try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            }
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(bytes: serial),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: validFrom,
            notValidAfter: now + Double(days) * 86400,
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .sha1WithRSAEncryption,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }

    private static func pemBlock(_ text: String, _ label: String) -> Data? {
        guard let start = text.range(of: "-----BEGIN \(label)-----"),
            let end = text.range(of: "-----END \(label)-----", range: start.upperBound..<text.endIndex)
        else { return nil }
        return Data(base64Encoded: String(text[start.upperBound..<end.lowerBound]), options: .ignoreUnknownCharacters)
    }

    private static func save(_ data: Data, to url: URL, mode: mode_t) throws {
        let temporary = url.path + ".\(getpid()).tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw Failure.unreadable(temporary) }
        let ok = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) == $0.count }
        guard close(fd) == 0, ok, rename(temporary, url.path) == 0 else {
            unlink(temporary)
            throw Failure.unreadable(url.path)
        }
    }
}

#if canImport(Security)
    extension WebProxyCA {
        /// A TLS server identity for `host` (SecureTransport's, GuestTLS.c): `leafCertificate(for:key:)` with its key.
        public func identity(for host: String, key leafKey: Key) throws -> SecIdentity {
            let der = try leafCertificate(for: host, key: leafKey)
            guard
                let secKey = SecKeyCreateWithData(
                    leafKey.derRepresentation as CFData,
                    [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary,
                    nil
                ),
                let certificate = SecCertificateCreateWithData(nil, der as CFData),
                let identity = Self.createIdentity?(nil, certificate, secKey)?.takeRetainedValue()
            else { throw Failure.identity }
            return identity
        }

        /// SecIdentityCreate (Security.framework SPI): an identity from a key that isn't in a keychain.
        /// The public way (SecPKCS12Import's kSecImportToMemoryOnly) needs macOS 15; the app supports 14.4.
        private typealias IdentityCreate =
            @convention(c) (CFAllocator?, SecCertificate, SecKey) -> Unmanaged<SecIdentity>?
        private static let createIdentity: IdentityCreate? = dlsym(
            UnsafeMutableRawPointer(bitPattern: -2),
            "SecIdentityCreate"
        )
        .map { unsafeBitCast($0, to: IdentityCreate.self) }
    }
#endif
