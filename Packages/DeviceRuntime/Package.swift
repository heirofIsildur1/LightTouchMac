// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DeviceRuntime",
    platforms: [.macOS(.v13)],
    products: [.library(name: "DeviceRuntime", type: .static, targets: ["DeviceRuntime"])],
    dependencies: [
        .package(path: "../HostRuntime"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.21.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.3"),
    ],
    targets: [
        .target(name: "LTMLinkC", publicHeadersPath: "."),
        .target(
            name: "DeviceRuntime",
            dependencies: [
                "HostRuntime", "LTMLinkC", .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .executableTarget(name: "RendezvousTestPeer", dependencies: ["LTMLinkC"]),
        .testTarget(name: "DeviceRuntimeTests", dependencies: ["DeviceRuntime", "RendezvousTestPeer"]),
    ]
)
