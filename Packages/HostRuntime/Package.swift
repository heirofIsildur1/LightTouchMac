// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HostRuntime",
    platforms: [.macOS(.v13)],
    products: [.library(name: "HostRuntime", type: .static, targets: ["HostRuntime"])],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3")],
    targets: [
        .target(name: "HostRuntime", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "HostRuntimeTests", dependencies: ["HostRuntime"]),
    ]
)
