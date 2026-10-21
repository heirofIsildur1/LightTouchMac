// swift-tools-version: 6.0
// FirmwareKit: IPSW -> emulated device preparation.
// Swift owns device preparation. Tests use frozen reference hashes and
// optional corpus inputs; strict acceptance fails when selected prerequisites are absent. Each module lives in its own
// subdirectory of Sources/FirmwareKit so agents can add modules without editing this file.
//
// Dependencies are pinned to exact versions and recorded with their licenses in build-support/dependencies.json
// (BuildTools' dependency sources manifest): ZIPFoundation (IPSW members), MachOKit (Mach-O headers, fat
// files, code signatures), swift-subprocess (`diskutil image` / `hdiutil` through DiskImage), Unrar.swift (a "rar"
// source's IPSW: RARLAB's UnRAR, extraction only), swift-argument-parser (the firmwarekit command
// lines, FirmwareSchema's FirmwareCommand).
import PackageDescription

let package = Package(
    name: "FirmwareKit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "FirmwareKit", targets: ["FirmwareKit"]),
        .library(name: "FirmwareSchema", type: .static, targets: ["FirmwareSchema"]),
        .executable(name: "firmwarekit", targets: ["FirmwareKitCLI"])
    ],
    dependencies: [
        .package(path: "../HostRuntime"),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", exact: "0.9.20"),
        .package(url: "https://github.com/p-x9/MachOKit.git", exact: "0.53.0"),
        .package(url: "https://github.com/swiftlang/swift-subprocess.git", exact: "1.0.0"),
        .package(url: "https://github.com/mtgto/Unrar.swift.git", exact: "0.5.4"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
        .package(url: "https://github.com/apple/swift-binary-parsing.git", exact: "0.0.4")
    ],
    targets: [
        .target(
            name: "FirmwareSchema",
            dependencies: [.product(name: "ArgumentParser", package: "swift-argument-parser")]
        ),
        .target(name: "CActivation", cSettings: [.define("LT_ACTIVATION_LIBRARY")]),
        .target(
            name: "FirmwareKit",
            dependencies: [
                "CActivation", "FirmwareSchema",
                .product(name: "HostRuntime", package: "HostRuntime"),
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
                .product(name: "MachOKit", package: "MachOKit"),
                .product(name: "Subprocess", package: "swift-subprocess"),
                .product(name: "Unrar", package: "Unrar.swift"),
                .product(name: "BinaryParsing", package: "swift-binary-parsing")
            ]
        ),
        .executableTarget(
            name: "FirmwareKitCLI",
            dependencies: [
                "FirmwareKit",
                .product(name: "HostRuntime", package: "HostRuntime"),
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ]
        ),
        .testTarget(
            name: "FirmwareKitTests",
            dependencies: ["FirmwareKit", "FirmwareSchema", .product(name: "HostRuntime", package: "HostRuntime")],
            exclude: ["iboot-trees"]  // KBootIBootTests reads them from the source tree
        )
    ]
)
