// swift-tools-version: 6.0
// The build's own tools (scripts/ltm-build runs them): scripts/vendor (with HostRuntime's machine options from the
// vendored QEMU), the Mach-O closure check of the native builds (ReleaseChecks' MachOClosure), the universal merge of
// per-architecture native roots, the pinned dependency sources (fetch, stage-git, note) with the native and static
// build records, and scripts/ship's release checks (catalog, Amore id, appcast).
import PackageDescription

let package = Package(
    name: "BuildTools",
    platforms: [.macOS("14.4")],
    products: [.executable(name: "ltm-build", targets: ["ltm-build"])],
    dependencies: [
        .package(path: "../ReleaseChecks"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2")
    ],
    targets: [
        .target(name: "BuildTools", dependencies: [.product(name: "ReleaseChecks", package: "ReleaseChecks")]),
        .executableTarget(
            name: "ltm-build",
            dependencies: ["BuildTools", .product(name: "ArgumentParser", package: "swift-argument-parser")]
        ),
        .testTarget(
            name: "BuildToolsTests",
            dependencies: ["BuildTools", .product(name: "ReleaseChecks", package: "ReleaseChecks")]
        )
    ]
)
