// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDECore",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "IDECore", targets: ["IDECore"])
    ],
    targets: [
        .target(name: "IDECore"),
        .testTarget(name: "IDECoreTests", dependencies: ["IDECore"])
    ],
    swiftLanguageVersions: [.v5]
)
