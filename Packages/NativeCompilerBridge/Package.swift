// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NativeCompilerBridge",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "NativeCompilerBridge", targets: ["NativeCompilerBridge"])],
    targets: [
        .target(name: "NativeCompilerBridge", publicHeadersPath: "include",
                cxxSettings: [.unsafeFlags(["-std=c++17"])]),
    ],
    cxxLanguageStandard: .cxx17
)
