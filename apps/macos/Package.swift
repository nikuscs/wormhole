// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "WormholeMenuBar",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "WormholeMenuBar", targets: ["WormholeMenuBar"]),
    ],
    targets: [
        .executableTarget(
            name: "WormholeMenuBar",
            resources: [.copy("Resources/app-icon.svg")]
        ),
        .testTarget(
            name: "WormholeMenuBarTests",
            dependencies: ["WormholeMenuBar"]
        ),
    ],
    swiftLanguageModes: [.v5]
)
