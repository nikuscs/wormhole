import Foundation
import Testing
@testable import WormholeMenuBar

@Test func decodesDaemonAndEndpointJSON() throws {
    let status = try JSONDecoder().decode(
        DaemonStatus.self,
        from: Data(#"{"version":"0.4.0","uptime_seconds":42,"pid":7,"services":1,"endpoints":1}"#.utf8)
    )
    #expect(status.services == 1)
    #expect(status.uptimeSeconds == 42)

    let endpointJSON = #"[{"id":"5b968970-4ace-4feb-9cc9-cf5542a95bea","service":"web","driver":"cloudflare","urls":["https://web.example"],"status":{"error":"connection lost"},"buffered_pending":2,"since":"2026-01-01T00:00:00Z"}]"#
    let endpoints = try JSONDecoder().decode([Endpoint].self, from: Data(endpointJSON.utf8))
    #expect(endpoints[0].status == .error("connection lost"))
    #expect(endpoints[0].bufferedPending == 2)
    #expect(endpoints[0].bufferedDelivered == 0)
}

@Test func locatorHonorsOverrideAndDerivesMacRuntimePath() {
    let home = URL(fileURLWithPath: "/Users/test")
    let locator = CLILocator(
        environment: ["WORMHOLE_CLI_PATH": "/custom/wormhole"],
        homeDirectory: home,
        isExecutable: { $0 == "/custom/wormhole" }
    )
    #expect(locator.locate()?.path == "/custom/wormhole")
    #expect(locator.runtimeDirectory().path == "/Users/test/Library/Application Support/wormhole")
}

@Test func locatorUsesXdgRuntimeAndCommonInstallLocations() {
    let locator = CLILocator(
        environment: ["PATH": "", "XDG_RUNTIME_DIR": "/tmp/runtime"],
        homeDirectory: URL(fileURLWithPath: "/Users/test"),
        isExecutable: { $0 == "/Users/test/.cargo/bin/wormhole" }
    )
    #expect(locator.locate()?.path == "/Users/test/.cargo/bin/wormhole")
    #expect(locator.runtimeDirectory().path == "/tmp/runtime/wormhole")
}

@Test func processRunnerCapturesOutputAndExitStatus() async throws {
    let result = try await ProcessRunner().run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "printf '{\\\"ok\\\":true}'; printf ignored >&2; exit 3"]
    )
    #expect(result.terminationStatus == 3)
    #expect(String(decoding: result.standardOutput, as: UTF8.self) == #"{"ok":true}"#)
}
