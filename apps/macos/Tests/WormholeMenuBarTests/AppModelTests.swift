import Foundation
import Testing
@testable import WormholeMenuBar

private let testStatus = DaemonStatus(
    version: "0.4.0",
    uptimeSeconds: 42,
    pid: 7,
    services: 1,
    endpoints: 1
)

private final class FakeWormholeClient: WormholeClient {
    var statusResult: Result<DaemonStatus, Error> = .success(testStatus)
    var endpointsResult: Result<[Endpoint], Error> = .success([])
    var startError: Error?
    var reloadError: Error?
    var stopError: Error?
    var endpointStopError: Error?
    var startDelay: Duration?

    func status() async throws -> DaemonStatus { try statusResult.get() }
    func endpoints() async throws -> [Endpoint] { try endpointsResult.get() }

    func startDaemon() async throws {
        if let startDelay { try await Task.sleep(for: startDelay) }
        if let startError { throw startError }
    }

    func stopDaemon() async throws {
        if let stopError { throw stopError }
    }

    func reloadDaemon() async throws {
        if let reloadError { throw reloadError }
    }

    func stopEndpoint(_: UUID) async throws {
        if let endpointStopError { throw endpointStopError }
    }
}

private final class FakeLoginItemManager: LoginItemManaging {
    var status: LoginItemStatus
    var resultingStatus: LoginItemStatus?
    var updateError: Error?
    private(set) var openedSettings = false

    init(status: LoginItemStatus) {
        self.status = status
    }

    func setEnabled(_ enabled: Bool) throws {
        if let updateError { throw updateError }
        status = resultingStatus ?? (enabled ? .enabled : .disabled)
    }

    func openSettings() {
        openedSettings = true
    }
}

@MainActor
private func testModel(
    client: FakeWormholeClient,
    loginItemManager: FakeLoginItemManager = FakeLoginItemManager(status: .disabled)
) -> AppModel {
    let locator = CLILocator(
        environment: ["WORMHOLE_CLI_PATH": "/test/wormhole"],
        homeDirectory: URL(fileURLWithPath: "/Users/test"),
        isExecutable: { $0 == "/test/wormhole" }
    )
    return AppModel(
        locator: locator,
        clientFactory: { _ in client },
        socketExists: { _ in true },
        loginItemManager: loginItemManager
    )
}

@Test @MainActor
func actionPublishesProgressAndDisablesConflictingWork() async throws {
    let client = FakeWormholeClient()
    client.startDelay = .milliseconds(100)
    let model = testModel(client: client)

    let action = Task { await model.startDaemon() }
    try await Task.sleep(for: .milliseconds(20))
    #expect(model.activeAction == .startDaemon)
    #expect(model.isPerformingAction)

    await action.value
    #expect(model.activeAction == nil)
    #expect(model.noticeMessage == "Daemon started.")
}

@Test @MainActor
func actionFailureSurvivesSuccessfulRefresh() async {
    let client = FakeWormholeClient()
    client.reloadError = CLIClientError.commandFailed(4, "invalid configuration")
    let model = testModel(client: client)

    await model.reloadDaemon()

    #expect(model.daemonStatus == testStatus)
    #expect(model.actionErrorMessage?.contains("invalid configuration") == true)
    #expect(model.refreshErrorMessage == nil)
}

@Test @MainActor
func endpointRefreshFailureKeepsKnownDaemonAndEndpoints() async throws {
    let client = FakeWormholeClient()
    let endpoint = try decodedEndpoint()
    client.endpointsResult = .success([endpoint])
    let model = testModel(client: client)
    await model.refresh()

    client.endpointsResult = .failure(CLIClientError.commandFailed(5, "list unavailable"))
    await model.refresh()

    #expect(model.daemonStatus == testStatus)
    #expect(model.endpoints == [endpoint])
    #expect(model.refreshErrorMessage?.contains("Daemon is running") == true)
}

@Test @MainActor
func launchAtLoginTracksEnabledAndApprovalStates() async {
    let client = FakeWormholeClient()
    let loginItems = FakeLoginItemManager(status: .disabled)
    let model = testModel(client: client, loginItemManager: loginItems)

    await model.setLaunchAtLoginEnabled(true)
    #expect(model.launchAtLoginEnabled)
    #expect(model.noticeMessage == "Launch at Login enabled.")

    loginItems.resultingStatus = .requiresApproval
    await model.setLaunchAtLoginEnabled(false)
    #expect(!model.launchAtLoginEnabled)
    #expect(model.launchAtLoginRequiresApproval)
    #expect(model.actionErrorMessage?.contains("System Settings") == true)

    model.openLoginItemSettings()
    #expect(loginItems.openedSettings)

    loginItems.status = .enabled
    await model.refresh()
    #expect(model.launchAtLoginEnabled)
    #expect(!model.launchAtLoginRequiresApproval)
}

private func decodedEndpoint() throws -> Endpoint {
    let json = #"{"id":"5b968970-4ace-4feb-9cc9-cf5542a95bea","service":"web","driver":"wormhole","urls":["https://web.example"],"status":"online"}"#
    return try JSONDecoder().decode(Endpoint.self, from: Data(json.utf8))
}
