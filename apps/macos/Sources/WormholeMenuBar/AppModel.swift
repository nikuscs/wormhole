import AppKit
import Foundation

enum AppAction: Equatable {
    case startDaemon
    case reloadDaemon
    case stopDaemon
    case stopEndpoint(UUID)
    case enableLaunchAtLogin
    case disableLaunchAtLogin

    var progressLabel: String {
        switch self {
        case .startDaemon: "Starting daemon…"
        case .reloadDaemon: "Reloading configuration…"
        case .stopDaemon: "Stopping daemon…"
        case .stopEndpoint: "Stopping endpoint…"
        case .enableLaunchAtLogin: "Enabling Launch at Login…"
        case .disableLaunchAtLogin: "Disabling Launch at Login…"
        }
    }

    var successMessage: String {
        switch self {
        case .startDaemon: "Daemon started."
        case .reloadDaemon: "Configuration reloaded."
        case .stopDaemon: "Daemon stopped."
        case .stopEndpoint: "Endpoint stopped."
        case .enableLaunchAtLogin: "Launch at Login enabled."
        case .disableLaunchAtLogin: "Launch at Login disabled."
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var cliURL: URL?
    @Published private(set) var daemonStatus: DaemonStatus?
    @Published private(set) var endpoints = [Endpoint]()
    @Published private(set) var isRefreshing = false
    @Published private(set) var activeAction: AppAction?
    @Published private(set) var actionErrorMessage: String?
    @Published private(set) var refreshErrorMessage: String?
    @Published private(set) var noticeMessage: String?
    @Published private(set) var launchAtLoginEnabled: Bool
    @Published private(set) var launchAtLoginRequiresApproval: Bool

    private let locator: CLILocator
    private let clientFactory: (URL) -> any WormholeClient
    private let socketExists: (URL) -> Bool
    private let loginItemManager: any LoginItemManaging
    private var noticeTask: Task<Void, Never>?

    init(
        locator: CLILocator = CLILocator(),
        clientFactory: @escaping (URL) -> any WormholeClient = { CLIClient(executable: $0) },
        socketExists: @escaping (URL) -> Bool = { FileManager.default.fileExists(atPath: $0.path) },
        loginItemManager: any LoginItemManaging = MainAppLoginItemManager()
    ) {
        self.locator = locator
        self.clientFactory = clientFactory
        self.socketExists = socketExists
        self.loginItemManager = loginItemManager
        cliURL = locator.locate()
        let loginItemStatus = loginItemManager.status
        launchAtLoginEnabled = loginItemStatus == .enabled
        launchAtLoginRequiresApproval = loginItemStatus == .requiresApproval
    }

    var daemonSocketExists: Bool {
        socketExists(locator.runtimeDirectory().appendingPathComponent("daemon.sock"))
    }

    var isPerformingAction: Bool { activeAction != nil }

    func refresh() async {
        guard !isRefreshing, !isPerformingAction else { return }
        updateLoginItemStatus()
        if cliURL == nil { cliURL = locator.locate() }
        guard let cliURL else {
            daemonStatus = nil
            endpoints = []
            refreshErrorMessage = nil
            return
        }
        guard daemonSocketExists else {
            daemonStatus = nil
            endpoints = []
            refreshErrorMessage = nil
            return
        }
        isRefreshing = true
        defer { isRefreshing = false }
        let client = clientFactory(cliURL)
        do {
            daemonStatus = try await client.status()
        } catch {
            daemonStatus = nil
            endpoints = []
            refreshErrorMessage = "Could not read daemon status. \(displayMessage(for: error))"
            return
        }
        do {
            endpoints = try await client.endpoints()
            refreshErrorMessage = nil
        } catch {
            refreshErrorMessage = "Daemon is running, but tunnels could not be refreshed. \(displayMessage(for: error))"
        }
    }

    func runRefreshLoop() async {
        await refresh()
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(5))
            await refresh()
        }
    }

    func startDaemon() async {
        await perform(.startDaemon) { try await $0.startDaemon() }
    }

    func reloadDaemon() async {
        await perform(.reloadDaemon) { try await $0.reloadDaemon() }
    }

    func stopDaemon() async {
        await perform(.stopDaemon) { try await $0.stopDaemon() }
    }

    func confirmAndStopDaemon() async {
        let alert = NSAlert()
        alert.messageText = "Stop the Wormhole daemon?"
        alert.informativeText = "Active temporary tunnels will not return automatically."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Stop Daemon")
        alert.buttons.first?.hasDestructiveAction = true
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        await stopDaemon()
    }

    func stopEndpoint(_ endpoint: Endpoint) async {
        await perform(.stopEndpoint(endpoint.id)) { try await $0.stopEndpoint(endpoint.id) }
    }

    func setLaunchAtLoginEnabled(_ enabled: Bool) async {
        guard activeAction == nil else { return }
        let action: AppAction = enabled ? .enableLaunchAtLogin : .disableLaunchAtLogin
        activeAction = action
        actionErrorMessage = nil
        noticeMessage = nil
        do {
            try loginItemManager.setEnabled(enabled)
            updateLoginItemStatus()
            if launchAtLoginRequiresApproval {
                actionErrorMessage = "macOS requires approval in System Settings before Wormhole can launch at login."
            } else {
                showNotice(action.successMessage)
            }
        } catch {
            updateLoginItemStatus()
            actionErrorMessage = "Could not update Launch at Login. \(displayMessage(for: error))"
        }
        activeAction = nil
    }

    func openLoginItemSettings() {
        loginItemManager.openSettings()
    }

    func copy(_ value: String, label: String = "Copied to clipboard.") {
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(value, forType: .string) {
            showNotice(label)
        } else {
            actionErrorMessage = "Could not copy to the clipboard."
        }
    }

    func open(_ value: String) {
        guard let url = URL(string: value), ["http", "https"].contains(url.scheme?.lowercased()) else {
            actionErrorMessage = "Wormhole returned an invalid URL."
            return
        }
        if !NSWorkspace.shared.open(url) {
            actionErrorMessage = "No application could open this URL."
        }
    }

    func viewLogs() {
        let log = locator.runtimeDirectory().appendingPathComponent("daemon.log")
        let target = FileManager.default.fileExists(atPath: log.path) ? log : locator.runtimeDirectory()
        if !NSWorkspace.shared.open(target) {
            actionErrorMessage = "Could not open the Wormhole logs folder."
        }
    }

    func dismissMessages() {
        actionErrorMessage = nil
        refreshErrorMessage = nil
        noticeMessage = nil
    }

    private func perform(
        _ action: AppAction,
        operation: (any WormholeClient) async throws -> Void
    ) async {
        guard activeAction == nil, let cliURL else { return }
        activeAction = action
        actionErrorMessage = nil
        noticeMessage = nil
        var succeeded = false
        do {
            try await operation(clientFactory(cliURL))
            succeeded = true
        } catch {
            actionErrorMessage = displayMessage(for: error)
        }
        activeAction = nil
        await refresh()
        if succeeded { showNotice(action.successMessage) }
    }

    private func updateLoginItemStatus() {
        let status = loginItemManager.status
        launchAtLoginEnabled = status == .enabled
        launchAtLoginRequiresApproval = status == .requiresApproval
    }

    private func showNotice(_ message: String) {
        noticeTask?.cancel()
        noticeMessage = message
        noticeTask = Task {
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            noticeMessage = nil
        }
    }

    private func displayMessage(for error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? "Wormhole is unavailable."
    }
}
