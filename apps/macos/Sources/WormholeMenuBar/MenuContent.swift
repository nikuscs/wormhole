import SwiftUI

struct MenuContent: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Group {
            daemonControl
            daemonSummary
            operationFeedback
            Divider()
            endpointItems
            Divider()
            daemonActions
            Divider()
            appActions
            Divider()
            Button("Quit Wormhole") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
        }
    }

    private var daemonControl: some View {
        Toggle("Wormhole Daemon", isOn: daemonBinding)
            .disabled(model.cliURL == nil || model.isPerformingAction)
    }

    @ViewBuilder
    private var daemonSummary: some View {
        if model.cliURL == nil {
            Label("CLI not installed", systemImage: "exclamationmark.triangle")
                .disabled(true)
        } else if let status = model.daemonStatus {
            Label(
                "Running · v\(status.version) · \(status.services) services",
                systemImage: "checkmark.circle.fill"
            )
            .disabled(true)
        } else {
            Label("Stopped", systemImage: "stop.circle")
                .disabled(true)
        }
    }

    @ViewBuilder
    private var operationFeedback: some View {
        if let action = model.activeAction {
            Label(action.progressLabel, systemImage: "hourglass")
                .disabled(true)
        }
        if model.isRefreshing {
            Label("Refreshing…", systemImage: "arrow.clockwise")
                .disabled(true)
        }
        if let message = model.noticeMessage {
            Label(message, systemImage: "checkmark.circle")
                .disabled(true)
        }
        if let message = model.actionErrorMessage {
            errorMenu(title: "Wormhole action failed", message: message)
        }
        if let message = model.refreshErrorMessage {
            errorMenu(title: "Wormhole refresh failed", message: message)
        }
    }

    @ViewBuilder
    private var endpointItems: some View {
        if model.cliURL == nil {
            Button("Copy Install Command") {
                model.copy(installCommand, label: "Install command copied.")
            }
        } else if model.daemonStatus == nil {
            Label("No active daemon", systemImage: "moon.zzz")
                .disabled(true)
        } else if model.endpoints.isEmpty {
            Label("No active tunnels", systemImage: "circle.dotted")
                .disabled(true)
        } else {
            Section("Tunnels") {
                ForEach(model.endpoints) { endpoint in
                    endpointMenu(endpoint)
                }
            }
        }
    }

    @ViewBuilder
    private var daemonActions: some View {
        Button("Refresh", systemImage: "arrow.clockwise") {
            Task { await model.refresh() }
        }
        .keyboardShortcut("r")
        .disabled(model.isPerformingAction)

        Button("View Logs", systemImage: "doc.text.magnifyingglass") {
            model.viewLogs()
        }

        if model.daemonStatus != nil {
            Button("Reload Configuration", systemImage: "arrow.triangle.2.circlepath") {
                Task { await model.reloadDaemon() }
            }
            .disabled(model.isPerformingAction)

            Button("Stop Daemon…", systemImage: "stop.circle", role: .destructive) {
                Task { await model.confirmAndStopDaemon() }
            }
            .disabled(model.isPerformingAction)
        }
    }

    @ViewBuilder
    private var appActions: some View {
        Toggle("Launch at Login", isOn: launchAtLoginBinding)
            .disabled(model.isPerformingAction)
        if model.launchAtLoginRequiresApproval {
            Button("Open Login Items Settings", systemImage: "gear") {
                model.openLoginItemSettings()
            }
        }
    }

    private var daemonBinding: Binding<Bool> {
        Binding(
            get: { model.daemonStatus != nil },
            set: { enabled in
                Task {
                    if enabled { await model.startDaemon() }
                    else { await model.confirmAndStopDaemon() }
                }
            }
        )
    }

    private var launchAtLoginBinding: Binding<Bool> {
        Binding(
            get: { model.launchAtLoginEnabled },
            set: { enabled in Task { await model.setLaunchAtLoginEnabled(enabled) } }
        )
    }

    private func errorMenu(title: String, message: String) -> some View {
        Menu {
            Text(message).disabled(true)
            Divider()
            Button("Dismiss") { model.dismissMessages() }
        } label: {
            Label(title, systemImage: "exclamationmark.triangle.fill")
        }
    }

    private func endpointMenu(_ endpoint: Endpoint) -> some View {
        Menu {
            Label("\(endpoint.status.label) · \(endpoint.driver)", systemImage: endpoint.status.symbol)
                .disabled(true)
            if let detail = endpoint.status.detail {
                Text(detail).disabled(true)
            }
            if endpoint.urls.isEmpty {
                Text("No public URLs").disabled(true)
            } else {
                Divider()
                ForEach(endpoint.urls, id: \.self) { url in
                    urlMenu(url)
                }
            }
            if endpoint.bufferedPending > 0 || endpoint.bufferedFailed > 0 {
                Divider()
                Text("Buffered: \(endpoint.bufferedPending) pending · \(endpoint.bufferedFailed) failed")
                    .disabled(true)
            }
            Divider()
            Button("Stop Endpoint", role: .destructive) {
                Task { await model.stopEndpoint(endpoint) }
            }
            .disabled(model.isPerformingAction)
        } label: {
            Label(endpoint.service, systemImage: endpoint.status.symbol)
        }
    }

    private func urlMenu(_ url: String) -> some View {
        Menu(url) {
            if url.hasPrefix("http://") || url.hasPrefix("https://") {
                Button("Open in Browser", systemImage: "arrow.up.right.square") {
                    model.open(url)
                }
            }
            Button("Copy URL", systemImage: "doc.on.doc") {
                model.copy(url, label: "URL copied.")
            }
        }
    }
}
