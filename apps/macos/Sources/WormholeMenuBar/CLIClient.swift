import Darwin
import Foundation

let installCommand = "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormhole-cli-installer.sh | sh"

struct CLILocator {
    var environment: [String: String] = ProcessInfo.processInfo.environment
    var homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    var isExecutable: (String) -> Bool = FileManager.default.isExecutableFile(atPath:)

    func locate() -> URL? {
        var paths = [String]()
        if let override = environment["WORMHOLE_CLI_PATH"], !override.isEmpty {
            paths.append(NSString(string: override).expandingTildeInPath)
        }
        paths += (environment["PATH"] ?? "").split(separator: ":").map { "\($0)/wormhole" }
        paths += [
            homeDirectory.appendingPathComponent(".local/bin/wormhole").path,
            homeDirectory.appendingPathComponent(".cargo/bin/wormhole").path,
            "/opt/homebrew/bin/wormhole",
            "/usr/local/bin/wormhole",
        ]
        var visited = Set<String>()
        return paths.first { visited.insert($0).inserted && isExecutable($0) }.map(URL.init(fileURLWithPath:))
    }

    func runtimeDirectory() -> URL {
        if let override = environment["WORMHOLE_STATE_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: NSString(string: override).expandingTildeInPath)
        }
        if let runtime = environment["XDG_RUNTIME_DIR"], !runtime.isEmpty {
            return URL(fileURLWithPath: runtime).appendingPathComponent("wormhole", isDirectory: true)
        }
        return homeDirectory.appendingPathComponent("Library/Application Support/wormhole", isDirectory: true)
    }
}

struct CommandResult {
    let standardOutput: Data
    let standardError: Data
    let terminationStatus: Int32
}

enum CLIClientError: LocalizedError, Equatable {
    case commandFailed(Int32, String?)
    case invalidOutput
    case timedOut

    var errorDescription: String? {
        switch self {
        case let .commandFailed(code, detail):
            if let detail { "Wormhole command failed: \(detail) (exit \(code))." }
            else { "Wormhole command failed (exit \(code))." }
        case .invalidOutput: "Wormhole returned an unsupported response. Update the CLI and try again."
        case .timedOut: "Wormhole did not respond in time. Check the daemon logs and try again."
        }
    }
}

struct ProcessRunner {
    var timeout: Duration = .seconds(15)

    func run(executable: URL, arguments: [String]) async throws -> CommandResult {
        try Task.checkCancellation()
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = errors
        try process.run()

        async let outputData = output.fileHandleForReading.readToEnd()
        async let errorData = errors.fileHandleForReading.readToEnd()
        let exitedNormally = await waitForExit(process)
        let capturedOutput = try await outputData ?? Data()
        let capturedError = try await errorData ?? Data()
        try Task.checkCancellation()
        guard exitedNormally else { throw CLIClientError.timedOut }
        return CommandResult(
            standardOutput: capturedOutput,
            standardError: capturedError,
            terminationStatus: process.terminationStatus
        )
    }

    private func waitForExit(_ process: Process) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await Task.detached { process.waitUntilExit() }.value
                return true
            }
            group.addTask {
                do {
                    try await Task.sleep(for: timeout)
                    return false
                } catch {
                    return false
                }
            }
            let exitedNormally = await group.next() ?? false
            if !exitedNormally, process.isRunning {
                process.terminate()
                try? await Task.sleep(for: .milliseconds(200))
                if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            }
            group.cancelAll()
            return exitedNormally
        }
    }
}

protocol WormholeClient {
    func status() async throws -> DaemonStatus
    func endpoints() async throws -> [Endpoint]
    func startDaemon() async throws
    func stopDaemon() async throws
    func reloadDaemon() async throws
    func stopEndpoint(_ id: UUID) async throws
}

struct CLIClient: WormholeClient {
    let executable: URL
    var runner = ProcessRunner()

    func status() async throws -> DaemonStatus {
        try await decode(DaemonStatus.self, arguments: ["--json", "status"])
    }

    func endpoints() async throws -> [Endpoint] {
        try await decode([Endpoint].self, arguments: ["--json", "ls"])
    }

    func startDaemon() async throws {
        _ = try await status()
    }

    func stopDaemon() async throws {
        try await command(["--json", "daemon", "stop"])
    }

    func reloadDaemon() async throws {
        try await command(["--json", "daemon", "reload"])
    }

    func stopEndpoint(_ id: UUID) async throws {
        try await command(["--json", "down", id.uuidString.lowercased()])
    }

    private func decode<T: Decodable>(_ type: T.Type, arguments: [String]) async throws -> T {
        let result = try await runner.run(executable: executable, arguments: arguments)
        try validate(result)
        do {
            return try JSONDecoder().decode(type, from: result.standardOutput)
        } catch {
            throw CLIClientError.invalidOutput
        }
    }

    private func command(_ arguments: [String]) async throws {
        try validate(try await runner.run(executable: executable, arguments: arguments))
    }

    private func validate(_ result: CommandResult) throws {
        guard result.terminationStatus == 0 else {
            throw CLIClientError.commandFailed(result.terminationStatus, diagnostic(from: result.standardError))
        }
    }

    private func diagnostic(from data: Data) -> String? {
        let message = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: " ")
        guard !message.isEmpty else { return nil }
        return String(message.prefix(500))
    }
}
