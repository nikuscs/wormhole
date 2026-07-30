import Foundation
import Testing
@testable import WormholeMenuBar

@Test func commandFailureIncludesBoundedStderrDiagnostic() async throws {
    let executable = try temporaryExecutable(
        script: "#!/bin/sh\nprintf 'invalid remote configuration\\n' >&2\nexit 7\n"
    )
    defer { try? FileManager.default.removeItem(at: executable.deletingLastPathComponent()) }
    let client = CLIClient(executable: executable)

    do {
        _ = try await client.status()
        Issue.record("Expected the command to fail")
    } catch let error as CLIClientError {
        guard case let .commandFailed(code, detail) = error else {
            Issue.record("Expected commandFailed, received \(error)")
            return
        }
        #expect(code == 7)
        #expect(detail == "invalid remote configuration")
        #expect(error.errorDescription?.contains("invalid remote configuration") == true)
    }
}

@Test func processRunnerTimesOutAndTerminatesTheCommand() async throws {
    let clock = ContinuousClock()
    let started = clock.now

    do {
        _ = try await ProcessRunner(timeout: .milliseconds(50)).run(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["2"]
        )
        Issue.record("Expected the command to time out")
    } catch let error as CLIClientError {
        #expect(error == .timedOut)
    }

    #expect(started.duration(to: clock.now) < .seconds(1))
}

@Test func cancellingProcessRunnerTerminatesTheCommand() async throws {
    let runner = ProcessRunner(timeout: .seconds(10))
    let task = Task {
        try await runner.run(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["2"]
        )
    }
    try await Task.sleep(for: .milliseconds(50))
    task.cancel()

    do {
        _ = try await task.value
        Issue.record("Expected cancellation")
    } catch is CancellationError {
        // Expected.
    }
}

private func temporaryExecutable(script: String) throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("wormhole-menu-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let executable = directory.appendingPathComponent("wormhole-test")
    try Data(script.utf8).write(to: executable)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return executable
}
