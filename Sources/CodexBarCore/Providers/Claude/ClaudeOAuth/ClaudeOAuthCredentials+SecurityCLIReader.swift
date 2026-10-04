import Dispatch
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

extension ClaudeOAuthCredentialsStore {
    private static let securityBinaryPath = "/usr/bin/security"
    private static let securityCLIReadTimeout: TimeInterval = 1.5
    static let isolatedSecurityCLIKeychainEnvironmentKey = "CODEXBAR_CLAUDE_SECURITY_CLI_KEYCHAIN"

    struct SecurityCLIReadRequest {
        let account: String?
    }

    static func shouldPreferSecurityCLIKeychainRead(
        readStrategy: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current())
        -> Bool
    {
        readStrategy == .securityCLIExperimental
    }

    #if os(macOS)
    private enum SecurityCLIReadError: Error {
        case binaryUnavailable
        case isolatedKeychainUnavailable
        case launchFailed
        case timedOut
        case nonZeroExit(status: Int32, stderrLength: Int)
    }

    private struct SecurityCLIReadCommandResult {
        let status: Int32
        let stdout: Data
        let stderrLength: Int
        let durationMs: Double
    }

    /// Attempts a Claude keychain read via `/usr/bin/security` when the experimental reader is enabled.
    /// The external reader follows the stored prompt policy because `security` can prompt.
    static func loadFromClaudeKeychainViaSecurityCLIIfEnabled(
        interaction: ProviderInteraction,
        readStrategy: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current())
        -> Data?
    {
        guard let sanitized = self.readRawClaudeKeychainPayloadViaSecurityCLIIfEnabled(
            interaction: interaction,
            readStrategy: readStrategy)
        else {
            return nil
        }

        let interactionMetadata = interaction == .userInitiated ? "user" : "background"
        let parsedCredentials: ClaudeOAuthCredentials
        do {
            parsedCredentials = try ClaudeOAuthCredentials.parse(data: sanitized)
        } catch {
            self.log.warning(
                "Claude keychain security CLI output invalid; falling back",
                metadata: [
                    "reader": "securityCLI",
                    "callerInteraction": interactionMetadata,
                    "payload_bytes": "\(sanitized.count)",
                    "parse_error_type": String(describing: type(of: error)),
                ])
            return nil
        }

        var metadata: [String: String] = [
            "reader": "securityCLI",
            "callerInteraction": interactionMetadata,
            "payload_bytes": "\(sanitized.count)",
        ]
        for (key, value) in parsedCredentials.diagnosticsMetadata(now: Date()) {
            metadata[key] = value
        }
        self.log.debug(
            "Claude keychain security CLI read succeeded",
            metadata: metadata)
        return sanitized
    }

    static func readRawClaudeKeychainPayloadViaSecurityCLIIfEnabled(
        interaction: ProviderInteraction,
        readStrategy: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current(),
        environment: [String: String] = ProcessInfo.processInfo.environment)
        -> Data?
    {
        guard self.shouldPreferSecurityCLIKeychainRead(readStrategy: readStrategy) else { return nil }
        // `/usr/bin/security` is not constrained by Security.framework's no-UI flags. Keep the ownership gate at
        // the process-launch boundary so no caller can bypass it by selecting the experimental reader.
        guard self.keychainAccessAllowed else { return nil }
        let mode = ClaudeOAuthKeychainPromptPreference.storedMode()
        guard mode == .always || mode == .onlyOnUserAction && interaction == .userInitiated else { return nil }
        return self.runSecurityCLIKeychainRead(
            account: self.preferredClaudeKeychainAccountForSecurityCLIRead(interaction: interaction),
            interaction: interaction,
            environment: environment).payload
    }

    /// Whether Claude Code's item is readable through `/usr/bin/security` without a prompt right now: the user
    /// consented to direct reads and a no-UI ACL preflight for that tool returns `.allowed`. The delegated `claude`
    /// refresh reads and rewrites the item through the same tool, so it needs no prompt either.
    static func isClaudeKeychainReadableViaSecurityCLIWithoutPrompt() -> Bool {
        guard self.keychainAccessAllowed, let target = self.securityCLIReadTargetWithoutPrompt() else { return false }
        return KeychainAccessPreflight.checkGenericPassword(
            service: self.claudeKeychainService,
            account: target.account,
            reader: .securityTool) == .allowed
    }

    /// Reads Claude Code's item through `/usr/bin/security` only when that read is proven prompt-free.
    ///
    /// Claude Code writes `Claude Code-credentials` through `/usr/bin/security`, so the item's decrypt ACL and
    /// partition list normally admit that tool and nothing else. Security.framework reads from CodexBar then need a
    /// Keychain dialog, while the same read through `/usr/bin/security` needs none. This path runs only when the
    /// user consented to direct reads and a no-UI ACL preflight evaluated for `/usr/bin/security` returns `.allowed`.
    /// It does not depend on the Security.framework prompt policy because it never asks for interaction. A read that
    /// still times out (the signature of a dialog the preflight did not predict) starts the shared denial cooldown,
    /// which suppresses further background attempts.
    static func readClaudeKeychainViaSecurityCLIWithoutPrompt(
        interaction: ProviderInteraction,
        now: Date = Date(),
        environment: [String: String] = ProcessInfo.processInfo.environment) -> Data?
    {
        guard self.keychainAccessAllowed else { return nil }
        let interactionMetadata = interaction == .userInitiated ? "user" : "background"
        if interaction != .userInitiated, !ClaudeOAuthKeychainAccessGate.shouldAllowPrompt(now: now) {
            self.log.debug(
                "Claude keychain security CLI no-prompt read skipped during denial cooldown",
                metadata: ["reader": "securityCLI", "callerInteraction": interactionMetadata])
            return nil
        }
        guard let target = self.securityCLIReadTargetWithoutPrompt() else { return nil }
        let preflight = KeychainAccessPreflight.checkGenericPassword(
            service: self.claudeKeychainService,
            account: target.account,
            reader: .securityTool)
        guard preflight == .allowed else {
            self.log.info(
                "Claude keychain item is not readable by /usr/bin/security without a prompt; skipping",
                metadata: [
                    "reader": "securityCLI",
                    "callerInteraction": interactionMetadata,
                    "preflight": String(describing: preflight),
                ])
            return nil
        }
        let result = self.runSecurityCLIKeychainRead(
            account: target.account,
            interaction: interaction,
            environment: environment)
        if result.timedOut {
            ClaudeOAuthKeychainAccessGate.recordDenied(now: now)
        }
        return result.payload
    }

    private struct SecurityCLIKeychainReadResult {
        var payload: Data?
        var timedOut = false
    }

    private static func runSecurityCLIKeychainRead(
        account preferredAccount: String?,
        interaction: ProviderInteraction,
        environment: [String: String]) -> SecurityCLIKeychainReadResult
    {
        let interactionMetadata = interaction == .userInitiated ? "user" : "background"

        do {
            let output: Data
            let status: Int32
            let stderrLength: Int
            let durationMs: Double
            #if DEBUG
            if let override = self.taskSecurityCLIReadOverride {
                switch override {
                case let .data(data):
                    output = data ?? Data()
                    status = 0
                    stderrLength = 0
                    durationMs = 0
                case .timedOut:
                    throw SecurityCLIReadError.timedOut
                case .nonZeroExit:
                    throw SecurityCLIReadError.nonZeroExit(status: 1, stderrLength: 0)
                case let .dynamic(read):
                    output = read(SecurityCLIReadRequest(account: preferredAccount)) ?? Data()
                    status = 0
                    stderrLength = 0
                    durationMs = 0
                }
            } else {
                let result = try self.runClaudeSecurityCLIRead(
                    timeout: self.securityCLIReadTimeout,
                    account: preferredAccount,
                    environment: environment)
                output = result.stdout
                status = result.status
                stderrLength = result.stderrLength
                durationMs = result.durationMs
            }
            #else
            let result = try self.runClaudeSecurityCLIRead(
                timeout: self.securityCLIReadTimeout,
                account: preferredAccount,
                environment: environment)
            output = result.stdout
            status = result.status
            stderrLength = result.stderrLength
            durationMs = result.durationMs
            #endif

            let sanitized = self.sanitizeSecurityCLIOutput(output)
            guard !sanitized.isEmpty else { return SecurityCLIKeychainReadResult() }
            if ClaudeOAuthCredentials.isMcpOAuthOnlyPayload(data: sanitized) {
                self.log.warning(
                    "Claude keychain security CLI output is MCP OAuth only; falling back",
                    metadata: [
                        "reader": "securityCLI",
                        "callerInteraction": interactionMetadata,
                        "status": "\(status)",
                        "duration_ms": String(format: "%.2f", durationMs),
                        "stderr_length": "\(stderrLength)",
                        "payload_bytes": "\(sanitized.count)",
                    ])
            } else {
                self.log.debug(
                    "Claude keychain security CLI raw read succeeded",
                    metadata: [
                        "reader": "securityCLI",
                        "callerInteraction": interactionMetadata,
                        "status": "\(status)",
                        "duration_ms": String(format: "%.2f", durationMs),
                        "stderr_length": "\(stderrLength)",
                        "payload_bytes": "\(sanitized.count)",
                    ])
            }
            return SecurityCLIKeychainReadResult(payload: sanitized)
        } catch let error as SecurityCLIReadError {
            var metadata: [String: String] = [
                "reader": "securityCLI",
                "callerInteraction": interactionMetadata,
                "error_type": String(describing: type(of: error)),
            ]
            switch error {
            case .binaryUnavailable:
                metadata["reason"] = "binaryUnavailable"
            case .isolatedKeychainUnavailable:
                metadata["reason"] = "isolatedKeychainUnavailable"
            case .launchFailed:
                metadata["reason"] = "launchFailed"
            case .timedOut:
                metadata["reason"] = "timedOut"
            case let .nonZeroExit(status, stderrLength):
                metadata["reason"] = "nonZeroExit"
                metadata["status"] = "\(status)"
                metadata["stderr_length"] = "\(stderrLength)"
            }
            self.log.warning("Claude keychain security CLI read failed; falling back", metadata: metadata)
            if case .timedOut = error {
                return SecurityCLIKeychainReadResult(timedOut: true)
            }
            return SecurityCLIKeychainReadResult()
        } catch {
            self.log.warning(
                "Claude keychain security CLI read failed; falling back",
                metadata: [
                    "reader": "securityCLI",
                    "callerInteraction": interactionMetadata,
                    "error_type": String(describing: type(of: error)),
                ])
            return SecurityCLIKeychainReadResult()
        }
    }

    private static func sanitizeSecurityCLIOutput(_ data: Data) -> Data {
        var sanitized = data
        while let last = sanitized.last, last == 0x0A || last == 0x0D {
            sanitized.removeLast()
        }
        return sanitized
    }

    private static func runClaudeSecurityCLIRead(
        timeout: TimeInterval,
        account: String?,
        environment: [String: String]) throws -> SecurityCLIReadCommandResult
    {
        guard FileManager.default.isExecutableFile(atPath: self.securityBinaryPath) else {
            throw SecurityCLIReadError.binaryUnavailable
        }
        guard let arguments = self.securityCLIReadArguments(account: account, environment: environment) else {
            throw SecurityCLIReadError.isolatedKeychainUnavailable
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: self.securityBinaryPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        process.standardInput = nil

        let startedAt = DispatchTime.now().uptimeNanoseconds
        do {
            try process.run()
        } catch {
            throw SecurityCLIReadError.launchFailed
        }

        var processGroup: pid_t?
        let pid = process.processIdentifier
        if setpgid(pid, pid) == 0 {
            processGroup = pid
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }

        if process.isRunning {
            self.terminate(process: process, processGroup: processGroup)
            throw SecurityCLIReadError.timedOut
        }

        let stdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let status = process.terminationStatus
        let durationMs = Double(DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000.0
        guard status == 0 else {
            throw SecurityCLIReadError.nonZeroExit(status: status, stderrLength: stderr.count)
        }

        return SecurityCLIReadCommandResult(
            status: status,
            stdout: stdout,
            stderrLength: stderr.count,
            durationMs: durationMs)
    }

    static func securityCLIReadArguments(
        account: String?,
        environment: [String: String]) -> [String]?
    {
        let isolatedKeychainPath = self.isolatedSecurityCLIKeychainPath(environment: environment)
        if KeychainTestSafety.shouldBlockRealKeychainAccess(environment: environment),
           isolatedKeychainPath == nil
        {
            return nil
        }

        var arguments = [
            "find-generic-password",
            "-s",
            self.claudeKeychainService,
        ]
        if let account, !account.isEmpty {
            arguments.append(contentsOf: ["-a", account])
        }
        arguments.append("-w")

        let rawIsolatedPath = environment[self.isolatedSecurityCLIKeychainEnvironmentKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if rawIsolatedPath != nil || KeychainAccessGate.isDisabledByEnvironment(environment) {
            guard let isolatedKeychainPath else {
                return nil
            }
            arguments.append(isolatedKeychainPath)
        }
        return arguments
    }

    private static func terminate(process: Process, processGroup: pid_t?) {
        guard process.isRunning else { return }
        process.terminate()
        if let processGroup {
            kill(-processGroup, SIGTERM)
        }
        let deadline = Date().addingTimeInterval(0.4)
        while process.isRunning, Date() < deadline {
            usleep(50000)
        }
        if process.isRunning {
            if let processGroup {
                kill(-processGroup, SIGKILL)
            }
            kill(process.processIdentifier, SIGKILL)
        }
    }
    #else
    static func loadFromClaudeKeychainViaSecurityCLIIfEnabled(
        interaction _: ProviderInteraction,
        readStrategy _: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current())
        -> Data?
    {
        nil
    }

    static func readRawClaudeKeychainPayloadViaSecurityCLIIfEnabled(
        interaction _: ProviderInteraction,
        readStrategy _: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current(),
        environment _: [String: String] = ProcessInfo.processInfo.environment)
        -> Data?
    {
        nil
    }

    static func isClaudeKeychainReadableViaSecurityCLIWithoutPrompt() -> Bool {
        false
    }

    static func readClaudeKeychainViaSecurityCLIWithoutPrompt(
        interaction _: ProviderInteraction,
        now _: Date = Date(),
        environment _: [String: String] = ProcessInfo.processInfo.environment) -> Data?
    {
        nil
    }
    #endif

    private static func isolatedSecurityCLIKeychainPath(environment: [String: String]) -> String? {
        guard KeychainAccessGate.isDisabledByEnvironment(environment) else { return nil }
        guard let rawPath = environment[self.isolatedSecurityCLIKeychainEnvironmentKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !rawPath.isEmpty,
            (rawPath as NSString).isAbsolutePath
        else {
            return nil
        }
        return URL(fileURLWithPath: rawPath).standardizedFileURL.path
    }

    static func isMcpOAuthOnlyClaudeKeychainPayloadPresent(
        interaction: ProviderInteraction,
        readStrategy: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current(),
        keychainAccessDisabled: Bool = KeychainAccessGate.isDisabled,
        environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool
    {
        guard !keychainAccessDisabled || self.isolatedSecurityCLIKeychainPath(environment: environment) != nil else {
            return false
        }
        let promptMode = ClaudeOAuthKeychainPromptPreference.effectiveMode(readStrategy: readStrategy)
        guard promptMode != .never else {
            return false
        }
        // A Security.framework query configured as "no UI" can still display a legacy Keychain ACL dialog.
        // Respect the user-action-only policy before background discovery touches Claude Code credentials.
        guard readStrategy != .securityFramework
            || promptMode != .onlyOnUserAction
            || interaction == .userInitiated
        else {
            return false
        }
        let payload: Data? = switch readStrategy {
        case .securityFramework:
            self.readRawClaudeKeychainPayloadViaSecurityFrameworkWithoutPrompt()
        case .securityCLIExperimental:
            self.readRawClaudeKeychainPayloadViaSecurityCLIIfEnabled(
                interaction: interaction,
                readStrategy: readStrategy,
                environment: environment)
        }
        guard let payload else { return false }
        return ClaudeOAuthCredentials.isMcpOAuthOnlyPayload(data: payload)
    }

    static func shouldBlockSelectedProfileForMcpOnlyClaudeKeychain(
        interaction: ProviderInteraction,
        readStrategy: ClaudeOAuthKeychainReadStrategy = ClaudeOAuthKeychainReadStrategyPreference.current(),
        keychainAccessDisabled: Bool = KeychainAccessGate.isDisabled,
        environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool
    {
        // The global Keychain item has no profile identity. It can diagnose a missing selected profile,
        // but cannot veto an OAuth credentials file attributable to that profile.
        guard !self.hasSelectedProfileOAuthCredentialsFile(environment: environment) else { return false }
        return self.isMcpOAuthOnlyClaudeKeychainPayloadPresent(
            interaction: interaction,
            readStrategy: readStrategy,
            keychainAccessDisabled: keychainAccessDisabled,
            environment: environment)
    }
}
