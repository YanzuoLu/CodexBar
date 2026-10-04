import Foundation
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct ClaudeOAuthSecurityCLINoPromptReadTests {
    private typealias Store = ClaudeOAuthCredentialsStore

    private final class Recorder: @unchecked Sendable {
        var securityReads: [String?] = []
        var preflightReaders: [KeychainAccessPreflight.Reader] = []
    }

    private static func credentialsData(accessToken: String) -> Data {
        let millis = Int(Date(timeIntervalSinceNow: 3600).timeIntervalSince1970 * 1000)
        return Data("""
        {"claudeAiOauth":{"accessToken":"\(accessToken)","expiresAt":\(millis),"scopes":["user:profile"]}}
        """.utf8)
    }

    /// Loads like the app's background refresh and `codexbar usage --source oauth`: no interactive prompt,
    /// consented Keychain repair enabled (disabled for Auto's safe-source-only loads), and Claude Code's item ACL
    /// rejecting CodexBar itself.
    private static func loadInBackground(
        consent: Bool,
        promptMode: ClaudeOAuthKeychainPromptMode = .onlyOnUserAction,
        securityToolPreflight: KeychainAccessPreflight.Outcome,
        securityRead: Store.SecurityCLIReadOverride,
        deniedUntil: ClaudeOAuthKeychainAccessGate.DeniedUntilStore = .init(),
        itemPresent: Bool? = nil,
        safeSourcesOnly: Bool = false,
        recorder: Recorder) throws -> ClaudeOAuthCredentialRecord
    {
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("credentials.json")
        let recordingRead: Store.SecurityCLIReadOverride = switch securityRead {
        case let .data(data):
            .dynamic { request in
                recorder.securityReads.append(request.account)
                return data
            }
        default:
            securityRead
        }
        return try KeychainCacheStore.withServiceOverrideForTesting("com.steipete.codexbar.cache.tests.\(UUID())") {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }
                return try Store.withIsolatedMemoryCacheForTesting {
                    try Store.withCredentialsURLOverrideForTesting(fileURL) {
                        try ClaudeOAuthDirectKeychainReadConsent.withTaskOverrideForTesting(consent) {
                            try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(promptMode) {
                                try ClaudeOAuthKeychainAccessGate.withDeniedUntilStoreOverrideForTesting(deniedUntil) {
                                    try KeychainAccessPreflight.withReaderCheckGenericPasswordOverrideForTesting
                                        { _, _, reader in
                                            recorder.preflightReaders.append(reader)
                                            // Claude Code's ACL trusts only /usr/bin/security.
                                            return reader == .securityTool
                                                ? securityToolPreflight
                                                : .interactionRequired
                                        } operation: {
                                            try Self.loadWithSecurityCLIOverrides(
                                                read: recordingRead,
                                                itemPresent: itemPresent,
                                                safeSourcesOnly: safeSourcesOnly)
                                        }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static func loadWithSecurityCLIOverrides(
        read: Store.SecurityCLIReadOverride,
        itemPresent: Bool?,
        safeSourcesOnly: Bool) throws -> ClaudeOAuthCredentialRecord
    {
        try Store.withSecurityCLIReadAccountOverrideForTesting("claude-user") {
            try Store.withClaudeKeychainItemPresenceOverrideForTesting(itemPresent) {
                try Store.withSecurityCLIReadOverrideForTesting(read) {
                    try ProviderInteractionContext.$current.withValue(.background) {
                        try Store.loadRecord(
                            environment: [:],
                            allowKeychainPrompt: false,
                            respectKeychainPromptCooldown: true,
                            allowClaudeKeychainRepairWithoutPrompt: !safeSourcesOnly)
                    }
                }
            }
        }
    }

    @Test(arguments: [ClaudeOAuthKeychainPromptMode.never, .onlyOnUserAction, .always])
    func `consented background load reads claude keychain through security CLI without prompt policy`(
        mode: ClaudeOAuthKeychainPromptMode) throws
    {
        let recorder = Recorder()
        let record = try Self.loadInBackground(
            consent: true,
            promptMode: mode,
            securityToolPreflight: .allowed,
            securityRead: .data(Self.credentialsData(accessToken: "security-cli-token")),
            recorder: recorder)

        #expect(record.credentials.accessToken == "security-cli-token")
        #expect(record.owner == .claudeCLI)
        #expect(record.source == .claudeKeychain)
        #expect(recorder.securityReads == ["claude-user"])
        #expect(recorder.preflightReaders.contains(.securityTool))
    }

    @Test
    func `auto safe-source load reads claude keychain through security CLI without prompt`() throws {
        let recorder = Recorder()
        let record = try Self.loadInBackground(
            consent: true,
            promptMode: .never,
            securityToolPreflight: .allowed,
            securityRead: .data(Self.credentialsData(accessToken: "auto-security-cli-token")),
            safeSourcesOnly: true,
            recorder: recorder)

        #expect(record.credentials.accessToken == "auto-security-cli-token")
        #expect(record.source == .claudeKeychain)
        #expect(recorder.securityReads == ["claude-user"])
        #expect(!recorder.preflightReaders.contains(.currentProcess))
    }

    @Test
    func `security CLI read stays closed without direct read consent`() {
        let recorder = Recorder()
        #expect(throws: ClaudeOAuthCredentialsError.self) {
            try Self.loadInBackground(
                consent: false,
                securityToolPreflight: .allowed,
                securityRead: .data(Self.credentialsData(accessToken: "must-not-read")),
                recorder: recorder)
        }
        #expect(recorder.securityReads.isEmpty)
    }

    @Test
    func `item that would prompt security CLI is reported as unreadable instead of missing`() {
        let recorder = Recorder()
        do {
            _ = try Self.loadInBackground(
                consent: true,
                securityToolPreflight: .interactionRequired,
                securityRead: .data(Self.credentialsData(accessToken: "must-not-read")),
                itemPresent: true,
                recorder: recorder)
            Issue.record("Expected an unreadable-item error")
        } catch let error as ClaudeOAuthCredentialsError {
            guard case .keychainReadRequiresInteraction = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(error.localizedDescription.contains("cannot read it without a macOS Keychain prompt"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(recorder.securityReads.isEmpty)
    }

    @Test
    func `security CLI timeout starts the background cooldown`() {
        let deniedUntil = ClaudeOAuthKeychainAccessGate.DeniedUntilStore()
        let first = Recorder()
        #expect(throws: ClaudeOAuthCredentialsError.self) {
            try Self.loadInBackground(
                consent: true,
                securityToolPreflight: .allowed,
                securityRead: .timedOut,
                deniedUntil: deniedUntil,
                recorder: first)
        }
        #expect(deniedUntil.deniedUntil != nil)

        let second = Recorder()
        #expect(throws: ClaudeOAuthCredentialsError.self) {
            try Self.loadInBackground(
                consent: true,
                securityToolPreflight: .allowed,
                securityRead: .data(Self.credentialsData(accessToken: "skipped-during-cooldown")),
                deniedUntil: deniedUntil,
                recorder: second)
        }
        #expect(second.securityReads.isEmpty)
        #expect(!second.preflightReaders.contains(.securityTool))
    }

    @Test
    func `terminal classification separates unreadable items from missing credentials`() {
        func classify(consent: Bool, itemPresent: Bool) -> ClaudeOAuthCredentialsError {
            ClaudeOAuthCredentialsStore.classifyTerminalMissingCredentialsError(
                directReadConsentGranted: consent,
                keychainAccessDisabled: false,
                keychainAccessDenied: false,
                previousKeychainGrantRecorded: false,
                loggedInProfilePresent: true,
                claudeKeychainItemPresent: itemPresent)
        }
        guard case .keychainReadRequiresInteraction = classify(consent: true, itemPresent: true) else {
            Issue.record("Consented unreadable item must not be reported as missing")
            return
        }
        guard case .notFound = classify(consent: true, itemPresent: false),
              case .notFound = classify(consent: false, itemPresent: true)
        else {
            Issue.record("Absent item or missing consent must stay typed absence")
            return
        }
    }

    @Test
    func `partition ACL description decodes apple tool partition`() {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string></array></dict></plist>
        """
        let hex = Data(plist.utf8).map { String(format: "%02x", $0) }.joined()

        #expect(KeychainAccessPreflight.partitionIDs(fromACLDescription: hex) == ["apple-tool:"])
        #expect(KeychainAccessPreflight.partitionIDs(fromACLDescription: "Claude Code-credentials") == nil)
    }
}
