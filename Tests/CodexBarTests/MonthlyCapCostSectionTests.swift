import Foundation
import Testing
@testable import CodexBar
@testable import CodexBarCLI
@testable import CodexBarCore

/// Claude extra usage and Codex monthly credit limits are monthly caps: their existing cost sections show the
/// percent in the used/remaining preference, the reset, and calendar-month pace, in the menu card and the CLI.
struct MonthlyCapCostSectionTests {
    private static func date(_ value: String) throws -> Date {
        try #require(ISO8601DateFormatter().date(from: value))
    }

    /// 3.5 of October's 31 days have elapsed, so pace expects 11% used.
    private static func now() throws -> Date {
        try self.date("2026-10-04T12:00:00Z")
    }

    private static func nextMonth() throws -> Date {
        try self.date("2026-11-01T00:00:00Z")
    }

    /// A Claude Enterprise account: no session or weekly window, only the spend limit.
    private static func claudeEnterpriseSnapshot() throws -> UsageSnapshot {
        let now = try Self.now()
        return try UsageSnapshot(
            primary: nil,
            secondary: nil,
            providerCost: ProviderCostSnapshot(
                used: 1042.24,
                limit: 10000,
                currencyCode: "USD",
                period: "Spend limit",
                resetsAt: Self.nextMonth(),
                updatedAt: now),
            updatedAt: now,
            identity: ProviderIdentitySnapshot(
                providerID: .claude,
                accountEmail: nil,
                accountOrganization: nil,
                loginMethod: "Claude Enterprise"))
    }

    private static func codexBusinessCredits() throws -> CreditsSnapshot {
        let now = try Self.now()
        return try CreditsSnapshot(
            remaining: 0,
            events: [],
            updatedAt: now,
            codexCreditLimit: CodexCreditLimitSnapshot(
                used: 29356.8,
                limit: 250_000,
                remainingPercent: 88,
                resetsAt: Self.nextMonth(),
                updatedAt: now))
    }

    private static func codexProjection(
        surface: CodexConsumerProjection.Surface,
        snapshot: UsageSnapshot,
        credits: CreditsSnapshot) throws -> CodexConsumerProjection
    {
        try CodexConsumerProjection.make(
            surface: surface,
            context: CodexConsumerProjection.Context(
                snapshot: snapshot,
                rawUsageError: nil,
                liveCredits: credits,
                rawCreditsError: nil,
                liveDashboard: nil,
                rawDashboardError: nil,
                dashboardAttachmentAuthorized: false,
                dashboardRequiresLogin: false,
                now: Self.now()))
    }

    private static func cardModel(
        provider: UsageProvider,
        snapshot: UsageSnapshot,
        credits: CreditsSnapshot? = nil,
        projection: CodexConsumerProjection? = nil,
        showUsed: Bool) throws -> UsageMenuCardView.Model
    {
        let metadata = try #require(ProviderDefaults.metadata[provider])
        return try UsageMenuCardView.Model.make(.init(
            provider: provider,
            metadata: metadata,
            snapshot: snapshot,
            codexProjection: projection,
            credits: credits,
            creditsError: nil,
            dashboardError: nil,
            tokenSnapshot: nil,
            tokenError: nil,
            account: AccountInfo(email: nil, plan: nil),
            isRefreshing: false,
            lastError: nil,
            usageBarsShowUsed: showUsed,
            resetTimeDisplayStyle: .countdown,
            tokenCostUsageEnabled: false,
            showOptionalCreditsAndExtraUsage: true,
            hidePersonalInfo: false,
            now: Self.now()))
    }

    private static func renderText(
        provider: UsageProvider,
        snapshot: UsageSnapshot,
        credits: CreditsSnapshot? = nil) throws -> String
    {
        try CLIRenderer.renderText(
            provider: provider,
            snapshot: snapshot,
            credits: credits,
            context: RenderContext(header: "Header", status: nil, useColor: false, resetStyle: .countdown),
            now: Self.now())
    }

    private static func jsonObject(provider: UsageProvider, snapshot: UsageSnapshot) throws -> [String: Any] {
        let payload = try ProviderPayload(
            provider: provider,
            account: nil,
            version: nil,
            source: "oauth",
            status: nil,
            usage: snapshot,
            credits: nil,
            antigravityPlanInfo: nil,
            openaiDashboard: nil,
            error: nil,
            pace: CLIRenderer.providerPacePayload(provider: provider, snapshot: snapshot, now: Self.now()))
        let data = try JSONEncoder().encode(payload)
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test
    func `claude oauth spend limit resets at the start of the next local calendar month`() throws {
        let json = """
        {
          "five_hour": null, "seven_day": null, "seven_day_opus": null, "seven_day_sonnet": null,
          "extra_usage": {
            "is_enabled": true, "monthly_limit": 1000000, "used_credits": 104224.0,
            "utilization": 10.4224, "currency": "USD"
          }
        }
        """
        let usage = try ClaudeUsageFetcher._mapOAuthUsageForTesting(Data(json.utf8), subscriptionType: "enterprise")
        let snapshot = ClaudeOAuthFetchStrategy._snapshotForTesting(from: usage)

        let cost = try #require(snapshot.providerCost)
        let resetsAt = try #require(cost.resetsAt)
        #expect(resetsAt == Calendar.current.dateInterval(of: .month, for: cost.updatedAt)?.end)
        #expect(snapshot.primary == nil)
        #expect(snapshot.extraRateWindows == nil)
        #expect(abs((snapshot.claudeSpendLimitWindow?.usedPercent ?? 0) - 10.4224) < 0.0001)
    }

    @Test(arguments: [true, false])
    func `claude extra usage section shows percent reset and calendar month pace`(showUsed: Bool) throws {
        let model = try Self.cardModel(provider: .claude, snapshot: Self.claudeEnterpriseSnapshot(), showUsed: showUsed)

        let section = try #require(model.providerCost)
        #expect(section.title == "Extra usage")
        #expect(section.spendLine == "Spend limit: $1,042.24 / $10,000.00")
        #expect(section.percentLine == (showUsed ? "10% used" : "90% left"))
        let displayPercent = try #require(section.displayPercent)
        #expect(abs(displayPercent - (showUsed ? 10.4224 : 89.5776)) < 0.0001)
        #expect(section.resetText?.hasPrefix("Resets in") == true)
        let pace = try #require(section.pace)
        #expect(pace.leftLabel == "On pace")
        #expect(pace.rightLabel == "Lasts until reset")
        #expect(section.cycleLine == "\(section.resetText ?? "") · On pace · Lasts until reset")
        // The cap stays in its section; no separate usage row repeats it.
        #expect(model.metrics.allSatisfy { !$0.title.contains("Spend limit") })
    }

    @Test(arguments: [true, false])
    func `claude extra usage section places the pace marker in the preferred direction`(showUsed: Bool) throws {
        // 30% used against 11% expected is ahead of pace, so the marker shows where usage is expected.
        let snapshot = try Self.claudeEnterpriseSnapshot()
        let cost = try #require(snapshot.providerCost)
        let ahead = snapshot.with(providerCost: ProviderCostSnapshot(
            used: 3000,
            limit: cost.limit,
            currencyCode: cost.currencyCode,
            period: cost.period,
            resetsAt: cost.resetsAt,
            updatedAt: cost.updatedAt))
        let section = try #require(Self.cardModel(provider: .claude, snapshot: ahead, showUsed: showUsed).providerCost)

        let pace = try #require(section.pace)
        let marker = try #require(pace.pacePercent)
        #expect(abs(marker - (showUsed ? 11.29 : 88.71)) < 0.01)
        #expect(!pace.paceOnTop)
        #expect(section.percentLine == (showUsed ? "30% used" : "70% left"))
    }

    @Test
    func `claude extra usage section without a reset date keeps its existing lines`() throws {
        let now = try Self.now()
        let snapshot = UsageSnapshot(
            primary: RateWindow(usedPercent: 5, windowMinutes: 300, resetsAt: now, resetDescription: nil),
            secondary: nil,
            providerCost: ProviderCostSnapshot(
                used: 5,
                limit: 20,
                currencyCode: "USD",
                period: "Monthly cap",
                updatedAt: now),
            updatedAt: now)
        let section = try #require(Self.cardModel(provider: .claude, snapshot: snapshot, showUsed: true).providerCost)

        #expect(section.percentLine == "25% used")
        #expect(section.resetText == nil)
        #expect(section.pace == nil)
        #expect(section.cycleLine == nil)
        #expect(snapshot.claudeSpendLimitWindow == nil)
    }

    @Test(arguments: [true, false])
    func `claude enterprise switcher bar follows the spend limit`(showUsed: Bool) throws {
        let percent = try #require(StatusItemController.switcherWeeklyMetricPercent(
            for: .claude,
            snapshot: Self.claudeEnterpriseSnapshot(),
            showUsed: showUsed))

        #expect(abs(percent - (showUsed ? 10.4224 : 89.5776)) < 0.0001)
    }

    @Test(arguments: [true, false])
    func `claude enterprise menu bar shows the spend limit percent`(showUsed: Bool) throws {
        let window = try MenuBarMetricWindowResolver.rateWindow(
            preference: .automatic,
            provider: .claude,
            snapshot: Self.claudeEnterpriseSnapshot(),
            supportsAverage: false)

        #expect(MenuBarDisplayText.percentText(window: window, showUsed: showUsed) == (showUsed ? "10%" : "90%"))
    }

    @Test(arguments: [true, false])
    func `codex business extra usage section shows percent reset and pace beside the credits bar`(
        showUsed: Bool) throws
    {
        let snapshot = try UsageSnapshot(primary: nil, secondary: nil, updatedAt: Self.now())
        let credits = try Self.codexBusinessCredits()
        let model = try Self.cardModel(
            provider: .codex,
            snapshot: snapshot,
            credits: credits,
            projection: Self.codexProjection(surface: .liveCard, snapshot: snapshot, credits: credits),
            showUsed: showUsed)

        // The Credits section keeps the cap's progress, scale, and used/reset hint.
        #expect(model.creditsProgressPercent == 88)
        #expect(model.creditsScaleText == "of 250000")
        #expect(model.creditsHintText?.contains("resets") == true)
        #expect(model.metrics.allSatisfy { $0.id != "monthly" })

        let section = try #require(model.providerCost)
        #expect(section.title == "Extra usage")
        #expect(section.spendLine == "Monthly credit limit: 29356.8 / 250000")
        #expect(section.percentLine == (showUsed ? "12% used" : "88% left"))
        #expect(section.resetText?.hasPrefix("Resets in") == true)
        let pace = try #require(section.pace)
        #expect(pace.leftLabel == "On pace")
        #expect(pace.isPaceDerived)
    }

    @Test(arguments: [true, false])
    func `codex business menu bar shows the monthly credit limit percent`(showUsed: Bool) throws {
        let snapshot = try UsageSnapshot(primary: nil, secondary: nil, updatedAt: Self.now())
        let projection = try Self.codexProjection(
            surface: .menuBar,
            snapshot: snapshot,
            credits: Self.codexBusinessCredits())

        let window = projection.menuBarSelectableRateWindow(for: .monthly)
        #expect(MenuBarDisplayText.percentText(window: window, showUsed: showUsed) == (showUsed ? "12%" : "88%"))
    }

    @Test
    func `CLI prints the claude spend limit cost line with percent pace and reset`() throws {
        let snapshot = try Self.claudeEnterpriseSnapshot()
        let lines = try Self.renderText(provider: .claude, snapshot: snapshot).split(separator: "\n").map(String.init)

        let costIndex = try #require(lines.firstIndex { $0.hasPrefix("Cost: 1042.2 / 10000.0 · 90% left [") })
        #expect(lines[costIndex + 1] == "Pace: On pace | Expected 11% used | Lasts until reset")
        #expect(lines[costIndex + 2].hasPrefix("Resets in"))

        let json = try Self.jsonObject(provider: .claude, snapshot: snapshot)
        let usage = try #require(json["usage"] as? [String: Any])
        let cost = try #require(usage["providerCost"] as? [String: Any])
        let usedPercent = try #require(cost["usedPercent"] as? Double)
        #expect(abs(usedPercent - 10.4224) < 0.0001)
        let pace = try #require(json["pace"] as? [String: Any])
        let costPace = try #require(pace["providerCost"] as? [String: Any])
        #expect(costPace["expectedUsedPercent"] as? Double == 11)
        #expect(costPace["stage"] as? String == "onTrack")
    }

    @Test
    func `CLI prints the codex monthly credit limit cost line with percent pace and reset`() throws {
        let credits = try Self.codexBusinessCredits()
        let snapshot = try CodexExtraUsageCost.attaching(
            to: UsageSnapshot(primary: nil, secondary: nil, updatedAt: Self.now()),
            credits: credits)
        let lines = try Self.renderText(provider: .codex, snapshot: snapshot, credits: credits)
            .split(separator: "\n").map(String.init)

        let costIndex = try #require(lines.firstIndex { $0.hasPrefix("Cost: 29356.8 / 250000.0 · 88% left [") })
        #expect(lines[costIndex + 1].hasPrefix("Pace: On pace | Expected 11% used"))
        #expect(lines[costIndex + 2].hasPrefix("Resets in"))

        let json = try Self.jsonObject(provider: .codex, snapshot: snapshot)
        let usage = try #require(json["usage"] as? [String: Any])
        let cost = try #require(usage["providerCost"] as? [String: Any])
        let usedPercent = try #require(cost["usedPercent"] as? Double)
        #expect(abs(usedPercent - 11.74272) < 0.0001)
        let pace = try #require(json["pace"] as? [String: Any])
        #expect(pace["providerCost"] is [String: Any])
    }

    @Test
    func `capped costs without a monthly cadence get a percent but no pace`() throws {
        let now = try Self.now()
        let snapshot = try UsageSnapshot(
            primary: nil,
            secondary: nil,
            providerCost: ProviderCostSnapshot(
                used: 25,
                limit: 100,
                currencyCode: "USD",
                resetsAt: Self.nextMonth(),
                updatedAt: now),
            updatedAt: now)
        let text = try Self.renderText(provider: .cursor, snapshot: snapshot)

        #expect(text.contains("Cost: 25.0 / 100.0 · 75% left ["))
        #expect(!text.contains("Pace:"))
        #expect(try CLIRenderer.providerPacePayload(provider: .cursor, snapshot: snapshot, now: Self.now()) == nil)
    }
}
