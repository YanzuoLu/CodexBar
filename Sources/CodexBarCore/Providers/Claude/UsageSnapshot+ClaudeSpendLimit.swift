import Foundation

extension UsageSnapshot {
    /// The Claude spend-limit window when the account only exposes an enterprise/extra-usage spend limit
    /// and has no real session/weekly quota lanes (`primary` nil or an explicitly marked placeholder, no weekly,
    /// model-scoped, or scoped weekly windows). Lets the menu bar, switcher, and widgets surface the spend limit
    /// instead of an empty or 0% placeholder lane. Returns nil for accounts that expose genuine quota lanes.
    public var claudeSpendLimitWindow: RateWindow? {
        guard self.primary == nil || self.primary?.isSyntheticPlaceholder == true,
              self.secondary == nil, self.tertiary == nil,
              self.claudeScopedWeeklyWindow == nil
        else { return nil }
        return self.providerCost?.spendLimitWindow
    }
}
