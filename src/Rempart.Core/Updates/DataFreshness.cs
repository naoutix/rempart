using System.Globalization;

namespace Rempart.Core.Updates;

/// <summary>
/// The age of the data at scan time.
///
/// <see cref="Unknown"/> matters as much as the rest: a date we cannot parse must not
/// pass for fresh data. Same principle as everywhere else in the project — a failure
/// must not be presented as a favorable result.
/// </summary>
public sealed record DataAge(
    string AsOfUtc,
    int Days,
    bool Stale,
    bool Unknown,
    int ThresholdDays);

/// <summary>
/// Computes how old the evaluated data is.
///
/// <para>
/// ADR-002 (D15) requires this in every report: a six-month-old binary audits with
/// six-month-old rules, and nothing used to signal it. The catalog fingerprint said
/// <em>what</em>; the age says <em>when</em>.
/// </para>
///
/// <para>
/// The alert threshold is provisional — the ADR calls it "arbitrary until the actual
/// cadence has been observed". 180 days, matching the six-month order of magnitude cited
/// by the decision, to be revisited once the publication frequency is known.
/// </para>
/// </summary>
public static class DataFreshness
{
    public const int DefaultThresholdDays = 180;

    public static DataAge At(string asOfUtc, string nowUtc, int thresholdDays = DefaultThresholdDays)
    {
        if (!TryParse(asOfUtc, out var asOf) || !TryParse(nowUtc, out var now))
        {
            // Neither fresh nor stale: unreadable. The report states it as such rather
            // than implying the data is up to date.
            return new DataAge(asOfUtc, 0, Stale: false, Unknown: true, thresholdDays);
        }

        // A replayed snapshot carries a frozen clock, often earlier than the date of the
        // embedded data: the age comes out negative there and is meaningless. Clamp it
        // to zero — "at least as recent as the scan" — rather than display a negative
        // day count nobody could interpret.
        var days = (int)Math.Floor((now - asOf).TotalDays);
        if (days < 0)
        {
            days = 0;
        }

        return new DataAge(asOfUtc, days, days > thresholdDays, Unknown: false, thresholdDays);
    }

    private static bool TryParse(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out parsed);
}
