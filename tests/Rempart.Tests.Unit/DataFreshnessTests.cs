using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class DataFreshnessTests
{
    [Fact]
    public void Fresh_data_reports_zero_days_and_is_not_stale()
    {
        var age = DataFreshness.At("2026-07-01T00:00:00Z", "2026-07-01T12:00:00Z");

        Assert.Equal(0, age.Days);
        Assert.False(age.Stale);
        Assert.False(age.Unknown);
    }

    [Fact]
    public void Age_is_counted_in_whole_days()
    {
        var age = DataFreshness.At("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z");

        Assert.Equal(30, age.Days);
        Assert.False(age.Stale);
    }

    [Fact]
    public void Beyond_the_threshold_the_data_is_flagged_stale()
    {
        var age = DataFreshness.At("2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z");

        Assert.True(age.Days > DataFreshness.DefaultThresholdDays);
        Assert.True(age.Stale);
    }

    /// <summary>
    /// A replayed snapshot carries a frozen time, often earlier than the data
    /// date. The age would be negative; it is clamped to zero rather than shown
    /// as-is — "at least as recent as the scan" is readable, "-201 days" is not.
    /// </summary>
    [Fact]
    public void Data_newer_than_the_scan_clamps_to_zero_never_negative()
    {
        var age = DataFreshness.At("2026-07-21T00:00:00Z", "2026-01-01T00:00:00Z");

        Assert.Equal(0, age.Days);
        Assert.False(age.Stale);
        Assert.False(age.Unknown);
    }

    /// <summary>
    /// An unreadable date must not pass for fresh data: same principle as
    /// <c>Unknown ≠ Fail</c>, applied to age.
    /// </summary>
    [Theory]
    [InlineData("pas une date", "2026-07-01T00:00:00Z")]
    [InlineData("2026-07-01T00:00:00Z", "")]
    public void An_unreadable_date_is_unknown_not_fresh(string asOf, string now)
    {
        var age = DataFreshness.At(asOf, now);

        Assert.True(age.Unknown);
        Assert.False(age.Stale);
    }

    /// <summary>
    /// The embedded date must be readable by the age calculator: a malformed
    /// constant would yield "unknown" on every scan, with nothing to explain it.
    /// </summary>
    [Fact]
    public void The_embedded_reference_date_is_parseable()
    {
        var age = DataFreshness.At(
            Rempart.Core.Rules.RuleCatalog.EmbeddedAsOfUtc, "2026-07-21T00:00:00Z");

        Assert.False(age.Unknown);
    }
}
