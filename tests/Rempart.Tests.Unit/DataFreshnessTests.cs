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
    /// Un instantané rejoué porte une heure figée, souvent antérieure à la date des
    /// données. L'âge y serait négatif ; il est plafonné à zéro plutôt qu'affiché tel
    /// quel — « au moins aussi récente que le scan » se lit, « -201 jours » non.
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
    /// Une date qu'on ne sait pas lire ne doit pas passer pour une donnée fraîche :
    /// c'est le même principe que <c>Unknown ≠ Fail</c>, appliqué à l'ancienneté.
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
    /// La date embarquée doit être lisible par le calculateur d'âge : une constante mal
    /// formée ferait rendre « inconnu » à chaque scan, sans que rien ne l'explique.
    /// </summary>
    [Fact]
    public void The_embedded_reference_date_is_parseable()
    {
        var age = DataFreshness.At(
            Rempart.Core.Rules.RuleCatalog.EmbeddedAsOfUtc, "2026-07-21T00:00:00Z");

        Assert.False(age.Unknown);
    }
}
