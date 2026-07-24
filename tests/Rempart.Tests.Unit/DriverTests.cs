using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

internal sealed class FakeDriverProvider(params LoadedDriver[] drivers) : IDriverProvider
{
    public IReadOnlyList<LoadedDriver> Enumerate() => drivers;
}

public class DriverTests
{
    private static IReadOnlyList<Finding> Collect(
        DriverBlocklist blocklist, ISignatureProvider signatures, params LoadedDriver[] drivers) =>
        new LoadedDriversCollector(blocklist).Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            drivers: new FakeDriverProvider(drivers)));

    private static DriverBlocklist Blocklist(params BlockedDriver[] drivers)
    {
        var entries = string.Join(",", drivers.Select(d =>
            $$"""{"sha256":"{{d.Sha256}}","name":"{{d.Name}}","category":"{{d.Category}}"}"""));
        return DriverBlocklist.Parse(
            $$"""{"asOfUtc":"2026-09-01T00:00:00Z","source":"test","drivers":[{{entries}}]}""");
    }

    /// <summary>
    /// On a healthy machine, every kernel driver is validly signed: none stands out.
    /// That is the result observed in the wild (190 drivers, 190 valid), and proof
    /// that the collector makes no noise.
    /// </summary>
    [Fact]
    public void A_validly_signed_driver_absent_from_the_blocklist_is_benign()
    {
        var findings = Collect(
            DriverBlocklist.Empty,
            new FakeSignatureProvider().With(@"C:\W\drivers\ok.sys", SignatureStatus.Valid),
            new LoadedDriver("ok.sys", @"C:\W\drivers\ok.sys"));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// An unsigned kernel driver has no place on a Secure Boot machine: it is the
    /// first sign of a forced load. The verdict comes from the common scale, the same
    /// one used for an autorun.
    /// </summary>
    [Fact]
    public void An_unsigned_driver_is_suspicious()
    {
        var findings = Collect(
            DriverBlocklist.Empty,
            new FakeSignatureProvider().With(@"C:\tmp\evil.sys", SignatureStatus.Unsigned),
            new LoadedDriver("evil.sys", @"C:\tmp\evil.sys"));

        Assert.Equal(FindingSeverity.Suspicious, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// A perfectly signed but known-vulnerable driver is suspicious: it is precisely a
    /// legitimate driver that an attacker brings along to use as leverage (BYOVD).
    /// The blocklist can only worsen the signature verdict.
    /// </summary>
    [Fact]
    public void A_validly_signed_but_known_vulnerable_driver_is_suspicious()
    {
        const string Hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";

        var findings = Collect(
            Blocklist(new BlockedDriver(Hash, "capcom.sys", "vulnerable")),
            new FakeSignatureProvider().With(@"C:\W\drivers\capcom.sys", SignatureStatus.Valid, sha256: Hash),
            new LoadedDriver("capcom.sys", @"C:\W\drivers\capcom.sys"));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("vulnérable connu", string.Join(" ", finding.Reasons));
        Assert.Equal("vulnerable", finding.Details["loldrivers"]);
    }

    /// <summary>
    /// Matching is done on the hash regardless of case: the signature provider and
    /// the list may render it differently.
    /// </summary>
    [Fact]
    public void Blocklist_match_is_case_insensitive_on_the_hash()
    {
        var lower = "deadbeef" + new string('0', 56);

        Assert.NotNull(
            Blocklist(new BlockedDriver(lower.ToUpperInvariant(), "x", "malicious")).Match(lower));
    }

    /// <summary>
    /// A driver whose hash could not be computed is not declared safe: it is simply
    /// not found in the list, and its verdict remains the one its signature earns.
    /// </summary>
    [Fact]
    public void A_driver_without_a_hash_is_not_matched()
    {
        Assert.Null(DriverBlocklist.Empty.Match(null));
        Assert.Null(DriverBlocklist.Empty.Match(""));
    }

    /// <summary>
    /// An unreadable list is not an empty list: throw rather than load a truncated
    /// security list "as best we can".
    /// </summary>
    [Fact]
    public void An_unreadable_blocklist_throws_rather_than_loading_partially()
    {
        Assert.ThrowsAny<Exception>(() => DriverBlocklist.Parse("pas du json"));
    }

    /// <summary>
    /// A bloatware catalog signed without <c>--kind</c> routes here by default (Infer):
    /// without the "drivers" key, an empty list must not be loaded silently.
    /// </summary>
    [Fact]
    public void Parse_throws_when_the_drivers_key_is_absent() =>
        Assert.ThrowsAny<Exception>(() => DriverBlocklist.Parse(
            """{"asOfUtc":"x","source":null,"entries":[]}"""));

    [Fact]
    public void Parse_accepts_a_present_but_empty_drivers_array()
    {
        var blocklist = DriverBlocklist.Parse("""{"asOfUtc":"x","source":"t","drivers":[]}""");
        Assert.Equal(0, blocklist.Count);
    }
}
