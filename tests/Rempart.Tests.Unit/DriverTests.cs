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
    /// Sur une machine saine, chaque pilote noyau est validement signé : aucun ne
    /// ressort. C'est le résultat observé en vrai (190 pilotes, 190 valides), et la
    /// preuve que le collecteur ne fait pas de bruit.
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
    /// Un pilote noyau non signé n'a rien à faire sur une machine à Secure Boot : c'est
    /// le premier signe d'un chargement forcé. Le jugement est celui de l'échelle
    /// commune, la même que pour un démarrage automatique.
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
    /// Un pilote parfaitement signé mais connu vulnérable est suspect : c'est justement
    /// un pilote légitime qu'un attaquant apporte pour s'en servir de levier (BYOVD).
    /// La liste de blocage ne peut qu'aggraver le verdict de signature.
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
    /// La correspondance se fait sur l'empreinte quelle que soit la casse : le
    /// fournisseur de signature et la liste peuvent la rendre différemment.
    /// </summary>
    [Fact]
    public void Blocklist_match_is_case_insensitive_on_the_hash()
    {
        var lower = "deadbeef" + new string('0', 56);

        Assert.NotNull(
            Blocklist(new BlockedDriver(lower.ToUpperInvariant(), "x", "malicious")).Match(lower));
    }

    /// <summary>
    /// Un pilote dont l'empreinte n'a pas pu être calculée n'est pas déclaré sûr : il
    /// n'est simplement pas trouvé dans la liste, et son verdict reste celui de sa
    /// signature.
    /// </summary>
    [Fact]
    public void A_driver_without_a_hash_is_not_matched()
    {
        Assert.Null(DriverBlocklist.Empty.Match(null));
        Assert.Null(DriverBlocklist.Empty.Match(""));
    }

    /// <summary>
    /// Une liste illisible n'est pas une liste vide : lever plutôt que charger « au
    /// mieux » une liste de sécurité tronquée.
    /// </summary>
    [Fact]
    public void An_unreadable_blocklist_throws_rather_than_loading_partially()
    {
        Assert.ThrowsAny<Exception>(() => DriverBlocklist.Parse("pas du json"));
    }

    /// <summary>
    /// Un catalogue bloatware signé sans <c>--kind</c> route ici par défaut (Infer) :
    /// sans la clé « drivers », il ne faut pas charger silencieusement une liste vide.
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
