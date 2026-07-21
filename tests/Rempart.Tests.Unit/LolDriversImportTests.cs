using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class LolDriversImportTests
{
    // La forme réelle de loldrivers.io, réduite à ce qu'on lit : catégorie, et des
    // échantillons portant SHA256, Filename, etc. Clés en PascalCase, comme la source.
    private const string Source = """
        [
          {
            "Category": "vulnerable driver",
            "KnownVulnerableSamples": [
              { "Filename": "capcom.sys", "SHA256": "AA11BB22CC33DD44EE55FF66AA11BB22CC33DD44EE55FF66AA11BB22CC33DD44" },
              { "Filename": "", "OriginalFilename": "secours.sys", "SHA256": "1111111111111111111111111111111111111111111111111111111111111111" }
            ]
          },
          {
            "Category": "malicious",
            "KnownVulnerableSamples": [
              { "SHA256": "2222222222222222222222222222222222222222222222222222222222222222" },
              { "Filename": "sans-hash.sys" },
              { "Filename": "trop-court.sys", "SHA256": "abc" }
            ]
          }
        ]
        """;

    [Fact]
    public void It_flattens_samples_into_unique_hashes()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");

        // 3 empreintes valides : 2 du premier pilote, 1 du second. Les échantillons
        // sans SHA256 ou avec une empreinte trop courte sont écartés.
        Assert.Equal(3, file.Drivers.Count);
        Assert.Equal("2026-07-21T00:00:00Z", file.AsOfUtc);
        Assert.Equal(LolDriversImport.SourceUrl, file.Source);
    }

    [Fact]
    public void The_category_of_the_entry_is_carried_to_each_sample()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");
        var blocklist = DriverBlocklist.Parse(RempartJsonRoundtrip(file));

        Assert.Equal("vulnerable driver",
            blocklist.Match("aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44")!.Category);
        Assert.Equal("malicious",
            blocklist.Match("2222222222222222222222222222222222222222222222222222222222222222")!.Category);
    }

    /// <summary>
    /// Le nom retombe sur le premier champ non vide — Filename, puis OriginalFilename —
    /// et à défaut sur un préfixe de l'empreinte. Jamais vide, jamais inventé.
    /// </summary>
    [Fact]
    public void The_name_falls_back_through_the_available_fields()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");
        var byHash = file.Drivers.ToDictionary(d => d.Sha256, d => d.Name);

        Assert.Equal("capcom.sys",
            byHash["aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"]);
        Assert.Equal("secours.sys", // Filename vide → OriginalFilename
            byHash["1111111111111111111111111111111111111111111111111111111111111111"]);
        Assert.Equal("222222222222", // aucun nom → préfixe de l'empreinte
            byHash["2222222222222222222222222222222222222222222222222222222222222222"]);
    }

    /// <summary>
    /// L'empreinte est normalisée en minuscules, pour que la correspondance au scan ne
    /// dépende pas de la casse que la source a employée.
    /// </summary>
    [Fact]
    public void Hashes_are_lowercased()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");

        Assert.All(file.Drivers, d => Assert.Equal(d.Sha256.ToLowerInvariant(), d.Sha256));
    }

    /// <summary>
    /// Une même empreinte présente dans deux entrées n'est cataloguée qu'une fois.
    /// </summary>
    [Fact]
    public void Duplicate_hashes_are_kept_once()
    {
        const string WithDup = """
            [
              {"Category":"a","KnownVulnerableSamples":[{"Filename":"x.sys","SHA256":"3333333333333333333333333333333333333333333333333333333333333333"}]},
              {"Category":"b","KnownVulnerableSamples":[{"Filename":"y.sys","SHA256":"3333333333333333333333333333333333333333333333333333333333333333"}]}
            ]
            """;

        Assert.Single(LolDriversImport.Transform(WithDup, "2026-07-21T00:00:00Z").Drivers);
    }

    private static string RempartJsonRoundtrip(DriverBlocklistFile file) =>
        Rempart.Core.Json.RempartJson.SerialiseCompact(file);
}
