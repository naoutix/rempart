using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class LolDriversImportTests
{
    // The real shape of loldrivers.io, reduced to what we read: a category, and samples
    // carrying SHA256, Filename, etc. Keys in PascalCase, as in the source.
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

        // 3 valid hashes: 2 from the first driver, 1 from the second. Samples without a
        // SHA256, or with a hash that is too short, are discarded.
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
    /// The name falls back to the first non-empty field — Filename, then OriginalFilename —
    /// and failing that to a prefix of the hash. Never empty, never invented.
    /// </summary>
    [Fact]
    public void The_name_falls_back_through_the_available_fields()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");
        var byHash = file.Drivers.ToDictionary(d => d.Sha256, d => d.Name);

        Assert.Equal("capcom.sys",
            byHash["aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"]);
        Assert.Equal("secours.sys", // empty Filename → OriginalFilename
            byHash["1111111111111111111111111111111111111111111111111111111111111111"]);
        Assert.Equal("222222222222", // no name → prefix of the hash
            byHash["2222222222222222222222222222222222222222222222222222222222222222"]);
    }

    /// <summary>
    /// The hash is normalised to lowercase, so that matching at scan time does not
    /// depend on the casing the source happened to use.
    /// </summary>
    [Fact]
    public void Hashes_are_lowercased()
    {
        var file = LolDriversImport.Transform(Source, "2026-07-21T00:00:00Z");

        Assert.All(file.Drivers, d => Assert.Equal(d.Sha256.ToLowerInvariant(), d.Sha256));
    }

    /// <summary>
    /// The same hash appearing in two entries is catalogued only once.
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
