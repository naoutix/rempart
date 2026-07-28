using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The join between the upstream list and the judgement written here (ADR-006, D19).
///
/// <para>
/// Three of these tests exist because opening the upstream data turned up three ways an
/// obvious import goes silently wrong: the risk fields are orthogonal, one entry of 141 has a
/// different schema, and the identifiers are not in the form the matcher compares against.
/// None of the three fails loudly on its own.
/// </para>
/// </summary>
public sealed class Win11DebloatImportTests
{
    /// <summary>
    /// A judgement covering everything the upstream fragments below declare. Written out
    /// rather than generated: these tests are about what the join does with a judgement, so
    /// the judgement has to be readable at the point of use.
    /// </summary>
    private const string Judgement = """
        { "entries": [
          { "appId": "AD2F1837.HPSupportAssistant", "category": "oem", "risk": "Unwanted",
            "impact": "Assistance et mises à jour HP. Sa suppression prive la machine des correctifs de firmware distribués par ce canal.",
            "impactSource": "Upstream" },
          { "appId": "Microsoft.Edge", "category": "browser", "risk": "SecurityRelevant",
            "impact": "Navigateur par défaut. Sa suppression retire le seul navigateur du bac à sable Windows.",
            "impactSource": "Upstream" },
          { "appId": "XPFFTQ037JWMHS", "category": "browser", "risk": "SecurityRelevant",
            "impact": "Même navigateur, désigné par son identifiant produit du Store.",
            "impactSource": "Upstream" },
          { "appId": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe", "category": "game", "risk": "Unwanted",
            "impact": "Superposition de jeu Xbox.", "impactSource": "Verified" } ] }
        """;

    private static string Upstream(string appIdJson, string recommendation = "optional") => $$"""
        { "Version": "1.1", "Apps": [
          { "FriendlyName": "Test App", "AppId": {{appIdJson}}, "Description": "Upstream blurb",
            "SelectedByDefault": true, "Recommendation": "{{recommendation}}",
            "RemovalMethod": "Appx" } ] }
        """;

    [Fact]
    public void An_upstream_identifier_becomes_a_package_name_entry_carrying_the_local_judgement()
    {
        var file = Win11DebloatImport.Transform(
            Upstream("\"AD2F1837.HPSupportAssistant\""), Judgement, "2026-07-28T00:00:00Z");

        var entry = Assert.Single(file.Entries);
        Assert.Equal(BloatwareMatch.PackageName, entry.Match);
        Assert.Equal("AD2F1837.HPSupportAssistant", entry.Value);
        Assert.Equal("oem", entry.Category);
        Assert.Equal(BloatwareRisk.Unwanted, entry.Risk);
        Assert.Contains("firmware", entry.Impact, StringComparison.Ordinal);
        Assert.Equal(ImpactProvenance.Upstream, entry.ImpactSource);
    }

    [Fact]
    public void An_identifier_carrying_a_publisher_hash_becomes_a_full_family_name_entry()
    {
        // The match mode follows the *form of the value*, not what upstream says about
        // removal: a value with a hash is a family name, one without is a package name. The
        // shape guard in BloatwareCatalogTests holds the same pairing from the other side.
        var file = Win11DebloatImport.Transform(
            Upstream("\"Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\""), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(BloatwareMatch.Pfn, file.Entries[0].Match);
    }

    [Fact]
    public void The_upstream_recommendation_never_decides_the_risk()
    {
        // Trap 1: the two fields are orthogonal. "unsafe" says what breaks if you remove it;
        // Risk says why the entry is catalogued at all. Microsoft Store is unsafe to remove
        // and is not security-relevant; a telemetry app is safe to remove and is.
        var file = Win11DebloatImport.Transform(
            Upstream("\"Microsoft.Edge\"", recommendation: "unsafe"), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(BloatwareRisk.SecurityRelevant, file.Entries[0].Risk);

        var same = Win11DebloatImport.Transform(
            Upstream("\"Microsoft.Edge\"", recommendation: "safe"), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(file.Entries[0].Risk, same.Entries[0].Risk);
    }

    [Fact]
    public void An_upstream_entry_carrying_several_identifiers_produces_one_entry_per_identifier()
    {
        // Trap 2: Microsoft Edge is the one entry of 141 whose AppId is an array, and its two
        // values are not even the same kind of identifier -- a package name and a Store
        // product id.
        var file = Win11DebloatImport.Transform(
            Upstream("[\"Microsoft.Edge\", \"XPFFTQ037JWMHS\"]"), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(2, file.Entries.Count);
        Assert.Contains(file.Entries, e => e.Value == "Microsoft.Edge");
        Assert.Contains(file.Entries, e => e.Value == "XPFFTQ037JWMHS");
        Assert.Equal(2, file.Entries.Select(e => e.Id).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void An_identifier_nobody_has_judged_fails_the_import_and_is_named()
    {
        // D19: neither shipped without a note, nor dropped in silence.
        var thrown = Assert.Throws<UnjudgedEntriesException>(() => Win11DebloatImport.Transform(
            Upstream("\"Vendor.BrandNewApp\""), Judgement, "2026-07-28T00:00:00Z"));

        Assert.Contains("Vendor.BrandNewApp", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("Vendor.BrandNewApp", thrown.AppIds);
    }

    [Fact]
    public void Every_unjudged_identifier_is_named_at_once_rather_than_one_per_run()
    {
        // Fixing them one download at a time would be the same list rediscovered N times.
        var upstream = """
            { "Version": "1.1", "Apps": [
              { "FriendlyName": "A", "AppId": "Vendor.A", "Description": "", "SelectedByDefault": true,
                "Recommendation": "safe", "RemovalMethod": "Appx" },
              { "FriendlyName": "B", "AppId": "Vendor.B", "Description": "", "SelectedByDefault": true,
                "Recommendation": "safe", "RemovalMethod": "Appx" } ] }
            """;

        var thrown = Assert.Throws<UnjudgedEntriesException>(
            () => Win11DebloatImport.Transform(upstream, Judgement, "2026-07-28T00:00:00Z"));

        Assert.Equal(2, thrown.AppIds.Count);
    }

    [Fact]
    public void The_verified_provenance_of_a_judgement_reaches_the_catalogue()
    {
        var file = Win11DebloatImport.Transform(
            Upstream("\"Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\""), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(ImpactProvenance.Verified, file.Entries[0].ImpactSource);
    }

    [Fact]
    public void The_source_field_credits_the_upstream_list_and_its_licence()
    {
        // MIT requires attribution, and BloatwareCatalogFile already carries the field.
        var file = Win11DebloatImport.Transform(
            Upstream("\"AD2F1837.HPSupportAssistant\""), Judgement, "2026-07-28T00:00:00Z");

        Assert.Contains("Win11Debloat", file.Source!, StringComparison.Ordinal);
        Assert.Contains("MIT", file.Source!, StringComparison.Ordinal);
    }

    [Fact]
    public void The_same_upstream_twice_produces_the_same_file()
    {
        // The output is signed, so a re-run that reorders entries would make every diff
        // unreadable and every signature look like a change.
        var first = Win11DebloatImport.Transform(
            Upstream("[\"Microsoft.Edge\", \"XPFFTQ037JWMHS\"]"), Judgement, "2026-07-28T00:00:00Z");
        var second = Win11DebloatImport.Transform(
            Upstream("[\"XPFFTQ037JWMHS\", \"Microsoft.Edge\"]"), Judgement, "2026-07-28T00:00:00Z");

        Assert.Equal(
            first.Entries.Select(e => e.Id + "|" + e.Value),
            second.Entries.Select(e => e.Id + "|" + e.Value));
    }

    [Fact]
    public void The_upstream_source_is_pinned_to_a_revision_rather_than_to_a_branch()
    {
        // Written because the first draft of this file pinned nothing: its comment claimed
        // "pinned by commit" while the URL said "master". D18 asks for a revision someone
        // chose, and a comment is not a lock -- this is.
        var segments = Win11DebloatImport.SourceUrl.Split('/');
        var revision = segments[^3];

        Assert.True(revision.Length == 40 && revision.All(Uri.IsHexDigit),
            $"La source amont est épinglée sur « {revision} », qui n'est pas une empreinte de "
            + "commit. Une branche bouge sous les pieds : le jeu de données qu'un outil de "
            + "sécurité signe doit venir d'une révision choisie.");
    }

    [Fact]
    public void An_upstream_response_of_another_shape_is_refused_rather_than_read_as_empty()
    {
        // The lesson of the fixtures-anonymised job: a guard that finds nothing must not
        // report success. An upstream that changed shape produces zero entries, and zero
        // entries would sign as "no bloatware known".
        Assert.ThrowsAny<Exception>(() => Win11DebloatImport.Transform(
            """{ "Version": "1.1" }""", Judgement, "2026-07-28T00:00:00Z"));
    }
}
