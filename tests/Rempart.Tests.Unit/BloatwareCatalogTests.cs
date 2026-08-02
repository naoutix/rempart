using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class BloatwareCatalogTests
{
    private static InstalledSoftware Appx(string pfn, string name = "X") =>
        new(name, null, null, SoftwareSource.Appx, false, false, pfn);

    private static InstalledSoftware Uninstall(string key, string name = "X", string? publisher = null) =>
        new(name, null, publisher, SoftwareSource.Uninstall, false, true, key);

    private static BloatwareCatalog Catalog(params BloatwareEntry[] entries) =>
        BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
            new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [.. entries])));

    private static BloatwareEntry Entry(
        string id, BloatwareMatch match, string value,
        BloatwareRisk risk = BloatwareRisk.Unwanted) =>
        new(id, match, value, "test-cat", risk, "Impact non vide.");

    [Fact]
    public void An_empty_catalog_matches_nothing() =>
        Assert.Null(BloatwareCatalog.Empty.Match(Appx("Anything_hash")));

    [Fact]
    public void A_pfn_entry_matches_an_appx_by_exact_identifier()
    {
        var hit = Catalog(Entry("B1", BloatwareMatch.Pfn, "king.CandyCrush_kgqvny"))
            .Match(Appx("king.CandyCrush_kgqvny"));

        Assert.Equal("B1", hit?.Id);
    }

    [Fact]
    public void A_pfn_entry_does_not_match_a_uninstall_entry_of_the_same_string()
    {
        // Source-gated: a PFN only matches an Appx.
        Assert.Null(Catalog(Entry("B1", BloatwareMatch.Pfn, "shared-id"))
            .Match(Uninstall("shared-id")));
    }

    [Fact]
    public void A_uninstall_entry_matches_by_exact_key()
    {
        Assert.Equal("B2", Catalog(Entry("B2", BloatwareMatch.Uninstall, "{GUID-123}"))
            .Match(Uninstall("{GUID-123}"))?.Id);
    }

    [Fact]
    public void A_name_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B3", Catalog(Entry("B3", BloatwareMatch.Name, "mcafee"))
            .Match(Uninstall("k", name: "McAfee LiveSafe"))?.Id);
    }

    [Fact]
    public void A_publisher_entry_matches_a_case_insensitive_substring()
    {
        Assert.Equal("B4", Catalog(Entry("B4", BloatwareMatch.Publisher, "acme oem"))
            .Match(Uninstall("k", name: "Whatever", publisher: "ACME OEM Inc."))?.Id);
    }

    [Fact]
    public void When_several_entries_match_the_highest_risk_wins()
    {
        var hit = Catalog(
            Entry("LOW", BloatwareMatch.Name, "vendor", BloatwareRisk.Unwanted),
            Entry("HIGH", BloatwareMatch.Publisher, "vendor", BloatwareRisk.SecurityRelevant))
            .Match(Uninstall("k", name: "Vendor Tool", publisher: "Vendor"));

        Assert.Equal("HIGH", hit?.Id);
        Assert.Equal(BloatwareRisk.SecurityRelevant, hit?.Risk);
    }

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_impact() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"B","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":""}]}"""));

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_id() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"","match":"Name","value":"v","category":"c","risk":"Unwanted","impact":"i"}]}"""));

    [Fact]
    public void Parse_throws_when_an_entry_has_an_empty_value() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"entries":[{"id":"B","match":"Name","value":"","category":"c","risk":"Unwanted","impact":"i"}]}"""));

    [Fact]
    public void SerialiseCompact_writes_enums_as_strings_not_integers()
    {
        var json = RempartJson.SerialiseCompact(new BloatwareCatalogFile(
            "2026-07-23T00:00:00Z", "test",
            [new BloatwareEntry("B1", BloatwareMatch.Name, "v", "cat", BloatwareRisk.Unwanted, "impact")]));

        Assert.Contains("\"match\":\"Name\"", json);
        Assert.Contains("\"risk\":\"Unwanted\"", json);
    }

    [Fact]
    public void Parse_throws_when_the_entries_key_is_absent() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":null,"drivers":[]}"""));

    [Fact]
    public void Parse_accepts_a_present_but_empty_entries_array()
    {
        var catalog = BloatwareCatalog.Parse("""{"asOfUtc":"x","source":null,"entries":[]}""");
        Assert.Equal(0, catalog.Count);
    }

    [Fact]
    public void An_unreadable_catalog_throws_rather_than_loading_partially() =>
        Assert.ThrowsAny<Exception>(() => BloatwareCatalog.Parse("pas du json"));

    /// <summary>
    /// A duplicate identifier is refused by the reader, and refused as a
    /// <see cref="JsonException"/> — the type both callers filter on. It used to load, and
    /// the crash came out of <c>Merge</c>'s <c>ToDictionary</c> as an
    /// <see cref="ArgumentException"/> nobody catches.
    /// </summary>
    [Fact]
    public void Parse_refuses_a_catalogue_where_two_entries_share_an_id() =>
        Assert.Throws<JsonException>(() => Catalog(
            Entry("B1", BloatwareMatch.Name, "mcafee"),
            Entry("B1", BloatwareMatch.Name, "norton")));

    /// <summary>
    /// Case does not make two identifiers, because it does not make two keys either:
    /// <c>Merge</c> indexes with <see cref="StringComparer.OrdinalIgnoreCase"/>, so a guard
    /// comparing them exactly would let "B1"/"b1" straight back into the exception it was
    /// written to prevent.
    /// </summary>
    [Fact]
    public void Parse_refuses_two_identifiers_that_differ_only_in_case() =>
        Assert.Throws<JsonException>(() => Catalog(
            Entry("B1", BloatwareMatch.Name, "mcafee"),
            Entry("b1", BloatwareMatch.Name, "norton")));

    [Fact]
    public void Merge_lets_an_incoming_entry_override_the_base_by_id()
    {
        var merged = BloatwareCatalog.Merge(
            Catalog(Entry("B1", BloatwareMatch.Name, "old")),
            Catalog(Entry("B1", BloatwareMatch.Name, "new"), Entry("B2", BloatwareMatch.Name, "extra")));

        Assert.Equal("B1", merged.Match(Uninstall("k", name: "new tool"))?.Id);   // overridden
        Assert.Null(merged.Match(Uninstall("k", name: "old tool")));               // old pattern gone
        Assert.Equal("B2", merged.Match(Uninstall("k", name: "extra tool"))?.Id);  // added
    }

    [Fact]
    public void The_embedded_baseline_parses_and_is_non_empty()
    {
        Assert.True(BloatwareCatalog.Embedded.Count > 0);
    }

    [Fact]
    public void The_embedded_baseline_matches_a_known_provisioned_appx()
    {
        // Xbox Game Bar: a provisioned Microsoft Appx, the textbook bloatware that returns.
        var hit = BloatwareCatalog.Embedded.Match(new InstalledSoftware(
            "Xbox Game Bar", null, null, SoftwareSource.Appx, true, true,
            "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe"));

        Assert.NotNull(hit);
        Assert.False(string.IsNullOrWhiteSpace(hit!.Impact));
    }

    [Fact]
    public void A_package_name_entry_matches_the_family_name_that_carries_the_publisher_hash()
    {
        // Upstream ships bare package names; an installed Appx carries the full family name.
        // Comparing the two by equality is what would have loaded 141 entries and matched
        // nothing at all, with no test going red (ADR-006, piège 3).
        var hit = Catalog(Entry("B9", BloatwareMatch.PackageName, "AD2F1837.HPSupportAssistant"))
            .Match(Appx("AD2F1837.HPSupportAssistant_v10z8vjag6ke6"));

        Assert.Equal("B9", hit?.Id);
    }

    [Fact]
    public void A_package_name_entry_does_not_match_a_longer_name_sharing_its_prefix()
    {
        // Equality on the name segment, never a prefix test: "Microsoft.Xbox" must not claim
        // "Microsoft.XboxGamingOverlay", which is a different package.
        Assert.Null(Catalog(Entry("B10", BloatwareMatch.PackageName, "Microsoft.Xbox"))
            .Match(Appx("Microsoft.XboxGamingOverlay_8wekyb3d8bbwe")));
    }

    [Fact]
    public void A_package_name_entry_ignores_software_that_is_not_an_appx()
    {
        // Source-gated like Pfn: a package name only means something for an Appx.
        Assert.Null(Catalog(Entry("B11", BloatwareMatch.PackageName, "Some.Package"))
            .Match(Uninstall("Some.Package")));
    }

    [Fact]
    public void A_package_name_entry_matches_a_capture_that_stored_no_publisher_hash()
    {
        // Not every recorded identifier carries the hash. Falling back to the whole string
        // keeps such a capture comparable instead of silently matching nothing.
        Assert.Equal("B12", Catalog(Entry("B12", BloatwareMatch.PackageName, "Vendor.App"))
            .Match(Appx("Vendor.App"))?.Id);
    }

    [Fact]
    public void An_entry_that_states_no_provenance_reads_back_as_described_upstream()
    {
        // The conservative default, and the reason the field has one: a catalogue written
        // before this existed verified nothing on a machine, and must not come back claiming
        // it did (ADR-006, D20).
        var catalog = Catalog(Entry("B13", BloatwareMatch.PackageName, "Vendor.App"));

        Assert.Equal(ImpactProvenance.Upstream, catalog.Entries[0].ImpactSource);
    }

    [Fact]
    public void A_verified_provenance_survives_a_serialisation_round_trip()
    {
        // It travels through the signed channel, so it has to survive the same round trip
        // the catalogue does -- and under AOT that is a source-generated context, not
        // reflection.
        var file = new BloatwareCatalogFile("2026-07-28T00:00:00Z", "test",
        [
            new BloatwareEntry("B14", BloatwareMatch.PackageName, "Vendor.App", "oem",
                BloatwareRisk.Unwanted, "Note vérifiée.", ImpactProvenance.Verified),
        ]);

        var again = BloatwareCatalog.Parse(RempartJson.SerialiseCompact(file));

        Assert.Equal(ImpactProvenance.Verified, again.Entries[0].ImpactSource);
    }

    [Fact]
    public void No_embedded_name_pattern_is_a_bare_vendor_name()
    {
        // A Name match is a Contains with no negative form. The upstream project this
        // catalogue borrows vendor coverage from matches on bare vendor names AND carries a
        // counter-pattern to undo its own over-matching -- an admission that the positive half
        // catches too much. Porting the positive half alone would report Intel and Realtek
        // driver packages as unwanted on essentially every Windows machine.
        //
        // A pattern that is too precise MISSES an installation; one that is too broad ACCUSES.
        // Missing is acceptable here, accusing is not, so vendor entries name the product.
        string[] bareVendors =
        [
            "ASUS", "MSI", "Acer", "Razer", "Intel", "Realtek", "Lenovo", "Dell", "HP",
            "Waves", "Nvidia", "AMD",
        ];

        foreach (var entry in BloatwareCatalog.Embedded.Entries)
        {
            if (entry.Match is not (BloatwareMatch.Name or BloatwareMatch.Publisher))
            {
                continue;
            }

            Assert.False(
                bareVendors.Contains(entry.Value.Trim(), StringComparer.OrdinalIgnoreCase),
                $"{entry.Id} apparie sur « {entry.Value} », un nom de marque nu. Un motif de "
                + "marque attrape les pilotes et les panneaux de configuration du constructeur, "
                + "et les signale comme indésirables sur presque chaque machine de cette marque. "
                + "Nommer le produit.");
        }
    }

    [Fact]
    public void Every_embedded_entry_states_its_identifier_in_the_form_its_match_mode_expects()
    {
        // The shape guard for the confusion above. Nothing else relates a match mode to the
        // form of its value, and getting it wrong is silent: the catalogue loads, announces
        // its count, and recognises nothing.
        foreach (var entry in BloatwareCatalog.Embedded.Entries)
        {
            if (entry.Match == BloatwareMatch.Pfn)
            {
                Assert.True(entry.Value.Contains('_', StringComparison.Ordinal),
                    $"{entry.Id} apparie en Pfn mais « {entry.Value} » ne porte pas de "
                    + "condensat d'éditeur : aucun paquet installé n'aura cette valeur.");
            }

            if (entry.Match == BloatwareMatch.PackageName)
            {
                Assert.False(entry.Value.Contains('_', StringComparison.Ordinal),
                    $"{entry.Id} apparie en PackageName mais « {entry.Value} » porte un "
                    + "condensat d'éditeur : le segment comparé n'en a jamais.");
            }
        }
    }

    /// <summary>
    /// Every live claim about the share of unverified impact notes, held against the catalogue
    /// it describes instead of against a second number written by the same hand.
    ///
    /// <para>
    /// It had already drifted. <c>DET-NOTES-AMONT</c> said "113 of 116", true the day it was
    /// written and stale from the commit that catalogued four more vendors: seven entries
    /// added, none of them observed on a machine, so both halves moved and neither followed.
    /// The ROADMAP said 120 of 123, in three places — only the register, the document whose
    /// whole job is to be the honest one, was behind.
    /// </para>
    ///
    /// <para>
    /// So the sweep, and not that one row: this count is copied by hand into four sentences
    /// across two documents, and a guard holding one of them leaves the other three free to
    /// drift the next time a piece of software is actually observed — which is precisely the
    /// movement the debt exists to measure. The four are found by what they say rather than by
    /// where they sit, so a fifth copy written tomorrow is held too, and <c>Expected</c>
    /// makes a copy deleted rather than corrected fail rather than pass quietly.
    /// </para>
    ///
    /// <para>
    /// Both files also carry dated measurements frozen on purpose — an archived figure must not
    /// be asked to age — which is why the sweep matches only sentences naming the impact notes,
    /// never every pair of numbers in the file.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_document_states_the_share_of_impact_notes_the_catalogue_has_not_verified()
    {
        // Four sentences today: one in the debt register, three in the roadmap. The number is
        // the point — a copy silently dropped is a claim that stopped being checked.
        const int Expected = 4;

        // Count of entries, not a second pass over the file: Parse rejects an entry without an
        // impact note, so the catalogue's size is the number of notes.
        var total = BloatwareCatalog.Embedded.Count;
        var upstream = BloatwareCatalog.Embedded.Entries
            .Count(entry => entry.ImpactSource == ImpactProvenance.Upstream);

        var wrong = new List<string>();
        var seen = 0;

        foreach (var document in new[] { "docs/DEBT.md", "docs/ROADMAP.md" })
        {
            foreach (var line in RepositoryFiles.Read(document).Split('\n'))
            {
                if (!line.Contains("notes d'impact", StringComparison.OrdinalIgnoreCase)
                    && !line.Contains("DET-NOTES-AMONT", StringComparison.Ordinal))
                {
                    continue;
                }

                // Two shapes in use: "120 des 123" wherever both halves are stated, and
                // "les 120 notes d'impact" where only the unverified share is.
                foreach (Match claim in Regex.Matches(line, @"(\d+) des (\d+)"))
                {
                    seen++;
                    if (Number(claim.Groups[1]) != upstream || Number(claim.Groups[2]) != total)
                    {
                        wrong.Add($"{document} : « {claim.Value} »");
                    }
                }

                foreach (Match claim in Regex.Matches(line, @"les (\d+) notes d'impact"))
                {
                    seen++;
                    if (Number(claim.Groups[1]) != upstream)
                    {
                        wrong.Add($"{document} : « {claim.Value} »");
                    }
                }
            }
        }

        Assert.True(wrong.Count == 0,
            $"Le catalogue porte {upstream} notes d'impact non vérifiées sur {total}. "
            + $"Affirment autre chose : {string.Join(" ; ", wrong)}. Cette dette se réduit "
            + "d'une unité à chaque logiciel réellement observé : un chiffre recopié à la "
            + "main ne peut pas suivre ce mouvement, et la documentation finit par annoncer "
            + "une dette plus petite que la vraie.");

        Assert.True(seen == Expected,
            $"{seen} affirmation(s) chiffrée(s) sur les notes d'impact trouvée(s), "
            + $"{Expected} attendue(s) : une phrase a été reformulée ou supprimée, et ce "
            + "test en garde d'autant moins qu'il n'en dit rien.");
    }

    /// <summary>
    /// The catalogue's own size, wherever a document states it, held against the catalogue.
    ///
    /// <para>
    /// The sweep above holds four sentences and its documentation claims that a fifth copy
    /// written tomorrow is held too. That is true inside the two French documents it reads,
    /// and false one file over: the README states the same total in English — "a signed
    /// 123-entry bloatware catalog" — where neither the file list nor the French shapes reach
    /// it. It was correct when this was written, which is exactly the state the other count
    /// was in before it drifted by seven entries.
    /// </para>
    ///
    /// <para>
    /// Held on the total alone, and separately, because it is a different claim: the share of
    /// unverified notes moves when a machine is observed, the catalogue's size moves when a
    /// vendor is catalogued, and a guard that folded the two would go green on a document
    /// stating one of them.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_document_that_counts_the_catalogue_counts_it_right()
    {
        var total = BloatwareCatalog.Embedded.Count;
        var wrong = new List<string>();
        var seen = 0;

        foreach (var document in new[] { "README.md", "docs/DEBT.md", "docs/ROADMAP.md" })
        {
            foreach (var line in RepositoryFiles.Read(document).Split('\n'))
            {
                // Scoped to the sentence and not to the file, for the reason the sweep above
                // states: both roadmap and register carry dated measurements frozen on purpose
                // — « socle de 5 entrées », « 3 entrées confirmées » — and an archived figure
                // must not be asked to age. A line stating the size of *this* catalogue names it.
                if (line.IndexOf("bloatware", StringComparison.OrdinalIgnoreCase) < 0
                    && line.IndexOf("catalogue", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                // Both spellings in use: "123-entry bloatware catalog" in the English showcase,
                // "123 entrées" where a French document states the size on its own.
                foreach (Match claim in Regex.Matches(line, @"(\d+)[- ]entr(?:y|ies|ée|ées)\b"))
                {
                    seen++;
                    if (Number(claim.Groups[1]) != total)
                    {
                        wrong.Add($"{document} : « {claim.Value} »");
                    }
                }
            }
        }

        Assert.True(wrong.Count == 0,
            $"Le catalogue embarqué porte {total} entrées. Affirment autre chose : "
            + $"{string.Join(" ; ", wrong)}. Un chiffre recopié à la main cesse d'être vrai "
            + "au premier éditeur catalogué.");

        Assert.True(seen > 0,
            "Aucune affirmation chiffrée sur la taille du catalogue n'a été trouvée : la "
            + "phrase a été reformulée, et ce test n'en garde plus aucune.");
    }

    private static int Number(Group group) =>
        int.Parse(group.Value, CultureInfo.InvariantCulture);
}
