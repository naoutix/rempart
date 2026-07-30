using System.Text.Json;
using System.Text.Json.Nodes;
using Rempart.Core.Json;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The JSON datasets the signed channel carries, held to the promise the manifest verifier
/// was taught to keep about the envelope: a hole is refused, never thrown on.
///
/// <para>
/// The verifier's guard stops at the manifest. One level further in sit the files it
/// describes, and their readers repeated the mistake the verifier had just been cured of —
/// a <c>record</c> imposes nothing on deserialisation, so <c>"drivers":[null]</c> came back
/// as an entry whose every field was null and <c>NullReferenceException</c> came out of
/// <c>Parse</c>. Neither caller catches that: <see cref="UpdateStore"/> and
/// <see cref="UpdatePlanner"/> filter on <see cref="JsonException"/> and
/// <c>RuleFormatException</c>, so what escapes here ends the scan instead of taking the
/// documented "update refused, embedded baseline kept" path.
/// </para>
///
/// <para>
/// The content has to pass signature verification to get this far, so this is robustness
/// and not an open door — but "signed and unreadable by this version" is precisely the case
/// the fallback exists for, and a process that dies is not that fallback.
/// </para>
/// </summary>
public class DatasetHoleTests
{
    /// <summary>A JSON dataset reader, and the shape it is judged on once it has read.</summary>
    /// <param name="Kind">The <see cref="DatasetKind"/> the channel routes to this reader.</param>
    /// <param name="Valid">A file with nothing missing, the sweep's starting point.</param>
    /// <param name="Load">
    /// Parses, then renders what was actually retained. Only what a reader keeps can be a
    /// hole in what it hands on, so each row renders its own result rather than the file it
    /// was given.
    /// </param>
    private sealed record Reader(string Kind, string Valid, Func<string, JsonNode?> Load);

    private const string Fingerprint =
        "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";

    private static IReadOnlyList<Reader> Readers =>
    [
        new(DatasetKind.Drivers,
            RempartJson.SerialiseCompact(new DriverBlocklistFile(
                "2026-07-29T00:00:00Z", "test",
                [new BlockedDriver(Fingerprint, "capcom.sys", "vulnerable")])),
            json => Retained(DriverBlocklist.Parse(json))),

        new(DatasetKind.Bloatware,
            RempartJson.SerialiseCompact(new BloatwareCatalogFile(
                "2026-07-29T00:00:00Z", "test",
                [new BloatwareEntry("B1", BloatwareMatch.Name, "mcafee", "oem",
                    BloatwareRisk.Unwanted, "Impact non vide.", ImpactProvenance.Verified)])),
            json => Retained(BloatwareCatalog.Parse(json))),
    ];

    /// <summary>
    /// Every hole in a signed dataset is refused as a dataset the reader cannot read, and
    /// nothing that got through carries one.
    ///
    /// <para>
    /// Two assertions per variant, and they are not the same one. That nothing but a
    /// <see cref="JsonException"/> leaves <c>Parse</c> is what keeps the refusal inside the
    /// callers' <c>catch</c> filters. That a dataset which <em>did</em> load has no null in
    /// it is what keeps the crash from simply moving downstream — a blocked driver's
    /// category becomes a value in a finding's details, and a null there is a null in the
    /// report.
    /// </para>
    ///
    /// <para>
    /// The variants come from the serialised shape, not from a list written here, so a field
    /// added tomorrow to <see cref="BlockedDriver"/> or <see cref="BloatwareEntry"/> is swept
    /// without anyone remembering to come back. One thing it cannot see, and
    /// <see cref="JsonHoles"/> says so too: a field of value type that is <em>removed</em>
    /// reads as its zero rather than as a hole. That is not academic here —
    /// <see cref="BloatwareEntry.Match"/> and <see cref="BloatwareEntry.Risk"/> are enums, so
    /// a catalogue written without them loads as <c>Pfn</c> and <c>Unwanted</c> and
    /// recognises the wrong software rather than refusing. Written as <c>null</c> they are
    /// refused, which is the half this sweep covers.
    /// </para>
    /// </summary>
    [Fact]
    public void No_hole_in_a_signed_dataset_is_thrown_on_or_loaded()
    {
        foreach (var reader in Readers)
        {
            // The unpunctured file has to load cleanly, or every variant below would be
            // refused for a reason that has nothing to do with its hole.
            var intact = JsonHoles.FirstNull(reader.Load(reader.Valid));

            Assert.True(intact is null,
                $"{reader.Kind} : le fichier de départ porte déjà {intact} nul, "
                + "le balayage ne prouverait rien.");

            var variants = JsonHoles.Holes(JsonNode.Parse(reader.Valid)!).ToList();

            // A shape that stopped being walked would make this test vacuously green.
            Assert.NotEmpty(variants);

            foreach (var (label, punctured) in variants)
            {
                JsonNode? retained = null;
                var thrown = Record.Exception(
                    () => retained = reader.Load(punctured.ToJsonString()));

                Assert.True(thrown is null or JsonException,
                    $"{reader.Kind}, {label} : {thrown?.GetType().Name} a échappé au lecteur — "
                    + $"{thrown?.Message} Les deux appelants ne filtrent que JsonException, "
                    + "donc ce qui sort d'ici emporte le scan au lieu de refuser la mise à jour.");

                var hole = thrown is null ? JsonHoles.FirstNull(retained) : null;

                Assert.True(hole is null,
                    $"{reader.Kind}, {label} : jeu de données chargé avec {hole} nul. "
                    + "Le trou n'a pas disparu, il a été déplacé chez le collecteur.");
            }
        }
    }

    /// <summary>A table declaring one kind in each of the two forms, for the read below.</summary>
    private static class KindsInBothForms
    {
        public const string Written = "written";

        /// <summary>Not a const, and could not be — the case the first read missed.</summary>
        public static readonly string Computed = string.Concat("comp", "uted");
    }

    /// <summary>
    /// The read that feeds the guard sees both forms. Narrowed to <c>IsLiteral</c> it saw
    /// only the const, and the guard stayed green while blind — the one thing a guard must
    /// never do.
    ///
    /// <para>
    /// The read itself now lives in <see cref="StringTables"/>, because the guard in
    /// <c>UpdatePlannerTests</c> derives its coverage from the same table and had its own
    /// half-blind copy of it. One read, tested here, used by both.
    /// </para>
    /// </summary>
    [Fact]
    public void The_kind_table_is_read_in_both_forms_a_string_field_can_take() =>
        Assert.Equal(
            ["computed", "written"],
            StringTables.Declared(typeof(KindsInBothForms)).Order(StringComparer.Ordinal));

    /// <summary>
    /// The sweep above walks the fields by construction; this one keeps the list of
    /// <em>readers</em> from being the hand-kept half. The kinds are read off
    /// <see cref="DatasetKind"/>, so a kind added tomorrow arrives here on its own and its
    /// author has to place it on one side or the other rather than find out later that
    /// nobody swept it.
    /// </summary>
    [Fact]
    public void Every_dataset_kind_the_channel_routes_is_swept_or_declared_out_of_scope()
    {
        var declared = StringTables.Declared(typeof(DatasetKind));

        // Reflection that stopped finding anything would make this vacuously green.
        Assert.NotEmpty(declared);

        // Neither exclusion is a claim about the whole path a kind takes, only about the
        // JSON reader this file sweeps. Rules are YAML, read by RuleLoader, which refuses a
        // hole with its own exception — one both callers filter on — and has its own tests;
        // what UpdateStore then does with the rules it loaded is not swept here. A binary
        // entry is a stick seal: UpdateStore recognises it by name and never loads it as a
        // dataset at all.
        string[] outOfScope = [DatasetKind.Rules, DatasetKind.Binary];

        var unswept = declared
            .Except(Readers.Select(reader => reader.Kind), StringComparer.Ordinal)
            .Except(outOfScope, StringComparer.Ordinal)
            .ToList();

        Assert.True(unswept.Count == 0,
            $"Type(s) de jeu de données sans balayage de trous : {string.Join(", ", unswept)}. "
            + "Un lecteur JSON de plus dans le canal signé est un NullReferenceException de "
            + "plus à un endroit qu'aucun appelant n'attrape.");
    }

    /// <summary>
    /// The measured case, and the reason for everything above: fifty bytes of well-formed
    /// JSON, correctly signed, that used to reach <c>d.Sha256</c> on a null element.
    /// </summary>
    [Fact]
    public void A_null_element_in_a_blocklist_is_refused_not_thrown() =>
        Assert.Throws<JsonException>(() => DriverBlocklist.Parse(
            """{"asOfUtc":"x","source":"t","drivers":[null]}"""));

    /// <summary>The same, one reader over: <c>entry.Id</c> on a null element.</summary>
    [Fact]
    public void A_null_element_in_a_bloatware_catalogue_is_refused_not_thrown() =>
        Assert.Throws<JsonException>(() => BloatwareCatalog.Parse(
            """{"asOfUtc":"x","source":"t","entries":[null]}"""));

    /// <summary>What a reader kept of a blocklist, as JSON.</summary>
    private static JsonNode? Retained(DriverBlocklist blocklist) =>
        JsonSerializer.SerializeToNode(
            // Source is the one field neither reader keeps — nothing reads it back — so it
            // is restated here rather than left as the null it would otherwise look like a
            // reader had let through.
            new DriverBlocklistFile(blocklist.AsOfUtc, "non conservé", [.. blocklist.Drivers]),
            RempartJsonContext.Default.DriverBlocklistFile);

    /// <summary>What a reader kept of a bloatware catalogue, as JSON.</summary>
    private static JsonNode? Retained(BloatwareCatalog catalog) =>
        JsonSerializer.SerializeToNode(
            new BloatwareCatalogFile(catalog.AsOfUtc, "non conservé", [.. catalog.Entries]),
            RempartJsonContext.Default.BloatwareCatalogFile);
}
