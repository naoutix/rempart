using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Rempart.Core.Cli;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The store does I/O: these tests rely on a real temporary directory, like the
/// external-rules tests. Each one cleans up its own.
/// </summary>
public sealed class UpdateStoreTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "rempart-store-" + Guid.NewGuid().ToString("n"));

    private string Source => EnsureDir(Path.Combine(root, "src"));
    private string Store => Path.Combine(root, "store");

    private static readonly string BaseRule = """
        - id: WIN-STORE-001
          title: Un contrôle
          severity: high
          domain: test
          check:
            type: registry
            path: HKLM\Software\Test
            value: Flag
            operator: equals
            expect: "1"
            windowsDefault: "0"
          rationale: Pour le test.
          references: []
        """;

    private IReadOnlyList<Rule> BaseCatalog() => RuleLoader.Load(BaseRule);

    /// <summary>The same check under another identifier, for the collisions below.</summary>
    private static string RuleText(string id) =>
        BaseRule.Replace("WIN-STORE-001", id, StringComparison.Ordinal);

    /// <summary>
    /// Writes a signed manifest and its dataset into the source directory, ready to be
    /// applied. Returns the manifest path, the public key and its fingerprint.
    /// </summary>
    private (string ManifestPath, ManifestVerifier Verifier) Publish(
        TestPublisher publisher, string datasetName, string content,
        string publishedAt = "2026-08-01T00:00:00Z", string? kind = null) =>
        SignManifest(publisher, [Stage(datasetName, content, kind)], publishedAt);

    /// <summary>
    /// Writes one dataset into the source directory and describes it for the manifest.
    /// Split out because a manifest may sign several, and only the manifest ever sees
    /// them together.
    /// </summary>
    private ManifestEntry Stage(string name, string content, string? kind = null)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        File.WriteAllBytes(Path.Combine(Source, name), bytes);

        return new ManifestEntry(
            name, "2.0.0", Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length,
            kind ?? DatasetKind.Infer(name));
    }

    private (string ManifestPath, ManifestVerifier Verifier) SignManifest(
        TestPublisher publisher, List<ManifestEntry> entries,
        string publishedAt = "2026-08-01T00:00:00Z")
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ManifestPayload(1, publishedAt, entries),
            RempartJsonContext.Default.ManifestPayload);

        var manifestPath = Path.Combine(Source, UpdateStore.ManifestFileName);
        File.WriteAllText(manifestPath, RempartJson.Serialise(new SignedManifest(
            Convert.ToBase64String(payload),
            [new ManifestSignature(publisher.KeyId, publisher.Sign(payload))])));

        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        return (manifestPath, verifier);
    }

    [Fact]
    public void No_store_leaves_the_base_catalogue_and_embedded_date()
    {
        using var publisher = new TestPublisher();
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Single(resolution.Rules);
        Assert.Equal(RuleCatalog.EmbeddedAsOfUtc, resolution.AsOfUtc);
        Assert.Null(resolution.UpdateNote);
    }

    [Fact]
    public void An_applied_bloatware_dataset_resolves_into_the_catalog()
    {
        using var publisher = new TestPublisher();

        var catalogJson = RempartJson.SerialiseCompact(new BloatwareCatalogFile(
            "2026-08-01T00:00:00Z", "test",
            [new BloatwareEntry("BLOAT-SIGNED", BloatwareMatch.Name, "signedware",
                "oem-preinstall", BloatwareRisk.Unwanted, "Ajouté par catalogue signé.")]));

        var (manifestPath, verifier) = Publish(publisher, "bloatware.json", catalogJson, kind: DatasetKind.Bloatware);
        UpdateStore.Apply(manifestPath, Store, ["bloatware.json"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        // The embedded baseline holds, the signed entry adds to it.
        Assert.True(resolution.Catalog.Count > BloatwareCatalog.Embedded.Count);
        Assert.Equal("BLOAT-SIGNED", resolution.Catalog.Match(new InstalledSoftware(
            "SignedWare Pro", null, null, SoftwareSource.Uninstall, false, true, "{s}"))?.Id);
    }

    [Fact]
    public void Without_a_store_the_catalog_is_the_embedded_baseline()
    {
        using var publisher = new TestPublisher();
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(BloatwareCatalog.Embedded.Count, resolution.Catalog.Count);
    }

    /// <summary>
    /// The full round trip: publish, apply, resolve. A new rule is added, and the data
    /// date becomes the publication date (D15).
    /// </summary>
    [Fact]
    public void An_applied_update_adds_rules_and_dates_from_the_manifest()
    {
        using var publisher = new TestPublisher();

        var addOne = BaseRule + """

            - id: WIN-STORE-002
              title: Ajouté
              severity: medium
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: Neuf
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", addOne, "2026-08-15T00:00:00Z");
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(2, resolution.Rules.Count);
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-002");
        Assert.Equal("2026-08-15T00:00:00Z", resolution.AsOfUtc);
        Assert.Contains("appliquée", resolution.UpdateNote);
    }

    /// <summary>
    /// D12: an update corrects an embedded check with the same identifier, without
    /// changing their count. The incoming version wins.
    /// </summary>
    [Fact]
    public void An_update_corrects_an_embedded_rule_of_the_same_id()
    {
        using var publisher = new TestPublisher();

        var corrected = BaseRule.Replace("expect: \"1\"", "expect: \"2\"");
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", corrected);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        var rule = Assert.Single(resolution.Rules);
        Assert.Equal("2", rule.Check.Expected);
    }

    /// <summary>
    /// D12, the floor: an update that does not mention an embedded check does not
    /// remove it. It stays, as is.
    /// </summary>
    [Fact]
    public void An_update_that_omits_an_embedded_rule_does_not_remove_it()
    {
        using var publisher = new TestPublisher();

        var onlyNew = """
            - id: WIN-STORE-999
              title: Seulement nouveau
              severity: low
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: X
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", onlyNew);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(2, resolution.Rules.Count);
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-001"); // the baseline holds
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-999");
    }

    /// <summary>
    /// D13: the scan re-verifies. A store file tampered with after apply is rejected —
    /// the baseline holds, and the report says why. Never silently.
    /// </summary>
    [Fact]
    public void A_store_file_tampered_after_apply_is_rejected_not_loaded()
    {
        using var publisher = new TestPublisher();
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        // Someone alters the dataset in the store after the fact.
        File.WriteAllText(Path.Combine(Store, "regles.yaml"), "- id: INJECTE");

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Single(resolution.Rules); // baseline only
        Assert.DoesNotContain(resolution.Rules, r => r.Id == "INJECTE");
        Assert.Contains("ne correspond", resolution.UpdateNote);
    }

    /// <summary>
    /// A store manifest signed by an unknown key: refused, baseline kept, and said.
    /// This is what separates "the store was compromised" from a silent load.
    /// </summary>
    [Fact]
    public void An_untrusted_store_manifest_is_refused_and_said()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var (manifestPath, _) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var strangerVerifier = new ManifestVerifier(
            new Dictionary<string, string> { [stranger.KeyId] = stranger.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), strangerVerifier);

        Assert.Single(resolution.Rules);
        Assert.Contains("refusée", resolution.UpdateNote);
    }

    /// <summary>
    /// A store file the operating system will not hand over is a <em>refused</em> update,
    /// not the end of the scan — and it says which of the two it is.
    ///
    /// <para>
    /// Neither read was guarded: an <c>IOException</c> on a manifest held open, or an
    /// <c>UnauthorizedAccessException</c> on a dataset, left <c>Resolve</c>, crossed
    /// <c>CliHost</c> and landed in <c>Program</c>'s catch-all. No report at all, over a
    /// folder the stick seal excludes by design — the same ending REV-06 was closed to
    /// stop, one door along.
    /// </para>
    ///
    /// <para>
    /// Two disguises are refused as firmly as the crash. Saying nothing would read as
    /// « pas de mise à jour disponible », and the store's whole job is to tell « I could
    /// not read » from « there is nothing ». Reusing the fingerprint wording would accuse
    /// a file of being <em>altéré</em> on the strength of a read that never happened.
    /// </para>
    ///
    /// <para>
    /// The files come from the store on disk rather than from a list written here, so a
    /// third file a later version keeps there is swept without anyone remembering to come
    /// back — with the store's shape required, a manifest and at least one dataset, since
    /// the dataset branch carries half of this and "not empty" would not have noticed it
    /// go. The exception types are three, and are not a specification: the guard has no
    /// filter, which is why the third one is deliberately outside any list a reader would
    /// have thought to write.
    /// </para>
    /// </summary>
    [Fact]
    public void An_unreadable_store_file_refuses_the_update_instead_of_ending_the_scan()
    {
        using var publisher = new TestPublisher();
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var files = Directory.GetFiles(Store);

        // Required by shape rather than by an exact list: a manifest and at least one
        // dataset. "Not empty" would stay green the day Apply stopped copying the
        // dataset, and the unreadable-dataset branch carries half of what is claimed
        // here — the sweep would quietly shrink to the manifest alone. Naming the two
        // files instead would cost the property below, that a third one is swept
        // without this line being revisited.
        var names = files.Select(file => Path.GetFileName(file)!).ToList();

        Assert.Contains(names, name => name == UpdateStore.ManifestFileName);
        Assert.Contains(names, name => name != UpdateStore.ManifestFileName);

        Exception[] failures =
        [
            new IOException("le fichier est ouvert en exclusif"),
            new UnauthorizedAccessException("accès refusé au magasin"),
            new InvalidOperationException("panne qu'aucune liste n'aurait prévue"),
        ];

        foreach (var file in files)
        {
            foreach (var failure in failures)
            {
                var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier,
                    path => string.Equals(path, file, StringComparison.OrdinalIgnoreCase)
                        ? throw failure
                        : File.ReadAllBytes(path));

                var seen = $"{Path.GetFileName(file)}, {failure.GetType().Name}";
                var note = resolution.UpdateNote;

                Assert.True(note is not null,
                    $"{seen} : aucune note. Un magasin qu'on n'a pas pu lire se présenterait "
                    + "comme un magasin absent, qui est la seule situation muette.");

                Assert.True(
                    note!.Contains("illisible", StringComparison.Ordinal)
                    && note.Contains(failure.Message, StringComparison.Ordinal)
                    && note.Contains("Socle embarqué conservé", StringComparison.Ordinal),
                    $"{seen} : la note ne dit pas que la lecture a échoué ni ce qu'elle a "
                    + $"gardé — « {note} »");

                Assert.True(!note.Contains("altéré", StringComparison.Ordinal),
                    $"{seen} : une lecture qui n'a pas eu lieu accuse le fichier d'être "
                    + $"altéré — « {note} »");

                Assert.True(resolution.Rules.Count == BaseCatalog().Count,
                    $"{seen} : le socle n'est plus intact, {resolution.Rules.Count} contrôles.");
            }
        }
    }

    /// <summary>
    /// No file of the store is consumed behind the injected reader's back: what the reader
    /// saw and what the store holds are the same set, so a read <em>moved</em> off the seam
    /// leaves its file unaccounted for and turns this red.
    ///
    /// <para>
    /// Two sets, which is exactly as far as it goes: a read <em>added</em> beside the seam
    /// on a file the seam already read is invisible here, since the file is in both sets
    /// either way. Measured, not assumed — inserting <c>File.ReadAllBytes(manifestPath)</c>
    /// in front of the manifest's <c>TryRead</c> left this test and the sweep above green.
    /// The second door is closed by
    /// <see cref="Nothing_but_the_seam_turns_a_store_path_into_bytes"/>, which reads the
    /// source rather than the behaviour, because that claim is about code that does not
    /// exist and no run can observe one of those.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_file_of_the_store_is_read_through_the_one_guarded_reader()
    {
        using var publisher = new TestPublisher();
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var read = new List<string>();

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier, path =>
        {
            read.Add(path);
            return File.ReadAllBytes(path);
        });

        // Resolution has to have gone all the way, or nothing would have been read.
        Assert.Contains("appliquée", resolution.UpdateNote);

        var onDisk = Directory.GetFiles(Store)
            .Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var throughReader = read
            .Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.True(onDisk.SetEquals(throughReader),
            "Le lecteur gardé n'a pas vu passer tout le magasin. Lus hors de lui : "
            + $"{Names(onDisk.Except(throughReader))} ; lus sans être dans le magasin : "
            + $"{Names(throughReader.Except(onDisk))}. Une lecture qui ne passe pas par "
            + "lui n'est pas gardée.");

        static string Names(IEnumerable<string> paths) =>
            string.Join(", ", paths.Select(Path.GetFileName).DefaultIfEmpty("aucun"));
    }

    /// <summary>
    /// The half no run can show: that there is no second door. A read added beside the seam
    /// is a line of source, and the two tests above only ever see the reads that happen —
    /// so this one reads the source, as <c>RuleFileTests</c> does over the YAML extension
    /// no second class of the core may spell out.
    ///
    /// <para>
    /// A whitelist of what the store may do to the file system, not a list of forbidden
    /// calls: a blacklist is a list to keep up to date, which is the habit
    /// <c>UpdateStore.TryRead</c> exists to break. Anything else has to be added below
    /// deliberately, and the single <c>ReadAllBytes</c> left is pinned to the line that
    /// hands it to the guarded overload.
    /// </para>
    ///
    /// <para>
    /// What it does not cover, said outright: it reads the text of one file, so a store
    /// read placed in some other class would be outside it, and a path opened through a
    /// name this list does not contain would need that name added. It is the claim
    /// « nothing else in <c>UpdateStore</c> reads the store », no wider.
    /// </para>
    /// </summary>
    [Fact]
    public void Nothing_but_the_seam_turns_a_store_path_into_bytes()
    {
        // Comments dropped first. That file's prose names File.ReadAllText and
        // File.ReadAllBytes on purpose — a mention is not a read, and a guard that
        // could not tell them apart would be answered by rewording a comment.
        var source = string.Join('\n',
            RepositoryFiles.Read("src/Rempart.Core/Updates/UpdateStore.cs")
                .Split('\n')
                .Select(line => Regex.Replace(line, "//.*$", string.Empty)));

        var strays = Regex.Matches(source, @"\bFile\.(\w+)")
            .Select(match => match.Groups[1].Value)
            .Where(name => name is not ("Exists" or "Copy" or "WriteAllBytes" or "ReadAllBytes"))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(strays.Count == 0,
            $"UpdateStore touche au système de fichiers hors de la liste : File.{string.Join(", File.", strays)}. "
            + "Une lecture du magasin passe par le lecteur injecté, sinon son échec n'est gardé "
            + "par rien et emporte le scan.");

        const string Seam = "Resolve(storeDirectory, baseRules, verifier, File.ReadAllBytes);";

        var reads = source.Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Contains("File.ReadAllBytes", StringComparison.Ordinal))
            .ToList();

        Assert.True(reads.Count == 1 && reads[0] == Seam,
            "La seule lecture d'octets d'UpdateStore doit être celle remise au lecteur gardé. "
            + $"Trouvé : {string.Join(" | ", reads.DefaultIfEmpty("aucune"))}");

        // A stream opened on a path would read the store without ever naming File.
        Assert.DoesNotContain("FileStream", source, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two rule datasets of one signed manifest declaring the same identifier: a refused
    /// update, not the end of the scan.
    ///
    /// <para>
    /// <c>RuleLoader</c> rejects a duplicate inside a file, and <c>RuleCatalog.Load</c>
    /// rejects one spread across the external directory. Between those two, the store had
    /// nothing: the rules of every dataset piled into one list, and the merge indexed that
    /// list by identifier — <c>ArgumentException</c>, out of <c>Resolve</c>, through
    /// <c>CliHost</c>, into <c>Program</c>'s catch-all. No report, on content this binary
    /// had just verified the signature and the hashes of.
    /// </para>
    ///
    /// <para>
    /// Worse where it is least visible: <c>update --check</c> and <c>--apply</c> read each
    /// dataset on its own and both succeed, so what dies is the next scan.
    /// </para>
    /// </summary>
    [Fact]
    public void Two_rule_datasets_declaring_one_identifier_refuse_the_update()
    {
        using var publisher = new TestPublisher();

        var (manifestPath, verifier) = SignManifest(publisher,
            [Stage("a.yaml", RuleText("WIN-STORE-777")),
             Stage("b.yaml", RuleText("WIN-STORE-777"))]);

        UpdateStore.Apply(manifestPath, Store, ["a.yaml", "b.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.NotNull(resolution.UpdateNote);
        Assert.Contains("illisible par cette version", resolution.UpdateNote, StringComparison.Ordinal);
        Assert.Contains("WIN-STORE-777", resolution.UpdateNote, StringComparison.Ordinal);
        Assert.Contains("Socle embarqué conservé", resolution.UpdateNote, StringComparison.Ordinal);

        // The baseline is what a refused update leaves behind — whole, and by itself.
        Assert.Equal(BaseCatalog().Count, resolution.Rules.Count);
        Assert.DoesNotContain(resolution.Rules, rule => rule.Id == "WIN-STORE-777");
    }

    /// <summary>
    /// The manifest read moved from <c>File.ReadAllText</c> to bytes decoded here, and a
    /// manifest saved with a byte-order mark — any editor will do that — resolved before
    /// and has to resolve after. The guard is the change; the reading is not.
    /// </summary>
    [Fact]
    public void A_manifest_saved_with_a_byte_order_mark_still_resolves()
    {
        using var publisher = new TestPublisher();
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var stored = Path.Combine(Store, UpdateStore.ManifestFileName);
        File.WriteAllBytes(stored, [.. Encoding.UTF8.GetPreamble(), .. File.ReadAllBytes(stored)]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Contains("appliquée", resolution.UpdateNote);
    }

    /// <summary>
    /// The second level, in the sense REV-08 gave the word: whatever <c>Resolve</c> ends up
    /// doing, a store never costs the scan.
    ///
    /// <para>
    /// <c>TryRead</c> guards the reads and nothing else, which was argued in this file as
    /// safe because verification, parsing and merging "stay outside, where an unexpected
    /// exception still surfaces as one". It does surface — through <c>CliHost</c>, into
    /// <c>Program</c>, as a lost audit. Measured: a dataset name that cannot be turned into
    /// a path — one null character is enough — reaches <c>Path.GetFullPath</c> before any
    /// read, and <c>ArgumentException : Null character in path</c> came out of
    /// <c>Resolve</c>. Signed content, hashes about to be checked, and no report.
    /// </para>
    ///
    /// <para>
    /// The objection that outer guard was refused on does not hold against this one: it
    /// hands back <see cref="CatalogResolution.Rules"/> untouched — the baseline, plus
    /// whatever <c>--rules</c> added, whole — and a note, which is the documented shape of a
    /// refused update rather than a truncated catalogue or a silence.
    /// </para>
    /// </summary>
    [Fact]
    public void A_dataset_name_that_is_not_a_path_refuses_the_update()
    {
        const string Prefix = "Mise à jour présente mais illisible par cette version : ";
        const string Suffix = " Socle embarqué conservé.";

        var note = BrokenStore().UpdateNote;

        Assert.NotNull(note);
        Assert.StartsWith(Prefix, note, StringComparison.Ordinal);
        Assert.EndsWith(Suffix, note, StringComparison.Ordinal);

        // What is between the two is the failure's own words. Asserted for length rather
        // than spelled out: the sentence that used to be pinned here — "Null character in
        // path" — belongs to System.Private.CoreLib, and would be the first assertion in
        // this repository to depend on the culture the runner happens to have.
        Assert.NotEmpty(note[Prefix.Length..^Suffix.Length].Trim());

        // Not accused of anything it was never read for, and the baseline is whole.
        Assert.DoesNotContain("altéré", note, StringComparison.Ordinal);
        Assert.Equal(BaseCatalog().Count, BrokenStore().Rules.Count);
    }

    /// <summary>
    /// The half a note in the report header cannot reach: the caller who reads the exit
    /// code and nothing else.
    ///
    /// <para>
    /// <c>ExitCodes.ForScan</c> reads the collectors, the findings and the verdicts, and a
    /// <see cref="CatalogResolution"/> used to have a channel to none of them. So the guard
    /// added above turned the measured case — a signed manifest whose dataset name holds a
    /// null character — from an ended run into a silent success: full report, note in the
    /// header, <c>0</c>. Every other branch of the resolution says "refused", and this one
    /// arriving as the same number would tell a scheduler that a defect of this version and
    /// a signature we do not trust call for the same thing, which is nothing.
    /// </para>
    ///
    /// <para>
    /// <see cref="AuditGap.Broken"/> and not <see cref="AuditGap.Refused"/>: re-running
    /// elevated does not repair a version that threw. Not a verdict about the machine
    /// either — nothing was observed, so the severity stays
    /// <see cref="FindingSeverity.Notable"/> and the score, which reads verdicts, never
    /// sees it.
    /// </para>
    /// </summary>
    [Fact]
    public void A_store_this_version_breaks_down_over_reaches_the_exit_code()
    {
        var clean = Finished();

        Assert.Equal(ExitCode.Success, ExitCodes.ForScan(clean));

        var carried = BrokenStore().AppliedTo(clean);

        Assert.True(carried.Findings.Count == 1,
            $"Le scan porte {carried.Findings.Count} constat(s) au lieu d'un. Un magasin "
            + "sur lequel cette version casse n'atteint le code de sortie que par un "
            + "constat : l'en-tête n'est pas un canal que l'ordonnanceur lit.");

        var line = carried.Findings[0];

        Assert.True(line.Gap == AuditGap.Broken,
            $"Le magasin sur lequel cette version casse porte {line.Gap?.ToString() ?? "aucune lacune"}. "
            + "Broken est ce que lit ExitCodes, et relancer en élévation ne le répare pas.");

        Assert.True(line.Severity == FindingSeverity.Notable,
            $"Sévérité {line.Severity} : rien n'a été observé, donc rien n'est reproché à "
            + "la machine.");

        Assert.Equal(UpdateStore.BreakdownKind, line.Kind);
        Assert.Equal(UpdateStore.BreakdownSource, line.Source);
        Assert.NotEmpty(line.Reasons.Single());

        Assert.True(ReportLabels.Family(line.Kind) != line.Kind,
            $"La famille « {line.Kind} » n'a pas de libellé dans ReportLabels.Family, donc "
            + "le rapport titre la section avec l'identifiant.");

        Assert.True(ExitCodes.ForScan(carried) == ExitCode.Failure,
            $"Le magasin sur lequel cette version casse rend {ExitCodes.ForScan(carried)}. "
            + "L'ordonnanceur ne lit que ce nombre, et il vaut 0 pour une mise à jour "
            + "refusée : les deux arriveraient identiques.");

        Assert.Equal(BrokenStore().UpdateNote, carried.UpdateNote);
    }

    /// <summary>
    /// The other side of the same line, and the one that must not move with it: a refused
    /// update is not a failed run.
    ///
    /// <para>
    /// Each of these decided something — the key is not one we pinned, the bytes no longer
    /// match their fingerprint, the file would not open. The baseline holds, the report says
    /// so, and the scan is worth exactly what it says: nothing to fix, exit <c>0</c>. Making
    /// the breakdown above reach the exit code is only worth anything if these do not follow
    /// it there.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_update_never_becomes_a_failed_run()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();

        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var strangerVerifier = new ManifestVerifier(
            new Dictionary<string, string> { [stranger.KeyId] = stranger.PublicKey });

        var datasetPath = Path.Combine(Store, "regles.yaml");

        (string Refusal, CatalogResolution Resolution)[] refusals =
        [
            ("signature d'une clé inconnue",
                UpdateStore.Resolve(Store, BaseCatalog(), strangerVerifier)),
            ("fichier que le système refuse d'ouvrir",
                UpdateStore.Resolve(Store, BaseCatalog(), verifier,
                    path => string.Equals(path, datasetPath, StringComparison.OrdinalIgnoreCase)
                        ? throw new IOException("le fichier est ouvert en exclusif")
                        : File.ReadAllBytes(path))),
            ("empreinte qui ne correspond plus",
                UpdateStore.Resolve(Store, BaseCatalog(), verifier,
                    path => string.Equals(path, datasetPath, StringComparison.OrdinalIgnoreCase)
                        ? Encoding.UTF8.GetBytes(RuleText("WIN-STORE-999"))
                        : File.ReadAllBytes(path))),
        ];

        foreach (var (refusal, resolution) in refusals)
        {
            Assert.True(resolution.UpdateNote is not null,
                $"{refusal} : aucune note, alors que seul un magasin absent est muet.");

            Assert.True(resolution.Breakdown is null,
                $"{refusal} : un refus délibéré est présenté comme une panne de cette "
                + $"version — « {resolution.Breakdown?.Reasons[0]} ». Un refus n'est pas un "
                + "échec, et l'appelant qui ne lit que le code de sortie ne pourrait plus "
                + "les distinguer.");

            var carried = resolution.AppliedTo(Finished());

            Assert.True(ExitCodes.ForScan(carried) == ExitCode.Success,
                $"{refusal} : le scan rend {ExitCodes.ForScan(carried)} alors que rien n'a "
                + "échoué — le socle a été évalué en entier.");
        }
    }

    /// <summary>
    /// The store whose resolution this version cannot carry out: a signed manifest naming a
    /// dataset that cannot be turned into a path. One null character is enough, and it is
    /// met by <c>Path.GetFullPath</c> before a byte of the store is read.
    /// </summary>
    private CatalogResolution BrokenStore()
    {
        using var publisher = new TestPublisher();

        var bytes = Encoding.UTF8.GetBytes(BaseRule);

        var (manifestPath, verifier) = SignManifest(publisher,
            [new ManifestEntry("\0.yaml", "2.0.0",
                Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length,
                DatasetKind.Rules)]);

        // Copied rather than applied: Apply resolves the name too, and what a scan meets is
        // the state of the store, however it got there.
        Directory.CreateDirectory(Store);
        File.Copy(manifestPath, Path.Combine(Store, UpdateStore.ManifestFileName), overwrite: true);

        return UpdateStore.Resolve(Store, BaseCatalog(), verifier);
    }

    /// <summary>A scan that went perfectly, so that the exit code below is the store's.</summary>
    private static ScanResult Finished() =>
        new("1.0.0", "2026-07-30T00:00:00Z", [], [], [], null, "abc",
            DataFreshness.At("2026-07-01T00:00:00Z", "2026-07-30T00:00:00Z"));

    private static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
