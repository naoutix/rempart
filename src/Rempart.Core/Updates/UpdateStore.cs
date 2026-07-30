using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// The catalog actually evaluated, once the embedded baseline has been extended with
/// an update when one is present and trusted.
/// </summary>
public sealed record CatalogResolution(
    IReadOnlyList<Rule> Rules,
    DriverBlocklist Blocklist,
    BloatwareCatalog Catalog,
    string AsOfUtc,

    /// <summary>
    /// What the report must say about the store, or <c>null</c> when there is nothing
    /// to say. An applied update is visible; a refused one too — never in silence
    /// (ADR-002, D17).
    /// </summary>
    string? UpdateNote);

/// <summary>
/// The updated-data store: what <c>rempart update --apply</c> writes, and what every
/// scan reads back.
///
/// <para>
/// Centrepiece of ADR-002. Two invariants govern it. <b>D13</b>: nothing is loaded
/// without verification — the scan re-checks signature and hashes on every read; it
/// does not trust what an earlier <c>--apply</c> wrote, so a store file tampered with
/// since then is rejected, not loaded. <b>D12</b>: the embedded baseline is a floor —
/// an update may fix or add a check, never remove one.
/// </para>
///
/// <para>
/// <b>A store that cannot be read is a refused update, never a lost scan.</b> Both reads
/// in <see cref="Resolve(string, IReadOnlyList{Rule}, ManifestVerifier)"/> were bare. One
/// process holding <c>rempart-data\manifest.json</c> without sharing reads was enough for
/// the <c>IOException</c> to leave here, cross <c>CliHost</c> and reach the catch-all in
/// <c>Program</c>: no report, no integrity note, no score — a whole audit lost to a file
/// that happened to be open. The store is the one folder the stick seal excludes by
/// design, so nothing else was watching it. Same ending as REV-06, reached through the
/// file system rather than through the JSON.
/// </para>
///
/// <para>
/// That ending had a second door a few lines further down, and this one did not even need
/// the file system: two rule datasets of a single signed manifest declaring the same
/// identifier reached the merge, whose dictionary raised <c>ArgumentException</c> out of
/// here. Signed content, hashes checked, and no report. It is a refused update now, in the
/// wording every dataset this version cannot read already gets.
/// </para>
///
/// <para>
/// The refusal keeps its own wording throughout. "I could not read the store" is not
/// "there is no update" — silence is reserved for the store that is genuinely absent —
/// and it is not "this file no longer matches its fingerprint" either, which would accuse
/// a file on the strength of a read that never took place.
/// </para>
///
/// <para>
/// The invariant is held at two levels now, as REV-08 held its own. <see cref="TryRead"/>
/// answers for the reads, precisely; the guard around the whole resolution answers for the
/// rest of it, whatever that comes to be. It had to: a dataset name that cannot be turned
/// into a path reaches <c>Path.GetFullPath</c> before any read, and the
/// <c>ArgumentException</c> came out of <c>Resolve</c> with the store's signature and
/// hashes about to be checked — the bold sentence above, not holding.
/// </para>
/// </summary>
public static class UpdateStore
{
    public const string ManifestFileName = "manifest.json";

    /// <summary>
    /// Copies a verified manifest and its datasets into the store.
    ///
    /// Does not re-verify: the caller just did (<see cref="UpdatePlanner"/>). The
    /// scan will re-verify — that is where the guarantee lives, not here.
    /// </summary>
    public static void Apply(string sourceManifestPath, string storeDirectory, IEnumerable<string> datasetNames)
    {
        Directory.CreateDirectory(storeDirectory);

        var sourceDir = Path.GetDirectoryName(Path.GetFullPath(sourceManifestPath))
            ?? throw new InvalidOperationException("Manifeste sans dossier parent.");

        File.Copy(sourceManifestPath, Path.Combine(storeDirectory, ManifestFileName), overwrite: true);

        foreach (var name in datasetNames)
        {
            File.Copy(
                WithinOrThrow(sourceDir, name),
                WithinOrThrow(storeDirectory, name),
                overwrite: true);
        }
    }

    /// <summary>
    /// Writes a verified manifest and its datasets from bytes — the download case,
    /// where there is no source folder to copy from. The bytes are the ones the
    /// preparation step just verified, never re-downloaded: the scan will re-verify
    /// them anyway.
    /// </summary>
    public static void Write(
        string storeDirectory, byte[] manifest, IReadOnlyDictionary<string, byte[]> datasets)
    {
        Directory.CreateDirectory(storeDirectory);
        File.WriteAllBytes(Path.Combine(storeDirectory, ManifestFileName), manifest);

        foreach (var (name, bytes) in datasets)
        {
            File.WriteAllBytes(WithinOrThrow(storeDirectory, name), bytes);
        }
    }

    /// <summary>
    /// Resolves the catalog to evaluate: the baseline, extended with the store's
    /// update when it verifies.
    /// </summary>
    /// <param name="baseRules">
    /// The baseline — embedded rules, possibly joined by the <c>--rules</c> ones.
    /// The update layers on top, never removing any.
    /// </param>
    public static CatalogResolution Resolve(
        string storeDirectory, IReadOnlyList<Rule> baseRules, ManifestVerifier verifier) =>
        Resolve(storeDirectory, baseRules, verifier, File.ReadAllBytes);

    /// <summary>
    /// The same resolution with the file read handed in — the seam the guard is tested
    /// through. <see cref="UpdatePlanner"/> already hands its dataset read in the same way
    /// (ADR-001, D5), for a neighbouring reason rather than this one: there, to stay
    /// independent of where the bytes come from, a local file or the network.
    ///
    /// <para>
    /// Internal because it exists for the test suite: producing a read that fails needs a
    /// file the operating system refuses, and <see cref="FileShare"/> is only enforced on
    /// Windows, so the unit suite — which runs on Linux — could otherwise only watch the
    /// happy path. The real read against a real lock is covered too, over in the Windows
    /// suite; this seam is what makes the refusal provable on both.
    /// </para>
    /// </summary>
    /// <param name="readFile">How a store file becomes bytes. It is only ever called
    /// through <see cref="TryRead"/> — but that every read of the store goes through
    /// <em>it</em> is not something this signature can enforce: a second read written
    /// straight onto <see cref="File"/> would compile, and would not be guarded. What
    /// holds that is a guard over this file's own source, in <c>UpdateStoreTests</c>.</param>
    internal static CatalogResolution Resolve(
        string storeDirectory, IReadOnlyList<Rule> baseRules, ManifestVerifier verifier,
        Func<string, byte[]> readFile)
    {
        try
        {
            return FromStore(storeDirectory, baseRules, verifier, readFile);
        }
        catch (Exception ex)
        {
            // The second level, in REV-08's sense: whatever the resolution below ends up
            // doing, a store never costs the scan. The wording is the one every dataset
            // this version cannot read already gets, rather than a new one for the same
            // fact — and it never says "altéré", because nothing was judged.
            return Refused(baseRules,
                "Mise à jour présente mais illisible par cette version : " +
                $"{ex.Message} Socle embarqué conservé.");
        }
    }

    /// <summary>
    /// The resolution itself, which may throw — the level the guard above answers for.
    /// </summary>
    private static CatalogResolution FromStore(
        string storeDirectory, IReadOnlyList<Rule> baseRules, ManifestVerifier verifier,
        Func<string, byte[]> readFile)
    {
        var manifestPath = Path.Combine(storeDirectory, ManifestFileName);

        if (!File.Exists(manifestPath))
        {
            // The normal offline case: no store, no note. The binary alone stays
            // fully usable (D12).
            return new CatalogResolution(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);
        }

        var (manifestBytes, unreadable) = TryRead(readFile, manifestPath);

        if (manifestBytes is null)
        {
            // Present and unopenable. Not "no update", which is the only silent case, and
            // not "refused (Malformed)" either: nothing was read, so nothing is judged.
            return Refused(baseRules,
                $"Mise à jour présente mais son manifeste est illisible ({ManifestFileName}) : " +
                $"{unreadable} Socle embarqué conservé.");
        }

        var verdict = verifier.Verify(Decode(manifestBytes));

        if (!verdict.IsTrusted || verdict.Payload is null)
        {
            // A refused update is not applied — and is not silent either. The baseline
            // holds, and the report says why the update was not retained.
            return Refused(baseRules,
                $"Mise à jour présente mais refusée ({verdict.Status}) : {verdict.Explanation} " +
                "Socle embarqué conservé.");
        }

        // A stick seal shares this envelope but is not an update. Recognised before
        // anything else: what it declares are the stick's own files, which have no
        // reason to sit in the store, so the generic "dataset missing" would send the
        // reader looking for a file that was never supposed to be here.
        if (verdict.Payload.Datasets.Any(entry => entry.Kind == DatasetKind.Binary))
        {
            return Refused(baseRules,
                "Le magasin contient un sceau d'intégrité, pas une mise à jour. Il se " +
                "vérifie avec « rempart seal --check ». Socle embarqué conservé.");
        }

        var incoming = new List<Rule>();
        var incomingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var blocklist = DriverBlocklist.Empty;
        var catalog = BloatwareCatalog.Embedded;

        foreach (var entry in verdict.Payload.Datasets)
        {
            var path = TryWithin(storeDirectory, entry.Name);
            byte[]? bytes = null;

            if (path is not null && File.Exists(path))
            {
                var (read, why) = TryRead(readFile, path);

                if (read is null)
                {
                    // Its own wording, and separating it is the point: the reading below
                    // is a verdict on content, and no content was obtained. Sending an
                    // unreadable file down that branch would accuse it of being "altéré"
                    // on the strength of a read that never happened.
                    return Refused(baseRules,
                        $"Mise à jour présente mais un jeu de données ({entry.Name}) est " +
                        $"illisible : {why} Socle embarqué conservé.");
                }

                bytes = read;
            }

            if (bytes is null || !ManifestVerifier.FileMatches(entry, bytes))
            {
                // One dataset missing or no longer matching, and nothing is installed:
                // half an update is never applied. The file may have been tampered
                // with after being written — exactly what re-verification catches.
                return Refused(baseRules,
                    $"Mise à jour présente mais un jeu de données ({entry.Name}) ne correspond " +
                    "plus à son empreinte : altéré ou incomplet. Socle embarqué conservé.");
            }

            var text = System.Text.Encoding.UTF8.GetString(bytes);

            try
            {
                switch (entry.Kind)
                {
                    case DatasetKind.Rules:
                        // Uniqueness across datasets, checked here because nowhere else
                        // sees more than one of them: RuleLoader's own check spans a
                        // single file, and a manifest may sign several rule datasets.
                        // Two of them declaring the same identifier used to reach Merge,
                        // whose dictionary threw ArgumentException straight out of
                        // Resolve — a correctly signed store ending the scan, which is
                        // the very failure this file was fixed to stop having.
                        // RuleCatalog.Load runs the same check across the external
                        // directory; the comparer is the one Merge indexes with.
                        foreach (var rule in RuleLoader.Load(text, entry.Name))
                        {
                            if (!incomingIds.Add(rule.Id))
                            {
                                throw new RuleFormatException(
                                    $"identifiant « {rule.Id} » déjà défini par un autre jeu " +
                                    "de données du même manifeste.");
                            }

                            incoming.Add(rule);
                        }

                        break;

                    case DatasetKind.Drivers:
                        blocklist = DriverBlocklist.Parse(text);
                        break;

                    case DatasetKind.Bloatware:
                        catalog = BloatwareCatalog.Merge(BloatwareCatalog.Embedded, BloatwareCatalog.Parse(text));
                        break;

                    default:
                        // A kind a newer version understands, not this one: refuse it
                        // all, rather than apply what we can read and silence the rest.
                        return Refused(baseRules,
                            $"Mise à jour d'un type inconnu ({entry.Kind}) : installer une " +
                            "version plus récente. Socle embarqué conservé.");
                }
            }
            catch (Exception ex) when (ex is RuleFormatException or System.Text.Json.JsonException)
            {
                return Refused(baseRules,
                    $"Mise à jour présente mais illisible par cette version ({entry.Name}) : " +
                    $"{ex.Message} Socle embarqué conservé.");
            }
        }

        var merged = Merge(baseRules, incoming);
        var driverNote = blocklist.Count > 0 ? $", {blocklist.Count} pilotes surveillés" : "";
        var bloatNote = catalog.Count != BloatwareCatalog.Embedded.Count
            ? $", {catalog.Count} entrées bloatware" : "";

        return new CatalogResolution(merged, blocklist, catalog, verdict.Payload.PublishedAtUtc,
            $"Mise à jour appliquée, publiée le {verdict.Payload.PublishedAtUtc} : " +
            $"{merged.Count} contrôles ({baseRules.Count} au socle){driverNote}{bloatNote}.");
    }

    /// <summary>
    /// One store file, or the reason it could not be read. The single door every read of
    /// the store goes through, so that "unreadable" has one answer instead of one per
    /// call site.
    ///
    /// <para>
    /// <b>The <c>catch</c> has no filter, deliberately.</b> A list of exception types is a
    /// list to keep up to date, and three of this repository's have been caught short:
    /// REV-08 lost a whole scan to a <c>NotSupportedException</c> nobody had listed,
    /// <c>HttpTransport.Get</c> let an <c>InvalidOperationException</c> past
    /// <c>HttpRequestException or TaskCanceledException or UriFormatException</c> on a
    /// relative URL, and <c>SealCommand.SealNote</c> wrote the obvious
    /// <c>IOException or UnauthorizedAccessException</c> over a body that enumerates,
    /// hashes and deserialises. All three lost their filter in the end.
    /// </para>
    ///
    /// <para>
    /// What makes an unfiltered <c>catch</c> safe is the <em>size</em> of what it covers,
    /// not the types it names: the only statement inside this one is the read, so nothing
    /// that verification or parsing does can be reported as a file that would not open.
    /// That is why the read keeps its own guard even though
    /// <see cref="Resolve(string, IReadOnlyList{Rule}, ManifestVerifier, Func{string, byte[]})"/>
    /// now has one around the whole of the resolution — the two say different things, and
    /// the narrow one says the more precise.
    /// </para>
    ///
    /// <para>
    /// That outer guard was argued against here, on the grounds that it "would hand back a
    /// silently truncated catalogue". It does not, and the argument was wrong twice over:
    /// it hands back <see cref="CatalogResolution.Rules"/> exactly as it received them —
    /// the baseline, whole — with a note, which is the documented shape of a refused update
    /// and the opposite of silent. What the sentence was reaching for is the real cost,
    /// stated plainly below.
    /// </para>
    ///
    /// <para>
    /// The cost, said rather than left to be found: a defect in this file's own
    /// verification or merging now reads as "mise à jour illisible par cette version"
    /// rather than ending the run, so a bug here looks like bad data until someone reads
    /// the message it carries. Measured against what it replaces — a signed manifest whose
    /// dataset name held a null character ended the scan out of <c>Path.GetFullPath</c>,
    /// before a byte was read. A baseline-only report that says why is a usable answer; an
    /// ended scan is not.
    /// </para>
    /// </summary>
    private static (byte[]? Bytes, string? Failure) TryRead(
        Func<string, byte[]> readFile, string path)
    {
        try
        {
            return (readFile(path), null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    /// <summary>
    /// The manifest's bytes as text, reading exactly as <see cref="File.ReadAllText(string)"/>
    /// did before the read moved behind <c>readFile</c>: UTF-8, and a byte-order mark
    /// consumed rather than left in front of the JSON. A manifest saved with one by an
    /// editor resolved yesterday and has to resolve today: the guard is the change, the
    /// reading is not.
    /// </summary>
    private static string Decode(byte[] bytes)
    {
        using var reader = new StreamReader(
            new MemoryStream(bytes), System.Text.Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true);

        return reader.ReadToEnd();
    }

    private static CatalogResolution Refused(IReadOnlyList<Rule> baseRules, string note) =>
        new(baseRules, DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, note);

    /// <summary>
    /// Merges the update into the baseline (D12).
    ///
    /// An incoming rule with a known identifier replaces the baseline one — a fix; a
    /// brand-new incoming rule is appended. No baseline rule ever disappears, even
    /// when the update does not mention it: the floor holds. Baseline order is
    /// preserved so a report's list of failures stays stable from one version to
    /// the next.
    ///
    /// <para>
    /// <paramref name="incoming"/> is indexed by identifier, so its own identifiers have
    /// to be unique before it gets here — the loop in <c>Resolve</c> holds that across
    /// datasets. Leaving the dictionary to discover it meant an <c>ArgumentException</c>
    /// out of a signed store, ending the scan.
    /// </para>
    /// </summary>
    private static IReadOnlyList<Rule> Merge(
        IReadOnlyList<Rule> baseRules, IReadOnlyList<Rule> incoming)
    {
        var overrides = incoming.ToDictionary(r => r.Id, r => r, StringComparer.OrdinalIgnoreCase);
        var result = new List<Rule>(baseRules.Count);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in baseRules)
        {
            if (overrides.TryGetValue(rule.Id, out var replacement))
            {
                result.Add(replacement);
                used.Add(rule.Id);
            }
            else
            {
                result.Add(rule);
            }
        }

        foreach (var rule in incoming)
        {
            if (!used.Contains(rule.Id))
            {
                result.Add(rule);
            }
        }

        return result;
    }

    private static string WithinOrThrow(string directory, string name) =>
        TryWithin(directory, name)
        ?? throw new InvalidOperationException(
            $"Nom de jeu de données hors du dossier : {name}");

    /// <summary>
    /// Resolves a name inside a folder, or <c>null</c> when it escapes it. A name
    /// like « ..\\.. » must not become an arbitrary path — the trailing separator
    /// also avoids mistaking the folder for a sibling with a close name.
    /// </summary>
    private static string? TryWithin(string directory, string name)
    {
        var root = Path.GetFullPath(directory)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, name));

        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? full : null;
    }
}
