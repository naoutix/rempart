using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds <see cref="ScanEngine.DefaultFindingCollectors"/> against the collectors that
/// actually exist — the implementations compiled into <c>Rempart.Core</c>, and the files
/// that declare them.
///
/// <para>
/// This is the collector half of D2, left open when the provider half was closed. A provider
/// added to <c>ProviderSet</c> and forgotten in the replay wiring is caught by
/// <c>FixtureReplayTests.Every_provider_is_wired_into_the_replay</c>; a <em>collector</em>
/// forgotten in the registration was caught by nothing, because it needs no new provider —
/// one that reads the registry, the filesystem or WMI leaves the provider count at twenty and
/// that guard green. Measured on this repository before this file existed: unregistering
/// <see cref="ComHijackCollector"/>, <see cref="UnquotedServicePathCollector"/>,
/// <see cref="HostsFileCollector"/> or <see cref="SoftwareInventoryCollector"/> left all 765
/// unit tests passing, goldens included — the collector runs nowhere, so every reference
/// stays identical to the byte. Written, reviewed, merged, never executed, and the report
/// says « rien trouvé » about the surface it was written for.
/// </para>
///
/// <para>
/// Derived rather than restated, which is the whole point: the only place that mentioned
/// <see cref="IFindingCollector"/> in this suite was <c>CompromiseMarkersTests</c>, which
/// builds its own list of eight and says why. A guard confronting one hand-kept list with a
/// second written by the same hand in the same sitting verifies that the author agreed with
/// themselves.
/// </para>
///
/// <para>
/// The registration itself has to stay a hand-written table — ADR-001 ships Native AOT
/// without reflection — so deriving the expectation is the tests' job, not the product's.
/// <see cref="Path"/> is legitimate here: these are paths on the machine running the test,
/// not Windows paths captured on one machine and replayed on another.
/// </para>
/// </summary>
public sealed class FindingCollectorRegistrationTests
{
    /// <summary>
    /// Collectors deliberately kept out of the default registration, each with its reason.
    ///
    /// <para>
    /// Empty today — every implementation is registered. It exists so that the first
    /// legitimate exception has to be written down and defended here, rather than taken by
    /// deleting a line: from the outside, a collector left out on purpose and one left out by
    /// accident are the same missing line, and only this array tells them apart.
    /// </para>
    /// </summary>
    private static readonly string[] DeliberatelyUnregistered = [];

    /// <summary>
    /// Every compiled collector is registered, and nothing is registered that no longer
    /// exists.
    ///
    /// <para>
    /// Both directions from one <c>SetEquals</c>, and the second direction is what keeps the
    /// guard honest: were the reflection filter to stop matching — a collector moved behind an
    /// abstract base, the interface renamed — the compiled set would come back empty and the
    /// registered ones would have nothing to match, so the assertion fails instead of passing
    /// vacuously. A filter that quietly stops looking reports success, which is the failure
    /// this file exists to prevent.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_finding_collector_compiled_into_the_core_is_registered()
    {
        var compiled = Compiled();

        Assert.True(compiled.Count > 0,
            "Aucune implémentation d'IFindingCollector trouvée dans Rempart.Core : le filtre "
            + "de cette garde ne voit plus rien, et une garde qui n'inspecte rien passe.");

        var expected = compiled
            .Except(DeliberatelyUnregistered, StringComparer.Ordinal)
            .ToHashSet(StringComparer.Ordinal);

        var registered = Registered();

        Assert.True(expected.SetEquals(registered),
            "Les collecteurs de constats compilés et ceux enregistrés dans "
            + "ScanEngine.DefaultFindingCollectors ont divergé. "
            + $"Compilés mais jamais enregistrés, donc jamais exécutés : {Join(expected.Except(registered))}. "
            + $"Enregistrés sans implémentation compilée correspondante : {Join(registered.Except(expected))}. "
            + "Un collecteur non enregistré ne remonte aucun constat et ne fait bouger aucune "
            + "référence : le rapport dit « rien trouvé » de sa surface, ce qui se lit comme "
            + "une machine saine.");
    }

    /// <summary>
    /// The same claim against the source tree, which the reflection above cannot make.
    ///
    /// <para>
    /// Dropping <c>: IFindingCollector</c> from a collector removes it from the compiled set
    /// <em>and</em> forces its removal from the registration — the collection expression is
    /// typed — so the two shrink together and the guard above stays green while the scan
    /// quietly loses a surface. The files in <c>Findings/</c> do not move on their own, so
    /// they are the third party that notices.
    /// </para>
    ///
    /// <para>
    /// A missing directory throws rather than yielding an empty set, which is the loud
    /// failure wanted: renaming <c>Findings/</c> must break this test, not silence it.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_collector_file_in_Findings_is_registered()
    {
        var onDisk = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("src/Rempart.Core/Findings"),
                "*Collector.cs", SearchOption.TopDirectoryOnly)
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .ToHashSet(StringComparer.Ordinal);

        var expected = onDisk
            .Except(DeliberatelyUnregistered, StringComparer.Ordinal)
            .ToHashSet(StringComparer.Ordinal);

        var registered = Registered();

        Assert.True(expected.SetEquals(registered),
            "Les fichiers de collecteurs de src/Rempart.Core/Findings et "
            + "ScanEngine.DefaultFindingCollectors ont divergé. "
            + $"Présents sur le disque mais jamais enregistrés : {Join(expected.Except(registered))}. "
            + $"Enregistrés sans fichier du même nom : {Join(registered.Except(expected))}.");
    }

    /// <summary>
    /// What the product actually builds, by type name.
    ///
    /// <para>
    /// The instances the registration hands back, never types this guard activates itself:
    /// <see cref="LoadedDriversCollector"/> takes a blocklist and
    /// <see cref="SoftwareInventoryCollector"/> a catalog, and a guard that had to know how to
    /// construct each collector would be a third list to keep in step with the other two. It
    /// is also the only way to see a collector registered under a condition rather than
    /// registered.
    /// </para>
    ///
    /// <para>
    /// The empty blocklist and the empty catalog are what a replay evaluates and what
    /// <c>ScanEngine.Run</c> falls back to (D12): nothing here depends on their contents,
    /// only on which types come back.
    /// </para>
    /// </summary>
    private static HashSet<string> Registered()
    {
        var collectors = ScanEngine.DefaultFindingCollectors(
            DriverBlocklist.Empty, BloatwareCatalog.Empty);

        var names = collectors.Select(collector => collector.GetType().Name)
            .ToHashSet(StringComparer.Ordinal);

        // The set comparisons above would swallow a collector registered twice, and twice is
        // not harmless: it emits every one of its findings a second time, and the report
        // counts them as two occurrences of the same persistence.
        Assert.True(names.Count == collectors.Count,
            $"{collectors.Count} collecteurs enregistrés pour {names.Count} types distincts : "
            + "l'un d'eux est enregistré deux fois, et rendra chacun de ses constats en double.");

        return names;
    }

    /// <summary>
    /// Every concrete <see cref="IFindingCollector"/> the assembly holds, wherever it lives.
    ///
    /// <para>
    /// The whole of <c>Rempart.Core</c> rather than the <c>Findings</c> namespace alone:
    /// scoping the search to the namespace would mean that moving a collector elsewhere takes
    /// it out of this guard's sight without failing anything, which is the same silence one
    /// directory over.
    /// </para>
    /// </summary>
    private static HashSet<string> Compiled() =>
        typeof(IFindingCollector).Assembly.GetTypes()
            .Where(type => type is { IsClass: true, IsAbstract: false }
                && typeof(IFindingCollector).IsAssignableFrom(type))
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

    private static string Join(IEnumerable<string> names)
    {
        var listed = names.OrderBy(name => name, StringComparer.Ordinal).ToList();
        return listed.Count == 0 ? "aucun" : string.Join(", ", listed);
    }
}
