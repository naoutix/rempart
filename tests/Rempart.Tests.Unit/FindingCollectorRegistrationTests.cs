using System.Reflection;
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
    /// A scan cannot be run without being told which finding collectors to run — and
    /// therefore without the driver blocklist and the bloatware catalog they judge with.
    ///
    /// <para>
    /// The two guards above say which collectors exist; this one says a run has to be handed
    /// them. <c>ScanEngine.Run</c> took the list as an optional parameter falling back to
    /// <c>DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty)</c>, so
    /// dropping the argument at the call site compiled — in Release, warnings as errors, no
    /// diagnostic at all — the sixteen collectors still ran, and they ran against an empty
    /// blocklist and an empty catalog. The omission #151 closed made a collector vanish; this
    /// one leaves every collector in place and takes away what they judge with, which no
    /// golden reference and no count of findings can see: the report says « aucun pilote
    /// bloqué » of a machine carrying one.
    /// </para>
    ///
    /// <para>
    /// Reflection over the signature rather than a guard reading <c>ScanCommand</c> as text:
    /// what the compiler refuses outright needs no watching, and the call site lives in
    /// <c>Rempart.Cli</c>, which no test assembly references. Every <c>Run</c> is checked
    /// rather than the only one that exists, because an overload without the parameter would
    /// put the shorter call back within reach — the reason #136 changed <c>ListValues</c>'
    /// return type instead of adding an overload beside it.
    /// </para>
    /// </summary>
    [Fact]
    public void No_scan_runs_without_being_told_which_finding_collectors_to_run()
    {
        var runs = typeof(ScanEngine)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Where(method => method.Name == "Run")
            .ToList();

        Assert.True(runs.Count > 0,
            "Aucune méthode publique ScanEngine.Run : cette garde ne regarde plus rien, et "
            + "une garde qui n'inspecte rien passe.");

        var lenient = runs
            .Where(run => run.GetParameters()
                    .FirstOrDefault(parameter => parameter.Name == "findingCollectors")
                is null or { IsOptional: true })
            .Select(Signature)
            .ToList();

        Assert.True(lenient.Count == 0,
            $"Ces surcharges de ScanEngine.Run se lancent sans collecteurs de constats : "
            + $"{Join(lenient)}. Le scan tourne alors avec une liste de pilotes vulnérables "
            + "et un catalogue bloatware vides, et le rapport dit « aucun pilote bloqué, "
            + "aucun bloatware » d'une machine qui en porte.");
    }

    /// <summary>
    /// No finding collector lets the data it judges with be left out.
    ///
    /// <para>
    /// The same silence one constructor down, and the reason the guard above does not close
    /// it on its own: <see cref="SoftwareInventoryCollector"/> took
    /// <c>BloatwareCatalog? catalog = null</c> and substituted the empty catalog, so dropping
    /// <c>catalog</c> from the registration line itself compiled and left the whole suite
    /// green — measured on this repository, 968 unit tests and 132 Windows tests, no failure.
    /// Its neighbour <see cref="LoadedDriversCollector"/> has always demanded its blocklist,
    /// and nothing said why the two differed.
    /// </para>
    ///
    /// <para>
    /// Derived from the assembly, so the collector written next year is held to it without
    /// this file being edited. One that genuinely wants a default has to argue for it here,
    /// which is the point: from the outside, data deliberately omitted and data forgotten are
    /// the same missing argument.
    /// </para>
    /// </summary>
    [Fact]
    public void No_finding_collector_defaults_away_the_data_it_judges_with()
    {
        var compiled = CompiledTypes();

        Assert.True(compiled.Count > 0,
            "Aucune implémentation d'IFindingCollector trouvée dans Rempart.Core : le filtre "
            + "de cette garde ne voit plus rien, et une garde qui n'inspecte rien passe.");

        var lenient = compiled
            .SelectMany(type => type.GetConstructors()
                .SelectMany(constructor => constructor.GetParameters())
                .Where(parameter => parameter.IsOptional)
                .Select(parameter =>
                    $"{type.Name}({parameter.ParameterType.Name} {parameter.Name} = …)"))
            .ToList();

        Assert.True(lenient.Count == 0,
            $"Ces collecteurs se construisent sans la donnée qu'ils confrontent : {Join(lenient)}. "
            + "Omise, elle est remplacée par une liste vide et le collecteur ne reconnaît plus "
            + "rien : il rend les mêmes constats bénins qu'une machine saine, sans qu'aucune "
            + "référence figée ni aucun compte de constats ne bouge.");
    }

    /// <summary>Parameters as written, so the failure names the offending overload.</summary>
    private static string Signature(MethodInfo method) =>
        $"Run({string.Join(", ", method.GetParameters().Select(parameter =>
            $"{parameter.ParameterType.Name} {parameter.Name}"
            + (parameter.IsOptional ? " = …" : string.Empty)))})";

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
    /// The empty blocklist and the empty catalog are what a scan with no update to apply
    /// evaluates (D12): nothing here depends on their contents, only on which types come
    /// back. They are named rather than left out — no caller can leave them out any more,
    /// which is what the two guards above hold.
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
        CompiledTypes().Select(type => type.Name).ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The same collectors as types. One filter for both readings of the assembly: two
    /// copies would let a guard keep seeing what the other has stopped seeing.
    /// </summary>
    private static List<Type> CompiledTypes() =>
        [.. typeof(IFindingCollector).Assembly.GetTypes()
            .Where(type => type is { IsClass: true, IsAbstract: false }
                && typeof(IFindingCollector).IsAssignableFrom(type))];

    private static string Join(IEnumerable<string> names)
    {
        var listed = names.OrderBy(name => name, StringComparer.Ordinal).ToList();
        return listed.Count == 0 ? "aucun" : string.Join(", ", listed);
    }
}
