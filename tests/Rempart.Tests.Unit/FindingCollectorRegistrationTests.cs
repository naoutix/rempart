using System.Reflection;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds <see cref="ScanEngine.DefaultFindingCollectors"/> against the collectors that
/// actually exist — the implementations compiled into <c>Rempart.Core</c>, and the files
/// that declare them — and against the data those collectors judge with: that a run cannot
/// be started without them, that no collector offers a way in that leaves the data out, and
/// that the two lists handed to the registration reach the collectors holding them.
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
    /// Reflection over the signature, and what that holds is narrower than "the compiler
    /// refuses it". The compiler refuses the <em>omission</em> — deleting the argument at the
    /// <c>ScanCommand</c> call site stops compiling. It does not refuse a
    /// <em>substitution</em>: writing
    /// <c>DefaultFindingCollectors(DriverBlocklist.Empty, BloatwareCatalog.Empty)</c> there
    /// builds clean in Release, warnings as errors, and leaves the whole unit suite green —
    /// measured, not assumed. Nothing here claims otherwise. A guard reading
    /// <c>ScanCommand</c> as text is perfectly available — <c>ScanCommandStepTests</c> does
    /// exactly that two files over, reading the source rather than calling it because no test
    /// assembly references <c>Rempart.Cli</c> — but it could not tell the two cases apart: the
    /// replay branch legitimately resolves <c>DriverBlocklist.Empty</c> alongside the embedded
    /// catalog. A written <c>.Empty</c> is a sentence a reader can disagree with, which is the
    /// trade-off <see cref="SoftwareInventoryCollector"/> states, and not a pattern a guard can
    /// ban. What is closed here is the argument that was not written at all.
    /// </para>
    ///
    /// <para>
    /// Every <c>Run</c> is checked rather than the only one that exists, because an overload
    /// without the parameter would put the shorter call back within reach — the reason #136
    /// changed <c>ListValues</c>' return type instead of adding an overload beside it.
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
            .Select(run => $"Run({Parameters(run)})")
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
    /// Two shapes, one door. A default on a parameter is the one this commit removed; a
    /// <em>second public constructor</em> is the same thing with the argument list rewritten,
    /// and reading only <c>IsOptional</c> misses it entirely — a constructor with no
    /// parameters has no parameter to be optional. Measured on this repository rather than
    /// reasoned about: adding
    /// <c>public SoftwareInventoryCollector() : this(BloatwareCatalog.Empty) { }</c> beside
    /// the demanding one and registering <c>new SoftwareInventoryCollector()</c> built in
    /// Release with no diagnostic and left all 970 unit tests passing, dropping the catalogue
    /// exactly as the default did. So the count of public constructors is held too: exactly
    /// one way in, and no default on it.
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

        var lenient = new List<string>();

        foreach (var type in compiled)
        {
            var constructors = type.GetConstructors();

            // A collector taking nothing at all is not the fault — most of them judge on the
            // providers alone and have exactly one, parameterless, way in. The fault is a
            // second one, which necessarily offers a shorter call than the longest.
            if (constructors.Length > 1)
            {
                lenient.Add($"{type.Name} : {constructors.Length} constructeurs publics, "
                    + string.Join(" et ", constructors
                        .Select(constructor => $"{type.Name}({Parameters(constructor)})")
                        .OrderBy(signature => signature, StringComparer.Ordinal)));
            }

            lenient.AddRange(constructors
                .SelectMany(constructor => constructor.GetParameters())
                .Where(parameter => parameter.IsOptional)
                .Select(parameter =>
                    $"{type.Name}({parameter.ParameterType.Name} {parameter.Name} = …)"));
        }

        Assert.True(lenient.Count == 0,
            $"Ces collecteurs se construisent sans la donnée qu'ils confrontent : {Join(lenient)}. "
            + "Omise, elle est remplacée par une liste vide et le collecteur ne reconnaît plus "
            + "rien : il rend les mêmes constats bénins qu'une machine saine, sans qu'aucune "
            + "référence figée ni aucun compte de constats ne bouge. Un paramètre facultatif "
            + "laisse omettre l'argument, un second constructeur laisse appeler sans : même "
            + "porte, deux écritures.");
    }

    /// <summary>
    /// The blocklist and the catalog handed to
    /// <see cref="ScanEngine.DefaultFindingCollectors"/> reach the two collectors that judge
    /// with them.
    ///
    /// <para>
    /// The guards above hold the signatures; this one holds the wiring behind them, and
    /// nothing did. Both parameters could be accepted and then dropped one line further in —
    /// <c>new LoadedDriversCollector(DriverBlocklist.Empty)</c>,
    /// <c>new SoftwareInventoryCollector(BloatwareCatalog.Empty)</c> inside the table itself.
    /// Measured: that builds clean in Release, warnings as errors, C# not warning on an unused
    /// parameter, and leaves all 970 unit tests passing while behaviour returns bit for bit to
    /// the bug this branch closes. Worse than the omission it replaces, because
    /// <c>ScanCommand</c> still reads <c>resolution.Blocklist, resolution.Catalog</c> and a
    /// reviewer sees a correct call site. The cause was that all eight test uses of
    /// <c>DefaultFindingCollectors</c> passed <c>Empty</c> for both, so no test in the
    /// repository could tell the parameters from constants.
    /// </para>
    ///
    /// <para>
    /// Non-empty data on both, therefore, and the escalation asserted rather than the
    /// construction: a driver whose fingerprint is on the blocklist comes back
    /// <see cref="FindingSeverity.Suspicious"/> despite a valid signature, and software the
    /// catalog names comes back <see cref="FindingSeverity.Notable"/>. Both are exactly the
    /// verdicts that collapse to <see cref="FindingSeverity.Benign"/> when the lists do not
    /// arrive, which is the defect being watched: the same count of findings, the same report
    /// shape, one severity quietly lowered.
    /// </para>
    /// </summary>
    [Fact]
    public void The_blocklist_and_the_catalog_reach_the_collectors_that_judge_with_them()
    {
        const string Fingerprint =
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        const string DriverPath = @"C:\Windows\System32\drivers\capcom.sys";

        var collectors = ScanEngine.DefaultFindingCollectors(
            DriverBlocklist.Parse(
                $$"""
                {"asOfUtc":"2026-09-01T00:00:00Z","source":"test","drivers":[
                {"sha256":"{{Fingerprint}}","name":"capcom.sys","category":"vulnerable"}]}
                """),
            BloatwareCatalog.Parse(RempartJson.SerialiseCompact(
                new BloatwareCatalogFile("2026-07-23T00:00:00Z", "test", [
                    new BloatwareEntry("BLOAT-GAME", BloatwareMatch.Name, "candy crush",
                        "game", BloatwareRisk.Unwanted,
                        "Jeu préinstallé, désinstallable sans impact.")]))));

        // Pulled out of the registration by type rather than rebuilt here: the claim is about
        // the instances that table hands back, not about collectors this test constructs.
        var drivers = Assert.Single(collectors.OfType<LoadedDriversCollector>());
        var software = Assert.Single(collectors.OfType<SoftwareInventoryCollector>());

        var driverFinding = Assert.Single(drivers.Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            signatures: new FakeSignatureProvider()
                .With(DriverPath, SignatureStatus.Valid, sha256: Fingerprint),
            drivers: new FakeDriverProvider(new LoadedDriver("capcom.sys", DriverPath)))));

        Assert.Equal(FindingSeverity.Suspicious, driverFinding.Severity);
        Assert.Equal("vulnerable", driverFinding.Details["loldrivers"]);

        var softwareFinding = Assert.Single(software.Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            softwareInventory: new FakeSoftwareInventoryProvider(new InstalledSoftware(
                "Candy Crush Saga", null, null, SoftwareSource.Appx,
                Provisioned: true, SurvivesFeatureUpdate: true)))));

        Assert.Equal(FindingSeverity.Notable, softwareFinding.Severity);
        Assert.Equal("BLOAT-GAME", softwareFinding.Details["catalogue"]);
    }

    /// <summary>
    /// No engine is built without a rule catalog, for the same reason no run is started
    /// without finding collectors.
    ///
    /// <para>
    /// <c>ScanEngine(IReadOnlyList&lt;ICollector&gt; collectors)</c> substituted an empty rule
    /// catalog thirty lines above the parameter this branch made required — the shorter
    /// overload #136's reasoning rules out, quoted twice in this work and then not applied
    /// here. Taken, it evaluates no rule at all: no verdict,
    /// <see cref="ScanResult.Score"/> <c>null</c>, and <c>ExitCodes.ForScan</c> answering
    /// <c>Success</c>, because the <c>Unknown</c> rung never fires on an empty verdict list. A
    /// scheduler then cannot tell a machine judged by nothing from a clean one — the same
    /// silence as an empty blocklist, one constructor over and with the exit code on it.
    /// </para>
    ///
    /// <para>
    /// It had no caller when it was deleted, all seven construction sites passing both
    /// arguments, so this guard is what keeps it from coming back rather than what removed it.
    /// </para>
    /// </summary>
    [Fact]
    public void No_scan_engine_is_built_without_a_rule_catalog()
    {
        var constructors = typeof(ScanEngine).GetConstructors();

        Assert.True(constructors.Length > 0,
            "Aucun constructeur public de ScanEngine : cette garde ne regarde plus rien, et "
            + "une garde qui n'inspecte rien passe.");

        var lenient = constructors
            .Where(constructor => constructor.GetParameters()
                    .FirstOrDefault(parameter => parameter.Name == "rules")
                is null or { IsOptional: true })
            .Select(constructor => $"ScanEngine({Parameters(constructor)})")
            .ToList();

        Assert.True(lenient.Count == 0,
            $"Ces constructeurs de ScanEngine se passent de catalogue de règles : "
            + $"{Join(lenient)}. Le moteur n'évalue alors aucune règle : aucun verdict, un "
            + "score nul, et ExitCodes.ForScan rend Succès faute d'Unknown à voir. Un "
            + "ordonnanceur ne distingue plus une machine jugée par rien d'une machine saine.");
    }

    /// <summary>Parameters as written, so the failure names the offending overload.</summary>
    private static string Parameters(MethodBase method) =>
        string.Join(", ", method.GetParameters().Select(parameter =>
            $"{parameter.ParameterType.Name} {parameter.Name}"
            + (parameter.IsOptional ? " = …" : string.Empty)));

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
