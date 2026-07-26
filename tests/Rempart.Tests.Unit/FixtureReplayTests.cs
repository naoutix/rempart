using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Reports;
using Rempart.Core.Snapshots;
using Xunit.Abstractions;

namespace Rempart.Tests.Unit;

/// <summary>
/// Level-2 tests: the collectors replay snapshots, compared against a versioned
/// reference output. A regression becomes visible without starting a VM.
///
/// Two directories, two regimes:
/// <list type="bullet">
///   <item><c>synthetic/</c> — versioned, fabricated values. The repository being
///   public, no real machine appears there.</item>
///   <item><c>local/</c> — outside version control. Captures of real machines stay
///   there, and are replayed when present: that is where the cases live that
///   nobody would have thought to fabricate.</item>
/// </list>
/// </summary>
public sealed class FixtureReplayTests(ITestOutputHelper output)
{
    /// <summary>
    /// States what was actually replayed.
    ///
    /// <para>
    /// The fixture list is discovered on disk and <c>local/</c> is gitignored, so this
    /// workstation replays more cases than CI does — 513 unit tests against 511, a
    /// difference nothing announced. A suite that quietly does less work still reports
    /// green, and that green reads like the fuller one. The same rule already applies to
    /// the WMI tests: a check that did not run has to say so.
    /// </para>
    /// </summary>
    [Fact]
    public void The_replay_states_how_many_fixtures_it_found()
    {
        var synthetic = Fixtures().Cast<object[]>()
            .Select(row => (string)row[0])
            .ToList();

        var local = synthetic.Where(name => name.StartsWith("local/", StringComparison.Ordinal)).ToList();
        var versioned = synthetic.Except(local).ToList();

        output.WriteLine(
            $"Fixtures rejouées : {versioned.Count} versionnée(s), {local.Count} locale(s) — "
            + $"{synthetic.Count} au total.");

        foreach (var name in synthetic)
        {
            output.WriteLine($"  · {name}");
        }

        if (local.Count == 0)
        {
            output.WriteLine(
                "Aucune capture réelle dans tests/fixtures/local : les chemins que seule une "
                + "vraie machine exerce ne sont pas couverts par cette exécution. C'est le cas "
                + "en CI, par conception — le dépôt est public (voir DET-DIRTY).");
        }

        // The versioned fixtures are the contract: their absence means a broken checkout,
        // not a machine without local captures.
        Assert.NotEmpty(versioned);
    }

    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();
        foreach (var path in Directory.EnumerateFiles(FixtureDirectory, "*.capture.json",
                     SearchOption.AllDirectories))
        {
            data.Add(Path.GetRelativePath(FixtureDirectory, path)
                .Replace(".capture.json", string.Empty)
                .Replace(Path.DirectorySeparatorChar, '/'));
        }

        // Synthetic fixtures are versioned: their absence signals an incomplete
        // repository, not a machine without local captures.
        Assert.Contains(data.Cast<object[]>().Select(d => (string)d[0]),
            name => name.StartsWith("synthetic/", StringComparison.Ordinal));
        return data;
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Replay_matches_the_recorded_reference(string fixture)
    {
        var actual = Replay(fixture);
        var expectedPath = Path.Combine(FixtureDirectory, $"{fixture}.expected.json");

        if (!File.Exists(expectedPath))
        {
            File.WriteAllText(expectedPath, actual);
            Assert.Fail(
                $"Référence absente pour « {fixture} » : elle vient d'être écrite dans " +
                $"{expectedPath}. Relire le contenu, puis le versionner.");
        }

        Assert.Equal(Normalise(File.ReadAllText(expectedPath)), Normalise(actual));
    }

    /// <summary>
    /// Freezes the console output, which until now nothing observed.
    ///
    /// <para>
    /// The CLI wrote straight to <see cref="Console"/>, so a change in what the tool says
    /// was invisible: CI checks an exit code, not a text. The reports got this treatment
    /// in M6 and it is what caught the capped score gauges; the console never did. Now
    /// that the renderer is pure, the same golden-file discipline applies to it.
    /// </para>
    ///
    /// <para>
    /// The tool version is <c>test</c> here, as everywhere in the replay, so the reference
    /// does not churn on every release. That the extraction itself changed nothing was
    /// proved separately, by diffing the real CLI output on these three fixtures before
    /// and after the move.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void The_console_rendering_matches_its_reference(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        var result = ScanEngine.Default().Run(
            ReplayProviders(snapshot), "test", snapshot.CapturedAtUtc);

        var actual = Normalise(ConsoleReport.HumanReadable(result));
        var referencePath = Path.Combine(FixtureDirectory, $"{fixture}.console.txt");

        if (!File.Exists(referencePath))
        {
            File.WriteAllText(referencePath, actual);
            Assert.Fail(
                $"Référence console absente pour « {fixture} » : elle vient d'être écrite "
                + $"dans {referencePath}. Relire le contenu, puis le versionner.");
        }

        Assert.Equal(Normalise(File.ReadAllText(referencePath)), actual);
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Replay_is_deterministic(string fixture)
    {
        // A replay that varied from one run to the next would make any reference
        // unusable — including for rempart diff (M7).
        Assert.Equal(Replay(fixture), Replay(fixture));
    }

    [Fact]
    public void No_shipped_rule_fails_on_a_hardened_machine()
    {
        // A rule that can never pass is a bug: contradictory expectation, wrong
        // path, badly chosen operator. It would produce a permanent failure on
        // every machine, one that nobody could fix.
        //
        // The "hardened" fixture sets on each key the value its rule expects.
        //
        // NotApplicable remains an acceptable answer, and requiring its absence
        // would be a mistake: some rules exclude each other by construction. RDP
        // disabled satisfies WIN-RDP-001 and makes WIN-RDP-002 (NLA) moot — no
        // machine can satisfy both at once.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "hardened-win11.capture.json")));

        var result = ScanEngine.Default().Run(
            new ProviderSet(new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot),
                new SnapshotServiceStateProvider(snapshot),
                new SnapshotSecurityPolicyProvider(snapshot),
                new SnapshotWmiProvider(snapshot)),
            "test", snapshot.CapturedAtUtc);

        var failing = result.Verdicts
            .Where(v => v.Status is VerdictStatus.Fail or VerdictStatus.Unknown)
            .Select(v => $"{v.RuleId} (observé {v.Observed ?? "—"}, attendu {v.Expected ?? "—"})");

        Assert.Empty(failing);
        Assert.Equal(100, result.Score?.Overall);
    }

    [Fact]
    public void The_hardened_fixture_leaves_almost_no_rule_unevaluated()
    {
        // Guardrail against the opposite drift: a fixture that pushed most rules
        // out of scope would reach 100 % without proving anything. Exclusions
        // must stay rare and intentional.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "hardened-win11.capture.json")));

        var result = ScanEngine.Default().Run(
            new ProviderSet(new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot),
                new SnapshotServiceStateProvider(snapshot),
                new SnapshotSecurityPolicyProvider(snapshot),
                new SnapshotWmiProvider(snapshot)),
            "test", snapshot.CapturedAtUtc);

        var notApplicable = result.Verdicts.Count(v => v.Status == VerdictStatus.NotApplicable);

        Assert.True(notApplicable <= 2,
            $"{notApplicable} règles hors périmètre sur la fixture durcie : le 100 % " +
            "ne prouverait plus grand-chose.");
    }

    [Fact]
    public void Versioned_fixtures_are_anonymised()
    {
        var synthetic = Path.Combine(FixtureDirectory, "synthetic");

        foreach (var path in Directory.EnumerateFiles(synthetic, "*.capture.json"))
        {
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(path));

            // Guardrail: the repository is public. A raw capture dropped here by
            // mistake fails the test now, not six months later while rereading the repo.
            Assert.True(snapshot.Anonymised, $"Fixture non anonymisée : {path}");
            Assert.StartsWith("anon:", snapshot.SystemInfo?.MachineName, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Local_fixtures_stay_out_of_version_control()
    {
        // The policy lives in .gitignore; this test makes it visible from the code,
        // right where someone might drop a real capture out of convenience.
        var local = Path.Combine(FixtureDirectory, "local");
        var readme = Path.Combine(local, "README.md");

        Assert.True(File.Exists(readme),
            $"Le répertoire {local} doit porter un README rappelant qu'il n'est pas versionné.");
    }

    /// <summary>
    /// Every replay provider, wired as named arguments: the real scan supplies just as
    /// many (Program.cs), and a replay omitting one falls back to the default no-ops. The
    /// matching collectors then run on empty and the reference freezes "nothing found"
    /// over a capture that does hold the data — the worst kind of fixture, the reassuring
    /// one. The naming also prevents any silent swap between same-shaped providers.
    ///
    /// <para>
    /// Shared with <see cref="Every_provider_is_wired_into_the_replay"/> rather than
    /// inlined: the claim in the paragraph above had been written twice and verified
    /// never, and it was false both times (D2, D2b, and a third time for the component
    /// store). A comment cannot hold an invariant — a test can.
    /// </para>
    /// </summary>
    private static ProviderSet ReplayProviders(MachineSnapshot snapshot) =>
        new(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot),
            services: new SnapshotServiceStateProvider(snapshot),
            policy: new SnapshotSecurityPolicyProvider(snapshot),
            wmi: new SnapshotWmiProvider(snapshot),
            signatures: new SnapshotSignatureProvider(snapshot),
            files: new SnapshotFileSystemProvider(snapshot),
            scheduledTasks: new SnapshotScheduledTaskProvider(snapshot),
            drivers: new SnapshotDriverProvider(snapshot),
            processes: new SnapshotProcessProvider(snapshot),
            listeningPorts: new SnapshotListeningPortProvider(snapshot),
            firewall: new SnapshotFirewallProvider(snapshot),
            dns: new SnapshotDnsProvider(snapshot),
            hostsFile: new SnapshotHostsFileProvider(snapshot),
            proxy: new SnapshotProxyProvider(snapshot),
            wifi: new SnapshotWifiProfileProvider(snapshot),
            softwareInventory: new SnapshotSoftwareInventoryProvider(snapshot),
            browserExtensions: new SnapshotBrowserExtensionProvider(snapshot),
            componentStore: new SnapshotComponentStoreProvider(snapshot));

    /// <summary>
    /// Closes D2 and D2b, which are the same mistake made twice: a provider added to
    /// <see cref="ProviderSet"/> without being wired into the replay. Both times the
    /// collector ran on nothing and the reference froze "nothing found", which reads
    /// exactly like a clean machine.
    ///
    /// <para>
    /// Reflection rather than a hand-kept list, because a hand-kept list is the thing
    /// that was already forgotten twice. Every provider property must hold a
    /// <c>Snapshot*</c> implementation: the no-op fallbacks are what a missing argument
    /// silently leaves behind.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_provider_is_wired_into_the_replay()
    {
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(
            Path.Combine(FixtureDirectory, "synthetic", "default-win11.capture.json")));

        var missing = typeof(ProviderSet).GetProperties()
            .Where(property => property.PropertyType.IsInterface)
            .Select(property => (property.Name, Implementation: property.GetValue(ReplayProviders(snapshot))))
            .Where(wired => wired.Implementation?.GetType().Name
                .StartsWith("Snapshot", StringComparison.Ordinal) != true)
            .Select(wired => $"{wired.Name} → {wired.Implementation?.GetType().Name ?? "null"}")
            .ToList();

        Assert.True(missing.Count == 0,
            "Fournisseur(s) non câblé(s) au rejeu de fixtures, donc collecteur tournant à "
            + "vide derrière une référence qui fige « rien trouvé » : "
            + string.Join(", ", missing));
    }

    private static string Replay(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        var providers = ReplayProviders(snapshot);

        // Full engine, rules included: what we want frozen is the verdict rendered
        // on a given machine, not just the collected fields.
        var result = ScanEngine.Default().Run(providers, "test", snapshot.CapturedAtUtc);

        // Volatile fields are removed: a reference cannot freeze an uptime.
        var comparable = result with
        {
            Collectors = [.. result.Collectors.Select(c => c with
            {
                Fields = c.Fields
                    .Where(f => FieldSemantics.IsComparable(f.Key))
                    .ToDictionary(f => f.Key, f => f.Value),
            })],
        };

        return RempartJson.Serialise(comparable);
    }

    private static string Normalise(string json) => json.ReplaceLineEndings("\n").Trim();

    private static string FixtureDirectory { get; } = Locate();

    private static string Locate()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "tests", "fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Répertoire tests/fixtures introuvable.");
    }
}
