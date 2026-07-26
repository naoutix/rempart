using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

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
public sealed class FixtureReplayTests
{
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

    private static string Replay(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        // Every replay provider is wired in, as named arguments: the real scan
        // supplies just as many (Program.cs), and a replay omitting one would fall
        // back to the default no-ops. The matching collectors would then run on
        // empty and the reference would freeze "nothing found" over a capture that
        // does hold the data — the worst kind of fixture, the reassuring one. The
        // naming also prevents any silent swap between same-shaped providers.
        var providers = new ProviderSet(
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
            browserExtensions: new SnapshotBrowserExtensionProvider(snapshot));

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
