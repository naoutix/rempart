using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// What the "compromised" fixture is worth, checked here rather than left to the golden
/// files alone.
///
/// <para>
/// A reference file records what happened; it does not say what was supposed to happen.
/// If a collector stopped judging one of these markers, the replay would rewrite its
/// reference on the next run and the suite would go green over a fixture that had become
/// clean — exactly the failure DET-DIRTY describes, reproduced one layer up. Each marker
/// therefore states its own expected verdict, in code.
/// </para>
///
/// <para>
/// Run against the real collectors, not fakes: the point of the fixture is that judgement,
/// score and rendering see the compromise together, and a test wired to fakes would prove
/// the same thing the existing per-collector tests already prove.
/// </para>
/// </summary>
public sealed class CompromiseMarkersTests
{
    [Fact]
    public void Nothing_is_planted_unless_asked()
    {
        // The three existing fixtures go through the same factory. A marker that leaked
        // into them would rewrite their references and, worse, turn "hardened" into a
        // machine carrying an implant.
        var clean = Build(compromised: false);

        Assert.Null(clean.Drivers);
        Assert.Null(clean.ListeningPorts);
        Assert.Null(clean.Dns);
        Assert.Null(clean.BrowserExtensions);
        Assert.Empty(clean.RegistryLists);
        Assert.DoesNotContain(Findings(clean), f => f.Severity == FindingSeverity.Suspicious);
    }

    /// <summary>
    /// One row per marker: the family it lands in, the text identifying it, and the
    /// verdict expected of it. Named rather than counted — a count would still pass if
    /// two collectors swapped their findings.
    /// </summary>
    public static TheoryData<string, string, FindingSeverity> Markers() => new()
    {
        // Signature over name and path: the entry borrows Microsoft's name, the binary
        // comes from nobody.
        { "autorun", "OneDriveSync", FindingSeverity.Suspicious },
        { "autorun", "SecurityHealth", FindingSeverity.Benign },

        { "driver", "syndrv64", FindingSeverity.Suspicious },
        { "driver", "Ntfs", FindingSeverity.Benign },

        // Same file name, opposite verdicts. This pair is the whole claim of the
        // signature ladder in one fixture.
        { "process", @"Temp\svchost.exe", FindingSeverity.Suspicious },
        { "process", @"System32\svchost.exe", FindingSeverity.Benign },

        // Allowed inbound on Public by a rule the intrusion added: genuinely reachable.
        { "listening-port", "TCP 0.0.0.0:4444", FindingSeverity.Suspicious },

        // Same binary, same bind address, no rule: the firewall cross-check keeps it
        // out of the alerts instead of ranking it with the one above.
        { "listening-port", "TCP 0.0.0.0:5555", FindingSeverity.Benign },
        { "listening-port", "TCP 127.0.0.1:49669", FindingSeverity.Benign },

        { "wmi-subscription", "CommandLineEventConsumer / SystemUpdater", FindingSeverity.Suspicious },
        { "wmi-subscription", "__EventFilter / SystemUpdaterFilter", FindingSeverity.Notable },
        { "wmi-subscription", "__EventFilter / SCM Event Log Filter", FindingSeverity.Benign },

        { "dns-resolver", "Ethernet", FindingSeverity.Notable },
        { "dns-resolver", "Wi-Fi", FindingSeverity.Benign },

        // Provenance decides the tier: the sideload outranks the store install even
        // though both hold <all_urls>.
        { "browser-extension", "Secure Browsing Helper", FindingSeverity.Suspicious },
        { "browser-extension", "Password Vault", FindingSeverity.Notable },

        { "scheduled-task", "SystemMaintenance", FindingSeverity.Suspicious },
    };

    [Theory]
    [MemberData(nameof(Markers))]
    public void Each_marker_is_judged_as_expected(string kind, string needle, FindingSeverity expected)
    {
        var matching = Findings(Build(compromised: true))
            .Where(f => f.Kind == kind
                && (f.Source.Contains(needle, StringComparison.Ordinal)
                    || f.Target.Contains(needle, StringComparison.Ordinal)))
            .ToList();

        var single = Assert.Single(matching);

        Assert.Equal(expected, single.Severity);
    }

    /// <summary>
    /// The three absences the clean fixtures report — drivers, processes and listening
    /// ports missing from the snapshot — must be gone here, and gone because the data is
    /// present rather than because a collector fell silent. Left in place they would be
    /// the only flagged findings on a fixture whose whole purpose is the seven below them.
    ///
    /// <para>
    /// Listed by source and not by counting severities: all three are <c>Notable</c>, so a
    /// gap reopening would leave the seven <c>Suspicious</c> untouched and slip past a
    /// count. That is not hypothetical — this test named only two of the three for as long
    /// as the third existed, and setting the port status back to a refusal left the whole
    /// suite green.
    /// </para>
    /// </summary>
    [Fact]
    public void The_gaps_the_clean_fixtures_report_are_filled()
    {
        var findings = Findings(Build(compromised: true));

        Assert.DoesNotContain(findings,
            f => f.Source is "pilotes chargés" or "processus courants" or "ports en écoute");
        Assert.Equal(7, findings.Count(f => f.Severity == FindingSeverity.Suspicious));
    }

    /// <summary>
    /// The set the markers are judged through is the whole one, checked by the same
    /// reflection the replay guard uses rather than by reading the wiring below.
    ///
    /// <para>
    /// A slot left on its no-op fallback is invisible to everything else here.
    /// <see cref="Each_marker_is_judged_as_expected"/> only names markers that exist, so a
    /// silent provider is one the table never asks about; and
    /// <see cref="Nothing_is_planted_unless_asked"/> asserts <em>absences</em>, which an
    /// inert provider satisfies vacuously. That is how the hand-written wiring this file
    /// used to carry lost <c>dynamicPortRange</c> with the whole suite green.
    /// </para>
    /// </summary>
    [Fact]
    public void The_markers_are_judged_through_a_fully_wired_set()
    {
        FixtureReplayTests.AssertEveryProviderIsWired(
            Providers(Build(compromised: true)), "Snapshot",
            "sous les marqueurs de compromission, donc un collecteur qui tourne à vide "
            + "pendant que les assertions d'absence de ce fichier restent satisfaites");
    }

    /// <summary>
    /// The collectors whose surface the markers touch, named rather than taken wholesale
    /// from <see cref="ScanEngine.DefaultFindingCollectors"/>.
    ///
    /// <para>
    /// The others read named registry values, and a bare snapshot has none: they would
    /// raise "unrecorded read" and drown this test in a failure about Winlogon that has
    /// nothing to say about the markers. Naming them also means a collector added later
    /// cannot silently join in and shift the counts below.
    /// </para>
    ///
    /// <para>
    /// The blocklist is <see cref="Rempart.Core.Updates.DriverBlocklist.Empty"/> because
    /// that is what a replay evaluates — the shipped baseline is empty by design (D12).
    /// A driver here is judged on its signature and nothing else.
    /// </para>
    /// </summary>
    private static IReadOnlyList<IFindingCollector> Collectors() =>
    [
        new AutorunsCollector(),
        new LoadedDriversCollector(Rempart.Core.Updates.DriverBlocklist.Empty),
        new RunningProcessesCollector(),
        new ListeningPortsCollector(),
        new WmiSubscriptionsCollector(),
        new DnsResolverCollector(),
        new BrowserExtensionsCollector(),
        new ScheduledTasksCollector(),
    ];

    private static IReadOnlyList<Finding> Findings(MachineSnapshot snapshot)
    {
        var findings = new List<Finding>();

        foreach (var collector in Collectors())
        {
            findings.AddRange(collector.Collect(Providers(snapshot)));
        }

        return findings;
    }

    /// <summary>
    /// The replay wiring — <see cref="SnapshotProviders.Replaying"/>, the same call
    /// <c>rempart scan --from</c> makes, as <c>FixtureReplayTests</c> already does.
    ///
    /// <para>
    /// This used to be a second copy of that list, written by hand, and it had already
    /// drifted: <c>dynamicPortRange</c> was added to the shipped wiring and never here, so
    /// the markers were judged with the port-range provider silently on its no-op fallback.
    /// <c>ProviderSets.cs</c> claimed the copy eliminated while it was still standing —
    /// which is exactly why the claim is worth nothing unless the copy is gone.
    /// </para>
    /// </summary>
    private static ProviderSet Providers(MachineSnapshot snapshot) =>
        SnapshotProviders.Replaying(snapshot);

    /// <summary>
    /// A bare source capture: no scheduled tasks, no registry, nothing the markers could
    /// borrow. Whatever shows up in the findings was planted here and nowhere else.
    /// </summary>
    private static MachineSnapshot Build(bool compromised) =>
        SyntheticSnapshot.Build(
            new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default },
            [],
            SyntheticProfile.WindowsDefaults,
            "anon:test",
            compromised: compromised);
}
