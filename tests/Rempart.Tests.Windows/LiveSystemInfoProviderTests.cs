using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The three native calls — <c>GetFirmwareType</c>, <c>NetGetJoinInformation</c>,
/// elevation check — were covered by no test. A wrong P/Invoke signature is not
/// caught at compile time: it returns a plausible, silently wrong value, which rules
/// then act on.
/// </summary>
public sealed class LiveSystemInfoProviderTests
{
    private readonly SystemInfo info = new LiveSystemInfoProvider().Read();

    [Fact]
    public void Reports_a_plausible_machine_identity()
    {
        Assert.False(string.IsNullOrWhiteSpace(info.MachineName));
        Assert.StartsWith("10.", info.OsVersion, StringComparison.Ordinal);
        Assert.InRange(info.ProcessorCount, 1, 512);
        Assert.InRange(info.UptimeSeconds, 0, TimeSpan.FromDays(3650).TotalSeconds);
    }

    [Fact]
    public void Firmware_type_is_one_of_the_known_values()
    {
        // A wrong P/Invoke signature would return "unknown" permanently, and the
        // Secure Boot rule would lose all meaning without any signal.
        Assert.Contains(info.FirmwareType, new[] { "uefi", "bios", "unknown" });
    }

    // A test named Domain_membership_is_answered_without_throwing stood here, whose whole
    // body was `_ = info.IsDomainJoined;`, and it was deleted rather than repaired. Two
    // mutations say why. Inverting the verdict NetGetJoinInformation returns left all four
    // tests of this class green — the wrong-but-plausible answer the summary above warns
    // about, and nothing here sees it. Making the call throw failed all four at once, from
    // the field initialiser: the "without throwing" it claimed was the constructor's doing,
    // not its own. It asserted nothing that its neighbours were not already asserting.
    //
    // Nothing replaces it, because on a machine that is not domain-joined there is nothing
    // to confront the answer with: `false` is correct here whether the P/Invoke works or
    // fails, so no assertion available to CI can tell those two apart. The call itself stays
    // exercised — every test of this class materialises `info`, and the one below reads the
    // property back — and the gap is now visible instead of being papered over by a green
    // test. Same reasoning as the deletion recorded at the end of LiveProvidersTests.

    [Fact]
    public void Reading_twice_gives_a_stable_answer()
    {
        var second = new LiveSystemInfoProvider().Read();

        Assert.Equal(info.MachineName, second.MachineName);
        Assert.Equal(info.FirmwareType, second.FirmwareType);
        Assert.Equal(info.IsDomainJoined, second.IsDomainJoined);
        Assert.Equal(info.IsElevated, second.IsElevated);
    }
}

/// <summary>
/// The full path, against the real machine: what CI already exercised without
/// checking anything beyond the exit code.
/// </summary>
public sealed class EndToEndTests
{
    private static ProviderSet Live() =>
        new(new LiveRegistryProvider(), new LiveSystemInfoProvider());

    [Fact]
    public void A_real_scan_produces_verdicts_and_a_score()
    {
        var result = ScanEngine.Default().Run(Live(), "test", "2026-01-01T00:00:00Z");

        Assert.NotEmpty(result.Verdicts);
        Assert.NotNull(result.Score);
        Assert.NotEmpty(result.RulesFingerprint);

        // A scan that concluded on nothing would mean a silent catalog or registry
        // paths that are all wrong — yet the report would look normal.
        Assert.Contains(result.Verdicts, v => v.Status is VerdictStatus.Pass or VerdictStatus.Fail);
    }

    [Fact]
    public void The_inventory_collector_fills_the_fields_rules_depend_on()
    {
        var result = ScanEngine.Default().Run(Live(), "test", "2026-01-01T00:00:00Z");
        var inventory = Assert.Single(result.Collectors);

        Assert.NotEqual(CollectorStatus.Failed, inventory.Status);
        Assert.False(string.IsNullOrWhiteSpace(inventory.Fields["os.name"]));
        Assert.False(string.IsNullOrWhiteSpace(inventory.Fields["os.build"]));
    }

    [Fact]
    public void A_capture_replays_to_the_same_verdicts()
    {
        // The project's central promise: a replayed snapshot yields the same verdicts
        // as the scan that produced it. Never verified against a real machine before,
        // only between synthetic fixtures.
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00Z" };
        var recording = new ProviderSet(
            new RecordingRegistryProvider(new LiveRegistryProvider(), snapshot),
            new RecordingSystemInfoProvider(new LiveSystemInfoProvider(), snapshot));

        var engine = ScanEngine.Default();
        var live = engine.Run(recording, "test", "2026-01-01T00:00:00Z");

        var replayed = engine.Run(
            new ProviderSet(new SnapshotRegistryProvider(snapshot),
                new SnapshotSystemInfoProvider(snapshot)),
            "test", "2026-01-01T00:00:00Z");

        Assert.Equal(
            live.Verdicts.Select(v => (v.RuleId, v.Status, v.Observed)),
            replayed.Verdicts.Select(v => (v.RuleId, v.Status, v.Observed)));
    }
}
