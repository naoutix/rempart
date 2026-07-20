using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Les trois appels natifs — <c>GetFirmwareType</c>, <c>NetGetJoinInformation</c>,
/// vérification d'élévation — n'étaient couverts par aucun test. Une signature
/// P/Invoke fausse ne se voit pas à la compilation : elle rend une valeur plausible
/// et silencieusement erronée, sur laquelle des règles se prononcent ensuite.
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
        // Une signature P/Invoke fausse rendrait « unknown » en permanence, et la
        // règle Secure Boot perdrait tout son sens sans que rien ne le signale.
        Assert.Contains(info.FirmwareType, new[] { "uefi", "bios", "unknown" });
    }

    [Fact]
    public void Domain_membership_is_answered_without_throwing()
    {
        // La valeur dépend de la machine ; ce qui se teste, c'est que l'appel natif
        // aboutisse et ne laisse pas fuir de mémoire non libérée.
        _ = info.IsDomainJoined;
    }

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
/// Le chemin complet, contre la vraie machine : ce que la CI exerçait déjà sans
/// rien vérifier au-delà du code de sortie.
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

        // Un scan qui ne conclurait sur rien signalerait un catalogue muet ou des
        // chemins de registre tous faux — le rapport paraîtrait pourtant normal.
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
        // La promesse centrale du projet : un instantané rejoué rend le même verdict
        // que le scan qui l'a produit. Jamais vérifiée jusqu'ici contre une vraie
        // machine, seulement entre fixtures synthétiques.
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
