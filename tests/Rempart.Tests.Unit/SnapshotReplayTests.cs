using Rempart.Core.Collectors;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Le critère de sortie de M0 : un scan rejoué depuis un instantané doit produire
/// exactement la même sortie que le scan qui l'a produit. Sans cette garantie,
/// les fixtures ne valent rien comme banc de test.
/// </summary>
public sealed class SnapshotReplayTests
{
    [Fact]
    public void Replaying_a_snapshot_reproduces_the_original_result()
    {
        var live = Machine();
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-07-20T00:00:00Z" };

        var recorded = Collect(new ProviderSet(
            new RecordingRegistryProvider(live, snapshot),
            new RecordingSystemInfoProvider(new FakeSystemInfoProvider(), snapshot)));

        // Passage par le JSON : c'est la forme sous laquelle une fixture est versionnée.
        var replayed = Collect(FromJson(RempartJson.Serialise(snapshot)));

        Assert.Equal(recorded.Status, replayed.Status);
        Assert.Equal(recorded.Fields, replayed.Fields);
        Assert.Equal(recorded.Diagnostics, replayed.Diagnostics);
    }

    [Fact]
    public void Recording_captures_unsuccessful_reads_too()
    {
        var snapshot = new MachineSnapshot();
        var provider = new RecordingRegistryProvider(new FakeRegistryProvider(), snapshot);

        provider.ReadValue(@"HKLM\SOFTWARE\Absent", "Rien");

        // Sans cela, le rejeu divergerait précisément sur les cas qu'on veut tester.
        var read = Assert.Contains(@"HKLM\SOFTWARE\Absent||Rien", snapshot.Registry);
        Assert.Equal(ReadStatus.NotFound, read.Status);
    }

    [Fact]
    public void Replaying_an_unrecorded_read_fails_loudly()
    {
        var provider = new SnapshotRegistryProvider(new MachineSnapshot());

        var ex = Assert.Throws<SnapshotIncompleteException>(
            () => provider.ReadValue(@"HKLM\SOFTWARE\Jamais", "Capture"));

        Assert.Contains("non enregistrée", ex.Message, StringComparison.Ordinal);
    }

    private static CollectorResult Collect(ProviderSet providers) =>
        new InventoryCollector().Collect(providers);

    private static ProviderSet FromJson(string json)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(json);
        return new ProviderSet(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot));
    }

    private static FakeRegistryProvider Machine() => new FakeRegistryProvider()
        .WithText(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "Windows 11 Pro")
        .WithText(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", "25H2")
        .WithText(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber", "26200")
        .WithNumber(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", 1742)
        .WithText(@"HKLM\HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer", "Dell Inc.")
        .WithNumber(@"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", 1)
        .WithKey(@"HKLM\SYSTEM\CurrentControlSet\Services\TPM", ReadStatus.Found);
}
