using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Tests de niveau 2 : les collecteurs rejouent des instantanés de machines réelles,
/// comparés à une sortie de référence versionnée. C'est ce qui rend une régression
/// visible sans démarrer de VM — et une VM vierge n'aurait de toute façon rien
/// d'une machine OEM réelle.
/// </summary>
public sealed class FixtureReplayTests
{
    public static TheoryData<string> Fixtures()
    {
        var data = new TheoryData<string>();
        foreach (var path in Directory.EnumerateFiles(FixtureDirectory, "*.capture.json"))
        {
            data.Add(Path.GetFileNameWithoutExtension(path).Replace(".capture", string.Empty));
        }

        Assert.NotEmpty(data);
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
        // Un rejeu qui varierait d'une exécution à l'autre rendrait toute référence
        // inutilisable — y compris pour rempart diff (M7).
        Assert.Equal(Replay(fixture), Replay(fixture));
    }

    [Fact]
    public void Anonymised_fixtures_carry_no_machine_name()
    {
        foreach (var path in Directory.EnumerateFiles(FixtureDirectory, "*.capture.json"))
        {
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(path));

            // Garde-fou : une fixture brute commitée par inadvertance échoue ici,
            // pas six mois plus tard en relisant le dépôt.
            Assert.True(snapshot.Anonymised, $"Fixture non anonymisée : {path}");
            Assert.StartsWith("anon:", snapshot.SystemInfo?.MachineName, StringComparison.Ordinal);
        }
    }

    private static string Replay(string fixture)
    {
        var snapshot = RempartJson.DeserialiseSnapshot(
            File.ReadAllText(Path.Combine(FixtureDirectory, $"{fixture}.capture.json")));

        var providers = new ProviderSet(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot));

        var result = new ScanEngine(ScanEngine.DefaultCollectors)
            .Run(providers, "test", snapshot.CapturedAtUtc);

        // Les champs volatils sont retirés : une référence ne peut pas figer un uptime.
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
