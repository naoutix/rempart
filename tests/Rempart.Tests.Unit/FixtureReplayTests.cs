using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

/// <summary>
/// Tests de niveau 2 : les collecteurs rejouent des instantanés, comparés à une sortie
/// de référence versionnée. Une régression devient visible sans démarrer de VM.
///
/// Deux répertoires, deux régimes :
/// <list type="bullet">
///   <item><c>synthetic/</c> — versionné, valeurs fabriquées. Le dépôt étant public,
///   aucune machine réelle n'y figure.</item>
///   <item><c>local/</c> — hors versionnement. Les captures de machines réelles y
///   restent, et sont rejouées si présentes : c'est là que se trouvent les cas que
///   personne n'aurait pensé à fabriquer.</item>
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

        // Les fixtures synthétiques sont versionnées : leur absence signale un dépôt
        // incomplet, pas une machine sans captures locales.
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
        // Un rejeu qui varierait d'une exécution à l'autre rendrait toute référence
        // inutilisable — y compris pour rempart diff (M7).
        Assert.Equal(Replay(fixture), Replay(fixture));
    }

    [Fact]
    public void Versioned_fixtures_are_anonymised()
    {
        var synthetic = Path.Combine(FixtureDirectory, "synthetic");

        foreach (var path in Directory.EnumerateFiles(synthetic, "*.capture.json"))
        {
            var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(path));

            // Garde-fou : le dépôt est public. Une capture brute déposée ici par
            // inadvertance échoue au test, pas six mois plus tard en relisant le dépôt.
            Assert.True(snapshot.Anonymised, $"Fixture non anonymisée : {path}");
            Assert.StartsWith("anon:", snapshot.SystemInfo?.MachineName, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Local_fixtures_stay_out_of_version_control()
    {
        // La politique est portée par .gitignore ; ce test la rend visible depuis le code,
        // là où quelqu'un risque de déposer une capture réelle par commodité.
        var local = Path.Combine(FixtureDirectory, "local");
        var readme = Path.Combine(local, "README.md");

        Assert.True(File.Exists(readme),
            $"Le répertoire {local} doit porter un README rappelant qu'il n'est pas versionné.");
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
