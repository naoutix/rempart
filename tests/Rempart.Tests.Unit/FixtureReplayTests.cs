using Rempart.Core.Engine;
using Rempart.Core.Rules;
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
    public void No_shipped_rule_fails_on_a_hardened_machine()
    {
        // Une règle qui ne peut jamais passer est un bug : attendu contradictoire,
        // chemin erroné, opérateur mal choisi. Elle produirait un échec permanent sur
        // toutes les machines, que personne ne pourrait corriger.
        //
        // La fixture « hardened » pose sur chaque clé la valeur que sa règle attend.
        //
        // NotApplicable reste une réponse recevable, et l'exiger absent serait une
        // erreur : certaines règles s'excluent mutuellement par construction. RDP
        // désactivé satisfait WIN-RDP-001 et rend WIN-RDP-002 (NLA) sans objet —
        // aucune machine ne peut satisfaire les deux à la fois.
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
        // Garde-fou contre la dérive inverse : une fixture qui rendrait la plupart des
        // règles « hors périmètre » atteindrait 100 % sans rien prouver. Les exclusions
        // doivent rester rares et intentionnelles.
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
            new SnapshotSystemInfoProvider(snapshot),
            new SnapshotServiceStateProvider(snapshot),
            new SnapshotSecurityPolicyProvider(snapshot),
            new SnapshotWmiProvider(snapshot),

            // Sans ces trois-là, le rejeu n'exerçait aucun collecteur de constats : les
            // références figeaient « signature non vérifiable » et « tâches absentes de
            // l'instantané » sur des captures qui contenaient les unes et les autres.
            // La référence disait donc vrai sur ce que le test faisait, et faux sur ce
            // qu'un scan fait — la pire forme de fixture, celle qui rassure.
            new SnapshotSignatureProvider(snapshot),
            new SnapshotFileSystemProvider(snapshot),
            new SnapshotScheduledTaskProvider(snapshot));

        // Moteur complet, regles comprises : c'est le verdict rendu sur une machine
        // donnee qu'on veut voir figer, pas seulement les champs collectes.
        var result = ScanEngine.Default().Run(providers, "test", snapshot.CapturedAtUtc);

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
