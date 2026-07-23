using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Le canal ne transporte plus seulement des règles. Ces tests couvrent le routage par
/// type — règles vs pilotes — et le refus d'un type inconnu.
/// </summary>
public sealed class DatasetTypingTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "rempart-typing-" + Guid.NewGuid().ToString("n"));

    private string Store => Path.Combine(root, "store");

    /// <summary>
    /// Publie un jeu de données typé et l'applique au magasin, prêt à être résolu comme
    /// le ferait un scan. Renvoie le vérificateur armé de la clé de l'éditeur.
    /// </summary>
    private ManifestVerifier PublishAndApply(
        TestPublisher publisher, string name, string content, string? kind)
    {
        var source = Path.Combine(root, "src");
        Directory.CreateDirectory(source);
        File.WriteAllText(Path.Combine(source, name), content);

        var entry = ManifestSigner.Describe(name, Encoding.UTF8.GetBytes(content), kind);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ManifestPayload(1, "2026-09-01T00:00:00Z", [entry]),
            RempartJsonContext.Default.ManifestPayload);

        var manifestPath = Path.Combine(source, UpdateStore.ManifestFileName);
        File.WriteAllText(manifestPath, RempartJson.Serialise(new SignedManifest(
            Convert.ToBase64String(payload),
            [new ManifestSignature(publisher.KeyId, publisher.Sign(payload))])));

        UpdateStore.Apply(manifestPath, Store, [name]);

        return new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });
    }

    /// <summary>
    /// Le trajet complet d'une liste de pilotes : signée, appliquée, résolue, et un
    /// pilote chargé dont l'empreinte y figure ressort suspect. C'est ce que le typage
    /// débloque — la vraie donnée LOLDrivers, livrée par le même canal que les règles.
    /// </summary>
    [Fact]
    public void A_signed_driver_blocklist_flows_through_and_flags_a_loaded_driver()
    {
        const string Hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        using var publisher = new TestPublisher();

        var blocklistJson = $$"""
            {"asOfUtc":"2026-09-01T00:00:00Z","source":"test",
             "drivers":[{"sha256":"{{Hash}}","name":"capcom.sys","category":"vulnerable"}]}
            """;

        var verifier = PublishAndApply(publisher, "loldrivers.json", blocklistJson, kind: null);
        var resolution = UpdateStore.Resolve(Store, RuleCatalog.Load(), verifier);

        // Le magasin a chargé la liste, et le socle de règles est intact (D12).
        Assert.Equal(1, resolution.Blocklist.Count);
        Assert.Contains("pilotes surveillés", resolution.UpdateNote);

        // Un pilote chargé dont l'empreinte est dans la liste ressort suspect.
        var findings = new LoadedDriversCollector(resolution.Blocklist).Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: new FakeSignatureProvider()
                .With(@"C:\W\drivers\capcom.sys", SignatureStatus.Valid, sha256: Hash),
            drivers: new FakeDriverProvider(
                new LoadedDriver("capcom.sys", @"C:\W\drivers\capcom.sys"))));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal("vulnerable", finding.Details["loldrivers"]);
    }

    /// <summary>
    /// Le type est deviné à l'extension : un <c>.json</c> est une liste de pilotes, un
    /// <c>.yaml</c> des règles. L'éditeur n'a rien à déclarer dans le cas courant.
    /// </summary>
    [Fact]
    public void The_kind_is_inferred_from_the_extension()
    {
        Assert.Equal(DatasetKind.Rules, DatasetKind.Infer("securite.yaml"));
        Assert.Equal(DatasetKind.Rules, DatasetKind.Infer("securite.YML"));
        Assert.Equal(DatasetKind.Drivers, DatasetKind.Infer("loldrivers.json"));
    }

    /// <summary>
    /// Un manifeste d'un type qu'une vieille version ne connaît pas est refusé, pas
    /// deviné : la réponse doit être « mettre le binaire à jour », jamais un chargement
    /// partiel silencieux. Le socle tient (D12).
    /// </summary>
    [Fact]
    public void An_unknown_kind_is_refused_and_the_floor_holds()
    {
        using var publisher = new TestPublisher();
        // « bloatware » est devenu un type connu (M5b) : un vrai type futur, encore
        // inconnu de ce binaire, pour que le test continue d'exercer le refus voulu.
        var verifier = PublishAndApply(publisher, "cve.dat", "des données futures", kind: "signatures-malveillantes");

        var resolution = UpdateStore.Resolve(Store, RuleCatalog.Load(), verifier);

        Assert.Equal(RuleCatalog.Load().Count, resolution.Rules.Count); // socle intact
        Assert.Equal(0, resolution.Blocklist.Count);
        Assert.Contains("type inconnu", resolution.UpdateNote);
    }

    /// <summary>
    /// Un manifeste d'avant le typage n'a pas de champ <c>kind</c> : il doit se lire
    /// comme des règles, ce qu'il était. C'est la compatibilité ascendante que le
    /// défaut de <see cref="ManifestEntry.Kind"/> garantit.
    /// </summary>
    [Fact]
    public void A_manifest_without_a_kind_field_deserialises_as_rules()
    {
        const string Json = """
            {"name":"regles.yaml","version":"1.0.0","sha256":"aa","sizeBytes":10}
            """;

        var entry = JsonSerializer.Deserialize(Json, RempartJsonContext.Default.ManifestEntry);

        Assert.NotNull(entry);
        Assert.Equal(DatasetKind.Rules, entry.Kind);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
