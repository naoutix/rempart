using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The store does I/O: these tests rely on a real temporary directory, like the
/// external-rules tests. Each one cleans up its own.
/// </summary>
public sealed class UpdateStoreTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "rempart-store-" + Guid.NewGuid().ToString("n"));

    private string Source => EnsureDir(Path.Combine(root, "src"));
    private string Store => Path.Combine(root, "store");

    private static readonly string BaseRule = """
        - id: WIN-STORE-001
          title: Un contrôle
          severity: high
          domain: test
          check:
            type: registry
            path: HKLM\Software\Test
            value: Flag
            operator: equals
            expect: "1"
            windowsDefault: "0"
          rationale: Pour le test.
          references: []
        """;

    private IReadOnlyList<Rule> BaseCatalog() => RuleLoader.Load(BaseRule);

    /// <summary>
    /// Writes a signed manifest and its dataset into the source directory, ready to be
    /// applied. Returns the manifest path, the public key and its fingerprint.
    /// </summary>
    private (string ManifestPath, ManifestVerifier Verifier) Publish(
        TestPublisher publisher, string datasetName, string content,
        string publishedAt = "2026-08-01T00:00:00Z", string? kind = null)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        File.WriteAllBytes(Path.Combine(Source, datasetName), bytes);

        var entry = new ManifestEntry(
            datasetName, "2.0.0",
            Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length,
            kind ?? DatasetKind.Infer(datasetName));

        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ManifestPayload(1, publishedAt, [entry]),
            RempartJsonContext.Default.ManifestPayload);

        var manifestPath = Path.Combine(Source, UpdateStore.ManifestFileName);
        File.WriteAllText(manifestPath, RempartJson.Serialise(new SignedManifest(
            Convert.ToBase64String(payload),
            [new ManifestSignature(publisher.KeyId, publisher.Sign(payload))])));

        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        return (manifestPath, verifier);
    }

    [Fact]
    public void No_store_leaves_the_base_catalogue_and_embedded_date()
    {
        using var publisher = new TestPublisher();
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Single(resolution.Rules);
        Assert.Equal(RuleCatalog.EmbeddedAsOfUtc, resolution.AsOfUtc);
        Assert.Null(resolution.UpdateNote);
    }

    [Fact]
    public void An_applied_bloatware_dataset_resolves_into_the_catalog()
    {
        using var publisher = new TestPublisher();

        var catalogJson = RempartJson.SerialiseCompact(new BloatwareCatalogFile(
            "2026-08-01T00:00:00Z", "test",
            [new BloatwareEntry("BLOAT-SIGNED", BloatwareMatch.Name, "signedware",
                "oem-preinstall", BloatwareRisk.Unwanted, "Ajouté par catalogue signé.")]));

        var (manifestPath, verifier) = Publish(publisher, "bloatware.json", catalogJson, kind: DatasetKind.Bloatware);
        UpdateStore.Apply(manifestPath, Store, ["bloatware.json"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        // The embedded baseline holds, the signed entry adds to it.
        Assert.True(resolution.Catalog.Count > BloatwareCatalog.Embedded.Count);
        Assert.Equal("BLOAT-SIGNED", resolution.Catalog.Match(new InstalledSoftware(
            "SignedWare Pro", null, null, SoftwareSource.Uninstall, false, true, "{s}"))?.Id);
    }

    [Fact]
    public void Without_a_store_the_catalog_is_the_embedded_baseline()
    {
        using var publisher = new TestPublisher();
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(BloatwareCatalog.Embedded.Count, resolution.Catalog.Count);
    }

    /// <summary>
    /// The full round trip: publish, apply, resolve. A new rule is added, and the data
    /// date becomes the publication date (D15).
    /// </summary>
    [Fact]
    public void An_applied_update_adds_rules_and_dates_from_the_manifest()
    {
        using var publisher = new TestPublisher();

        var addOne = BaseRule + """

            - id: WIN-STORE-002
              title: Ajouté
              severity: medium
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: Neuf
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", addOne, "2026-08-15T00:00:00Z");
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(2, resolution.Rules.Count);
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-002");
        Assert.Equal("2026-08-15T00:00:00Z", resolution.AsOfUtc);
        Assert.Contains("appliquée", resolution.UpdateNote);
    }

    /// <summary>
    /// D12: an update corrects an embedded check with the same identifier, without
    /// changing their count. The incoming version wins.
    /// </summary>
    [Fact]
    public void An_update_corrects_an_embedded_rule_of_the_same_id()
    {
        using var publisher = new TestPublisher();

        var corrected = BaseRule.Replace("expect: \"1\"", "expect: \"2\"");
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", corrected);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        var rule = Assert.Single(resolution.Rules);
        Assert.Equal("2", rule.Check.Expected);
    }

    /// <summary>
    /// D12, the floor: an update that does not mention an embedded check does not
    /// remove it. It stays, as is.
    /// </summary>
    [Fact]
    public void An_update_that_omits_an_embedded_rule_does_not_remove_it()
    {
        using var publisher = new TestPublisher();

        var onlyNew = """
            - id: WIN-STORE-999
              title: Seulement nouveau
              severity: low
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: X
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", onlyNew);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Equal(2, resolution.Rules.Count);
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-001"); // the baseline holds
        Assert.Contains(resolution.Rules, r => r.Id == "WIN-STORE-999");
    }

    /// <summary>
    /// D13: the scan re-verifies. A store file tampered with after apply is rejected —
    /// the baseline holds, and the report says why. Never silently.
    /// </summary>
    [Fact]
    public void A_store_file_tampered_after_apply_is_rejected_not_loaded()
    {
        using var publisher = new TestPublisher();
        var (manifestPath, verifier) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        // Someone alters the dataset in the store after the fact.
        File.WriteAllText(Path.Combine(Store, "regles.yaml"), "- id: INJECTE");

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), verifier);

        Assert.Single(resolution.Rules); // baseline only
        Assert.DoesNotContain(resolution.Rules, r => r.Id == "INJECTE");
        Assert.Contains("ne correspond", resolution.UpdateNote);
    }

    /// <summary>
    /// A store manifest signed by an unknown key: refused, baseline kept, and said.
    /// This is what separates "the store was compromised" from a silent load.
    /// </summary>
    [Fact]
    public void An_untrusted_store_manifest_is_refused_and_said()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var (manifestPath, _) = Publish(publisher, "regles.yaml", BaseRule);
        UpdateStore.Apply(manifestPath, Store, ["regles.yaml"]);

        var strangerVerifier = new ManifestVerifier(
            new Dictionary<string, string> { [stranger.KeyId] = stranger.PublicKey });

        var resolution = UpdateStore.Resolve(Store, BaseCatalog(), strangerVerifier);

        Assert.Single(resolution.Rules);
        Assert.Contains("refusée", resolution.UpdateNote);
    }

    private static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
