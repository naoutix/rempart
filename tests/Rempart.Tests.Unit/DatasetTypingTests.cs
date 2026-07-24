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
/// The channel no longer carries rules alone. These tests cover routing by kind —
/// rules vs drivers — and the refusal of an unknown kind.
/// </summary>
public sealed class DatasetTypingTests : IDisposable
{
    private readonly string root =
        Path.Combine(Path.GetTempPath(), "rempart-typing-" + Guid.NewGuid().ToString("n"));

    private string Store => Path.Combine(root, "store");

    /// <summary>
    /// Publishes a typed dataset and applies it to the store, ready to be resolved the
    /// way a scan would. Returns the verifier armed with the publisher's key.
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
    /// The full journey of a driver blocklist: signed, applied, resolved, and a loaded
    /// driver whose hash it lists comes out suspicious. This is what typing unlocks —
    /// the real LOLDrivers data, delivered through the same channel as the rules.
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

        // The store loaded the list, and the rule baseline is intact (D12).
        Assert.Equal(1, resolution.Blocklist.Count);
        Assert.Contains("pilotes surveillés", resolution.UpdateNote);

        // A loaded driver whose hash is in the list comes out suspicious.
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
    /// The kind is inferred from the extension: a <c>.json</c> is a driver blocklist, a
    /// <c>.yaml</c> is rules. The publisher has nothing to declare in the common case.
    /// </summary>
    [Fact]
    public void The_kind_is_inferred_from_the_extension()
    {
        Assert.Equal(DatasetKind.Rules, DatasetKind.Infer("securite.yaml"));
        Assert.Equal(DatasetKind.Rules, DatasetKind.Infer("securite.YML"));
        Assert.Equal(DatasetKind.Drivers, DatasetKind.Infer("loldrivers.json"));
    }

    /// <summary>
    /// A manifest of a kind an old version does not know is refused, not guessed at:
    /// the answer must be "update the binary", never a silent partial load. The
    /// baseline holds (D12).
    /// </summary>
    [Fact]
    public void An_unknown_kind_is_refused_and_the_floor_holds()
    {
        using var publisher = new TestPublisher();
        // "bloatware" has become a known kind (M5b): use a genuinely future kind, still
        // unknown to this binary, so the test keeps exercising the intended refusal.
        var verifier = PublishAndApply(publisher, "cve.dat", "des données futures", kind: "signatures-malveillantes");

        var resolution = UpdateStore.Resolve(Store, RuleCatalog.Load(), verifier);

        Assert.Equal(RuleCatalog.Load().Count, resolution.Rules.Count); // baseline intact
        Assert.Equal(0, resolution.Blocklist.Count);
        Assert.Contains("type inconnu", resolution.UpdateNote);
    }

    /// <summary>
    /// A manifest predating typing has no <c>kind</c> field: it must read as rules,
    /// which is what it was. This is the backward compatibility the default of
    /// <see cref="ManifestEntry.Kind"/> guarantees.
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
