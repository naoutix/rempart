using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// Fake transport: serves known bytes at known URLs. A test "server" with no
/// network — the provider rule applied to downloads.
/// </summary>
internal sealed class FakeTransport : IUpdateTransport
{
    private readonly Dictionary<string, byte[]> byUrl = new(StringComparer.Ordinal);

    public FakeTransport Serve(string url, byte[] bytes)
    {
        byUrl[url] = bytes;
        return this;
    }

    public byte[]? Get(string url, out string? error)
    {
        if (byUrl.TryGetValue(url, out var bytes))
        {
            error = null;
            return bytes;
        }

        error = "404";
        return null;
    }
}

public class RemoteUpdateTests
{
    private const string Rule = """
        - id: WIN-REMOTE-001
          title: Ajouté par le réseau
          severity: medium
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

    private static (byte[] Manifest, byte[] Dataset, ManifestVerifier Verifier)
        Publish(TestPublisher publisher, string datasetName, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        var entry = ManifestSigner.Describe(datasetName, bytes, DatasetKind.Rules);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ManifestPayload(1, "2026-09-01T00:00:00Z", [entry]),
            RempartJsonContext.Default.ManifestPayload);

        var manifest = Encoding.UTF8.GetBytes(RempartJson.Serialise(new SignedManifest(
            Convert.ToBase64String(payload),
            [new ManifestSignature(publisher.KeyId, publisher.Sign(payload))])));

        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        return (manifest, bytes, verifier);
    }

    /// <summary>
    /// The full network path: download the manifest and its dataset, verify,
    /// preview. The result is identical to a local file's — the point of an
    /// injected transport.
    /// </summary>
    [Fact]
    public void A_downloaded_manifest_verifies_and_previews_like_a_local_one()
    {
        using var publisher = new TestPublisher();
        var (manifest, dataset, verifier) = Publish(publisher, "regles.yaml", Rule);

        var transport = new FakeTransport()
            .Serve("https://exemple.test/rempart/manifest.json", manifest)
            .Serve("https://exemple.test/rempart/regles.yaml", dataset);

        var (fetch, error) = RemoteUpdate.Prepare(
            "https://exemple.test/rempart", transport, verifier, []);

        Assert.Null(error);
        Assert.NotNull(fetch);
        Assert.True(fetch!.Preview.ReadyToApply);
        Assert.Equal(["WIN-REMOTE-001"], Assert.Single(fetch.Preview.Datasets).Diff!.Added);

        // The verified bytes are kept, to apply without re-downloading.
        Assert.True(fetch.DatasetBytes.ContainsKey("regles.yaml"));
        Assert.Equal(manifest, fetch.ManifestBytes);
    }

    /// <summary>
    /// An unreachable manifest is a transport failure, distinct from a refused
    /// manifest: the network failed, not the trust check. Report it as such.
    /// </summary>
    [Fact]
    public void An_unreachable_manifest_is_a_transport_error_not_a_refusal()
    {
        var (fetch, error) = RemoteUpdate.Prepare(
            "https://exemple.test/absent", new FakeTransport(),
            new ManifestVerifier(new Dictionary<string, string>()), []);

        Assert.Null(fetch);
        Assert.Contains("injoignable", error);
    }

    /// <summary>
    /// The base URL is joined to the resource without doubling or dropping the
    /// separator, whether or not a trailing slash is present.
    /// </summary>
    [Theory]
    [InlineData("https://h/rempart")]
    [InlineData("https://h/rempart/")]
    public void The_base_url_is_joined_cleanly(string baseUrl)
    {
        using var publisher = new TestPublisher();
        var (manifest, dataset, verifier) = Publish(publisher, "regles.yaml", Rule);

        var transport = new FakeTransport()
            .Serve("https://h/rempart/manifest.json", manifest)
            .Serve("https://h/rempart/regles.yaml", dataset);

        var (fetch, error) = RemoteUpdate.Prepare(baseUrl, transport, verifier, []);

        Assert.Null(error);
        Assert.True(fetch!.Preview.ReadyToApply);
    }

    /// <summary>
    /// The transport confers no trust: a downloaded manifest signed by an
    /// unknown key is refused exactly like a local file would be. HTTPS attests
    /// to nothing (ADR-002, option C rejected).
    /// </summary>
    [Fact]
    public void A_downloaded_manifest_signed_by_a_stranger_is_still_refused()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var (manifest, dataset, _) = Publish(publisher, "regles.yaml", Rule);

        var transport = new FakeTransport()
            .Serve("https://h/manifest.json", manifest)
            .Serve("https://h/regles.yaml", dataset);

        var strangerVerifier = new ManifestVerifier(
            new Dictionary<string, string> { [stranger.KeyId] = stranger.PublicKey });

        var (fetch, _) = RemoteUpdate.Prepare("https://h", transport, strangerVerifier, []);

        Assert.False(fetch!.Preview.Trusted);
        Assert.Equal(ManifestStatus.UnknownKey, fetch.Preview.Status);
    }
}
