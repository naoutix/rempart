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

    /// <summary>
    /// A transport that throws is a transport failure like any other, whatever it throws.
    ///
    /// <para>
    /// <see cref="IUpdateTransport"/> promises bytes or a reason, and its own
    /// implementation is the only place that promise can be kept — which is why the guard
    /// is here as well as there. This is the level REV-08 called "the only one where the
    /// invariant does not depend on the implementation chosen": whichever transport is
    /// plugged in, a download that fails becomes a sentence <c>update</c> prints, never an
    /// audit tool stopping on an English stack message.
    /// </para>
    /// </summary>
    [Fact]
    public void A_transport_that_throws_is_a_transport_error_not_a_lost_run()
    {
        var (fetch, error) = RemoteUpdate.Prepare(
            "https://exemple.test/rempart", new ThrowingTransport(
                new InvalidOperationException("An invalid request URI was provided.")),
            new ManifestVerifier(new Dictionary<string, string>()), []);

        Assert.Null(fetch);
        Assert.Contains("injoignable", error);
        Assert.Contains("An invalid request URI was provided.", error);
    }

    /// <summary>
    /// The same for a dataset, where the manifest already came back: the preview stands and
    /// names the dataset it could not check, rather than the command disappearing whole.
    /// </summary>
    [Fact]
    public void A_transport_that_throws_on_a_dataset_leaves_the_preview_standing()
    {
        using var publisher = new TestPublisher();
        var (manifest, _, verifier) = Publish(publisher, "regles.yaml", Rule);

        var (fetch, error) = RemoteUpdate.Prepare(
            "https://h", new ThrowingTransport(
                new NotSupportedException("The 'file' scheme is not supported."),
                except: ("https://h/manifest.json", manifest)),
            verifier, []);

        Assert.Null(error);
        Assert.True(fetch!.Preview.Trusted);
        Assert.False(fetch.Preview.ReadyToApply);
        Assert.NotNull(Assert.Single(fetch.Preview.Datasets).Problem);
    }
}

/// <summary>
/// A transport that fails the way a live one does: by throwing. <c>HttpTransport</c> filtered
/// its <c>catch</c> on three types, and neither the <c>InvalidOperationException</c> of a
/// relative URL nor the <c>NotSupportedException</c> of a <c>file://</c> one was among them.
/// </summary>
internal sealed class ThrowingTransport(Exception failure, (string Url, byte[] Bytes)? except = null)
    : IUpdateTransport
{
    public byte[]? Get(string url, out string? error)
    {
        if (except is { } served && string.Equals(served.Url, url, StringComparison.Ordinal))
        {
            error = null;
            return served.Bytes;
        }

        throw failure;
    }
}

/// <summary>
/// The transport that really goes out, held to the contract it declares: bytes, or
/// <c>null</c> and a reason. Nothing below touches the network — every URL here is settled
/// before a packet leaves.
/// </summary>
public sealed class HttpTransportTests
{
    /// <summary>
    /// The URL comes from <c>--url</c>, so it is whatever was typed. Four spellings a
    /// person actually types, and each used to leave <c>Get</c> as an exception: past
    /// <c>UpdateCommand</c>, past <c>Program</c>, and out as « Erreur : An invalid request
    /// URI was provided… » — an English sentence from <c>HttpClient</c> where the command
    /// had a French one ready.
    ///
    /// <para>
    /// The <c>file://</c> case throws the same exception REV-08 lost a whole scan to, one
    /// file over, and it was still not in this list.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("exemple.test/rempart")]
    [InlineData("")]
    [InlineData("file:///C:/rempart/manifest.json")]
    [InlineData("ftp://exemple.test/rempart")]
    public void An_unusable_url_is_an_error_not_an_exception(string url)
    {
        using var transport = new HttpTransport(TimeSpan.FromSeconds(2));

        var bytes = transport.Get(url, out var error);

        Assert.Null(bytes);
        Assert.False(string.IsNullOrWhiteSpace(error),
            $"URL « {url} » : aucune raison rendue. Un appelant qui reçoit null sans raison "
            + "n'a rien à afficher.");
    }
}
