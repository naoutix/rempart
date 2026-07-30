using System.Text;
using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// Fetches bytes at a URL. Abstracted so the network orchestration can be tested
/// without a network (ADR-001, D5) — a fake transport serves known bytes.
/// </summary>
public interface IUpdateTransport
{
    /// <summary>The bytes at that URL, or <c>null</c> on failure — reason in <paramref name="error"/>.</summary>
    byte[]? Get(string url, out string? error);
}

/// <summary>
/// What a download brought back: the preview, and the bytes already in hand for the
/// apply step — so that what was just verified is not downloaded again.
/// </summary>
public sealed record RemoteFetch(
    UpdatePreview Preview,
    byte[] ManifestBytes,
    IReadOnlyDictionary<string, byte[]> DatasetBytes);

/// <summary>
/// Downloads an update and prepares it — without ever trusting the transport.
///
/// <para>
/// This is where ADR-002 plays out in full. The "trust the transport" option was
/// <b>rejected</b>: HTTPS attests to nothing here. A downloaded manifest goes through
/// exactly the same verification as a file brought in by hand — signature against the
/// pinned keys, fingerprint of every dataset. A compromised server, a middleman, a
/// redirect: none of them can get data accepted that the publisher did not sign. The
/// transport brings only convenience, never trust.
/// </para>
///
/// <para>
/// The pipeline is that of <see cref="UpdatePlanner"/>, unchanged: only the source of
/// the bytes differs. This is what the injected read delegate made possible from the
/// start.
/// </para>
///
/// <para>
/// <see cref="IUpdateTransport"/> promises bytes or a reason, and its implementation is
/// the only place that promise can be kept — so it is also checked here, which is the one
/// level where it does not depend on the transport plugged in (REV-08). <c>HttpTransport</c>
/// broke it three ways at once, all of them out of a URL somebody typed; a future transport
/// will break it some fourth way. Below, a download that fails is a sentence, never an
/// audit tool that stops.
/// </para>
/// </summary>
public static class RemoteUpdate
{
    public static (RemoteFetch? Fetch, string? Error) Prepare(
        string baseUrl,
        IUpdateTransport transport,
        ManifestVerifier verifier,
        IReadOnlyList<Rule> currentRules)
    {
        var manifestUrl = Join(baseUrl, UpdateStore.ManifestFileName);
        var (manifestBytes, error) = Fetched(transport, manifestUrl);

        if (manifestBytes is null)
        {
            // An unreachable manifest is distinct from a refused one: the network
            // failed, not the trust. Say exactly that.
            return (null, $"Manifeste injoignable ({manifestUrl}) : {error}");
        }

        // The bytes of each dataset are kept as they pass through: the apply step reuses
        // them without a second download, and without a second round-trip where the
        // server could answer with something other than what was just verified.
        var cache = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        byte[]? Read(string name)
        {
            var (bytes, _) = Fetched(transport, Join(baseUrl, name));
            if (bytes is not null)
            {
                cache[name] = bytes;
            }

            return bytes;
        }

        var preview = UpdatePlanner.Prepare(
            Encoding.UTF8.GetString(manifestBytes), verifier, Read, currentRules);

        return (new RemoteFetch(preview, manifestBytes, cache), null);
    }

    /// <summary>
    /// The transport's answer, and whatever it throws turned into the reason it should have
    /// been. Untyped on purpose: a list of exception types is a list to keep up to date, and
    /// the transport this repository ships was caught short by three at once — a relative
    /// URL, a <c>file://</c> one, an <c>ftp://</c> one.
    ///
    /// <para>
    /// A dataset that cannot be downloaded is already an ordinary outcome here — the
    /// preview marks it unverified and <c>ReadyToApply</c> goes false — so the guard adds no
    /// silence: what changes is that the reason is reported instead of the process ending.
    /// </para>
    /// </summary>
    private static (byte[]? Bytes, string? Error) Fetched(IUpdateTransport transport, string url)
    {
        try
        {
            var bytes = transport.Get(url, out var error);
            return (bytes, error);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    /// <summary>
    /// Builds the URL of a resource under the base, neither doubling nor dropping the separator.
    /// </summary>
    private static string Join(string baseUrl, string name) =>
        baseUrl.TrimEnd('/') + "/" + name.TrimStart('/');
}
