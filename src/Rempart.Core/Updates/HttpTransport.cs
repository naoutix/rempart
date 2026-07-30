using System.Net.Http;

namespace Rempart.Core.Updates;

/// <summary>
/// The real HTTP transport, built on <see cref="HttpClient"/>.
///
/// <para>
/// Native AOT compatible — <c>SocketsHttpHandler</c> requires no reflection. The
/// response buffer is capped: a hostile server must not be able to exhaust memory by
/// serving an endless file. The cap is generous relative to the real data (a manifest
/// is under a kilobyte, the LOLDrivers list a few hundred).
/// </para>
///
/// <para>
/// No trust is placed in the transport: redirects are followed without concern, since
/// a manifest redirected to forged content will fail signature verification anyway.
/// The signature is what protects, not the channel.
/// </para>
///
/// <para>
/// The <c>catch</c> in <see cref="Get"/> is deliberately untyped. It used to name
/// <c>HttpRequestException or TaskCanceledException or UriFormatException</c>, and the URL
/// it reads comes from <c>--url</c>, which is to say from whatever was typed: <c>rempart
/// update --url exemple.test/rempart</c> — no scheme, so a relative URI — leaves
/// <c>HttpClient</c> as an <c>InvalidOperationException</c>, and <c>file://</c> or
/// <c>ftp://</c> as the very <c>NotSupportedException</c> REV-08 lost a whole scan to one
/// file over. None of the three was listed. Each of them walked past
/// <see cref="RemoteUpdate"/> and <c>UpdateCommand</c> to the catch-all in <c>Program</c>,
/// and came out as « Erreur : An invalid request URI was provided… » — a sentence from
/// <c>HttpClient</c>, in English, where this method had a reason to hand back and the
/// command a French sentence to print.
/// </para>
///
/// <para>
/// What makes an unfiltered <c>catch</c> safe here is the size of what it covers rather
/// than the types it names, the same reasoning <see cref="UpdateStore"/> records: the
/// <c>try</c> holds the request and the reading of its body, and nothing else. No
/// verification and no parsing happen inside it, so no failure of <em>those</em> can be
/// mistaken for a transport that did not answer.
/// </para>
/// </summary>
public sealed class HttpTransport : IUpdateTransport, IDisposable
{
    private const long MaxResponseBytes = 64 * 1024 * 1024;

    private readonly HttpClient client;

    public HttpTransport(TimeSpan? timeout = null)
    {
        client = new HttpClient
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaxResponseBytes,
        };

        // An honest user-agent header: nothing to hide, and some hosts reject a
        // request without one.
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rempart-update/1.0");
    }

    public byte[]? Get(string url, out string? error)
    {
        try
        {
            using var response = client.GetAsync(url).GetAwaiter().GetResult();

            if (!response.IsSuccessStatusCode)
            {
                error = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}";
                return null;
            }

            error = null;
            return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            // Unreachable, timed out, malformed URL, a scheme HttpClient will not speak:
            // a transport failure, never a trust verdict. The raw message is enough to
            // orient the user.
            error = ex.Message;
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
