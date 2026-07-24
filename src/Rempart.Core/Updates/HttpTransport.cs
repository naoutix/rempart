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
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            // Unreachable, timed out, malformed URL: a transport failure, never a
            // trust verdict. The raw message is enough to orient the user.
            error = ex.Message;
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
