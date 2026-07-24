using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;

namespace Rempart.Core.Dns;

/// <summary>
/// Real probe of encrypted resolvers — the only active part of the scan alongside the
/// VirusTotal enrichment and the PAC fetch, and like them never triggered without opt-in.
///
/// <para>
/// A single DNS wire packet serves both transports: DoH posts it as
/// <c>application/dns-message</c>, DoT sends it over a TLS/853 socket prefixed with its
/// length (DNS/TCP). Three samples per probe, one warm-up discarded, median kept.
/// AOT-compatible (HttpClient, sockets, SslStream require no reflection).
/// </para>
/// </summary>
public sealed class LiveDnsProbe : IDnsProbe, IDisposable
{
    private const int Samples = 3;
    private const string QueryName = "example.com";
    private const ushort QueryId = 0x1234;

    private readonly HttpClient http;
    private readonly TimeSpan timeout;

    public LiveDnsProbe(TimeSpan? timeout = null)
    {
        this.timeout = timeout ?? TimeSpan.FromSeconds(3);
        http = new HttpClient { Timeout = this.timeout };
    }

    public IReadOnlyList<DnsProbeResult> Probe()
    {
        var results = new List<DnsProbeResult>();

        foreach (var resolver in KnownResolvers.All)
        {
            results.Add(Measure(resolver, DnsProbeProtocol.DoH, () => QueryDoH(resolver.Host)));
            results.Add(Measure(resolver, DnsProbeProtocol.DoT, () => QueryDoT(resolver.Host)));
        }

        return results;
    }

    private DnsProbeResult Measure(EncryptedResolver resolver, DnsProbeProtocol protocol, Func<int> once)
    {
        // Warm-up sample: the first TLS/HTTP connection is slower, so it is discarded.
        // Its failure is not fatal — the following measurements try again.
        try
        {
            once();
        }
        catch
        {
            // ignored: the warm-up is not a measurement.
        }

        var samples = new List<int>();
        string? error = null;

        for (var i = 0; i < Samples; i++)
        {
            try
            {
                samples.Add(once());
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        if (samples.Count == 0)
        {
            return new DnsProbeResult(resolver.Name, protocol, false, null, error ?? "injoignable");
        }

        samples.Sort();
        return new DnsProbeResult(resolver.Name, protocol, true, samples[samples.Count / 2], null);
    }

    private int QueryDoH(string host)
    {
        var query = DnsWireFormat.BuildQuery(QueryName, QueryId);

        using var content = new ByteArrayContent(query);
        content.Headers.TryAddWithoutValidation("Content-Type", "application/dns-message");

        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://{host}/dns-query")
        {
            Content = content,
            // Most DoH endpoints want HTTP/2; prefer it, falling back to HTTP/1.1 so a
            // resolver that does not speak it is not excluded.
            Version = System.Net.HttpVersion.Version20,
            VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower,
        };
        request.Headers.TryAddWithoutValidation("Accept", "application/dns-message");

        var stopwatch = Stopwatch.StartNew();
        using var response = http.SendAsync(request).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var body = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        stopwatch.Stop();

        if (!DnsWireFormat.IsValidResponse(query, body))
        {
            throw new InvalidOperationException("réponse DoH non conforme");
        }

        return (int)stopwatch.ElapsedMilliseconds;
    }

    private int QueryDoT(string host)
    {
        var query = DnsWireFormat.BuildQuery(QueryName, QueryId);

        var stopwatch = Stopwatch.StartNew();

        using var tcp = new TcpClient();
        if (!tcp.ConnectAsync(host, 853).Wait(timeout))
        {
            throw new TimeoutException("connexion au port 853 expirée");
        }

        using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        ssl.ReadTimeout = (int)timeout.TotalMilliseconds;
        ssl.WriteTimeout = (int)timeout.TotalMilliseconds;
        ssl.AuthenticateAsClient(host);   // validates the certificate against the host name

        // DNS/TCP: the message is prefixed with its length on two bytes.
        var framed = new byte[2 + query.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        ssl.Write(framed);
        ssl.Flush();

        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(ReadExactly(ssl, 2));
        var response = ReadExactly(ssl, responseLength);
        stopwatch.Stop();

        if (!DnsWireFormat.IsValidResponse(query, response))
        {
            throw new InvalidOperationException("réponse DoT non conforme");
        }

        return (int)stopwatch.ElapsedMilliseconds;
    }

    private static byte[] ReadExactly(Stream stream, int count)
    {
        var buffer = new byte[count];
        var read = 0;

        while (read < count)
        {
            var got = stream.Read(buffer, read, count - read);
            if (got == 0)
            {
                throw new EndOfStreamException("réponse DoT tronquée");
            }

            read += got;
        }

        return buffer;
    }

    public void Dispose() => http.Dispose();
}
