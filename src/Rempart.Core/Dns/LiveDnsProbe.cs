using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;

namespace Rempart.Core.Dns;

/// <summary>
/// Sonde réelle des résolveurs chiffrés — le seul volet actif du scan avec l'enrichissement
/// VirusTotal et la récupération PAC, et comme eux jamais déclenché sans opt-in.
///
/// <para>
/// Un même paquet DNS wire sert les deux transports : DoH le poste en
/// <c>application/dns-message</c>, DoT l'envoie sur une socket TLS/853 préfixé de sa
/// longueur (DNS/TCP). Trois échantillons par sonde, un de chauffe écarté, médiane retenue.
/// Compatible AOT (HttpClient, sockets, SslStream ne demandent pas de réflexion).
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
        // Échantillon de chauffe : la première connexion TLS/HTTP est plus lente, on
        // l'écarte. Son échec n'est pas fatal, les mesures suivantes retentent.
        try
        {
            once();
        }
        catch
        {
            // ignoré : la chauffe n'est pas une mesure.
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
            // La plupart des endpoints DoH veulent HTTP/2 ; on le préfère, avec repli en
            // HTTP/1.1 pour ne pas exclure un résolveur qui ne le parle pas.
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
        ssl.AuthenticateAsClient(host);   // valide le certificat sur le nom d'hôte

        // DNS/TCP : le message est préfixé de sa longueur sur deux octets.
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
