using Rempart.Core.Providers;

namespace Rempart.Core.Collectors;

/// <summary>
/// Records what SCHANNEL says about each TLS protocol, and judges none of it.
///
/// <para>
/// <b>Why a collector before any rule.</b> TLS hardening rules have been deferred since M2b
/// for a reason that is not laziness: the effective defaults vary by Windows build, and a
/// guessed <c>windowsDefault</c> would fail machines that are correctly configured. M1 paid
/// that price once, with three false <c>CRITICAL</c> on a healthy machine, and a tool that
/// cries wolf stops being read.
/// </para>
///
/// <para>
/// What was missing was never the judgement — it was the evidence. A capture records
/// <em>only what was read</em>, and nothing in this tool read SCHANNEL, so not one capture
/// ever taken carries a single one of these values. Every future capture now does, on every
/// machine the tool visits, which is what turns "wait for machines" into "wait for captures".
/// The same order was followed for IPv6: the collection landed on 2026-07-26 and the
/// hardening rules are still deferred, with nobody crying wolf in between.
/// </para>
///
/// <para>
/// <b>Absence is the datum.</b> On SCHANNEL a missing value is the ordinary state and it
/// means "the default of this build applies" — which is exactly the unknown being measured.
/// It is therefore written down as <c>absent</c> rather than omitted: a field that only
/// appears when it has a value would make "this machine has no entry" indistinguishable from
/// "this capture predates the collector", and the comparison across builds rests on telling
/// those apart.
/// </para>
///
/// <para>
/// Read through <see cref="IRegistryProvider.ListValues"/> and not <c>ReadValue</c>, which
/// throws <c>SnapshotIncompleteException</c> for a location a capture never recorded. Every
/// fixture and every real capture taken before today is in that position, so reading value by
/// value would make this collector break the replay of every one of them.
/// </para>
/// </summary>
public sealed class TlsCollector : ICollector
{
    internal const string ProtocolsKey =
        @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    /// <summary>
    /// The four protocols, under the names Windows gives the keys. 1.0 and 1.1 are the ones
    /// a hardening guide disables; 1.3 is here because its <em>absence</em> on an older build
    /// is as informative as its state on a new one.
    /// </summary>
    internal static readonly IReadOnlyList<string> Protocols = ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"];

    /// <summary>
    /// Both sides, never one. A workstation acting as a client is the ordinary case, but the
    /// server side is where a machine offers a deprecated protocol to the network, and the
    /// two are configured independently.
    /// </summary>
    internal static readonly IReadOnlyList<string> Roles = ["Client", "Server"];

    /// <summary>The two values that decide a protocol's state, and they disagree usefully.</summary>
    internal static readonly IReadOnlyList<string> Values = ["Enabled", "DisabledByDefault"];

    public string Name => "tls";

    public CollectorResult Collect(ProviderSet providers)
    {
        var fields = new Dictionary<string, string?>(StringComparer.Ordinal);
        var diagnostics = new List<string>();
        var refused = false;

        foreach (var protocol in Protocols)
        {
            foreach (var role in Roles)
            {
                var key = $@"{ProtocolsKey}\{protocol}\{role}";
                var listing = providers.Registry.ListValues(key);

                // A refusal is not an absence, and the difference is the whole point: an
                // absence is evidence about this build's defaults, a refusal is evidence
                // about nothing at all. Counting the second as the first would poison the
                // very comparison this collector exists to make possible.
                var unreadable = listing.Status is ReadStatus.AccessDenied or ReadStatus.Failed;

                if (unreadable)
                {
                    refused |= listing.Status == ReadStatus.AccessDenied;
                    diagnostics.Add($"{protocol} ({role}) : lecture impossible ({listing.Status}).");
                }

                foreach (var value in Values)
                {
                    fields[FieldName(protocol, role, value)] = unreadable
                        ? "illisible"
                        : listing.Values.TryGetValue(value, out var read) ? read.ToString() : "absent";
                }
            }
        }

        return new CollectorResult(
            Name,
            refused ? CollectorStatus.InsufficientPrivileges
            : diagnostics.Count > 0 ? CollectorStatus.Failed
            : CollectorStatus.Ok,
            fields,
            diagnostics);
    }

    /// <summary>
    /// <c>tls.1_2.client.enabled</c>. The dot separates, so the version carries an underscore
    /// rather than its own dot — a field name that splits into five parts on one machine and
    /// four on another would be the first thing to break whatever aggregates these.
    /// </summary>
    internal static string FieldName(string protocol, string role, string value) =>
        $"tls.{protocol.Replace("TLS ", "", StringComparison.Ordinal).Replace('.', '_')}"
        + $".{role.ToLowerInvariant()}.{char.ToLowerInvariant(value[0])}{value[1..]}";
}
