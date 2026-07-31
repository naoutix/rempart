namespace Rempart.Core.Providers;

/// <summary>
/// Each interface's DNS configuration, read through <see cref="IRegistryProvider"/>.
///
/// <para>
/// It lives in Core and not in the Windows layer because there is nothing Windows about it:
/// no P/Invoke, no COM, no file — four registry reads and a split. It sat in
/// <c>Rempart.Windows</c> for as long as it did only because that is where the class that
/// wires it up lives, and the price was that its logic could be exercised nowhere but on a
/// Windows machine, by a test that walked whatever interfaces that machine happened to have.
/// The same move CatalogSignature made, for the same reason: what is a judgement goes down
/// here and is tested on the Linux job; what is interop stays up there and is tested against
/// the real thing.
/// </para>
///
/// <para>
/// Each interface has its own key under <c>Tcpip\Parameters\Interfaces</c>.
/// <c>NameServer</c> holds statically configured resolvers, <c>DhcpNameServer</c> those
/// handed out by the network — the distinction the collector evaluates, since a static
/// resolver on a machine that gets one by DHCP is a deliberate act.
/// </para>
///
/// <para>
/// Three reads deep, and each one can be denied on its own: the enumeration of the interfaces,
/// and the two values of each interface. All three are watched, because the cheapest place to
/// hide a resolver is the one nobody looks at — an ACL on a single adapter key used to remove
/// that adapter from the inventory without a word (#184).
/// </para>
/// </summary>
public sealed class RegistryDnsProvider(IRegistryProvider registry) : IDnsProvider
{
    public const string InterfacesKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    public DnsRead Read()
    {
        var interfaces = new List<DnsInterface>();

        // The denied paths, gathered rather than counted: what the report can act on is which
        // surface it lost, and a bare count of two would say nothing about where the hole is.
        var denied = new List<string>();

        var listing = registry.ListSubKeys(InterfacesKey);

        // The key itself. Refused here means no interface at all was seen, which used to be
        // the same empty list a machine with no configured adapter returns — the defect of
        // #184, on the surface a hijack is laid on.
        if (listing.Status is ReadStatus.AccessDenied)
        {
            return DnsRead.Refused([], [InterfacesKey]);
        }

        // The key is not on this machine. An answer, and one this read is allowed to give
        // silently: nothing resolves through an interface that was never configured.
        if (listing.Status is ReadStatus.NotFound)
        {
            return DnsRead.Absent;
        }

        foreach (var guid in listing.Names)
        {
            var keyPath = $@"{InterfacesKey}\{guid}";
            var staticRead = registry.ReadValue(keyPath, "NameServer");
            var dhcpRead = registry.ReadValue(keyPath, "DhcpNameServer");

            // The refusal one level down, and the one that hides a hijack most cheaply: an ACL
            // on a single interface key made both values read back as « rien », so the adapter
            // dropped out of the inventory with its static resolver. An absent value is the
            // ordinary case and stays silent; only a denial speaks.
            if (staticRead.Status is ReadStatus.AccessDenied
                || dhcpRead.Status is ReadStatus.AccessDenied)
            {
                denied.Add(keyPath);
            }

            var stat = Split(staticRead.Value?.Text);
            var dhcp = Split(dhcpRead.Value?.Text);

            // An interface with no resolver at all is not a finding and not an omission: a
            // machine carries a dozen of these — tunnels, loopback, disconnected adapters —
            // and listing them would bury the two that resolve anything.
            if (stat.Count > 0 || dhcp.Count > 0)
            {
                interfaces.Add(new DnsInterface(guid, stat, dhcp));
            }
        }

        // What the readable interfaces gave is kept beside the refusal: dropping them because
        // one adapter was denied would trade one silence for another.
        return denied.Count > 0
            ? DnsRead.Refused(interfaces, denied)
            : DnsRead.Found(interfaces);
    }

    /// <summary>
    /// Splits a resolver list.
    ///
    /// <para>
    /// Windows writes these three ways depending on how they were configured — spaces for a
    /// DHCP lease, commas for a static list set through the UI, and semicolons show up too.
    /// Getting the separators wrong does not fail: it produces one resolver whose address is
    /// two addresses glued together, which matches nothing in the well-known list and comes
    /// out as a <c>Notable</c> finding about a resolver that does not exist.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split([' ', ',', ';'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
