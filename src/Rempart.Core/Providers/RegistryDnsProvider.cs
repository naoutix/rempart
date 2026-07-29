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
/// </summary>
public sealed class RegistryDnsProvider(IRegistryProvider registry) : IDnsProvider
{
    public const string InterfacesKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    public IReadOnlyList<DnsInterface> Read()
    {
        var interfaces = new List<DnsInterface>();

        // .Names, without reading the status: IDnsProvider.Read carries no channel of its own
        // (partition guard: « une machine sans interface réseau configurée existe »), so a
        // refusal here has nowhere to go yet. Named rather than left implicit — it is the
        // one caller of this enumeration that still drops the answer.
        foreach (var guid in registry.ListSubKeys(InterfacesKey).Names)
        {
            var keyPath = $@"{InterfacesKey}\{guid}";
            var stat = Split(registry.ReadValue(keyPath, "NameServer").Value?.Text);
            var dhcp = Split(registry.ReadValue(keyPath, "DhcpNameServer").Value?.Text);

            // An interface with no resolver at all is not a finding and not an omission: a
            // machine carries a dozen of these — tunnels, loopback, disconnected adapters —
            // and listing them would bury the two that resolve anything.
            if (stat.Count > 0 || dhcp.Count > 0)
            {
                interfaces.Add(new DnsInterface(guid, stat, dhcp));
            }
        }

        return interfaces;
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
