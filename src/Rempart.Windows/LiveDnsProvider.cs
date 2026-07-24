using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads each interface's DNS configuration from the registry.
///
/// <para>
/// Each interface has its key under <c>Tcpip\Parameters\Interfaces</c>. <c>NameServer</c>
/// holds statically configured resolvers, <c>DhcpNameServer</c> those received from the
/// network — the distinction the collector evaluates. Addresses are separated by spaces
/// or commas.
/// </para>
/// </summary>
public sealed class LiveDnsProvider : IDnsProvider
{
    private const string InterfacesKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    private readonly IRegistryProvider registry;

    public LiveDnsProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public LiveDnsProvider(IRegistryProvider registry) => this.registry = registry;

    public IReadOnlyList<DnsInterface> Read()
    {
        var interfaces = new List<DnsInterface>();

        foreach (var guid in registry.ListSubKeys(InterfacesKey))
        {
            var keyPath = $@"{InterfacesKey}\{guid}";
            var stat = Split(registry.ReadValue(keyPath, "NameServer").Value?.Text);
            var dhcp = Split(registry.ReadValue(keyPath, "DhcpNameServer").Value?.Text);

            if (stat.Count > 0 || dhcp.Count > 0)
            {
                interfaces.Add(new DnsInterface(guid, stat, dhcp));
            }
        }

        return interfaces;
    }

    private static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
