using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// This machine's DNS configuration: the live registry, handed to the reader in Core.
///
/// <para>
/// Everything this class used to do is now <see cref="RegistryDnsProvider"/>, and that is the
/// whole change: the key path, the two value names and the separators are a judgement about
/// how Windows stores resolvers, testable against a fake registry on the Linux job, and they
/// were sitting in a project that job does not compile. What is left here is the one thing
/// that genuinely needs Windows — a real <see cref="LiveRegistryProvider"/> — and the name
/// the wiring looks for.
/// </para>
/// </summary>
public sealed class LiveDnsProvider(IRegistryProvider registry) : IDnsProvider
{
    private readonly RegistryDnsProvider inner = new(registry);

    public LiveDnsProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public DnsRead Read() => inner.Read();
}
