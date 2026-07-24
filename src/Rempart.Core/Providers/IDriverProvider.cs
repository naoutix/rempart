namespace Rempart.Core.Providers;

/// <summary>
/// A loaded kernel driver: its name and the file it comes from.
///
/// The hash is not here — it comes from <see cref="ISignatureProvider"/>, which
/// computes it while verifying the signature. The record carries only what identifies
/// the driver; judgment data is computed elsewhere.
/// </summary>
public sealed record LoadedDriver(string Name, string Path);

/// <summary>
/// Enumerates the kernel drivers currently loaded.
///
/// <para>
/// This covers vulnerable drivers actually in memory — the core of a "BYOVD" (bring
/// your own vulnerable driver) attack, where a signed but flawed driver is loaded to
/// gain kernel access. A driver present on disk but not loaded is not covered: it does
/// not execute, and listing it would misstate the inventory.
/// </para>
///
/// <para>
/// Abstracted like the rest (ADR-001, D5): the judgment is tested against a given
/// driver list, without loading a real one.
/// </para>
/// </summary>
public interface IDriverProvider
{
    IReadOnlyList<LoadedDriver> Enumerate();
}
