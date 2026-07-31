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
/// <summary>
/// The driver list, plus whether it could be read at all.
///
/// <para>
/// The status is not decoration. Enumeration goes through WMI, which on a degraded
/// machine answers every query with zero rows; before this record existed the provider
/// returned an empty list and the report showed no drivers, which reads exactly like a
/// machine with nothing loaded. This is the surface carrying the LOLDrivers comparison —
/// the one place where "nothing found" must never be produced by a failure to look.
/// </para>
/// </summary>
public sealed record DriverRead(
    ReadStatus Status,
    IReadOnlyList<LoadedDriver> Drivers,
    string? Diagnostic = null)
    : IStatusCarryingRead<DriverRead, LoadedDriver>
{
    /// <summary>The enumeration was refused. Elevation is the answer.</summary>
    public static readonly DriverRead AccessDenied = new(ReadStatus.AccessDenied, []);

    public static DriverRead Found(IReadOnlyList<LoadedDriver> drivers) =>
        new(ReadStatus.Found, drivers);

    /// <summary>
    /// The enumeration was attempted, did not complete, and was not denied — a WMI repository
    /// that stopped serving, a capture holding nothing on this surface. No privilege repairs
    /// either, so the status says so as plainly as the name does.
    /// </summary>
    public static DriverRead Failed(string reason) =>
        new(ReadStatus.Failed, [], reason);

    // Explicit, so "Drivers" stays the only name a caller sees and nothing new appears in
    // any serialised shape. See IStatusCarryingRead.
    IReadOnlyList<LoadedDriver> IStatusCarryingRead<DriverRead, LoadedDriver>.Items => Drivers;

    static DriverRead IStatusCarryingRead<DriverRead, LoadedDriver>.Compose(
        ReadStatus status, IReadOnlyList<LoadedDriver> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

public interface IDriverProvider
{
    DriverRead Enumerate();
}
