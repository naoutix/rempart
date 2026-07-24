namespace Rempart.Core.Providers;

/// <summary>Origin of an inventory entry — each source has its own reliability and semantics.</summary>
public enum SoftwareSource
{
    /// <summary>Classic uninstall keys (MSI/EXE), in the registry.</summary>
    Uninstall,

    /// <summary>Appx/MSIX package (Store, modern apps).</summary>
    Appx,

    /// <summary>Standalone executable registered under <c>App Paths</c>.</summary>
    AppPath,

    /// <summary>Package installed by Chocolatey.</summary>
    Chocolatey,
}

/// <summary>
/// An installed piece of software, whatever its source.
///
/// <para>
/// Two flags carry the D6/D7 distinction: a <b>provisioned</b> Appx package is staged
/// for all users and <b>comes back after a feature update</b> even if the user removed
/// it — the case that matters for bloatware. Classic software survives feature updates
/// without being provisioned.
/// </para>
/// </summary>
public sealed record InstalledSoftware(
    string Name,
    string? Version,
    string? Publisher,
    SoftwareSource Source,
    bool Provisioned,
    bool SurvivesFeatureUpdate,
    /// <summary>
    /// Stable identifier for exact catalog matching (M5b): the <b>Package Family
    /// Name</b> for an Appx, the <b>Uninstall key name</b> for a classic uninstall
    /// entry. <c>null</c> elsewhere (App Paths, Chocolatey), which then match only by
    /// name/publisher pattern. A capture from before M5b reads back with <c>null</c> —
    /// exact matching does not apply, pattern matching still does.
    /// </summary>
    string? Identifier = null);

/// <summary>
/// Enumerates installed software, already decoded. Abstracted like the rest
/// (ADR-001, D5): the judgment — and the bloatware catalog cross-check (M5b) — is
/// tested against a given list, without a machine.
/// </summary>
public interface ISoftwareInventoryProvider
{
    IReadOnlyList<InstalledSoftware> Read();
}
