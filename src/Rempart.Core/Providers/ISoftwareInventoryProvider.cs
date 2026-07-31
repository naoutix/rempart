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
/// The inventory, plus whether its sources could be read.
///
/// <para>
/// Four independent sources fill one list — three uninstall roots, two Appx keys, the App
/// Paths key, and the Chocolatey library — so this read is <b>partial by nature</b>: what one
/// source refused must not cost what the others gave. Before #184 it could say none of that.
/// Every one of those enumerations has been able to answer « refusé » since REV-11, the return
/// type had nowhere to put the answer, and an ACL laid on the uninstall keys produced the same
/// empty inventory as a machine with nothing installed.
/// </para>
///
/// <para>
/// Both causes are expressible because both occur, and they call for opposite advice: the
/// registry keys and the Chocolatey directory are denied by an ACL, which elevation opens;
/// the directory listing can also break without anyone denying anything, which no privilege
/// repairs. That is the split #173 had to make on the file channel, here from the start.
/// </para>
/// </summary>
public sealed record SoftwareInventoryRead(
    ReadStatus Status,
    IReadOnlyList<InstalledSoftware> Software,
    string? Diagnostic = null)
    : IStatusCarryingRead<SoftwareInventoryRead, InstalledSoftware>
{
    public static SoftwareInventoryRead Found(IReadOnlyList<InstalledSoftware> software) =>
        new(ReadStatus.Found, software);

    /// <summary>
    /// At least one source was denied. Elevation is the answer, and what the other sources
    /// gave is kept beside the hole.
    /// </summary>
    public static SoftwareInventoryRead Refused(
        IReadOnlyList<InstalledSoftware> software, IReadOnlyList<string> sources) =>
        new(ReadStatus.AccessDenied, software, Incomplete(sources));

    /// <summary>
    /// At least one source was attempted, did not answer, and was <b>not</b> denied — a
    /// Chocolatey library on a volume that went away. No privilege repairs it, so the status
    /// says so as plainly as the name does.
    /// </summary>
    public static SoftwareInventoryRead Failed(
        IReadOnlyList<InstalledSoftware> software, IReadOnlyList<string> sources) =>
        new(ReadStatus.Failed, software, Incomplete(sources));

    /// <summary>
    /// The sentence both states share. It names the sources and never the cause: the cause is
    /// the status beside it, which is what the collector branches on — the lesson of #179,
    /// where three summaries on one record disagreed about what a single member meant.
    /// </summary>
    private static string Incomplete(IReadOnlyList<string> sources) =>
        $"Inventaire logiciel incomplet — {sources.Count} source(s) non lue(s) : "
        + string.Join(", ", sources.Distinct(StringComparer.Ordinal))
        + ". Un logiciel installé par une de ces sources n'apparaît pas dans l'inventaire.";

    // Explicit, so "Software" stays the only name a caller sees and nothing new appears in any
    // serialised shape. See IStatusCarryingRead.
    IReadOnlyList<InstalledSoftware>
        IStatusCarryingRead<SoftwareInventoryRead, InstalledSoftware>.Items => Software;

    static SoftwareInventoryRead
        IStatusCarryingRead<SoftwareInventoryRead, InstalledSoftware>.Compose(
            ReadStatus status, IReadOnlyList<InstalledSoftware> items, string? diagnostic) =>
        new(status, items, diagnostic);
}

/// <summary>
/// Enumerates installed software, already decoded. Abstracted like the rest
/// (ADR-001, D5): the judgment — and the bloatware catalog cross-check (M5b) — is
/// tested against a given list, without a machine.
/// </summary>
public interface ISoftwareInventoryProvider
{
    SoftwareInventoryRead Read();
}
