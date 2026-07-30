using Rempart.Core.Updates;

namespace Rempart.Tests.Windows;

/// <summary>
/// The update store read against a file the operating system will not hand over.
///
/// <para>
/// Here rather than in the Linux suite because the failure has to be <em>real</em>: the
/// unit sweep hands <c>UpdateStore.Resolve</c> a reader that throws, which proves the
/// refusal but says nothing about whether the guard sits around the actual
/// <c>File.ReadAllBytes</c>. <see cref="FileShare.None"/> is enforced by Windows, so this
/// one makes the real read fail, deterministically, with no privilege and no degraded
/// machine — the same technique <c>CatalogSignatureTests</c> uses one folder over.
/// </para>
///
/// <para>
/// One process holding <c>rempart-data\manifest.json</c> without sharing reads is the
/// whole scenario, and the store is the one folder the stick seal excludes by design, so
/// nothing else notices.
/// </para>
/// </summary>
public class UpdateStoreLockTests : IDisposable
{
    private readonly string store =
        Path.Combine(Path.GetTempPath(), "rempart-store-lock-" + Guid.NewGuid().ToString("n"));

    /// <summary>
    /// A manifest that cannot be opened is an update refused, not the end of the scan.
    ///
    /// <para>
    /// Before the guard, <c>File.ReadAllText</c> raised <c>IOException</c> straight out of
    /// <c>Resolve</c>, through <c>CliHost</c>, to the catch-all in <c>Program</c>: no
    /// report, no integrity note, no score — a whole audit lost to a file that happened to
    /// be open. The manifest never has to be valid for this: the read comes first.
    /// </para>
    /// </summary>
    [Fact]
    public void A_manifest_held_open_refuses_the_update_instead_of_ending_the_scan()
    {
        Directory.CreateDirectory(store);
        var manifest = Path.Combine(store, UpdateStore.ManifestFileName);
        File.WriteAllText(manifest, """{"payload":"","signatures":[]}""");

        using var held = File.Open(manifest, FileMode.Open, FileAccess.Read, FileShare.None);

        var resolution = UpdateStore.Resolve(store, [], PinnedKeys.Verifier());

        // Refused, and refused as unreadable: "could not read" and "there is nothing" are
        // the distinction the whole store is built on, and a silent note would be the
        // second one.
        Assert.NotNull(resolution.UpdateNote);
        Assert.Contains("illisible", resolution.UpdateNote, StringComparison.Ordinal);
        Assert.Contains("Socle embarqué conservé", resolution.UpdateNote, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);

        if (Directory.Exists(store))
        {
            Directory.Delete(store, recursive: true);
        }
    }
}
