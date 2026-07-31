using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Updates;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Real-machine test: the runner's installed software is unknown, so we check that the
/// read does not throw, returns consistent entries, and finds at least uninstall entries
/// (every Windows machine has some).
/// </summary>
public sealed class LiveSoftwareInventoryProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var read = new LiveSoftwareInventoryProvider().Read();

        Assert.All(read.Software, entry => Assert.False(string.IsNullOrEmpty(entry.Name)));

        // Every Windows installation carries uninstall entries.
        Assert.Contains(read.Software, entry => entry.Source == SoftwareSource.Uninstall);

        // And the read says so. A machine refusing nothing has to come back « lue » and
        // silent; before #184 there was no field here to assert, and a refused uninstall key
        // reached the report as the empty inventory of a machine with nothing installed.
        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
    }

    [Fact]
    public void Appx_entries_carry_a_package_family_name_as_identifier()
    {
        var software = new LiveSoftwareInventoryProvider().Read().Software;
        var appx = software.Where(s => s.Source == SoftwareSource.Appx).ToList();

        // Every modern Windows machine has Appx packages, and each one has a PFN.
        Assert.NotEmpty(appx);
        Assert.All(appx, s => Assert.False(string.IsNullOrWhiteSpace(s.Identifier)));
    }

    /// <summary>
    /// The defect of #184 on the second of the two reads it named: the six enumerations under
    /// this provider have been able to say « refusé » since REV-11, and the read had nowhere
    /// to put the answer — so an ACL on the uninstall keys produced the same empty inventory
    /// as a machine with nothing installed, and the report said nothing at all.
    ///
    /// <para>
    /// Driven through the collector as well as the read, because the status alone would go
    /// green on a collector that stopped looking at it — the shape #177 found twice.
    /// </para>
    /// </summary>
    [Fact]
    public void A_refused_registry_is_a_refusal_and_not_a_machine_without_software()
    {
        var registry = new RefusingRegistry();

        var findings = new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(
            new ProviderSet(
                registry,
                new LiveSystemInfoProvider(),
                softwareInventory: new LiveSoftwareInventoryProvider(
                    registry, @"C:\Rempart\CeCheminNExistePas")));

        var finding = Assert.Single(findings);

        Assert.Equal(AuditGap.Refused, finding.Gap);
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    /// <summary>
    /// The Chocolatey library, which is the one source here that is not the registry and the
    /// only one that can fail without anyone denying anything. Both exceptions used to be
    /// caught by a single filter and dropped in silence, so a library the scan could not open
    /// looked exactly like a machine that never installed a package.
    ///
    /// <para>
    /// Through the seam, for the reason <c>LiveFileSystemProvider</c> takes one and #173 spent
    /// three rounds discovering: a real directory can be staged as refused but not as failing,
    /// so without it the branch that names the defect is the one branch no test can enter — and
    /// merging the two <c>catch</c> blocks back together leaves both suites green.
    /// </para>
    ///
    /// <para>
    /// Both cases in one test because it is the <em>difference</em> that is the invariant:
    /// asserting them apart would let someone align the two and fail nothing.
    /// </para>
    /// </summary>
    [Fact]
    public void A_chocolatey_library_that_fails_is_not_a_chocolatey_library_that_refused()
    {
        // A directory that really exists, because Directory.Exists decides « not installed »
        // before either catch is reachable.
        var library = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}");
        Directory.CreateDirectory(library);

        try
        {
            var denied = Read(library, _ => throw new UnauthorizedAccessException());
            Assert.Equal(ReadStatus.AccessDenied, denied.Status);
            Assert.Contains(library, denied.Diagnostic!, StringComparison.Ordinal);

            var broken = Read(library, _ => throw new IOException());
            Assert.Equal(ReadStatus.Failed, broken.Status);
            Assert.NotEqual(ReadStatus.AccessDenied, broken.Status);

            // And a library that answers is a library that answers: the package is inventoried
            // and the read stays silent, which is what makes the two states above mean
            // something.
            var read = Read(library, _ => [Path.Combine(library, "7zip")]);
            Assert.Equal(ReadStatus.Found, read.Status);
            Assert.Contains(read.Software,
                entry => entry.Source == SoftwareSource.Chocolatey && entry.Name == "7zip");
        }
        finally
        {
            Directory.Delete(library, recursive: true);
        }
    }

    /// <summary>
    /// A machine that denied one source <em>and</em> broke on another — the shape a real
    /// non-elevated scan takes on a workstation whose Chocolatey library sits on a network
    /// share, and the only input on which the ranking between the two causes is observable.
    ///
    /// <para>
    /// <b>Written because the ranking was unobserved and a mutation proved it.</b> Reversing
    /// the two branches — answering « échec » whenever anything failed, denials included —
    /// left both suites green at 1136 + 169. So the summary on <c>Read</c> claiming that a
    /// denial anywhere makes the whole read a refusal was prose nothing held, on the one
    /// decision that changes what the report tells its reader to do.
    /// </para>
    ///
    /// <para>
    /// A refusal, and the argument is what the reader can act on: elevating opens the denied
    /// keys, which is a real remedy for part of the hole, where « aucun droit n'y changera
    /// rien » would be false about that part. The sentence names both sources either way, so
    /// nothing is hidden by the ranking — only the advice moves.
    /// </para>
    /// </summary>
    [Fact]
    public void A_source_denied_beside_a_source_that_broke_still_advises_elevation()
    {
        var library = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}");
        Directory.CreateDirectory(library);

        try
        {
            var read = new LiveSoftwareInventoryProvider(
                new RefusingRegistry(), library, _ => throw new IOException()).Read();

            Assert.Equal(ReadStatus.AccessDenied, read.Status);
            Assert.NotEqual(ReadStatus.Failed, read.Status);

            // And both holes are named, which is what makes the ranking a choice about advice
            // rather than a choice about what the reader is told.
            Assert.Contains("Uninstall", read.Diagnostic!, StringComparison.Ordinal);
            Assert.Contains(library, read.Diagnostic!, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(library, recursive: true);
        }
    }

    /// <summary>
    /// The inventory of a machine whose registry answers nothing and whose Chocolatey library
    /// behaves as <paramref name="enumerate"/> says. An empty registry rather than a refusing
    /// one, so that what the assertions see comes from the one source under test.
    /// </summary>
    private static SoftwareInventoryRead Read(string library, Func<string, string[]> enumerate) =>
        new LiveSoftwareInventoryProvider(new EmptyRegistry(), library, enumerate).Read();

    /// <summary>Answers « cette clé n'existe pas » to everything: no source but Chocolatey.</summary>
    private sealed class EmptyRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) => RegistryRead.NotFound;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.NotFound;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.NotFound;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.NotFound;
    }

    /// <summary>Refuses every read: the machine-side half of the guard above.</summary>
    private sealed class RefusingRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) =>
            RegistryRead.AccessDenied;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.AccessDenied;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.AccessDenied;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.AccessDenied;
    }
}
