using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Updates;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// What the two WMI-backed inventories hand their collector, and what the collector makes
/// of it.
///
/// <para>
/// These two providers are a projection over <see cref="IWmiProvider"/> and nothing else, so
/// the WMI is a fake here and no machine state is involved. What is under test is the one
/// thing the projection can get wrong without any test noticing: whether the shape it hands
/// over still lets <see cref="Finding.WmiGap"/> tell a refused namespace from a repository
/// that stopped serving. That question is decided by a field, and a field is exactly what a
/// convenience default overwrites.
/// </para>
/// </summary>
public sealed class LiveDriverAndProcessProviderTests
{
    private sealed class AnsweringWmi(WmiRead read) : IWmiProvider
    {
        public WmiRead Query(string ns, string className, IReadOnlyList<string> properties) => read;
    }

    private static Finding DriverGap(WmiRead answer) =>
        Assert.Single(new LoadedDriversCollector(DriverBlocklist.Empty).Collect(
            new ProviderSet(
                new EmptyRegistry(), new FakeSystemInfo(),
                drivers: new LiveDriverProvider(new AnsweringWmi(answer)))));

    private static Finding ProcessGap(WmiRead answer) =>
        Assert.Single(new RunningProcessesCollector().Collect(
            new ProviderSet(
                new EmptyRegistry(), new FakeSystemInfo(),
                processes: new LiveProcessProvider(new AnsweringWmi(answer)))));

    /// <summary>
    /// The inversion #173 is about, on the channel that has a written contract for it.
    ///
    /// <para>
    /// <c>WmiRead</c> spells a denial as <c>AccessDenied</c> with <b>no</b> reason beside it —
    /// that is what <c>LiveWmiProvider.Classify</c> returns for the three denial HRESULTs, and
    /// the only reason <see cref="Finding.WmiGap"/> is allowed to exist. Both providers then
    /// filled that silence in with a sentence of their own before handing the read on, so the
    /// collector one layer up never saw a silent read and classified every refusal as a
    /// failure — while printing « relancer en administrateur » underneath it. The value and
    /// the sentence said opposite things in the same finding.
    /// </para>
    /// </summary>
    [Fact]
    public void A_namespace_that_refused_stays_a_refusal_through_the_projection()
    {
        Assert.Equal(AuditGap.Refused, DriverGap(WmiRead.AccessDenied).Gap);
        Assert.Equal(AuditGap.Refused, ProcessGap(WmiRead.AccessDenied).Gap);
    }

    /// <summary>
    /// The other half, which must keep answering the other way: a repository that faulted
    /// carries the code it faulted on, and no amount of rights re-serves it.
    /// </summary>
    [Fact]
    public void A_repository_that_failed_stays_a_failure_through_the_projection()
    {
        var failed = WmiRead.Failed("COM 0x8004100E : Win32_SystemDriver");

        Assert.Equal(AuditGap.Unreadable, DriverGap(failed).Gap);
        Assert.Equal(AuditGap.Unreadable, ProcessGap(failed).Gap);
    }

    /// <summary>
    /// The third state, which neither of the two collectors above filters out: they open on
    /// <c>Status != Found</c>, so an absent class reaches the same door. It carries no reason
    /// — <c>Classify</c> answers <c>WmiRead.NotFound</c> bare for the three "no such
    /// namespace / no such class" codes — and a rule reading the reason alone would call that
    /// silence a denial and send the reader to elevate over a class Windows does not have.
    /// </summary>
    [Fact]
    public void An_absent_class_is_not_a_refusal_either()
    {
        Assert.Equal(AuditGap.Unreadable, DriverGap(WmiRead.NotFound).Gap);
        Assert.Equal(AuditGap.Unreadable, ProcessGap(WmiRead.NotFound).Gap);
    }

    private sealed class EmptyRegistry : IRegistryProvider
    {
        public RegistryRead ReadValue(string keyPath, string valueName) => RegistryRead.NotFound;

        public ReadStatus KeyExists(string keyPath) => ReadStatus.NotFound;

        public RegistryValueList ListValues(string keyPath) => RegistryValueList.NotFound;

        public RegistrySubKeyList ListSubKeys(string keyPath) => RegistrySubKeyList.NotFound;
    }

    private sealed class FakeSystemInfo : ISystemInfoProvider
    {
        public SystemInfo Read() =>
            new("TEST", "10.0.26100", true, false, 4, 3600, "UEFI");
    }
}
