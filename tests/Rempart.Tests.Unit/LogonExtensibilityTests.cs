using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

public class LogonExtensibilityTests
{
    private const string Winlogon =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string Windows =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    private static IReadOnlyList<Finding> Collect(
        FakeRegistryProvider registry, ISignatureProvider signatures) =>
        new LogonExtensibilityCollector().Collect(new ProviderSet(
            registry, new FakeSystemInfoProvider(), signatures: signatures));

    /// <summary>
    /// The default configuration: Userinit and Shell point to their expected programs,
    /// both signed. Nothing to review — otherwise the report would cry wolf on every
    /// scan of a healthy machine.
    /// </summary>
    [Fact]
    public void The_default_userinit_and_shell_are_benign()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,")
            .WithText(Winlogon, "Shell", @"C:\W\explorer.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\W\explorer.exe", SignatureStatus.Valid);

        Assert.All(Collect(registry, signatures), f => Assert.Equal(FindingSeverity.Benign, f.Severity));
    }

    /// <summary>
    /// An executable appended to Userinit is flagged even when signed: what matters is
    /// the addition at this location, a classic persistence technique.
    /// </summary>
    [Fact]
    public void An_extra_userinit_entry_is_notable_even_when_signed()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,C:\evil\hook.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\evil\hook.exe", SignatureStatus.Valid);

        var extra = Collect(registry, signatures).Single(f => f.Target.Contains("hook"));

        Assert.Equal(FindingSeverity.Notable, extra.Severity);
        Assert.Contains("inattendue", string.Join(" ", extra.Reasons));
    }

    /// <summary>
    /// The same addition, unsigned, accumulates both reasons and stays at least
    /// suspicious: the signature can only aggravate, never lower.
    /// </summary>
    [Fact]
    public void An_extra_unsigned_userinit_entry_is_suspicious()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,C:\evil\hook.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid)
            .With(@"C:\evil\hook.exe", SignatureStatus.Unsigned);

        var extra = Collect(registry, signatures).Single(f => f.Target.Contains("hook"));

        Assert.Equal(FindingSeverity.Suspicious, extra.Severity);
    }

    /// <summary>
    /// A shell that is not <c>explorer.exe</c> is flagged — replacing it hijacks the
    /// logon sequence.
    /// </summary>
    [Fact]
    public void A_shell_other_than_explorer_is_flagged()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Shell", @"C:\evil\shell.exe");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\evil\shell.exe", SignatureStatus.Valid);

        Assert.Equal(FindingSeverity.Notable, Assert.Single(Collect(registry, signatures)).Severity);
    }

    /// <summary>
    /// A DLL in AppInit_DLLs is notable regardless of its signature: the mechanism
    /// injects into every GUI process and no longer has any place on a modern
    /// machine.
    /// </summary>
    [Fact]
    public void A_present_appinit_dll_is_notable_even_when_signed()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Windows, "AppInit_DLLs", @"C:\legit\hook.dll");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\legit\hook.dll", SignatureStatus.Valid);

        var finding = Assert.Single(Collect(registry, signatures));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("AppInit", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// An empty AppInit_DLLs — the normal case — produces no finding. The absence of a
    /// value is a healthy state, not a gap.
    /// </summary>
    [Fact]
    public void An_empty_appinit_produces_no_finding()
    {
        var registry = new FakeRegistryProvider()
            .WithText(Winlogon, "Userinit", @"C:\W\system32\userinit.exe,");

        var signatures = new FakeSignatureProvider()
            .With(@"C:\W\system32\userinit.exe", SignatureStatus.Valid);

        // Only Userinit is present: no AppInit finding.
        Assert.DoesNotContain(Collect(registry, signatures), f => f.Source == "AppInit_DLLs");
    }
}
