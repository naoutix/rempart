using System.Runtime.InteropServices;
using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real service control manager.
///
/// Three native calls and a two-step allocation protocol: an offset error in the
/// buffer reads would return a plausible but wrong state, which critical rules then
/// act on.
/// </summary>
public sealed class LiveServiceStateProviderTests
{
    private readonly LiveServiceStateProvider services = new();

    [Fact]
    public void Reads_a_service_windows_always_runs()
    {
        // The task scheduling service: present and started on any Windows machine
        // in working order.
        var read = services.Read("Schedule");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(ServiceState.Running, read.Info!.State);
    }

    [Fact]
    public void Reads_the_start_mode_as_a_known_value()
    {
        var read = services.Read("Schedule");

        // A wrong offset in the buffer would return "Unknown" permanently, and any
        // rule on the start mode would go silent without saying so.
        Assert.NotEqual(ServiceStartMode.Unknown, read.Info!.StartMode);
    }

    [Fact]
    public void A_service_that_does_not_exist_is_reported_absent_not_denied()
    {
        // The distinction drives different follow-ups: uninstalling an absent service
        // makes no sense, a denial calls for a retry as administrator.
        var read = services.Read("CeServiceNExistePasDuTout");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Null(read.Info);
    }

    [Fact]
    public void A_stopped_service_is_reported_stopped()
    {
        // RemoteRegistry is disabled by default on a workstation. If the test machine
        // has enabled it, at least check that the state is readable.
        var read = services.Read("RemoteRegistry");

        if (read.Status == ReadStatus.Found)
        {
            Assert.NotEqual(ServiceState.Unknown, read.Info!.State);
        }
    }

    /// <summary>
    /// A Win32 code the mapping has no verified opinion about. Synthesized, because none of
    /// these can be provoked on a healthy machine — an SCM that will not open, an RPC
    /// endpoint that is not there, a shutdown in progress — and the live checks above, which
    /// only ask that a well-known service answers, cannot tell any of them from a refusal.
    ///
    /// <para>
    /// Every one of them used to come back <c>ServiceRead.AccessDenied</c> with no
    /// diagnostic, so every <c>type: service</c> rule at once landed under « non vérifiable —
    /// accès refusé » and the report had nothing to say against re-running elevated.
    /// </para>
    ///
    /// <para>
    /// The values are read from <c>winerror.h</c>, not from memory. Four of the six appear
    /// in the return table of one of the calls this provider makes; the two that do not —
    /// <c>RPC_S_SERVER_UNAVAILABLE</c> and <c>ERROR_SERVICE_DATABASE_LOCKED</c> — are the
    /// very case the default arm exists for, since three of those tables end on « others can
    /// be set by the registry functions that are called by the service control manager ».
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(1065)] // ERROR_DATABASE_DOES_NOT_EXIST — documented for OpenSCManager
    [InlineData(123)]  // ERROR_INVALID_NAME — documented for OpenService
    [InlineData(6)]    // ERROR_INVALID_HANDLE — documented for three of the four
    [InlineData(1115)] // ERROR_SHUTDOWN_IN_PROGRESS — documented for QueryServiceStatusEx
    [InlineData(1722)] // RPC_S_SERVER_UNAVAILABLE — in no table: the SCM is reached by RPC
    [InlineData(1055)] // ERROR_SERVICE_DATABASE_LOCKED — in no table either
    public void A_win32_failure_names_its_code_instead_of_claiming_a_denial(int error)
    {
        var read = LiveServiceStateProvider.Classify("OpenService", error);

        Assert.NotNull(read.Diagnostic);
        Assert.Contains($"{error}", read.Diagnostic, StringComparison.Ordinal);

        // The call that failed, not just the code: three of the four sites can produce
        // ERROR_ACCESS_DENIED's neighbours, and « laquelle » is half of what to search for.
        Assert.Contains("OpenService", read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The counterpart. Dropping this arm would turn a real denial into a failure, and
    /// « relancer en administrateur » would stop being said where it is the right advice.
    /// ERROR_ACCESS_DENIED is documented for all four calls and is the only code among them
    /// that means the scan lacks a right.
    /// </summary>
    [Fact]
    public void A_genuine_refusal_stays_a_refusal_without_a_diagnostic()
    {
        var read = LiveServiceStateProvider.Classify("OpenService", 5);

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.Null(read.Info);
    }

    /// <summary>
    /// Absence, not refusal — the one distinction this file already made, kept.
    /// </summary>
    [Fact]
    public void An_absent_service_is_absence_not_refusal()
    {
        var read = LiveServiceStateProvider.Classify("OpenService", 1060);

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Null(read.Diagnostic);
    }

    /// <summary>
    /// And absence only from the call that can establish it. This is the one arm of the
    /// mapping that does not answer <c>Unknown</c>: <c>NotFound</c> reaches
    /// <c>CheckReader.ReadService</c> as <c>Denied: false</c> with « absent » observed, so
    /// <c>RuleEvaluator</c> compares it and rules. For WIN-SVC-002 — <c>mpssvc</c>,
    /// <c>state equals running</c>, severity critical — « absent » is a critical
    /// <c>Fail</c>.
    ///
    /// <para>
    /// Reading 1060 from the other three would therefore turn a read that <em>failed</em>
    /// into a verdict against the machine, which is worse than the defect this file was
    /// opened to fix: there the failure borrowed a refusal and stayed out of the score, here
    /// it would borrow a fact. The three cannot mean it anyway — the SCM does not know the
    /// name yet when <c>OpenSCManager</c> answers, and both queries hold a handle to a
    /// service that was found. Their tables are the very ones that end on « others can be
    /// set by the registry functions that are called by the service control manager », so a
    /// 1060 from them is an unexplained code and has to surface as one.
    /// </para>
    ///
    /// <para>
    /// It stops borrowing the refusal here too, since #177: <c>ServiceRead.Failed</c> carries
    /// <see cref="ReadStatus.Failed"/>. Both « not an absence » and « not a refusal » are
    /// asserted below, the first being the one the paragraph above is about — it is the arm
    /// where a wrong reading becomes a critical <c>Fail</c> — and that the verdict is still
    /// <c>Unknown</c> is held one project over, by
    /// <c>ServiceCheckTests.A_failed_read_stays_unverifiable_and_says_what_failed</c>, which
    /// runs on the Linux job where <c>CheckReader</c> is reachable.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("OpenSCManager")]
    [InlineData("QueryServiceStatusEx")]
    [InlineData("QueryServiceConfig")]
    public void Absence_is_read_only_from_the_call_that_can_report_it(string api)
    {
        var read = LiveServiceStateProvider.Classify(api, 1060);

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.NotEqual(ReadStatus.NotFound, read.Status);
        Assert.NotEqual(ReadStatus.AccessDenied, read.Status);
        Assert.Null(read.Info);
        Assert.Contains("1060", read.Diagnostic!, StringComparison.Ordinal);
        Assert.Contains(api, read.Diagnostic!, StringComparison.Ordinal);
    }

    /// <summary>
    /// A call that failed while the thread's last error says nothing went wrong — the sizing
    /// step of <c>Allocate</c> succeeding against a null buffer, which its own documentation
    /// says cannot happen.
    ///
    /// <para>
    /// Without its own arm the code falls to the default one, and the report of a tool whose
    /// single rule is not to dress a failure as something else would carry « erreur Win32 0
    /// (L'opération a réussi.) » about a read that returned nothing. The assertion is on that
    /// rendering rather than on the replacement wording: what must not happen is the
    /// sentence Windows attaches to zero, and it arrives in the language of the machine.
    /// </para>
    /// </summary>
    [Fact]
    public void A_failure_that_reports_no_error_code_is_not_rendered_as_a_success()
    {
        var read = LiveServiceStateProvider.Classify("QueryServiceStatusEx", 0);

        Assert.Equal(ReadStatus.Failed, read.Status);
        Assert.Null(read.Info);
        Assert.NotNull(read.Diagnostic);
        Assert.Contains("QueryServiceStatusEx", read.Diagnostic, StringComparison.Ordinal);
        Assert.DoesNotContain("erreur Win32 0", read.Diagnostic, StringComparison.Ordinal);
        Assert.DoesNotContain(
            Marshal.GetPInvokeErrorMessage(0), read.Diagnostic, StringComparison.Ordinal);
    }

    /// <summary>
    /// The live half of the same promise: a service that answers carries no diagnostic, and
    /// one that is genuinely absent carries none either. A mapping that named a failure on
    /// every read would be just as wrong in the other direction.
    /// </summary>
    [Fact]
    public void A_read_that_succeeded_or_found_nothing_carries_no_diagnostic()
    {
        Assert.Null(services.Read("Schedule").Diagnostic);
        Assert.Null(services.Read("CeServiceNExistePasDuTout").Diagnostic);
    }

    [Fact]
    public void Repeated_reads_stay_consistent_and_do_not_exhaust_handles()
    {
        // Each read opens two native handles. A missing close is invisible on a single
        // call but exhausts the resources of a full scan.
        var first = services.Read("Schedule");

        for (var i = 0; i < 200; i++)
        {
            var read = services.Read("Schedule");
            Assert.Equal(first.Status, read.Status);
            Assert.Equal(first.Info!.State, read.Info!.State);
        }
    }
}
