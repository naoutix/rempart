namespace Rempart.Core.Providers;

/// <summary>
/// A WMI instance reduced to its scalar properties, rendered as text.
///
/// The rule engine compares strings; stronger typing would add nothing and would force
/// each rule to know the CIM type of the property it queries.
/// </summary>
public sealed record WmiInstance(IReadOnlyDictionary<string, string> Properties)
{
    public string? Find(string property) =>
        Properties.TryGetValue(property, out var value) ? value : null;
}

public sealed record WmiRead(
    ReadStatus Status,
    IReadOnlyList<WmiInstance> Instances,

    /// <summary>
    /// Failure reason, when the failure is not a genuine access denial.
    ///
    /// An earlier version returned "access denied" for every failure, which made a bug
    /// indistinguishable from missing privileges — and did lead to a wrong diagnosis.
    /// Internal failures must be visible.
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly WmiRead AccessDenied = new(ReadStatus.AccessDenied, []);
    public static readonly WmiRead NotFound = new(ReadStatus.NotFound, []);

    public static WmiRead Found(IReadOnlyList<WmiInstance> instances) =>
        new(ReadStatus.Found, instances);

    /// <summary>
    /// The query was attempted, did not complete, and was not denied — a repository that
    /// stopped serving, a third-party provider faulting. <see cref="ReadStatus.Failed"/> since
    /// #177; it spelled itself <see cref="ReadStatus.AccessDenied"/> before, and what kept the
    /// answer right was <see cref="Diagnostic"/> being null for a denial and written here.
    /// That convention still holds and is still what <c>Finding.WmiGap</c> reads, but it is no
    /// longer the only thing standing between a faulting provider and « relancer en
    /// administrateur ».
    /// </summary>
    public static WmiRead Failed(string reason) =>
        new(ReadStatus.Failed, [], reason);

    /// <summary>
    /// What was read, and the walk that did not reach the end. Same shape as
    /// <see cref="ListeningPortRead.Partial"/> and <see cref="ScheduledTaskRead.Partial"/>,
    /// for the same reason: what arrived stays in the inventory and the gap is named beside
    /// it.
    ///
    /// <para>
    /// A WMI enumeration is not one call. <c>IEnumWbemClassObject::Next</c> is asked for one
    /// object at a time and can fail on the tenth after nine successes — a third-party
    /// provider faulting, a repository going bad underneath, a call cancelled. Handing the
    /// nine over as <see cref="Found"/> presented a truncated list as the machine's whole
    /// inventory; dropping them would lose nine drivers because the tenth did not come.
    /// </para>
    ///
    /// <para>
    /// <see cref="ReadStatus.Failed"/>, like <see cref="Failed"/> beside it: <c>Partial</c>
    /// says how much came back and never why the rest did not, so the status has to, and on
    /// this channel a walk that broke partway is never a denial — <c>LiveWmiProvider.Classify</c>
    /// sends the three refusal HRESULTs to <see cref="AccessDenied"/> before anything gets
    /// here. The reason is composed by the caller, which is the only place that knows which
    /// class stopped answering and on which code.
    /// </para>
    /// </summary>
    public static WmiRead Partial(IReadOnlyList<WmiInstance> instances, string reason) =>
        new(ReadStatus.Failed, instances, reason);
}

/// <summary>
/// Queries WMI. Still the only way to establish some states that neither the registry
/// nor the Win32 APIs expose: effective volume encryption, current Defender state.
///
/// Most of these namespaces require elevation. A denial must map to "not verifiable",
/// never to non-compliance: the scan could not look, which says nothing about the
/// machine.
/// </summary>
public interface IWmiProvider
{
    /// <param name="namespacePath">For example <c>root\CIMV2\Security\MicrosoftVolumeEncryption</c>.</param>
    /// <param name="className">Class to enumerate.</param>
    /// <param name="properties">
    /// Properties to read, named by the caller. Enumerating them would require a
    /// SAFEARRAY, which AOT-compatible interop cannot express — and a rule knows which
    /// property it queries anyway.
    /// </param>
    WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties);
}
