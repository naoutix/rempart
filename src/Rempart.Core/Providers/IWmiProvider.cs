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

    public static WmiRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);
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
