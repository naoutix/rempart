namespace Rempart.Core.Providers;

public enum SignatureStatus
{
    /// <summary>Valid signature, trust chain verified.</summary>
    Valid,

    /// <summary>No signature.</summary>
    Unsigned,

    /// <summary>Signed, but verification fails — expired, revoked, or tampered.</summary>
    Invalid,

    /// <summary>The file does not exist at the given path.</summary>
    FileNotFound,

    /// <summary>Verification could not complete. Neither valid nor invalid.</summary>
    Unknown,
}

public sealed record FileSignature(
    SignatureStatus Status,
    string? Publisher = null,
    string? Sha256 = null);

/// <summary>
/// Verifies the Authenticode signature of a file.
///
/// This is the only way to distinguish a legitimate binary launched at startup from a
/// program planted there by a third party. A path and a name prove nothing: both are
/// trivial to imitate.
///
/// A verification that fails returns <see cref="SignatureStatus.Unknown"/>, never
/// <see cref="SignatureStatus.Unsigned"/>: conflating "could not verify" with "not
/// signed" would produce false alerts on the machines that are hardest to audit.
/// </summary>
public interface ISignatureProvider
{
    FileSignature Verify(string path);
}
