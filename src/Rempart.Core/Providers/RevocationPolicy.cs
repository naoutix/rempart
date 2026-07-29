namespace Rempart.Core.Providers;

/// <summary>
/// The revocation regime every <c>WinVerifyTrust</c> call in this project runs under, and
/// what to conclude when a certificate's revocation status could not be established.
///
/// <para>
/// <b>Why this is a decision and not a constant at the call site.</b> Authenticode
/// verification validates the whole chain, revocation included, and revocation lives on a
/// CRL distribution point or an OCSP responder — on the network. With
/// <c>dwProvFlags</c> left at zero, <c>wintrust.dll</c> fetches them, at CryptoAPI's own
/// timeouts, once per binary the scan reports on: every autostart entry, every driver,
/// every running process, every scheduled-task target. Measured on the machine this was
/// written on, one third-party binary cost 391 ms that way and 3 ms from the cache.
/// </para>
///
/// <para>
/// That is outbound traffic on a path nobody opted into, which ADR-001 D9 does not allow:
/// the tool runs entirely offline, and every external enrichment — VirusTotal, the PAC
/// fetch, the DNS probe — is explicit and per-run. Revocation checking is not dropped, it
/// is restricted to what the machine already knows, which is what
/// <c>WTD_CACHE_ONLY_URL_RETRIEVAL</c> means.
/// </para>
///
/// <para>
/// <b>The consequence that had to be handled with it.</b> A cache that holds nothing about
/// a chain answers « I do not know », and CryptoAPI says so with an HRESULT of its own.
/// Reading that as a verdict on the file would accuse every binary on a machine that has
/// never been online — the machine this tool was built for. Hence
/// <see cref="CouldNotBeEstablished"/>, kept next to the flag that makes the case ordinary
/// rather than exotic.
/// </para>
/// </summary>
public static class RevocationPolicy
{
    /// <summary>
    /// <c>WTD_CACHE_ONLY_URL_RETRIEVAL</c>, from <c>wintrust.h</c>, where the value carries
    /// the comment « affects CRL retrieval and AIA retrieval » — both of the two ways a
    /// chain reaches out.
    /// </summary>
    private const uint CacheOnlyUrlRetrieval = 0x00001000;

    /// <summary>
    /// The <c>dwProvFlags</c> of every <c>WINTRUST_DATA</c> the project builds. One name,
    /// so that a third verification added later cannot quietly leave the field at its
    /// default of zero — which is the online regime.
    /// </summary>
    public const uint ProviderFlags = CacheOnlyUrlRetrieval;

    // « Revoked » and « not known to be revoked » are one hexadecimal digit apart:
    // 0x800B010C is CERT_E_REVOKED, 0x800B010E is CERT_E_REVOCATION_FAILURE. Read back from
    // certutil -error rather than from memory, because the two mean opposite things and the
    // pair below is the one that must never gain a member by accident.
    private const int CertRevocationFailure = unchecked((int)0x800B010E);
    private const int CryptNoRevocationCheck = unchecked((int)0x80092012);
    private const int CryptRevocationOffline = unchecked((int)0x80092013);

    /// <summary>
    /// Whether an HRESULT says the revocation check could not run, as opposed to saying the
    /// certificate was revoked.
    ///
    /// <para>
    /// The three codes here describe the checking, not the certificate: the process could
    /// not continue, no check was performed, the responder was unreachable.
    /// <c>CERT_E_REVOKED</c> and <c>CRYPT_E_REVOKED</c> are deliberately absent — those are
    /// the answer this whole verification exists to obtain, and they stay a failure of the
    /// file.
    /// </para>
    /// </summary>
    public static bool CouldNotBeEstablished(int hresult) =>
        hresult is CertRevocationFailure or CryptNoRevocationCheck or CryptRevocationOffline;
}
