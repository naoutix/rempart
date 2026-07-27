namespace Rempart.Core.Providers;

/// <summary>
/// Turns the two <c>WinVerifyTrust</c> results — the embedded HRESULT and the catalog
/// outcome — into the status the rest of the tool reasons about.
///
/// <para>
/// Pure, testable without Windows: the Windows layer does the interop and hands over what
/// it observed. That split is the whole point. Verifying a signature is irreducibly
/// <c>wintrust.dll</c>, but <b>deciding what the answer means</b> is arithmetic on
/// HRESULTs, and it is the half that decides a binary is sound — the half that had no
/// test at all, on either side of the line, because it lived inside a
/// <c>net10.0-windows</c> assembly the Linux job never compiles.
/// </para>
///
/// <para>
/// What rides on it: <c>SignatureLadder</c> turns <see cref="SignatureStatus.Unsigned"/>
/// into a <c>Suspicious</c> finding and <see cref="SignatureStatus.Unknown"/> into a
/// <c>Notable</c> one that says out loud « ce n'est pas un défaut du binaire ». One
/// accuses, the other reports a gap. Getting this mapping wrong does not crash anything;
/// it changes the verdict on every driver and every autostart entry of the machine.
/// </para>
/// </summary>
public static class AuthenticodeVerdict
{
    /// <summary>The file verified.</summary>
    public const int Ok = 0;

    // 0x800B0100 TRUST_E_NOSIGNATURE, 0x800B0003 TRUST_E_SUBJECT_FORM_UNKNOWN,
    // 0x800B0001 TRUST_E_PROVIDER_UNKNOWN.
    private const int TrustNoSignature = unchecked((int)0x800B0100);
    private const int TrustSubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustProviderUnknown = unchecked((int)0x800B0001);

    /// <summary>
    /// Whether the embedded check found nothing to judge, which is the only reason to go
    /// looking in a catalog.
    ///
    /// <para>
    /// Most Windows binaries land here: their signature lives in a <c>.cat</c> file
    /// indexed by hash, not in the file. Treating these three HRESULTs as a verdict
    /// rather than as a redirection would classify <c>cmd.exe</c> as unsigned, along with
    /// almost every autostart entry of a healthy install.
    /// </para>
    /// </summary>
    public static bool HasNoEmbeddedSignature(int embedded) =>
        embedded is TrustNoSignature or TrustSubjectFormUnknown or TrustProviderUnknown;

    /// <summary>
    /// What the HRESULT of a catalog's own <c>WinVerifyTrust</c> means, once a catalog
    /// covering the file has been found.
    ///
    /// <para>
    /// Success is the exact zero. An HRESULT is a bit field whose sign bit carries the
    /// failure, so a test written as "not negative", or as "below some threshold", would
    /// let a warning-level status through as a signature that held. Kept here rather than
    /// at the call site because it is arithmetic on a number, and arithmetic is the half
    /// of this check the Linux job can hold to account.
    /// </para>
    /// </summary>
    public static CatalogOutcome FromCatalogHResult(int hresult) =>
        hresult == Ok ? CatalogOutcome.Verified : CatalogOutcome.Refused;

    /// <summary>
    /// The status a file gets, from the embedded HRESULT and the catalog outcome.
    /// </summary>
    /// <param name="embedded">What <c>WinVerifyTrust</c> said about the file itself.</param>
    /// <param name="catalog">
    /// What the catalog lookup said. Only consulted when
    /// <see cref="HasNoEmbeddedSignature"/> holds, so the caller may pass
    /// <see cref="CatalogOutcome.NotAsked"/> whenever it did not run the lookup.
    /// </param>
    public static SignatureStatus Judge(int embedded, CatalogOutcome catalog)
    {
        if (embedded == Ok)
        {
            return SignatureStatus.Valid;
        }

        // Signed, and the chain does not hold: expired, revoked, or tampered with. Not a
        // reason to go to the catalog — the file answered for itself, badly.
        if (!HasNoEmbeddedSignature(embedded))
        {
            return SignatureStatus.Invalid;
        }

        return catalog switch
        {
            CatalogOutcome.Verified => SignatureStatus.Valid,

            // The store answered and no catalog references this file, so it is signed in
            // no way at all. This is the only branch that may accuse.
            CatalogOutcome.NotCatalogued => SignatureStatus.Unsigned,

            // A catalog covers it and refuses it.
            CatalogOutcome.Refused => SignatureStatus.Invalid,

            // Unaskable, and NotAsked on a file that needed asking: nobody answered, so
            // there is nothing to conclude. Until DET-CATALOGUE-MUET was closed these
            // arrived as the same null as NotCatalogued and came out Unsigned, which
            // SignatureLadder turns into a Suspicious finding — a driver the scan could
            // not open was accused of being unsigned instead of reported as unverifiable,
            // and that happened most on the machines that are hardest to audit.
            _ => SignatureStatus.Unknown,
        };
    }

    /// <summary>
    /// Whether the publisher name is worth reading off the file's embedded certificate.
    ///
    /// <para>
    /// It proves nothing on its own — <c>WinVerifyTrust</c> decides — but it is what makes
    /// a finding readable, so it is read whenever the file carries a certificate to read:
    /// a signature that held, or one that did not. It is skipped when the verdict came
    /// from the absence of a catalog or from a catalog that refused, because there is no
    /// embedded certificate in that case and the answer would be null anyway.
    /// </para>
    ///
    /// <para>
    /// The one case that looks inconsistent and is deliberate: a catalog-signed file
    /// (<paramref name="catalog"/> is <see cref="CatalogOutcome.Verified"/>) has no
    /// embedded certificate either, and the read still happens. It yields null,
    /// harmlessly. Frozen as it stands rather than tidied, because the extraction that
    /// brought this here was meant to prove it changed nothing.
    /// </para>
    /// </summary>
    public static bool ReadsPublisher(int embedded, CatalogOutcome catalog) =>
        !HasNoEmbeddedSignature(embedded) || catalog == CatalogOutcome.Verified;
}
