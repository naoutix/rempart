using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// The half of signature verification that is arithmetic rather than interop.
///
/// <para>
/// DET-WINDOWS-TESTS named <c>CatalogSignature</c> the most bothersome of its seven
/// untested providers, because catalog verification is what decides a binary is sound.
/// Most of that file is irreducibly <c>wintrust.dll</c> and can only be exercised on
/// Windows. The decision it feeds is not, and it now lives in Core — so these run on the
/// Linux job, which is the best available outcome for a check nothing was watching.
/// </para>
///
/// <para>
/// The HRESULTs are written out as literals here rather than borrowed from the code under
/// test. A test that reused the same constant would agree with the implementation by
/// construction and prove nothing about the value being right — the mistake ADR-005
/// recorded when the first dispatch guard compared two lists written by the same hand.
/// These four numbers come from <c>winerror.h</c>.
/// </para>
/// </summary>
public sealed class AuthenticodeVerdictTests
{
    private const int Ok = 0;
    private const int TrustNoSignature = unchecked((int)0x800B0100);
    private const int TrustSubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustProviderUnknown = unchecked((int)0x800B0001);

    /// <summary>An HRESULT that is a real failure, not a redirection to the catalog.</summary>
    private const int CertExpired = unchecked((int)0x800B0101);

    [Fact]
    public void A_valid_embedded_signature_settles_it_without_a_catalog()
    {
        // The catalog argument is deliberately the least favourable one: if it were
        // consulted at all, this would come back Unknown.
        Assert.Equal(SignatureStatus.Valid,
            AuthenticodeVerdict.Judge(Ok, CatalogOutcome.NotAsked));
    }

    [Theory]
    [InlineData(TrustNoSignature)]
    [InlineData(TrustSubjectFormUnknown)]
    [InlineData(TrustProviderUnknown)]
    public void The_three_redirections_send_the_file_to_the_catalog(int embedded)
    {
        Assert.True(AuthenticodeVerdict.HasNoEmbeddedSignature(embedded));

        // The point of the redirection: cmd.exe carries no embedded signature and must
        // not come out unsigned. Same three inputs, four different verdicts, decided only
        // by what the catalog answered.
        Assert.Equal(SignatureStatus.Valid,
            AuthenticodeVerdict.Judge(embedded, CatalogOutcome.Verified));
        Assert.Equal(SignatureStatus.Unsigned,
            AuthenticodeVerdict.Judge(embedded, CatalogOutcome.NotCatalogued));
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(embedded, CatalogOutcome.Refused));
        Assert.Equal(SignatureStatus.Unknown,
            AuthenticodeVerdict.Judge(embedded, CatalogOutcome.Unaskable));
    }

    [Fact]
    public void A_broken_embedded_signature_is_invalid_and_never_reaches_the_catalog()
    {
        Assert.False(AuthenticodeVerdict.HasNoEmbeddedSignature(CertExpired));

        // Whatever the catalog would have said, including that it validates: a file that
        // answered for itself badly is not rescued by a catalog. Passing Verified here
        // would flip the verdict if the order of the two checks were ever swapped.
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(CertExpired, CatalogOutcome.NotAsked));
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(CertExpired, CatalogOutcome.Verified));
    }

    /// <summary>
    /// Success is only the exact zero. An HRESULT is a bit field whose sign bit carries
    /// the failure, so a check written as "not negative" or "less than some threshold"
    /// would let a warning-level status through as a valid signature.
    /// </summary>
    [Fact]
    public void Only_zero_counts_as_verified()
    {
        Assert.Equal(CatalogOutcome.Verified, AuthenticodeVerdict.FromCatalogHResult(Ok));

        Assert.Equal(CatalogOutcome.Refused, AuthenticodeVerdict.FromCatalogHResult(1));
        Assert.Equal(CatalogOutcome.Refused,
            AuthenticodeVerdict.FromCatalogHResult(unchecked((int)0x80092003)));

        // And through to the verdict, because that is what the scan reads: a catalog that
        // covers the file and refuses it is an accusation about the file, distinct from a
        // store that could not be asked.
        Assert.Equal(SignatureStatus.Invalid, AuthenticodeVerdict.Judge(
            TrustNoSignature, AuthenticodeVerdict.FromCatalogHResult(1)));
    }

    /// <summary>
    /// The defect DET-CATALOGUE-MUET recorded, now asserted the other way round.
    ///
    /// <para>
    /// <b>What this used to say.</b> The Windows layer answered <c>int?</c>, and its
    /// <c>null</c> stood for two different things: « no catalog references this file »,
    /// which is an answer, and « the catalog API could not be asked » — a context it
    /// failed to acquire, a hash it could not compute, a file it could not open — which is
    /// not. Both came out <c>Unsigned</c>, and the test that lived here was named
    /// <c>An_unaskable_catalog_is_reported_as_unsigned_rather_than_unverifiable</c>: it
    /// froze the collapse on purpose, so that undoing it would have to be a decision taken
    /// here rather than a side effect noticed later.
    /// </para>
    ///
    /// <para>
    /// It was the exact shape of DET-WMI-MUET one layer down, and on the wrong side of it:
    /// the other occurrences hid a breakdown, this one invented an accusation. The two
    /// severities asserted below are the whole difference between a false positive and a
    /// stated gap, and they are asserted here rather than left to inference because
    /// nothing else in this file would notice if <c>SignatureLadder</c> started treating
    /// <c>Unknown</c> like <c>Unsigned</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void An_unaskable_catalog_is_reported_as_unverifiable_rather_than_unsigned()
    {
        Assert.Equal(SignatureStatus.Unknown,
            AuthenticodeVerdict.Judge(TrustNoSignature, CatalogOutcome.Unaskable));

        // And the answer that legitimately accuses is untouched: a store that answered and
        // found no catalog still yields Unsigned. Without this line the fix could have been
        // « never accuse anything », which would be the opposite failure.
        Assert.Equal(SignatureStatus.Unsigned,
            AuthenticodeVerdict.Judge(TrustNoSignature, CatalogOutcome.NotCatalogued));

        Assert.Equal(FindingSeverity.Suspicious,
            SignatureLadder.Judge(@"C:\Windows\System32\drivers\x.sys",
                new FixedSignature(SignatureStatus.Unsigned)).Severity);

        Assert.Equal(FindingSeverity.Notable,
            SignatureLadder.Judge(@"C:\Windows\System32\drivers\x.sys",
                new FixedSignature(SignatureStatus.Unknown)).Severity);
    }

    /// <summary>
    /// A catalog lookup that was never run is not a lookup that found nothing.
    ///
    /// <para>
    /// <see cref="CatalogOutcome.NotAsked"/> is the default value of the enum, so this is
    /// what a caller that forgets to fill the argument in produces. It must land on
    /// <c>Unknown</c>: mapping the default onto <c>NotCatalogued</c> would turn a wiring
    /// mistake into an accusation against every catalog-signed binary on the machine —
    /// which is precisely how the defect this file records came about in the first place.
    /// </para>
    /// </summary>
    [Fact]
    public void A_lookup_that_never_ran_concludes_nothing()
    {
        Assert.Equal(CatalogOutcome.NotAsked, default);

        Assert.Equal(SignatureStatus.Unknown,
            AuthenticodeVerdict.Judge(TrustNoSignature, default));
    }

    /// <summary>
    /// The publisher read follows the file, not the verdict: it is skipped exactly when
    /// there is no embedded certificate to read and the answer would be null anyway.
    /// </summary>
    [Fact]
    public void The_publisher_is_read_only_where_a_certificate_could_be()
    {
        Assert.True(AuthenticodeVerdict.ReadsPublisher(Ok, CatalogOutcome.NotAsked));
        Assert.True(AuthenticodeVerdict.ReadsPublisher(CertExpired, CatalogOutcome.NotAsked));

        // Catalog-signed: no embedded certificate, and the read happens anyway. Frozen as
        // it stands — see the remark on ReadsPublisher.
        Assert.True(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, CatalogOutcome.Verified));

        Assert.False(
            AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, CatalogOutcome.NotCatalogued));
        Assert.False(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, CatalogOutcome.Refused));
        Assert.False(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, CatalogOutcome.Unaskable));
    }

    /// <summary>A signature provider that answers the same thing whatever it is asked.</summary>
    private sealed class FixedSignature(SignatureStatus status) : ISignatureProvider
    {
        public FileSignature Verify(string path) => new(status);
    }
}
