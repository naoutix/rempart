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
        // The catalog argument is deliberately absurd: if it were consulted at all, this
        // would come back Unsigned.
        Assert.Equal(SignatureStatus.Valid, AuthenticodeVerdict.Judge(Ok, catalog: null));
    }

    [Theory]
    [InlineData(TrustNoSignature)]
    [InlineData(TrustSubjectFormUnknown)]
    [InlineData(TrustProviderUnknown)]
    public void The_three_redirections_send_the_file_to_the_catalog(int embedded)
    {
        Assert.True(AuthenticodeVerdict.HasNoEmbeddedSignature(embedded));

        // The point of the redirection: cmd.exe carries no embedded signature and must
        // not come out unsigned. Same three inputs, opposite verdicts, decided only by
        // what the catalog answered.
        Assert.Equal(SignatureStatus.Valid, AuthenticodeVerdict.Judge(embedded, catalog: Ok));
        Assert.Equal(SignatureStatus.Unsigned, AuthenticodeVerdict.Judge(embedded, catalog: null));
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(embedded, catalog: CertExpired));
    }

    [Fact]
    public void A_broken_embedded_signature_is_invalid_and_never_reaches_the_catalog()
    {
        Assert.False(AuthenticodeVerdict.HasNoEmbeddedSignature(CertExpired));

        // Whatever the catalog would have said, including that it validates: a file that
        // answered for itself badly is not rescued by a catalog. Passing Ok here would
        // flip the verdict if the order of the two checks were ever swapped.
        Assert.Equal(SignatureStatus.Invalid, AuthenticodeVerdict.Judge(CertExpired, catalog: null));
        Assert.Equal(SignatureStatus.Invalid, AuthenticodeVerdict.Judge(CertExpired, catalog: Ok));
    }

    /// <summary>
    /// Success is only the exact zero. An HRESULT is a bit field whose sign bit carries
    /// the failure, so a check written as "not negative" or "less than some threshold"
    /// would let a warning-level status through as a valid signature.
    /// </summary>
    [Fact]
    public void Only_zero_counts_as_verified()
    {
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(TrustNoSignature, catalog: 1));
        Assert.Equal(SignatureStatus.Invalid,
            AuthenticodeVerdict.Judge(TrustNoSignature, catalog: unchecked((int)0x80092003)));
    }

    /// <summary>
    /// The defect this extraction found and deliberately did not fix, recorded as
    /// DET-CATALOGUE-MUET.
    ///
    /// <para>
    /// The Windows layer answers <c>null</c> for two different things: « no catalog
    /// references this file », which is an answer, and « the catalog API could not be
    /// asked » — a context it failed to acquire, a hash it could not compute, a file it
    /// could not open — which is not. This test asserts the collapse rather than the
    /// behaviour anyone would want, so that closing it has to come here and say so.
    /// </para>
    ///
    /// <para>
    /// It is the exact shape of DET-WMI-MUET, one layer down, and it lands on the wrong
    /// side: the chain below turns it into an accusation.
    /// </para>
    /// </summary>
    [Fact]
    public void An_unaskable_catalog_is_reported_as_unsigned_rather_than_unverifiable()
    {
        Assert.Equal(SignatureStatus.Unsigned,
            AuthenticodeVerdict.Judge(TrustNoSignature, catalog: null));

        // What that costs downstream, spelled out rather than left to inference: an
        // unreadable file is accused, where an honest « non vérifiable » would only be
        // reported. The two severities are the whole difference between a false positive
        // and a stated gap.
        Assert.Equal(FindingSeverity.Suspicious,
            SignatureLadder.Judge(@"C:\Windows\System32\drivers\x.sys",
                new FixedSignature(SignatureStatus.Unsigned)).Severity);

        Assert.Equal(FindingSeverity.Notable,
            SignatureLadder.Judge(@"C:\Windows\System32\drivers\x.sys",
                new FixedSignature(SignatureStatus.Unknown)).Severity);
    }

    /// <summary>
    /// The publisher read follows the file, not the verdict: it is skipped exactly when
    /// there is no embedded certificate to read and the answer would be null anyway.
    /// </summary>
    [Fact]
    public void The_publisher_is_read_only_where_a_certificate_could_be()
    {
        Assert.True(AuthenticodeVerdict.ReadsPublisher(Ok, catalog: null));
        Assert.True(AuthenticodeVerdict.ReadsPublisher(CertExpired, catalog: null));

        // Catalog-signed: no embedded certificate, and the read happens anyway. Frozen as
        // it stands — see the remark on ReadsPublisher.
        Assert.True(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, catalog: Ok));

        Assert.False(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, catalog: null));
        Assert.False(AuthenticodeVerdict.ReadsPublisher(TrustNoSignature, catalog: CertExpired));
    }

    /// <summary>A signature provider that answers the same thing whatever it is asked.</summary>
    private sealed class FixedSignature(SignatureStatus status) : ISignatureProvider
    {
        public FileSignature Verify(string path) => new(status);
    }
}
