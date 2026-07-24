using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against real binaries. Authenticode verification is what distinguishes a legitimate
/// program launched at startup from an executable dropped there by a third party: a
/// path and a name are trivial to imitate, a signature is not.
/// </summary>
public sealed class LiveSignatureProviderTests
{
    private readonly LiveSignatureProvider signatures = new();

    [Fact]
    public void A_windows_binary_verifies_as_valid()
    {
        var result = signatures.Verify(Path.Combine(
            Environment.SystemDirectory, "kernel32.dll"));

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.NotNull(result.Sha256);
    }

    [Theory]
    [InlineData("cmd.exe")]
    [InlineData("notepad.exe")]
    [InlineData("SecurityHealthSystray.exe")]
    public void A_catalog_signed_binary_verifies_as_valid(string name)
    {
        // The important test. These binaries carry no embedded signature: theirs lives
        // in a separate .cat catalog. A verification that only examines the file
        // reports them as unsigned -- and then classifies nearly every automatic
        // startup entry of a healthy Windows as suspect.
        //
        // The first version did exactly that, which blocked its release.
        var path = Path.Combine(Environment.SystemDirectory, name);

        if (!File.Exists(path))
        {
            return;
        }

        Assert.Equal(SignatureStatus.Valid, signatures.Verify(path).Status);
    }

    [Fact]
    public void A_catalog_signed_binary_has_no_embedded_publisher()
    {
        // System binaries are catalog-signed, not signed with an embedded certificate:
        // WinVerifyTrust validates them, but there is nothing to read in the file. The
        // publisher therefore stays populated for third-party binaries, which almost
        // always carry an embedded signature -- and those are the ones that matter in
        // an enumeration of automatic startup entries.
        var result = signatures.Verify(Path.Combine(
            Environment.SystemDirectory, "kernel32.dll"));

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.Null(result.Publisher);
    }

    [Fact]
    public void An_unsigned_file_is_reported_unsigned_not_unknown()
    {
        // The whole finding rests on this distinction: "not signed" is a fact,
        // "could not verify" is a gap.
        var path = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

        try
        {
            Assert.Equal(SignatureStatus.Unsigned, signatures.Verify(path).Status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_missing_file_is_distinguished_from_an_unsigned_one()
    {
        // A startup entry pointing to a missing file is itself a finding: leftover
        // from an uninstall, or the target of a future hijack.
        Assert.Equal(SignatureStatus.FileNotFound,
            signatures.Verify(@"C:\CeFichierNExistePas\rien.exe").Status);
    }

    [Fact]
    public void The_hash_is_stable_across_reads()
    {
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        Assert.Equal(signatures.Verify(path).Sha256, signatures.Verify(path).Sha256);
    }

    [Fact]
    public void Repeated_verifications_do_not_exhaust_state()
    {
        // WinVerifyTrust allocates state that only a second call releases. Forgetting
        // it is invisible on a single file but exhausts the full enumeration of
        // automatic startup entries.
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        for (var i = 0; i < 60; i++)
        {
            Assert.Equal(SignatureStatus.Valid, signatures.Verify(path).Status);
        }
    }
}
