using Rempart.Core.Providers;
using Rempart.Windows;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// Against the real catalog store. The half of <c>CatalogSignature</c> that could not
/// descend into Core: acquiring a context, hashing a file through
/// <c>CryptCATAdminCalcHashFromFileHandle2</c>, finding the catalog that indexes that
/// hash, and validating it. That is irreducibly <c>wintrust.dll</c>, and it is the
/// mechanism that decides <c>cmd.exe</c> is a legitimate binary.
///
/// <para>
/// DET-WINDOWS-TESTS calls this the most bothersome of its seven untested providers, for
/// a reason visible in the signature of every call below: these are <c>LibraryImport</c>
/// declarations whose structs are walked by pointer. A wrong field offset does not
/// crash — it returns a plausible and wrong answer, and the whole tool is downstream of
/// that answer.
/// </para>
///
/// <para>
/// <b>These tests judge the interop, not the runner's catalog store.</b> Same discipline
/// as <c>LiveWmiProviderTests</c>, and for the same reason recorded as DET-WMI-FLAKY: a
/// shared runner that answers nothing must not turn a build red on a branch that changed
/// no C#. So each check first asks whether the catalog subsystem answered at all, says on
/// the test output when it did not, and only then holds it to account. What must never be
/// tolerated is the other failure — the API answering and the decoding getting it wrong.
/// </para>
/// </summary>
public sealed class CatalogSignatureTests(ITestOutputHelper output)
{
    /// <summary>
    /// Files every Windows installation carries, all shipped by Microsoft and therefore
    /// described by a system catalog. Several rather than one: a single hard-coded path
    /// makes the suite depend on one build's inventory, and this list only has to yield
    /// one survivor.
    ///
    /// <para>
    /// Hard-coded under <c>C:\Windows</c> on purpose, exactly as <c>WindowsPaths</c> is:
    /// these are paths on the machine running the test, and a machine whose Windows lives
    /// elsewhere simply drops them at the <c>File.Exists</c> filter below.
    /// </para>
    /// </summary>
    private static readonly string[] SystemBinaries =
    [
        @"C:\Windows\System32\kernel32.dll",
        @"C:\Windows\System32\advapi32.dll",
        @"C:\Windows\System32\cmd.exe",
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\System32\drivers\ACPI.sys",
    ];

    /// <summary>
    /// The one check in this class that refuses to skip, and the reason the others may.
    ///
    /// <para>
    /// Every other test here probes first and returns quietly when the catalog subsystem
    /// says nothing — the discipline DET-WMI-FLAKY established, so that a shared runner
    /// does not redden a pull request that touched no C#. Applied to all five, that
    /// discipline produces exactly the failure this repository keeps meeting: kill the
    /// interop entirely and the whole class goes green, having concluded nothing.
    /// </para>
    ///
    /// <para>
    /// So this one applies the other half of the doctrine, the one DET-WMI-MUET settled:
    /// <b>zero is not an answer when zero cannot be true.</b> On any Windows install,
    /// System32 binaries are covered by catalogs — that is how Windows ships them. None
    /// of five being covered is not a quiet machine, it is a dead subsystem, and a dead
    /// subsystem turns every catalog-signed binary on the audited machine into
    /// <c>Unsigned</c>, then into <c>Suspicious</c>. An audit that cries wolf over
    /// <c>kernel32.dll</c> is an audit nobody finishes reading.
    /// </para>
    /// </summary>
    [Fact]
    public void The_catalog_store_answers_at_all()
    {
        var present = SystemBinaries.Where(File.Exists).ToList();

        Assert.True(present.Count > 0,
            "Aucun des binaires système cherchés n'est présent : cette machine n'a pas la "
            + "disposition attendue, le contrôle ne peut rien conclure.");

        var covered = present.Where(path => CatalogSignature.Verify(path) is not null).ToList();

        Assert.True(covered.Count > 0,
            $"Le magasin de catalogues n'a répondu pour aucun des {present.Count} binaires "
            + "système présents. Ce n'est pas une machine sans catalogue — il n'en existe "
            + "pas — c'est le sous-système qui ne répond plus. Tout binaire signé par "
            + "catalogue sera alors rendu « non signé », donc « suspect ».");
    }

    /// <summary>
    /// The system binaries a catalog actually covers on this machine, or an empty list if
    /// the catalog subsystem is not answering — in which case nothing below can conclude
    /// anything and says so rather than passing quietly.
    ///
    /// <para>
    /// Skipping is safe here only because
    /// <see cref="The_catalog_store_answers_at_all"/> refuses to: it is what tells the
    /// difference between "this machine has nothing to say" and "this machine cannot
    /// speak".
    /// </para>
    /// </summary>
    private IReadOnlyList<string> Catalogued(string reason)
    {
        var present = SystemBinaries.Where(File.Exists).ToList();
        var covered = present.Where(path => CatalogSignature.Verify(path) is not null).ToList();

        if (covered.Count > 0)
        {
            return covered;
        }

        output.WriteLine(
            $"Le magasin de catalogues n'a répondu pour aucun binaire système sur cette "
            + $"machine ({present.Count} fichier(s) présent(s) sur {SystemBinaries.Length} "
            + $"cherché(s)). Contrôle non exécuté : {reason}");

        return [];
    }

    /// <summary>
    /// A system binary its catalog actually validates, or null — announced on the test
    /// output, never returned in silence.
    ///
    /// <para>
    /// The second filter earns its own helper because it is a second way to skip, and it
    /// was found by mutation rather than by reading: shrinking the declared hash size by
    /// one byte in <c>WintrustCatalogInfo</c> leaves the store answering — so
    /// <see cref="Catalogued"/> is satisfied — while nothing validates any more. The
    /// checks below then had nothing to work on and returned quietly, which is precisely
    /// the vacuous green this class claims not to produce.
    /// </para>
    /// </summary>
    private string? FirstValid(string reason)
    {
        var covered = Catalogued(reason);
        if (covered.Count == 0)
        {
            return null;
        }

        if (covered.FirstOrDefault(path => CatalogSignature.Verify(path) == 0) is { } valid)
        {
            return valid;
        }

        output.WriteLine(
            $"Le magasin répond mais ne valide aucun des {covered.Count} binaire(s) "
            + $"système couvert(s). Contrôle non exécuté : {reason}");

        return null;
    }

    /// <summary>
    /// The claim the whole class exists for. Most Windows binaries carry no embedded
    /// signature, so a check that stopped at the file itself would report them unsigned —
    /// and <c>SignatureLadder</c> turns unsigned into a <c>Suspicious</c> finding. Getting
    /// this wrong does not break the scan; it accuses a healthy machine of running
    /// hundreds of untrusted binaries.
    /// </summary>
    [Fact]
    public void A_system_binary_is_covered_by_a_valid_catalog()
    {
        var covered = Catalogued("un binaire système validé par son catalogue");
        if (covered.Count == 0) { return; }

        var verdicts = covered.ToDictionary(path => path, CatalogSignature.Verify);

        Assert.True(verdicts.Values.Any(hresult => hresult == 0),
            "Aucun binaire système n'est validé par son catalogue, alors que le magasin "
            + "répond. La chaîne hachage → catalogue → WinVerifyTrust rend un HRESULT et "
            + "pas zéro : " + string.Join(", ", verdicts.Select(
                v => $"{v.Key} → 0x{v.Value:X8}")));
    }

    /// <summary>
    /// The other direction, and the one that makes the first mean something: a file no
    /// catalog describes must come back as « aucun catalogue », not as validated.
    ///
    /// <para>
    /// Probed like the positive checks, for the subtler reason <c>LiveWmiProviderTests</c>
    /// recorded: a dead catalog API answers null for everything, so without the probe this
    /// test passes exactly when the machine is broken. A green that survives the failure
    /// it should detect is worse than no test.
    /// </para>
    /// </summary>
    [Fact]
    public void A_fabricated_file_is_described_by_no_catalog()
    {
        if (Catalogued("un fichier fabriqué rendu sans catalogue").Count == 0) { return; }

        var fabricated = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(fabricated, Guid.NewGuid().ToByteArray());

        try
        {
            Assert.Null(CatalogSignature.Verify(fabricated));
        }
        finally
        {
            File.Delete(fabricated);
        }
    }

    /// <summary>
    /// The lookup is indexed by content, not by location: a byte-for-byte copy of a
    /// catalogued binary, sitting somewhere no catalog mentions, still verifies.
    ///
    /// <para>
    /// Worth pinning rather than assuming, because it is the property the whole design
    /// rests on — the hash is the key — and because it is also a limitation a reader
    /// should know about: <c>cmd.exe</c> copied into <c>%TEMP%</c> stays « signé ». What
    /// flags that case is <c>SignatureLadder</c>'s unusual-location rule, not the
    /// signature, and confusing the two would leave a real gap looking covered.
    /// </para>
    /// </summary>
    [Fact]
    public void The_lookup_follows_the_hash_and_not_the_path()
    {
        if (FirstValid("copie d'un binaire catalogué hors de son emplacement") is not { } valid)
        {
            return;
        }

        var copy = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}.dll");
        File.Copy(valid, copy);

        try
        {
            Assert.Equal(0, CatalogSignature.Verify(copy));
        }
        finally
        {
            File.Delete(copy);
        }
    }

    /// <summary>
    /// The whole ladder, end to end: the embedded check, the redirection to the catalog,
    /// and the judgement now living in Core. Each half is tested on its own — this holds
    /// them to the answer they produce together, which is the only one the scan sees.
    /// </summary>
    [Fact]
    public void A_catalogued_binary_is_reported_valid_and_a_fabricated_one_unsigned()
    {
        if (FirstValid("verdict complet sur un binaire système") is not { } valid)
        {
            return;
        }

        var signatures = new LiveSignatureProvider();

        Assert.Equal(SignatureStatus.Valid, signatures.Verify(valid).Status);

        var fabricated = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(fabricated, Guid.NewGuid().ToByteArray());

        try
        {
            var read = signatures.Verify(fabricated);

            Assert.Equal(SignatureStatus.Unsigned, read.Status);

            // The hash is computed whatever the verdict: it is what the LOLDrivers
            // blocklist is matched against, and a driver the signature check refuses is
            // exactly the one whose hash has to be looked up.
            Assert.NotNull(read.Sha256);
        }
        finally
        {
            File.Delete(fabricated);
        }
    }

    /// <summary>
    /// A path that does not exist must be told apart from a file that fails verification:
    /// the ladder answers <c>FileNotFound</c>, which it reports as a leftover rather than
    /// as an accusation.
    /// </summary>
    [Fact]
    public void An_absent_file_is_not_confused_with_an_unsigned_one()
    {
        Assert.Equal(SignatureStatus.FileNotFound,
            new LiveSignatureProvider()
                .Verify(@"C:\Windows\System32\rempart-ce-fichier-n-existe-pas.exe")
                .Status);
    }
}
