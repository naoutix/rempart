using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Json;
using Rempart.Core.Packaging;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// The stick's integrity seal.
///
/// The scenario it exists for: the stick is plugged into the machines it audits, one of
/// them rewrites a file, and the next machine is audited by something else. What the
/// tests below pin down is that every way a stick can differ from its seal is reported —
/// including the one an attacker would use, which is adding a file rather than changing
/// one.
/// </summary>
public sealed class StickSealTests
{
    [Fact]
    public void The_seal_covers_the_binary_and_the_rules_but_not_what_normal_use_changes()
    {
        var sealed_ = StickSeal.Sealable(
        [
            "rempart.exe",
            "rules/securite.yaml",
            StickSeal.FileName,
            "reports/POSTE-01-2026-07-24/rapport.html",
            "rempart-data/manifest.json",
            "rempart-data/loldrivers.json",
        ]);

        // Sorted, so sealing the same stick twice produces the same file.
        Assert.Equal(["rempart.exe", "rules/securite.yaml"], sealed_);
    }

    /// <summary>
    /// Reports and the update store are excluded on purpose: both change while the
    /// stick is used normally, and a seal that always looks broken stops being read.
    /// The store loses nothing — ADR-002 (D13) re-verifies it at every scan.
    /// </summary>
    [Fact]
    public void A_scan_and_an_update_do_not_break_the_seal()
    {
        var before = StickSeal.Sealable(["rempart.exe"]);
        var after = StickSeal.Sealable(
        [
            "rempart.exe",
            "reports/POSTE-01-2026-07-24/rapport.json",
            "rempart-data/manifest.json",
        ]);

        Assert.Equal(before, after);
    }

    [Fact]
    public void An_untouched_stick_verifies()
    {
        var files = Stick(("rempart.exe", "MZ…"), ("rules/a.yaml", "- id: X"));
        var verdict = StickSeal.Check(StickSeal.Describe(files, When), Present(files));

        Assert.True(verdict.Intact);
        Assert.Empty(verdict.Deviations);
        Assert.Contains("2 fichier(s) conformes", verdict.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_rewritten_binary_is_reported()
    {
        var seal = StickSeal.Describe(Stick(("rempart.exe", "MZ légitime")), When);
        var verdict = StickSeal.Check(seal, Present(Stick(("rempart.exe", "MZ trojané"))));

        Assert.False(verdict.Intact);
        Assert.Equal(SealState.Modified, verdict.Files.Single().State);
        Assert.Contains("Sceau rompu", verdict.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_removed_rule_file_is_reported()
    {
        var seal = StickSeal.Describe(
            Stick(("rempart.exe", "MZ"), ("rules/a.yaml", "- id: X")), When);

        var verdict = StickSeal.Check(seal, Present(Stick(("rempart.exe", "MZ"))));

        Assert.False(verdict.Intact);
        Assert.Equal(SealState.Missing,
            verdict.Files.Single(f => f.Name == "rules/a.yaml").State);
    }

    /// <summary>
    /// The case a name-by-name check would miss entirely. Planting is done by adding —
    /// a DLL beside the executable, found ahead of the system copy — not by editing
    /// something the seal already knows about.
    /// </summary>
    [Fact]
    public void A_file_added_next_to_the_binary_is_reported()
    {
        var seal = StickSeal.Describe(Stick(("rempart.exe", "MZ")), When);

        var verdict = StickSeal.Check(seal,
            Present(Stick(("rempart.exe", "MZ"), ("version.dll", "charge utile"))));

        Assert.False(verdict.Intact);
        Assert.Equal(SealState.Unsealed,
            verdict.Files.Single(f => f.Name == "version.dll").State);
        Assert.Contains("1 ajouté(s)", verdict.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// The loop the whole thing rests on: sealed here, verified there, through the same
    /// signed envelope the update channel uses. A list of hashes stored beside the files
    /// it describes would protect against nothing — whoever alters a file recomputes the
    /// line — so what is tested is that altering one after signing is caught.
    /// </summary>
    [Fact]
    public void A_seal_signed_here_verifies_there_and_refuses_a_forged_stick()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var files = Stick(("rempart.exe", "MZ légitime"), ("rules/a.yaml", "- id: X"));

        var signed = ManifestSigner.Sign(StickSeal.Describe(files, When), key);

        var verifier = new ManifestVerifier(new Dictionary<string, string>
        {
            [ManifestVerifier.KeyId(key.ExportSubjectPublicKeyInfo())] =
                Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        });

        var verdict = verifier.Verify(RempartJson.Serialise(signed));
        Assert.Equal(ManifestStatus.Trusted, verdict.Status);

        Assert.True(StickSeal.Check(verdict.Payload!, Present(files)).Intact);

        // Same authentic seal, a stick that changed since: the signature still verifies,
        // and the comparison is what catches it. Two questions, two answers.
        var tampered = Stick(("rempart.exe", "MZ trojané"), ("rules/a.yaml", "- id: X"));
        Assert.False(StickSeal.Check(verdict.Payload!, Present(tampered)).Intact);
    }

    /// <summary>
    /// A seal is not an update. Dropped into the store it must be refused by name, not
    /// send the reader chasing a newer version that would change nothing.
    /// </summary>
    [Fact]
    public void A_seal_mistaken_for_an_update_is_refused_for_what_it_is()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Directory.CreateTempSubdirectory("rempart-seal-");

        try
        {
            var signed = ManifestSigner.Sign(
                StickSeal.Describe(Stick(("rempart.exe", "MZ")), When), key);

            File.WriteAllText(
                Path.Combine(directory.FullName, UpdateStore.ManifestFileName),
                RempartJson.Serialise(signed));

            var resolution = UpdateStore.Resolve(
                directory.FullName,
                [],
                new ManifestVerifier(new Dictionary<string, string>
                {
                    [ManifestVerifier.KeyId(key.ExportSubjectPublicKeyInfo())] =
                        Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                }));

            Assert.Contains("sceau d'intégrité", resolution.UpdateNote!, StringComparison.Ordinal);
            Assert.Contains("seal --check", resolution.UpdateNote!, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private const string When = "2026-07-24T09:15:00Z";

    private static IReadOnlyList<(string Name, byte[] Content)> Stick(
        params (string Name, string Content)[] files) =>
        [.. files.Select(f => (f.Name, Encoding.UTF8.GetBytes(f.Content)))];

    private static Dictionary<string, byte[]> Present(
        IReadOnlyList<(string Name, byte[] Content)> files) =>
        files.ToDictionary(f => f.Name, f => f.Content, StringComparer.OrdinalIgnoreCase);
}
