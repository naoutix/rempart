using Rempart.Core.Updates;

namespace Rempart.Core.Packaging;

/// <summary>What became of one sealed file.</summary>
public enum SealState
{
    /// <summary>Present, and byte-for-byte what was sealed.</summary>
    Intact,

    /// <summary>Present, and no longer what was sealed.</summary>
    Modified,

    /// <summary>Declared by the seal, absent from the stick.</summary>
    Missing,

    /// <summary>Present on the stick, absent from the seal.</summary>
    Unsealed,
}

public sealed record SealedFileState(string Name, SealState State);

/// <summary>
/// The outcome of a check: whether the stick is what was sealed, and what differs.
/// </summary>
public sealed record SealVerdict(
    bool Intact,
    IReadOnlyList<SealedFileState> Files,
    string Summary)
{
    public IEnumerable<SealedFileState> Deviations =>
        Files.Where(f => f.State != SealState.Intact);
}

/// <summary>
/// The stick's integrity seal: a signed list of what the stick is supposed to contain.
///
/// <para>
/// <b>What it is for.</b> A USB stick carrying an audit tool gets plugged into the very
/// machines it is meant to judge. Any one of them can rewrite <c>rempart.exe</c>, and
/// the next machine would then be audited by a binary of someone else's choosing.
/// </para>
///
/// <para>
/// <b>Why it is signed, and not merely hashed.</b> A plain list of hashes stored beside
/// the files it describes protects against nothing: whoever alters a file recomputes the
/// line. The seal reuses the publisher key of ADR-002 — the same trust anchor as the
/// update channel, the same pinned public key — so altering a file requires a signature
/// that cannot be produced without the offline private key.
/// </para>
///
/// <para>
/// <b>What it does not do, and this matters.</b> A tool verifying its own binary proves
/// little: a replaced <c>rempart.exe</c> can simply report that all is well. The seal
/// is worth what the copy checking it is worth, so the check is meaningful when run
/// <em>from a known-good copy</em> against a suspect stick, and is only an
/// error-detection convenience when a stick checks itself. Saying this plainly is the
/// point; a seal presented as protection it does not give is worse than none.
/// </para>
///
/// <para>
/// <b>What is deliberately left out.</b> Reports are produced by every scan, and the
/// update store changes at every <c>update --apply</c> — sealing either would break the
/// seal during normal use, and a seal that always looks broken stops being read. The
/// store loses nothing by it: ADR-002 (D13) already re-verifies it against its own
/// signed manifest at every scan.
/// </para>
/// </summary>
public static class StickSeal
{
    /// <summary>Sits at the root of the stick, beside the binary it describes.</summary>
    public const string FileName = "rempart-integrity.json";

    /// <summary>
    /// Directories left out of the seal, because they change while the stick is used
    /// normally.
    /// </summary>
    public static readonly IReadOnlyList<string> ExcludedDirectories = ["reports", "rempart-data"];

    /// <summary>
    /// Filters a listing down to what the seal covers. Names are relative to the stick
    /// root, with <c>/</c> as the separator, and come out sorted so that two seals of
    /// the same stick are identical files.
    /// </summary>
    public static IReadOnlyList<string> Sealable(IEnumerable<string> relativeNames) =>
    [
        .. relativeNames
            .Where(name => !string.Equals(name, FileName, StringComparison.OrdinalIgnoreCase))
            .Where(name => !ExcludedDirectories.Any(directory =>
                name.StartsWith($"{directory}/", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(name => name, StringComparer.Ordinal),
    ];

    /// <summary>
    /// Describes the files as a payload ready to sign — the same envelope the update
    /// channel uses, so there is one signature format and one verifier in the project.
    /// </summary>
    public static ManifestPayload Describe(
        IReadOnlyList<(string Name, byte[] Content)> files, string sealedAtUtc) =>
        new(1, sealedAtUtc,
        [
            .. files
                .OrderBy(file => file.Name, StringComparer.Ordinal)
                .Select(file => ManifestSigner.Describe(file.Name, file.Content, DatasetKind.Binary)),
        ]);

    /// <summary>
    /// Compares a seal that has already been authenticated against what is actually on
    /// the stick.
    ///
    /// <para>
    /// A file present but unsealed is reported rather than ignored. Adding a file is how
    /// you plant one — a DLL beside the executable, picked up ahead of the system copy —
    /// and a check that only looked at the names it already knew would never see it.
    /// </para>
    /// </summary>
    public static SealVerdict Check(
        ManifestPayload seal, IReadOnlyDictionary<string, byte[]> present)
    {
        var states = new List<SealedFileState>();
        var sealed_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in seal.Datasets.OrderBy(e => e.Name, StringComparer.Ordinal))
        {
            sealed_.Add(entry.Name);

            states.Add(new SealedFileState(entry.Name,
                !present.TryGetValue(entry.Name, out var content) ? SealState.Missing
                : ManifestVerifier.FileMatches(entry, content) ? SealState.Intact
                : SealState.Modified));
        }

        states.AddRange(present.Keys
            .Where(name => !sealed_.Contains(name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name => new SealedFileState(name, SealState.Unsealed)));

        var modified = states.Count(s => s.State == SealState.Modified);
        var missing = states.Count(s => s.State == SealState.Missing);
        var added = states.Count(s => s.State == SealState.Unsealed);
        var intact = modified == 0 && missing == 0 && added == 0;

        return new SealVerdict(intact, states, intact
            ? $"Sceau vérifié, scellé le {seal.PublishedAtUtc} : {states.Count} fichier(s) conformes."
            : $"Sceau rompu : {modified} fichier(s) modifié(s), {missing} manquant(s), "
              + $"{added} ajouté(s). Ne pas se fier à cette clé avant d'avoir tranché.");
    }
}
