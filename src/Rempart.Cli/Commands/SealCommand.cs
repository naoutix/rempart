using Rempart.Core.Json;
using Rempart.Core.Packaging;
using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Seals the stick, or checks it against its seal.
///
/// <para>
/// The stick gets plugged into the very machines it audits; any of them can rewrite
/// <c>rempart.exe</c>. The seal is signed by the publisher key of ADR-002 — a list of
/// hashes sitting next to the files it describes would protect against nothing, since
/// whoever alters a file recomputes the line.
/// </para>
///
/// <para>
/// Its limit is stated wherever it is used: a binary checking itself proves little. The
/// check is worth something run from a copy known to be good, against a stick one has
/// reason to doubt.
/// </para>
/// </summary>
internal static class SealCommand
{
    public static int Run(string[] args)
    {
        var root = OptionValue(args, "--dir") ?? AppContext.BaseDirectory;

        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine($"Dossier introuvable : {root}");
            return 1;
        }

        var sealPath = OptionValue(args, "--out") ?? Path.Combine(root, StickSeal.FileName);

        if (HasFlag(args, "--check"))
        {
            if (!File.Exists(sealPath))
            {
                Console.Error.WriteLine(
                    $"Aucun sceau dans {root}. En poser un : rempart seal --dir <dossier> " +
                    "--key <clé privée>.");
                return 1;
            }

            var verdict = CheckSeal(root, sealPath, out var detail);
            Console.WriteLine(detail);

            foreach (var deviation in verdict?.Deviations ?? [])
            {
                Console.WriteLine($"  {DescribeSealState(deviation.State),-11} {deviation.Name}");
            }

            if (verdict is { Intact: true })
            {
                Console.WriteLine();
                Console.WriteLine(
                    "Rappel : un binaire qui se vérifie lui-même prouve peu. Ce contrôle vaut " +
                    "lancé depuis une copie sûre, contre une clé dont on doute.");
                return 0;
            }

            return 1;
        }

        var keyPath = OptionValue(args, "--key");

        if (keyPath is null || !File.Exists(keyPath))
        {
            Console.Error.WriteLine(
                "Sceller exige la clé privée d'éditeur : rempart seal --dir <dossier> " +
                "--key <fichier>. Sans signature, une liste d'empreintes posée à côté des " +
                "fichiers qu'elle décrit ne protège de rien : qui modifie un fichier " +
                "recalcule la ligne.");
            return 1;
        }

        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine(
                "Cette commande exige une console : la phrase de passe ne doit pas transiter " +
                "par un tube ni par un argument.");
            return 1;
        }

        var files = ReadSealableFiles(root);

        if (files.Count == 0)
        {
            Console.Error.WriteLine($"Rien à sceller dans {root}.");
            return 1;
        }

        Console.WriteLine("Phrase de passe de la clé privée (non affichée) :");
        var passphrase = ReadHidden();

        SignedManifest signed;
        try
        {
            using var key = PublisherKey.Open(File.ReadAllText(keyPath).Trim(), passphrase);
            signed = ManifestSigner.Sign(StickSeal.Describe(files, UtcNow()), key);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            Console.Error.WriteLine("Clé illisible : phrase de passe erronée, ou fichier abîmé.");
            return 1;
        }

        File.WriteAllText(sealPath, RempartJson.Serialise(signed));

        Console.WriteLine();
        Console.WriteLine($"Sceau écrit dans {sealPath} — {files.Count} fichier(s), " +
                          $"signé par {signed.Signatures[0].KeyId}.");
        foreach (var (name, content) in files)
        {
            Console.WriteLine($"  {name}  ({content.LongLength} octets)");
        }

        Console.WriteLine();
        Console.WriteLine($"Hors sceau, par conception : {string.Join(", ", StickSeal.ExcludedDirectories)}" +
                          " — ils changent à l'usage normal. Le magasin de mise à jour est de");
        Console.WriteLine("toute façon revérifié à chaque scan contre son propre manifeste signé.");
        return 0;
    }

    /// <summary>
    /// The seal's verdict as one line for the scan header, or null when the stick carries
    /// no seal — the ordinary case, which must not read as a failure.
    ///
    /// <para>
    /// Public and here rather than in <see cref="CliHost"/>, although <c>scan</c> is its
    /// other caller: it is a one-line wrapper over <see cref="CheckSeal"/>, and splitting
    /// the two would put half of the seal's reasoning in a file about host paths.
    /// </para>
    /// </summary>
    public static string? SealNote(string root)
    {
        var sealPath = Path.Combine(root, StickSeal.FileName);

        if (!File.Exists(sealPath))
        {
            return null;
        }

        try
        {
            CheckSeal(root, sealPath, out var explanation);
            return explanation;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Unreadable is not intact. Saying so beats staying silent, which would read
            // as "nothing to report".
            return $"Sceau d'intégrité illisible : {ex.Message}";
        }
    }

    private static string DescribeSealState(SealState state) => state switch
    {
        SealState.Modified => "modifié",
        SealState.Missing => "manquant",
        SealState.Unsealed => "ajouté",
        _ => "conforme",
    };

    /// <summary>
    /// Authenticates the seal, then compares it to what is on the stick. Returns null when
    /// the seal itself is not trustworthy — a different problem from a stick that changed,
    /// and one that deserves its own wording.
    /// </summary>
    private static SealVerdict? CheckSeal(string root, string sealPath, out string explanation)
    {
        var verdict = PinnedKeys.Verifier().Verify(File.ReadAllText(sealPath));

        if (!verdict.IsTrusted || verdict.Payload is null)
        {
            // The verifier's wording is written for the update channel — it ends on
            // "install a newer version", which means nothing for a seal. Same statuses,
            // different consequences, so the sentences are the seal's own.
            explanation = verdict.Status switch
            {
                ManifestStatus.UnknownKey =>
                    "Sceau signé par une clé que ce binaire ne connaît pas : il ne prouve rien " +
                    "ici. Le vérifier depuis une copie qui connaît cette clé.",

                ManifestStatus.BadSignature =>
                    "Sceau dont la signature ne correspond pas à son contenu : il a été modifié " +
                    "après signature. Ne pas se fier à cette clé.",

                _ => $"Sceau illisible : {verdict.Explanation}",
            };

            return null;
        }

        var present = ReadSealableFiles(root)
            .ToDictionary(f => f.Name, f => f.Content, StringComparer.OrdinalIgnoreCase);

        var result = StickSeal.Check(verdict.Payload, present);
        explanation = result.Summary;
        return result;
    }

    /// <summary>
    /// The stick's files, as names relative to its root with <c>/</c> separators, so a seal
    /// produced on one machine reads the same on another.
    /// </summary>
    private static IReadOnlyList<(string Name, byte[] Content)> ReadSealableFiles(string root)
    {
        var full = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);

        var names = StickSeal.Sealable(Directory
            .EnumerateFiles(full, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(full, path)
                .Replace(Path.DirectorySeparatorChar, '/')));

        return [.. names.Select(name => (name,
            File.ReadAllBytes(Path.Combine(full, name.Replace('/', Path.DirectorySeparatorChar)))))];
    }
}
