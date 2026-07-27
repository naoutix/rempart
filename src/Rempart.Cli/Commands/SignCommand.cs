using Rempart.Core.Json;
using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Signs a manifest — the publication act of ADR-002.
///
/// <para>
/// The counterpart of <c>keygen</c>: run on the same offline machine, with the
/// encrypted private key that never leaves it (D16). Gathers the datasets of a
/// directory, computes their digests, and signs the lot. The resulting manifest is
/// exactly what <c>update</c> will know how to verify.
/// </para>
/// </summary>
internal static class SignCommand
{
    public static int Run(string[] args)
    {
        var keyPath = OptionValue(args, "--key");
        var dataDir = OptionValue(args, "--data") ?? ".";

        if (keyPath is null || !File.Exists(keyPath))
        {
            Console.Error.WriteLine(
                "Indiquer la clé privée chiffrée : rempart sign --key <fichier> --data <dossier>.");
            return 1;
        }

        if (!Directory.Exists(dataDir))
        {
            Console.Error.WriteLine($"Dossier de données introuvable : {dataDir}");
            return 1;
        }

        var outPath = OptionValue(args, "--out")
            ?? Path.Combine(dataDir, UpdateStore.ManifestFileName);

        // Neither the private key nor the produced manifest must sign themselves as
        // datasets: exclude both from the enumeration.
        var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.GetFullPath(keyPath), Path.GetFullPath(outPath),
        };

        var datasets = Directory
            .EnumerateFiles(dataDir, "*", SearchOption.TopDirectoryOnly)
            .Where(f => !excluded.Contains(Path.GetFullPath(f)))
            .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
            .ToList();

        if (datasets.Count == 0)
        {
            Console.Error.WriteLine(
                $"Aucun jeu de données à signer dans {dataDir}. Y placer les fichiers d'abord.");
            return 1;
        }

        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine(
                "Cette commande exige une console : la phrase de passe ne doit pas transiter " +
                "par un tube ni par un argument.");
            return 1;
        }

        Console.WriteLine("Phrase de passe de la clé privée (non affichée) :");
        var passphrase = ReadHidden();

        // Kind forced for all files, or guessed from the extension: a publisher usually
        // signs a single kind at a time (a rules update, or a drivers update).
        var kind = OptionValue(args, "--kind");

        var entries = datasets
            .Select(f => ManifestSigner.Describe(Path.GetFileName(f), File.ReadAllBytes(f), kind))
            .ToList();

        var payload = new ManifestPayload(
            1, OptionValue(args, "--published") ?? UtcNow(), entries);

        SignedManifest signed;
        try
        {
            using var key = PublisherKey.Open(File.ReadAllText(keyPath).Trim(), passphrase);
            signed = ManifestSigner.Sign(payload, key);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Wrong passphrase, or corrupted key file: not telling the two apart gives
            // an attacker nothing and avoids confirming that a phrase came close.
            Console.Error.WriteLine("Clé illisible : phrase de passe erronée, ou fichier abîmé.");
            return 1;
        }

        File.WriteAllText(outPath, RempartJson.Serialise(signed));

        Console.WriteLine();
        Console.WriteLine($"Manifeste signé écrit dans {outPath}.");
        Console.WriteLine($"  signé par {signed.Signatures[0].KeyId}, {entries.Count} jeu(x) de données");
        foreach (var entry in entries)
        {
            Console.WriteLine($"    {entry.Name}  ({entry.SizeBytes} octets, {entry.Sha256[..12]})");
        }

        Console.WriteLine();
        Console.WriteLine(
            "Apporter ce manifeste et les jeux de données sur la machine cible, côte à côte, " +
            "puis : rempart update --from <manifeste> --apply");
        return 0;
    }
}
