using Rempart.Core.Json;
using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Joins the upstream bloatware list with the judgement written in this repository, and
/// prepares the catalogue in the format <c>sign</c> then <c>update</c> know how to process.
///
/// <para>
/// Publisher-side and online, like <see cref="FetchLoldriversCommand"/>: the tool fetches the
/// data, the publisher signs it. Audited machines do not trust this download — they trust the
/// signature that follows, and the upstream list is the publisher's choice.
/// </para>
///
/// <para>
/// What differs from the driver import is the second input. A blocklist is fingerprints and
/// nothing else; a bloatware catalogue carries a judgement — what a piece of software is, and
/// what removing it costs — and that judgement is not importable. So the upstream identifiers
/// are joined with a local file, and an identifier nobody has judged stops the command
/// (ADR-006, D19) rather than shipping without a note or vanishing from the output.
/// </para>
/// </summary>
internal static class FetchBloatwareCommand
{
    public static int Run(string[] args)
    {
        var outPath = OptionValue(args, "--out") ?? "bloatware.json";
        var judgementPath = OptionValue(args, "--judgement") ?? "bloatware-judgement.json";

        if (!File.Exists(judgementPath))
        {
            Console.Error.WriteLine(
                $"Fichier de jugement introuvable : {judgementPath}. C'est lui qui porte les "
                + "catégories, les risques et les notes d'impact ; l'amont ne fournit que des "
                + "identifiants. Le désigner avec --judgement.");
            return 1;
        }

        Console.WriteLine($"Téléchargement depuis {Win11DebloatImport.SourceUrl} …");

        using var transport = new HttpTransport(TimeSpan.FromSeconds(120));
        var raw = transport.Get(Win11DebloatImport.SourceUrl, out var error);

        if (raw is null)
        {
            Console.Error.WriteLine($"Téléchargement impossible : {error}");
            return 1;
        }

        BloatwareCatalogFile catalogue;
        try
        {
            catalogue = Win11DebloatImport.Transform(
                System.Text.Encoding.UTF8.GetString(raw),
                File.ReadAllText(judgementPath),
                UtcNow());
        }
        catch (UnjudgedEntriesException ex)
        {
            // The expected outcome the day upstream adds something, and the reason this
            // command has an exit code at all: naming what is missing is the useful half.
            Console.Error.WriteLine();
            Console.Error.WriteLine($"{ex.AppIds.Count} identifiant(s) amont sans jugement :");
            foreach (var appId in ex.AppIds)
            {
                Console.Error.WriteLine($"  {appId}");
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine(
                $"Rien n'a été écrit. Compléter {judgementPath} — une entrée sans note "
                + "d'impact n'entre pas au catalogue.");
            return 1;
        }
        catch (System.Text.Json.JsonException ex)
        {
            // Either input may have changed shape: say so rather than write a truncated
            // catalogue that would pass for complete.
            Console.Error.WriteLine(
                $"Entrée illisible : {ex.Message} L'amont ou le fichier de jugement a pu changer.");
            return 1;
        }

        File.WriteAllText(outPath, RempartJson.SerialiseCompact(catalogue));

        var verified = catalogue.Entries.Count(e => e.ImpactSource == ImpactProvenance.Verified);

        Console.WriteLine();
        Console.WriteLine($"Écrit dans {outPath} — {catalogue.Entries.Count} entrées.");
        Console.WriteLine(
            $"  notes vérifiées sur machine : {verified} ; décrites en amont : "
            + $"{catalogue.Entries.Count - verified}.");
        Console.WriteLine(
            "Rien n'est signé : c'est ton geste. Sur une machine hors ligne, avec ta clé :");
        Console.WriteLine($"  rempart sign --key <clé privée> --data {Path.GetDirectoryName(Path.GetFullPath(outPath))}");
        Console.WriteLine("  puis  rempart update --from <…\\manifest.json> --apply");
        return 0;
    }
}
