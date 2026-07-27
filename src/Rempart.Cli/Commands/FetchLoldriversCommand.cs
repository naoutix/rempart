using Rempart.Core.Json;
using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Downloads the official LOLDrivers list and prepares it in the format that <c>sign</c>
/// then <c>update</c> know how to process.
///
/// <para>
/// The tool fetches the data; the publisher signs it. This is the publishing side,
/// online: the only place where we reach out to the network to produce a dataset,
/// never to apply one. The audited machines' trust does not rest on this download
/// but on the signature that follows — loldrivers.io is the upstream source the
/// publisher chooses, and their signature vouches for it.
/// </para>
/// </summary>
internal static class FetchLoldriversCommand
{
    public static int Run(string[] args)
    {
        var outPath = OptionValue(args, "--out") ?? "loldrivers.json";

        Console.WriteLine($"Téléchargement depuis {LolDriversImport.SourceUrl} …");

        using var transport = new HttpTransport(TimeSpan.FromSeconds(120));
        var raw = transport.Get(LolDriversImport.SourceUrl, out var error);

        if (raw is null)
        {
            Console.Error.WriteLine($"Téléchargement impossible : {error}");
            return 1;
        }

        DriverBlocklistFile blocklist;
        try
        {
            blocklist = LolDriversImport.Transform(
                System.Text.Encoding.UTF8.GetString(raw), UtcNow());
        }
        catch (System.Text.Json.JsonException ex)
        {
            // The source may have changed shape: say so rather than write a truncated
            // list that would pass for complete.
            Console.Error.WriteLine(
                $"La réponse n'a pas la forme attendue : {ex.Message} La source a pu changer.");
            return 1;
        }

        File.WriteAllText(outPath, RempartJson.SerialiseCompact(blocklist));

        Console.WriteLine();
        Console.WriteLine($"Écrit dans {outPath} — {blocklist.Drivers.Count} pilotes.");
        Console.WriteLine(
            "Rien n'est signé : c'est ton geste. Sur une machine hors ligne, avec ta clé :");
        Console.WriteLine($"  rempart sign --key <clé privée> --data {Path.GetDirectoryName(Path.GetFullPath(outPath))}");
        Console.WriteLine("  puis  rempart update --from <…\\manifest.json> --apply");
        return 0;
    }
}
