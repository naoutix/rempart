using Rempart.Core.Rules;
using Rempart.Core.Updates;
using static Rempart.Cli.CliHost;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli.Commands;

/// <summary>
/// Prepares a signed data update (ADR-002).
///
/// <para>
/// Verifies and shows — applies nothing without <c>--apply</c> (D14). The manifest and
/// every dataset are authenticated, the diff displayed. From a local file
/// (<c>--from</c>, the USB-stick flow) or from the network (<c>--url</c>): the
/// verification is exactly the same, because <b>the transport is never trusted</b>,
/// only the signature is.
/// </para>
/// </summary>
internal static class UpdateCommand
{
    public static int Run(string[] args)
    {
        var manifestPath = OptionValue(args, "--from");
        var url = OptionValue(args, "--url");

        if ((manifestPath is null) == (url is null))
        {
            Console.Error.WriteLine(
                "Indiquer soit --from <fichier>, soit --url <base>, mais pas les deux ni aucun.");
            return 1;
        }

        var current = RuleCatalog.Load(RulesDirectory(args));

        // Each source produces the same thing: a preview, and the means to apply it.
        // The rest — display, confirmation, writing — is shared.
        UpdatePreview preview;
        Action applyToStore;

        if (url is not null)
        {
            using var transport = new HttpTransport();
            var (fetch, error) = RemoteUpdate.Prepare(url, transport, PinnedKeys.Verifier(), current);

            if (fetch is null)
            {
                Console.Error.WriteLine(error);
                return 1;
            }

            preview = fetch.Preview;
            applyToStore = () =>
                UpdateStore.Write(StoreDirectory(args), fetch.ManifestBytes, fetch.DatasetBytes);
        }
        else
        {
            if (!File.Exists(manifestPath))
            {
                Console.Error.WriteLine($"Manifeste introuvable : {manifestPath}");
                return 1;
            }

            // Datasets live next to the manifest. The trailing separator distinguishes
            // "inside this directory" from "a sibling directory with a similar name".
            var directory = (Path.GetDirectoryName(Path.GetFullPath(manifestPath!)) ?? ".")
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            byte[]? ReadDataset(string name)
            {
                // A name like "..\\.." must not become an arbitrary path.
                var full = Path.GetFullPath(Path.Combine(directory, name));
                return full.StartsWith(directory, StringComparison.OrdinalIgnoreCase)
                    && File.Exists(full)
                    ? File.ReadAllBytes(full)
                    : null;
            }

            preview = UpdatePlanner.Prepare(
                File.ReadAllText(manifestPath!), PinnedKeys.Verifier(), ReadDataset, current);

            applyToStore = () => UpdateStore.Apply(
                manifestPath!, StoreDirectory(args), preview.Datasets.Select(d => d.Name));
        }

        return ReportAndMaybeApply(args, preview, applyToStore);
    }

    /// <summary>
    /// Displays the preview, then, given <c>--apply</c> and confirmation, writes to the
    /// store. Shared by both sources — verification has already happened, identically.
    /// </summary>
    private static int ReportAndMaybeApply(string[] args, UpdatePreview preview, Action applyToStore)
    {
        if (!preview.Trusted)
        {
            // Each rejection reason gets its own response: do not conflate them.
            Console.Error.WriteLine($"Manifeste refusé ({preview.Status}) : {preview.Explanation}");
            return 1;
        }

        Console.WriteLine($"Manifeste de confiance. {preview.Explanation}");
        Console.WriteLine();

        var blocked = false;
        foreach (var dataset in preview.Datasets)
        {
            WriteDataset(dataset);
            blocked |= !dataset.Verified;
        }

        if (preview.Datasets.Count == 0)
        {
            Console.WriteLine("Le manifeste ne décrit aucun jeu de données.");
            return 0;
        }

        Console.WriteLine();
        if (blocked)
        {
            Console.Error.WriteLine(
                "Au moins un jeu de données n'a pas pu être vérifié : rien ne serait appliqué. " +
                "On ne pose pas la moitié d'une mise à jour.");
            return 1;
        }

        if (!HasFlag(args, "--apply"))
        {
            Console.WriteLine(
                "Tout est vérifié. Rien n'a été écrit — relancer avec --apply pour poser cette " +
                "mise à jour, que les prochains scans utiliseront.");
            return 0;
        }

        // Applying changes what future scans will evaluate: confirm it, unless --yes.
        // Without a console, refuse rather than apply an update nobody validated.
        if (!HasFlag(args, "--yes"))
        {
            if (Console.IsInputRedirected)
            {
                Console.Error.WriteLine(
                    "Application non confirmée : ajouter --yes, ou lancer depuis une console.");
                return 1;
            }

            Console.Write("Appliquer cette mise à jour ? [o/N] ");
            var answer = Console.ReadLine()?.Trim();
            if (!string.Equals(answer, "o", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(answer, "oui", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Annulé. Rien n'a été écrit.");
                return 0;
            }
        }

        applyToStore();

        Console.WriteLine($"Mise à jour posée dans {StoreDirectory(args)}.");
        Console.WriteLine(
            "Les prochains scans la vérifieront de nouveau avant de l'utiliser, et " +
            "l'afficheront dans leur en-tête.");
        return 0;
    }

    private static void WriteDataset(DatasetPreview dataset)
    {
        if (!dataset.Verified)
        {
            Console.WriteLine($"  ✗ {dataset.Name} ({dataset.Version}) — {dataset.Problem}");
            return;
        }

        // A driver list has no diff: it replaces the previous one. Report its entry
        // count, the only measure that means anything.
        if (dataset.Kind == DatasetKind.Drivers)
        {
            Console.WriteLine($"  ✓ {dataset.Name} ({dataset.Version}) — " +
                              $"{dataset.DriverCount} pilote(s) vulnérable(s) surveillé(s)");
            return;
        }

        var diff = dataset.Diff!;
        if (diff.ChangesNothing)
        {
            Console.WriteLine($"  = {dataset.Name} ({dataset.Version}) — rien ne change " +
                              $"({diff.Unchanged} contrôles identiques)");
            return;
        }

        Console.WriteLine($"  ✓ {dataset.Name} ({dataset.Version}) — " +
                          $"{diff.Added.Count} ajouté(s), {diff.Modified.Count} modifié(s), " +
                          $"{diff.Unchanged} inchangé(s)");

        foreach (var id in diff.Added)
        {
            Console.WriteLine($"      + {id}");
        }

        foreach (var change in diff.Modified)
        {
            Console.WriteLine($"      ~ {change.Id}  ({change.Before} → {change.After})");
        }
    }
}
