using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Windows;

// Analyse d'arguments écrite à la main. L'ADR-001 prévoit System.CommandLine ; l'ajouter
// pour deux commandes serait prématuré. À basculer en M1, quand le nombre de commandes
// le justifiera.

const string Version = "0.1.0-m0";

// La console Windows n'est pas en UTF-8 par défaut : sans cela les diagnostics
// accentués sortent illisibles, et ce sont eux qu'il faut lire en priorité.
Console.OutputEncoding = System.Text.Encoding.UTF8;

var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0] : "help";

try
{
    return command switch
    {
        "scan" => Scan(args),
        "capture" => Capture(args),
        "version" => Print(Version),
        _ => Help(),
    };
}
catch (SnapshotIncompleteException ex)
{
    Console.Error.WriteLine($"Instantané incomplet : {ex.Message}");
    return 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Erreur : {ex.Message}");
    return 1;
}

static int Scan(string[] args)
{
    var snapshotPath = OptionValue(args, "--from");
    var asJson = HasFlag(args, "--json");

    ProviderSet providers;
    string origin;

    if (snapshotPath is not null)
    {
        // Rejeu hors-ligne : le même code de collecte, sans Windows.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(snapshotPath));
        providers = new ProviderSet(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot));
        origin = snapshot.CapturedAtUtc;
    }
    else
    {
        RequireWindows();
        providers = new ProviderSet(new LiveRegistryProvider(), new LiveSystemInfoProvider());
        origin = UtcNow();
    }

    var result = new ScanEngine(ScanEngine.DefaultCollectors).Run(providers, Version, origin);

    if (asJson)
    {
        Console.WriteLine(RempartJson.Serialise(result));
    }
    else
    {
        WriteHumanReadable(result);
    }

    // Un manque de droits n'est pas une erreur d'exécution, mais l'appelant doit
    // pouvoir le détecter sans relire la sortie.
    return result.Collectors.Any(c => c.Status == CollectorStatus.Failed) ? 1
        : result.Collectors.Any(c => c.Status == CollectorStatus.InsufficientPrivileges) ? 3
        : 0;
}

static int Capture(string[] args)
{
    RequireWindows();

    var raw = HasFlag(args, "--raw");
    var snapshot = new MachineSnapshot { CapturedAtUtc = UtcNow() };

    var providers = new ProviderSet(
        new RecordingRegistryProvider(new LiveRegistryProvider(), snapshot),
        new RecordingSystemInfoProvider(new LiveSystemInfoProvider(), snapshot));

    new ScanEngine(ScanEngine.DefaultCollectors).Run(providers, Version, snapshot.CapturedAtUtc);

    // Anonymisation par défaut : les fixtures finissent versionnées.
    if (!raw)
    {
        Anonymiser.Apply(snapshot);
    }

    var suffix = raw ? "raw" : "anon";
    var path = OptionValue(args, "--out")
        ?? $"rempart-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{suffix}.capture.json";

    File.WriteAllText(path, RempartJson.Serialise(snapshot));

    Console.WriteLine($"Instantané écrit : {path}");
    Console.WriteLine($"  lectures enregistrées : {snapshot.Registry.Count}");
    Console.WriteLine(raw
        ? "  ATTENTION : capture brute, non anonymisée. Ne pas versionner tel quel."
        : "  anonymisé : hostname, numéros de série et propriétaire remplacés par des empreintes.");

    return 0;
}

static void WriteHumanReadable(ScanResult result)
{
    Console.WriteLine($"Rempart {result.ToolVersion} — scan du {result.StartedAtUtc}");

    foreach (var collector in result.Collectors)
    {
        Console.WriteLine();
        Console.WriteLine($"[{collector.Name}] {collector.Status}");

        foreach (var (key, value) in collector.Fields)
        {
            Console.WriteLine($"  {key,-32} {value ?? "—"}");
        }

        foreach (var diagnostic in collector.Diagnostics)
        {
            Console.WriteLine($"  ! {diagnostic}");
        }
    }
}

static void RequireWindows()
{
    if (!OperatingSystem.IsWindows())
    {
        throw new PlatformNotSupportedException(
            "Rempart cible Windows. Utiliser « scan --from <instantané> » pour rejouer hors-ligne.");
    }
}

static string UtcNow() => DateTime.UtcNow.ToString("o");

static string? OptionValue(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static bool HasFlag(string[] args, string name) => Array.IndexOf(args, name) >= 0;

static int Print(string text)
{
    Console.WriteLine(text);
    return 0;
}

static int Help() => Print(
    """
    Rempart — audit de postes Windows

      rempart scan [--json] [--from <instantané>]
          Analyse la machine locale, ou rejoue un instantané hors-ligne.

      rempart capture [--out <fichier>] [--raw]
          Enregistre l'état brut de la machine, rejouable en test.
          Anonymisé par défaut ; --raw conserve les identifiants.

      rempart version

    Codes de sortie : 0 succès · 1 échec · 2 instantané incomplet · 3 droits insuffisants
    """);
