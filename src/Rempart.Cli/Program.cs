using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Windows;

// Analyse d'arguments écrite à la main. L'ADR-001 prévoit System.CommandLine ; l'ajouter
// pour deux commandes serait prématuré. À basculer en M1, quand le nombre de commandes
// le justifiera.

const string Version = "0.2.0-m1";

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
        "explain" => Explain(args),
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

    var result = ScanEngine.Default().Run(providers, Version, origin);

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

    // Le moteur complet, regles comprises : une fixture doit pouvoir rejouer tout ce
    // que fait un scan, sans quoi elle ne testerait que la moitie du chemin.
    ScanEngine.Default().Run(providers, Version, snapshot.CapturedAtUtc);

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

/// <summary>
/// Ce qu'on vient chercher d'abord : les problèmes. L'inventaire ferme le rapport —
/// c'est du contexte, et vingt-trois lignes de contexte avant le premier constat
/// font qu'on ne lit plus le constat.
/// </summary>
static void WriteHumanReadable(ScanResult result)
{
    Console.WriteLine($"Rempart {result.ToolVersion} — scan du {result.StartedAtUtc}");

    if (result.Score is { } score)
    {
        WritePosture(result, score);
    }

    Console.WriteLine();
    foreach (var collector in result.Collectors)
    {
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

static void WritePosture(ScanResult result, ScoreCard score)
{
    // Les règles satisfaites ne sont pas listées, seulement comptées : un rapport qui
    // noie trois problèmes dans cent lignes vertes ne sera pas lu.
    var failures = result.Verdicts
        .Where(v => v.Status == VerdictStatus.Fail)
        .OrderByDescending(v => v.Severity)
        .ToList();

    if (failures.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("[posture] à corriger");
        foreach (var verdict in failures)
        {
            Console.WriteLine(
                $"  {verdict.Severity.ToString().ToUpperInvariant(),-8} " +
                $"{verdict.RuleId}  {verdict.Title}");
            Console.WriteLine($"           observé : {verdict.Observed ?? "absent"}" +
                              (verdict.Expected is null ? "" : $"   attendu : {verdict.Expected}"));
        }
    }

    var unknown = result.Verdicts.Where(v => v.Status == VerdictStatus.Unknown).ToList();
    if (unknown.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("[posture] non vérifiable — accès refusé");
        foreach (var verdict in unknown)
        {
            Console.WriteLine($"  {verdict.RuleId}  {verdict.Title}");
        }
    }

    Console.WriteLine();
    Console.WriteLine("[score] par domaine");
    foreach (var domain in score.Domains)
    {
        var value = domain.Score is { } s ? $"{s,3} %" : "  n/d";
        Console.WriteLine(
            $"  {domain.Domain,-18} {value}   " +
            $"conformes {domain.Passed}, échecs {domain.Failed}, non vérifiés {domain.Unknown}");
    }

    Console.WriteLine();
    Console.WriteLine($"  {"GLOBAL",-18} {(score.Overall is { } o ? $"{o,3} %" : "  n/d")}");

    if (score.IsPartial)
    {
        Console.WriteLine();
        Console.WriteLine(
            $"  Score partiel : {score.TotalUnknown} contrôle(s) non vérifiable(s) sans élévation.");
        Console.WriteLine(
            "  Les contrôles non vérifiés sont exclus du calcul, jamais comptés comme conformes.");
    }

    if (failures.Count > 0 || unknown.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  « rempart explain <ID> » détaille une règle et ce que coûte sa correction.");
    }
}

/// <summary>
/// Rend accessible ce que le scan ne peut pas afficher : la justification, les
/// références, et le coût réel d'une correction. Sans cette commande, ces informations
/// n'existaient que dans les fichiers YAML — écrites, mais hors de portée à l'usage.
/// </summary>
static int Explain(string[] args)
{
    var id = args.Length > 1 ? args[1] : null;
    var rules = RuleCatalog.Load();

    if (id is null)
    {
        Console.WriteLine($"{rules.Count} contrôles :");
        foreach (var group in rules.GroupBy(r => r.Domain).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            Console.WriteLine();
            Console.WriteLine($"  {group.Key}");
            foreach (var rule in group)
            {
                Console.WriteLine($"    {rule.Id,-14} {rule.Severity,-8} {rule.Title}");
            }
        }

        return 0;
    }

    var found = rules.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
    if (found is null)
    {
        Console.Error.WriteLine($"Règle inconnue : {id}. « rempart explain » liste les contrôles.");
        return 1;
    }

    Console.WriteLine($"{found.Id} — {found.Title}");
    Console.WriteLine($"  sévérité   {found.Severity}");
    Console.WriteLine($"  domaine    {found.Domain}");
    if (found.References.Count > 0)
    {
        Console.WriteLine($"  références {string.Join(", ", found.References)}");
    }

    Console.WriteLine();
    Console.WriteLine("Pourquoi");
    WriteWrapped(found.Rationale);

    Console.WriteLine();
    Console.WriteLine("Ce qui est vérifié");
    Console.WriteLine($"  {found.Check.Path}");
    if (found.Check.ValueName is { } value)
    {
        Console.WriteLine($"  valeur « {value} » {found.Check.Operator} {found.Check.Expected}");
    }
    else
    {
        Console.WriteLine($"  la clé doit être {found.Check.Operator}");
    }

    if (found.Check.WindowsDefault is { } fallback)
    {
        Console.WriteLine($"  si la valeur est absente, Windows applique : {fallback}");
    }

    if (found.Remediation is not { } remediation)
    {
        Console.WriteLine();
        Console.WriteLine("Correction");
        Console.WriteLine("  Aucune remédiation décrite pour cette règle.");
        return 0;
    }

    Console.WriteLine();
    Console.WriteLine($"Correction — réversibilité : {remediation.Reversibility}");
    Console.WriteLine("  Ce qui cesse de fonctionner");
    WriteWrapped(remediation.Breaks, "    ");
    Console.WriteLine("  Qui est concerné");
    WriteWrapped(remediation.Affects, "    ");

    if (remediation.VerifyBefore is { } verify)
    {
        Console.WriteLine("  À vérifier avant d'appliquer");
        WriteWrapped(verify, "    ");
    }

    Console.WriteLine();
    Console.WriteLine("  La v1 n'applique aucune correction : elle constate et documente.");

    return 0;
}

static void WriteWrapped(string text, string indent = "  ")
{
    var words = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
    var line = new System.Text.StringBuilder(indent);

    foreach (var word in words)
    {
        if (line.Length + word.Length + 1 > 88)
        {
            Console.WriteLine(line.ToString());
            line.Clear().Append(indent);
        }

        line.Append(word).Append(' ');
    }

    if (line.Length > indent.Length)
    {
        Console.WriteLine(line.ToString().TrimEnd());
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

      rempart explain [<ID>]
          Liste les contrôles, ou détaille une règle : justification,
          références, et ce que coûte sa correction.

      rempart version

    Codes de sortie : 0 succès · 1 échec · 2 instantané incomplet · 3 droits insuffisants
    """);
