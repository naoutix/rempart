using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Points d'extension chargés à l'ouverture de session ou injectés dans chaque processus.
///
/// <para>
/// Ni des clés <c>Run</c>, ni des tâches : ces emplacements font exécuter du code sans
/// figurer dans les surfaces qu'un outil grand public inspecte. Chacun a une valeur par
/// défaut connue — <c>userinit.exe</c>, <c>explorer.exe</c>, une liste vide — et c'est
/// l'écart à ce défaut, ou un binaire référencé qui n'est pas signé, qui est le signal.
/// </para>
///
/// <para>
/// Trois emplacements, tous sous <c>HKLM</c>, lisibles sans élévation :
/// </para>
/// <list type="bullet">
///   <item><c>Winlogon\Userinit</c> — programmes lancés juste après l'ouverture de session.</item>
///   <item><c>Winlogon\Shell</c> — l'interpréteur graphique, <c>explorer.exe</c> par défaut.</item>
///   <item><c>AppInit_DLLs</c> — DLL chargées dans tout processus graphique. Vide par défaut,
///     et sa seule présence mérite un regard : c'est un point d'injection universel.</item>
/// </list>
/// </summary>
public sealed class LogonExtensibilityCollector : IFindingCollector
{
    private const string Winlogon =
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static readonly string[] WindowsKeys =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    public string Name => "logon-extension";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        CollectWinlogon(providers, findings, "Userinit", "userinit.exe");
        CollectWinlogon(providers, findings, "Shell", "explorer.exe");
        CollectAppInit(providers, findings);

        return findings;
    }

    /// <summary>
    /// Une valeur Winlogon peut lister plusieurs exécutables séparés par des virgules —
    /// <c>Userinit</c> en porte une en fin de valeur par défaut. Chacun est jugé ; celui
    /// qui n'est pas le programme attendu à cet emplacement est signalé même signé, car
    /// c'est l'ajout qui compte, pas seulement l'origine.
    /// </summary>
    private static void CollectWinlogon(
        ProviderSet providers, List<Finding> findings, string valueName, string expected)
    {
        var read = providers.Registry.ReadValue(Winlogon, valueName);
        if (read.Status != ReadStatus.Found || read.Value?.Text is not { Length: > 0 } text)
        {
            return;
        }

        foreach (var entry in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var path = ExtractExecutable(entry);
            if (path.Length == 0)
            {
                continue;
            }

            var expectedHere = string.Equals(
                Path.GetFileName(path), expected, StringComparison.OrdinalIgnoreCase);

            var finding = Judge(providers, $"Winlogon\\{valueName}", path, providers.Signatures);

            findings.Add(expectedHere
                ? finding
                : Escalate(finding, FindingSeverity.Notable,
                    $"Entrée inattendue dans {valueName} : « {expected} » est le programme " +
                    "par défaut à cet emplacement, celui-ci s'y ajoute."));
        }
    }

    /// <summary>
    /// <c>AppInit_DLLs</c> injecte ses DLL dans tout processus graphique. Sur une machine
    /// moderne, la valeur est vide ; une DLL présente est notable quelle que soit sa
    /// signature — le mécanisme lui-même est un levier d'injection, largement abandonné
    /// hors logiciels hérités.
    /// </summary>
    private static void CollectAppInit(ProviderSet providers, List<Finding> findings)
    {
        foreach (var key in WindowsKeys)
        {
            var read = providers.Registry.ReadValue(key, "AppInit_DLLs");
            if (read.Status != ReadStatus.Found || read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            foreach (var entry in text.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var finding = Judge(providers, "AppInit_DLLs", entry, providers.Signatures);
                findings.Add(Escalate(finding, FindingSeverity.Notable,
                    "DLL injectée dans chaque processus graphique via AppInit_DLLs — un "
                    + "point d'injection universel, inhabituel sur une machine moderne."));
            }
        }
    }

    private static Finding Judge(
        ProviderSet providers, string source, string reference, ISignatureProvider signatures)
    {
        var path = Resolve(reference);
        var judgement = SignatureLadder.Judge(path, signatures);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["référence"] = reference,
        };
        SignatureLadder.Describe(judgement.Signature, details);

        return new Finding(
            "logon-extension", source, path, judgement.Severity, judgement.Reasons, details);
    }

    /// <summary>
    /// Élève un constat à un plancher de gravité et ajoute une raison, sans jamais
    /// l'abaisser : un binaire déjà suspect par sa signature le reste.
    /// </summary>
    private static Finding Escalate(Finding finding, FindingSeverity floor, string reason) =>
        finding with
        {
            Severity = finding.Severity < floor ? floor : finding.Severity,
            Reasons = [reason, .. finding.Reasons],
        };

    /// <summary>Retire les guillemets et ne garde que le chemin de l'exécutable d'une entrée.</summary>
    private static string ExtractExecutable(string entry)
    {
        var trimmed = entry.Trim().Trim('"');
        var exe = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe >= 0 ? trimmed[..(exe + 4)] : trimmed;
    }

    /// <summary>
    /// Résout un nom nu vers son fichier réel. Un chemin déjà complet est rendu tel quel.
    ///
    /// <para>
    /// Windows ne cherche pas un nom nu qu'en System32 : <c>explorer.exe</c> vit dans le
    /// dossier Windows, pas System32. Chercher au seul System32 faisait ressortir le shell
    /// « fichier introuvable » — une lacune de résolution déguisée en constat, le même
    /// piège que les chemins nus des tâches. On essaie donc les emplacements réels ; ce
    /// qui reste introuvable partout est rendu tel quel, et la signature le dira sans
    /// accuser à tort.
    /// </para>
    /// </summary>
    private static string Resolve(string reference)
    {
        var expanded = Environment.ExpandEnvironmentVariables(reference);

        if (expanded.Contains('\\') || expanded.Contains('/'))
        {
            return expanded;
        }

        var candidates = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), expanded),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), expanded),
        };

        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                candidates.Add(Path.Combine(directory.Trim(), expanded));
            }
            catch (ArgumentException)
            {
                // Une entrée de PATH mal formée ne doit pas arrêter la résolution.
            }
        }

        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }
}
