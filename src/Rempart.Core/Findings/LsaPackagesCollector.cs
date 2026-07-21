using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Paquets chargés par l'autorité de sécurité locale (LSA).
///
/// <para>
/// LSA charge des DLL nommées dans le registre : fournisseurs d'authentification,
/// paquets de sécurité (SSP), paquets de notification de mot de passe. Une DLL ajoutée
/// à ces listes s'exécute dans le processus qui manipule les identifiants — c'est la
/// technique d'un vol d'identifiants persistant (le <c>mimilib</c> de mimikatz s'y
/// enregistre). Aucun outil grand public ne regarde là.
/// </para>
///
/// <para>
/// Sur une machine saine, ces paquets sont tous signés par Microsoft. Le signal est
/// donc une DLL non signée ou dont la signature ne vérifie pas — jugée par la même
/// échelle que le reste (<see cref="SignatureLadder"/>). Un paquet tiers légitimement
/// signé (carte à puce, par exemple) reste bénin : c'est l'absence de signature qui
/// alerte, pas la simple présence.
/// </para>
/// </summary>
public sealed class LsaPackagesCollector : IFindingCollector
{
    private const string Lsa = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    // Newer Windows a déplacé les paquets de sécurité sous ce sous-clé : on lit les deux
    // emplacements, sans quoi la surface serait manquée sur les builds récents.
    private const string LsaOsConfig = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig";

    private static readonly (string Key, string Value)[] Sources =
    [
        (Lsa, "Authentication Packages"),
        (Lsa, "Notification Packages"),
        (Lsa, "Security Packages"),
        (LsaOsConfig, "Security Packages"),
    ];

    public string Name => "lsa-packages";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (key, value) in Sources)
        {
            var read = providers.Registry.ReadValue(key, value);

            if (read.Status == ReadStatus.AccessDenied)
            {
                // Ne pas se taire : une liste illisible n'est pas une liste vide, et
                // c'est justement là qu'un paquet malveillant se logerait.
                findings.Add(new Finding("lsa-package", $"Lsa\\{value}", "—",
                    FindingSeverity.Notable,
                    ["Liste refusée à la lecture. Relancer en administrateur : un paquet " +
                     "LSA ajouté resterait invisible."],
                    new Dictionary<string, string>()));
                continue;
            }

            if (read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            // REG_MULTI_SZ est rendu joint par des sauts de ligne par le provider ;
            // certains paquets peuvent aussi apparaître separés par des espaces.
            foreach (var raw in text.Split(['\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // Windows note une liste vide par une valeur littérale « "" » : après
                // retrait des guillemets il ne reste rien. Ce n'est pas un paquet, et le
                // résoudre en « "".dll » faisait ressortir un introuvable inventé.
                var package = raw.Trim('"');
                if (package.Length == 0 || !seen.Add(package))
                {
                    // Marqueur de liste vide, ou paquet déjà jugé à un autre emplacement.
                    continue;
                }

                var path = Resolve(package);
                var judgement = SignatureLadder.Judge(path, providers.Signatures);

                var details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["paquet"] = package,
                    ["liste"] = value,
                };
                SignatureLadder.Describe(judgement.Signature, details);

                findings.Add(new Finding(
                    "lsa-package", $"Lsa\\{value}", path,
                    judgement.Severity, judgement.Reasons, details));
            }
        }

        return findings;
    }

    /// <summary>
    /// Un nom de paquet LSA est une DLL de System32, sans chemin ni toujours d'extension.
    /// Résolu en dur — <c>C:\Windows\System32\&lt;nom&gt;.dll</c> — sans toucher au disque
    /// ni à <c>System.IO.Path</c>, pour que capture et rejeu produisent le même chemin
    /// quelle que soit la machine.
    /// </summary>
    private static string Resolve(string package)
    {
        if (package.Contains('\\') || package.Contains('/'))
        {
            return package;
        }

        var name = package.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? package
            : package + ".dll";

        return @"C:\Windows\System32\" + name;
    }
}
