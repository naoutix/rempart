using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Détournement COM par enregistrement d'un composant côté utilisateur.
///
/// <para>
/// Quand une application résout un CLSID, Windows consulte d'abord
/// <c>HKCU\Software\Classes\CLSID</c> avant <c>HKLM</c>. Un objet enregistré là s'exécute
/// donc à la place du composant système attendu — sans droits d'administrateur, puisque
/// la ruche de l'utilisateur lui appartient. C'est le « COM hijacking » : une persistance
/// discrète, qu'aucune clé <c>Run</c> ne révèle.
/// </para>
///
/// <para>
/// Sur une machine saine, cette ruche contient peu d'enregistrements. Chacun est jugé sur
/// la signature de la bibliothèque qu'il désigne (<see cref="SignatureLadder"/>), et sa
/// seule présence côté utilisateur est notable — c'est l'emplacement inscriptible sans
/// privilège qui en fait un vecteur, pas la nature du composant.
/// </para>
/// </summary>
public sealed class ComHijackCollector : IFindingCollector
{
    private const string UserClsid = @"HKCU\Software\Classes\CLSID";

    // Les deux formes de serveur COM : une DLL chargée dans le processus, ou un
    // exécutable lancé à part. Les deux exécutent du code, les deux sont détournables.
    private static readonly string[] ServerKinds = ["InprocServer32", "LocalServer32"];

    public string Name => "com-hijack";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var clsid in providers.Registry.ListSubKeys(UserClsid))
        {
            foreach (var kind in ServerKinds)
            {
                var serverKey = $"{UserClsid}\\{clsid}\\{kind}";
                var read = providers.Registry.ReadValue(serverKey, string.Empty);

                if (read.Status != ReadStatus.Found || read.Value?.Text is not { Length: > 0 } server)
                {
                    continue;
                }

                findings.Add(Examine(clsid, kind, server, providers.Signatures));
            }
        }

        return findings;
    }

    private static Finding Examine(
        string clsid, string kind, string server, ISignatureProvider signatures)
    {
        var path = Resolve(server);
        var judgement = SignatureLadder.Judge(path, signatures);

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["clsid"] = clsid,
            ["serveur"] = server,
        };
        SignatureLadder.Describe(judgement.Signature, details);

        // La présence même d'un composant COM côté utilisateur mérite un regard : c'est
        // l'emplacement inscriptible sans privilège qui fait le vecteur. On pose donc un
        // plancher Notable, sans jamais abaisser un binaire déjà suspect par sa signature.
        var floor = FindingSeverity.Notable;
        var severity = judgement.Severity < floor ? floor : judgement.Severity;

        return new Finding(
            "com-hijack", $"CLSID {clsid} ({kind})", path, severity,
            [$"Composant COM enregistré côté utilisateur ({kind}) : il prime sur le "
             + "composant système de même CLSID, sans droits d'administrateur.",
             .. judgement.Reasons],
            details);
    }

    /// <summary>
    /// Chemin du binaire d'un serveur COM. Une valeur <c>LocalServer32</c> est une ligne
    /// de commande — <c>"C:\…\app.exe" -ToastActivated</c> — dont il faut extraire le seul
    /// exécutable ; sans quoi les arguments et le guillemet fermant se collent au chemin,
    /// qui ressort alors introuvable. Un <c>InprocServer32</c> est un chemin de DLL nu.
    ///
    /// <para>
    /// Un chemin complet est rendu tel quel ; un nom nu est supposé en System32. En dur,
    /// sans toucher au disque ni à <c>System.IO.Path</c>, pour que capture et rejeu
    /// produisent le même chemin quelle que soit la machine.
    /// </para>
    /// </summary>
    private static string Resolve(string server)
    {
        var executable = ExtractExecutable(server.Trim());

        return executable.Length == 0 || executable.Contains('\\') || executable.Contains('/')
            ? executable
            : @"C:\Windows\System32\" + executable;
    }

    private static string ExtractExecutable(string value)
    {
        if (value.StartsWith('"'))
        {
            var closing = value.IndexOf('"', 1);
            return closing > 0 ? value[1..closing] : value[1..];
        }

        foreach (var extension in (string[])[".exe", ".dll"])
        {
            var at = value.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            if (at >= 0)
            {
                return value[..(at + extension.Length)];
            }
        }

        return value;
    }
}
