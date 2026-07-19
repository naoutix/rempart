using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Remplace les identifiants machine par des empreintes stables.
///
/// Actif par défaut à la capture : les fixtures finissent versionnées, et un instantané
/// brut porte hostname, numéro de série et propriétaire enregistré. Le hachage reste
/// stable, donc deux captures de la même machine restent comparables.
/// </summary>
public static class Anonymiser
{
    private const string Prefix = "anon:";

    /// <summary>Noms de valeurs dont le contenu identifie la machine ou son détenteur.</summary>
    private static readonly string[] SensitiveValueFragments =
    [
        "serial",
        "owner",
        "organization",
        "username",
        "uuid",
        "productid",
    ];

    public static MachineSnapshot Apply(MachineSnapshot snapshot)
    {
        foreach (var (key, read) in snapshot.Registry)
        {
            if (read.Value?.Text is not { Length: > 0 } text)
            {
                continue;
            }

            var valueName = key[(key.LastIndexOf("||", StringComparison.Ordinal) + 2)..];
            if (IsSensitive(valueName))
            {
                snapshot.Registry[key] = read with { Value = read.Value with { Text = Hash(text) } };
            }
        }

        if (snapshot.SystemInfo is { } info)
        {
            snapshot.SystemInfo = info with { MachineName = Hash(info.MachineName) };
        }

        snapshot.Anonymised = true;
        return snapshot;
    }

    private static bool IsSensitive(string valueName) =>
        SensitiveValueFragments.Any(fragment =>
            valueName.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    /// <summary>Empreinte tronquée : suffisante pour comparer, insuffisante pour identifier.</summary>
    public static string Hash(string input)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Prefix + Convert.ToHexStringLower(digest)[..12];
    }
}
