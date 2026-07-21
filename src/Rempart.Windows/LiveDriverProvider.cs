using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Énumère les pilotes noyau chargés via WMI (<c>Win32_SystemDriver</c>).
///
/// <para>
/// La voie évidente — <c>EnumDeviceDrivers</c> — est un piège depuis Windows 10 : hors
/// élévation, elle rend le <b>nombre</b> de pilotes mais met leurs adresses noyau à
/// zéro, une protection contre la fuite d'adresses noyau (KASLR). Sans adresse, pas de
/// chemin, et l'énumération rendait zéro pilote en apparente réussite. Un succès qui
/// ment, exactement ce que ce projet traque.
/// </para>
///
/// <para>
/// <c>Win32_SystemDriver</c> donne le chemin du fichier directement, sans élévation et
/// sans jamais exposer d'adresse noyau. On ne retient que les pilotes <c>Running</c> :
/// un pilote installé mais arrêté ne s'exécute pas, et le dire chargé serait faux.
/// </para>
/// </summary>
public sealed class LiveDriverProvider(IWmiProvider wmi) : IDriverProvider
{
    private const string Namespace = @"root\CIMV2";

    public LiveDriverProvider()
        : this(new Wmi.LiveWmiProvider())
    {
    }

    public IReadOnlyList<LoadedDriver> Enumerate()
    {
        var read = wmi.Query(Namespace, "Win32_SystemDriver", ["Name", "PathName", "State"]);

        if (read.Status != ReadStatus.Found)
        {
            return [];
        }

        var drivers = new List<LoadedDriver>();

        foreach (var instance in read.Instances)
        {
            // Seuls les pilotes en cours d'exécution : les autres sont sur le disque
            // sans être chargés, et la surface qu'on veut juger est celle qui tourne.
            if (!string.Equals(instance.Find("State"), "Running", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var path = instance.Find("PathName");
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            drivers.Add(new LoadedDriver(
                instance.Find("Name") ?? Path.GetFileName(path), path));
        }

        return drivers;
    }
}
