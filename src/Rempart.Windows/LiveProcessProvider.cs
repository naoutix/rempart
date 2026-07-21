using System.Globalization;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Énumère les processus en cours via WMI (<c>Win32_Process</c>).
///
/// <para>
/// Même choix que pour les pilotes : WMI donne chemin, parent et ligne de commande en
/// une requête, sans P/Invoke à la chaîne (toolhelp, puis ouverture de chaque processus
/// pour son chemin, puis le PEB pour la ligne de commande). La ligne de commande d'un
/// processus appartenant à un autre utilisateur peut rester vide hors élévation — c'est
/// une lacune de droits, pas une absence, et le collecteur ne l'interprète pas autrement.
/// </para>
///
/// <para>
/// Les processus sans chemin — <c>System</c>, <c>Registry</c>, la compression mémoire —
/// sont écartés : ce sont des pseudo-processus du noyau, sans fichier à juger. Les
/// retenir n'ajouterait que du bruit invérifiable.
/// </para>
/// </summary>
public sealed class LiveProcessProvider(IWmiProvider wmi) : IProcessProvider
{
    private const string Namespace = @"root\CIMV2";

    public LiveProcessProvider()
        : this(new Wmi.LiveWmiProvider())
    {
    }

    public IReadOnlyList<RunningProcess> Enumerate()
    {
        var read = wmi.Query(Namespace, "Win32_Process",
            ["ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine"]);

        if (read.Status != ReadStatus.Found)
        {
            return [];
        }

        var processes = new List<RunningProcess>();

        foreach (var instance in read.Instances)
        {
            var path = instance.Find("ExecutablePath");
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            processes.Add(new RunningProcess(
                Number(instance.Find("ProcessId")),
                Number(instance.Find("ParentProcessId")),
                instance.Find("Name") ?? System.IO.Path.GetFileName(path),
                path,
                instance.Find("CommandLine") ?? string.Empty));
        }

        return processes;
    }

    private static int Number(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;
}
