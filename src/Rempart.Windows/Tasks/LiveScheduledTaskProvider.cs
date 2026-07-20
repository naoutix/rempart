using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Xml.Linq;
using Rempart.Core.Providers;
using Rempart.Windows.Wmi;

namespace Rempart.Windows.Tasks;

/// <summary>
/// Énumère les tâches planifiées par l'API COM du planificateur.
///
/// <para>
/// Les tâches vivent aussi sous forme de fichiers XML dans
/// <c>%SystemRoot%\System32\Tasks</c>, et les lire aurait évité tout ce COM. Deux
/// raisons de ne pas le faire : le planificateur tient l'état d'activation réel dans
/// le registre, qu'un fichier sur disque peut contredire ; et surtout, une tâche dont
/// on retire l'entrée de registre disparaît de l'ordonnanceur sans que son fichier
/// s'efface. Lire les fichiers rendrait donc des tâches qui ne s'exécutent pas, et
/// c'est exactement l'inverse du service rendu.
/// </para>
///
/// <para>
/// L'énumération non élevée voit les tâches de l'utilisateur et la plupart des tâches
/// système ; certains dossiers restent refusés. Un refus est consigné et
/// l'énumération continue : un inventaire partiel et honnête vaut mieux qu'aucun.
/// </para>
/// </summary>
public sealed unsafe partial class LiveScheduledTaskProvider : IScheduledTaskProvider
{
    private const int ClsctxInprocServer = 1;
    private const int ClsctxLocalServer = 4;

    /// <summary>
    /// Garde-fou contre une arborescence cyclique ou absurde. Les dossiers réels ne
    /// dépassent pas trois ou quatre niveaux ; au-delà on arrête plutôt que de tourner.
    /// </summary>
    private const int MaxDepth = 16;

    private static readonly XNamespace TaskNs =
        "http://schemas.microsoft.com/windows/2004/02/mit/task";

    [LibraryImport("ole32.dll")]
    private static partial int CoCreateInstance(
        in Guid clsid, IntPtr outer, int context, in Guid iid, out IntPtr instance);

    public ScheduledTaskRead Enumerate()
    {
        try
        {
            return Execute();
        }
        catch (COMException ex)
        {
            return (uint)ex.HResult switch
            {
                0x80070005 => ScheduledTaskRead.AccessDenied,

                // Une défaillance ne doit pas se déguiser en refus d'accès : cette
                // confusion a déjà fait conclure à tort qu'une élévation suffirait.
                _ => ScheduledTaskRead.Failed($"COM 0x{(uint)ex.HResult:X8} : {ex.Message}"),
            };
        }
        catch (Exception ex)
        {
            return ScheduledTaskRead.Failed($"{ex.GetType().Name} : {ex.Message}");
        }
    }

    private static ScheduledTaskRead Execute()
    {
        var service = CreateService();

        var empty = default(Variant);
        if (service.Connect(empty, empty, empty, empty) is var connected && connected < 0)
        {
            throw new COMException("ITaskService.Connect", connected);
        }

        if (service.GetFolder("\\", out var root) is var folder && folder < 0)
        {
            throw new COMException("GetFolder(\\)", folder);
        }

        var tasks = new List<ScheduledTask>();
        Walk(root, tasks, 0);

        return ScheduledTaskRead.Found(tasks);
    }

    private static ITaskService CreateService()
    {
        var result = CoCreateInstance(
            in TaskSchedulerIds.ClsidTaskScheduler,
            IntPtr.Zero,
            ClsctxInprocServer | ClsctxLocalServer,
            in TaskSchedulerIds.IidTaskService,
            out var pointer);

        if (result < 0)
        {
            throw new COMException("CoCreateInstance(TaskScheduler)", result);
        }

        try
        {
            return ComInterfaceMarshaller<ITaskService>.ConvertToManaged((void*)pointer)
                ?? throw new COMException("ITaskService non résolue", result);
        }
        finally
        {
            Marshal.Release(pointer);
        }
    }

    /// <summary>
    /// Parcourt un dossier et ses sous-dossiers. Un dossier illisible est ignoré sans
    /// interrompre les autres : la plupart des tâches vivent sous
    /// <c>\Microsoft\Windows</c>, en perdre une branche ne doit pas coûter le reste.
    /// </summary>
    private static void Walk(ITaskFolder folder, List<ScheduledTask> tasks, int depth)
    {
        if (depth > MaxDepth)
        {
            return;
        }

        if (folder.GetTasks(TaskSchedulerIds.EnumHidden, out var collection) >= 0
            && collection.get_Count(out var count) >= 0)
        {
            for (var i = 1; i <= count; i++)
            {
                if (collection.get_Item(Index(i), out var task) >= 0)
                {
                    if (Read(task) is { } read)
                    {
                        tasks.Add(read);
                    }
                }
            }
        }

        if (folder.GetFolders(0, out var children) < 0
            || children.get_Count(out var childCount) < 0)
        {
            return;
        }

        for (var i = 1; i <= childCount; i++)
        {
            if (children.get_Item(Index(i), out var child) >= 0)
            {
                Walk(child, tasks, depth + 1);
            }
        }
    }

    /// <summary>Un VARIANT entier : les collections COM s'indexent à partir de 1.</summary>
    private static Variant Index(int value) =>
        new() { Vt = VariantType.I4, Data = (IntPtr)value };

    private static ScheduledTask? Read(IRegisteredTask task)
    {
        if (task.get_Path(out var path) < 0)
        {
            return null;
        }

        task.get_Name(out var name);
        task.get_State(out var state);
        task.get_Enabled(out var enabled);

        var author = (string?)null;
        var userId = (string?)null;
        var runLevel = (string?)null;
        var actions = (IReadOnlyList<TaskAction>)[];

        // Une définition illisible ne doit pas faire disparaître la tâche de
        // l'inventaire : on la rend sans ses actions plutôt que pas du tout.
        if (task.get_Xml(out var xml) >= 0 && !string.IsNullOrEmpty(xml))
        {
            try
            {
                var document = XDocument.Parse(xml);
                author = Text(document, TaskNs + "RegistrationInfo", TaskNs + "Author");
                userId = Text(document, TaskNs + "Principals", TaskNs + "Principal",
                    TaskNs + "UserId");
                runLevel = Text(document, TaskNs + "Principals", TaskNs + "Principal",
                    TaskNs + "RunLevel");
                actions = ReadActions(document);
            }
            catch (System.Xml.XmlException)
            {
                // Signalé par l'absence d'actions, pas par un silence : le collecteur
                // en fait un constat « non jugée » plutôt qu'une tâche sans action.
            }
        }

        return new ScheduledTask(
            path, name ?? path, enabled != 0, StateName(state),
            author, userId, runLevel, actions);
    }

    private static IReadOnlyList<TaskAction> ReadActions(XDocument document)
    {
        var container = document.Root?.Element(TaskNs + "Actions");
        if (container is null)
        {
            return [];
        }

        var actions = new List<TaskAction>();

        foreach (var element in container.Elements())
        {
            if (element.Name == TaskNs + "Exec")
            {
                var command = element.Element(TaskNs + "Command")?.Value ?? string.Empty;
                var arguments = element.Element(TaskNs + "Arguments")?.Value ?? string.Empty;

                actions.Add(new TaskAction("exec", Expand(command), arguments.Trim()));
            }
            else
            {
                // ComHandler, SendEmail, ShowMessage : formes héritées, encore
                // présentes sur des machines réelles. Énumérées sans cible de
                // fichier — le collecteur ne prétendra pas en vérifier la signature.
                actions.Add(new TaskAction(element.Name.LocalName, string.Empty, string.Empty));
            }
        }

        return actions;
    }

    /// <summary>
    /// Résout le chemin d'un exécutable tel que le planificateur le ferait.
    ///
    /// <para>
    /// Deux écritures à traiter. Les variables d'environnement d'abord : les tâches du
    /// système écrivent <c>%windir%\system32\...</c>, et sans expansion aucune
    /// vérification ne trouverait le fichier.
    /// </para>
    ///
    /// <para>
    /// Le nom nu ensuite — <c>sc.exe</c>, <c>BthUdTask.exe</c> — que le planificateur
    /// résout à l'exécution. Ne pas le résoudre ici a produit deux constats « le
    /// fichier visé n'existe pas » sur des binaires parfaitement présents dans
    /// System32. C'est une lacune de résolution déguisée en fait sur la machine, et
    /// c'est précisément ce que ce projet refuse de laisser passer.
    /// </para>
    ///
    /// <para>
    /// Un nom qui reste introuvable est rendu tel quel, sans dossier : le collecteur y
    /// lit qu'il n'a pas su résoudre, et le dit, plutôt que d'accuser le fichier.
    /// </para>
    /// </summary>
    private static string Expand(string command)
    {
        var trimmed = Environment.ExpandEnvironmentVariables(command.Trim().Trim('"'));

        if (trimmed.Length == 0 || trimmed.Contains(Path.DirectorySeparatorChar)
            || trimmed.Contains(Path.AltDirectorySeparatorChar))
        {
            return trimmed;
        }

        return Resolve(trimmed) ?? trimmed;
    }

    private static string? Resolve(string fileName)
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var candidate = Path.Combine(system, fileName);
        if (File.Exists(candidate))
        {
            return candidate;
        }

        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                candidate = Path.Combine(directory.Trim(), fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch (ArgumentException)
            {
                // Une entree de PATH mal formee ne doit pas arreter la recherche.
            }
        }

        return null;
    }

    private static string? Text(XDocument document, params XName[] path)
    {
        XElement? current = document.Root;

        foreach (var name in path)
        {
            current = current?.Element(name);
        }

        var value = current?.Value.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    /// <summary>
    /// <c>TASK_STATE</c>. Rendu en texte parce que l'instantané le sérialise et qu'un
    /// entier nu dans une fixture ne se relit pas.
    /// </summary>
    private static string StateName(int state) => state switch
    {
        1 => "disabled",
        2 => "queued",
        3 => "ready",
        4 => "running",
        _ => "unknown",
    };
}
