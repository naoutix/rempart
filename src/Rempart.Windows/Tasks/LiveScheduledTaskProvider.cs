using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Xml.Linq;
using Rempart.Core.Providers;
using Rempart.Windows.Wmi;

namespace Rempart.Windows.Tasks;

/// <summary>
/// Enumerates scheduled tasks through the Task Scheduler COM API.
///
/// <para>
/// Tasks also exist as XML files in <c>%SystemRoot%\System32\Tasks</c>, and reading
/// them would have avoided all this COM. Two reasons not to: the scheduler keeps the
/// real enabled state in the registry, which a file on disk can contradict; and above
/// all, a task whose registry entry is removed disappears from the scheduler without
/// its file being deleted. Reading the files would therefore return tasks that do not
/// run, the exact opposite of what this provider is for.
/// </para>
///
/// <para>
/// Non-elevated enumeration sees the user's tasks and most system tasks; some folders
/// remain denied. A denial is recorded and enumeration continues: a partial, honest
/// inventory is better than none.
/// </para>
/// </summary>
public sealed unsafe partial class LiveScheduledTaskProvider : IScheduledTaskProvider
{
    private const int ClsctxInprocServer = 1;
    private const int ClsctxLocalServer = 4;

    /// <summary>
    /// Guard against a cyclic or absurd folder tree. Real folder trees do not exceed
    /// three or four levels; past that, stop rather than loop.
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

                // A failure must not masquerade as access denied: that confusion
                // already led to the wrong conclusion that elevation would be enough.
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
    /// Walks a folder and its subfolders. An unreadable folder is skipped without
    /// interrupting the others: most tasks live under <c>\Microsoft\Windows</c>, and
    /// losing one branch must not cost the rest.
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

    /// <summary>An integer VARIANT: COM collections are indexed starting at 1.</summary>
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

        // An unreadable definition must not remove the task from the inventory:
        // return it without its actions rather than not at all.
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
                // Signaled by the absence of actions, not silently: the collector
                // turns it into a "not assessed" finding rather than a task with no
                // action.
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
                // ComHandler, SendEmail, ShowMessage: legacy action types, still
                // present on real machines. Enumerated without a file target — the
                // collector will not pretend to verify their signature.
                actions.Add(new TaskAction(element.Name.LocalName, string.Empty, string.Empty));
            }
        }

        return actions;
    }

    /// <summary>
    /// Resolves an executable path the way the scheduler would.
    ///
    /// <para>
    /// Two notations to handle. Environment variables first: system tasks write
    /// <c>%windir%\system32\...</c>, and without expansion no verification would find
    /// the file.
    /// </para>
    ///
    /// <para>
    /// Then the bare name — <c>sc.exe</c>, <c>BthUdTask.exe</c> — which the scheduler
    /// resolves at run time. Not resolving it here produced two "target file does not
    /// exist" findings on binaries that were present in System32. That is a resolution
    /// gap disguised as a fact about the machine, which this project must not let
    /// through.
    /// </para>
    ///
    /// <para>
    /// A name that still cannot be found is returned as is, without a directory: the
    /// collector reads that as "could not resolve" and says so, rather than blaming
    /// the file.
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
                // A malformed PATH entry must not stop the search.
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
    /// <c>TASK_STATE</c>. Rendered as text because the snapshot serializes it, and a
    /// bare integer in a fixture cannot be read back meaningfully.
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
