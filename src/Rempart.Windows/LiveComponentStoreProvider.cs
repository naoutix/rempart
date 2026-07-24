using System.Diagnostics;
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// A reading together with the output it was derived from, and the tool's exit code.
/// </summary>
public sealed record ComponentStoreDiagnosis(
    ComponentStoreRead Read, string RawOutput, int ExitCode);

/// <summary>
/// Asks the servicing stack how large the component store is.
///
/// <para>
/// The only provider in the project that runs another program. There is no API for this:
/// the figures come from <c>DISM</c>, and measuring <c>WinSxS</c> from the filesystem
/// instead would count the same bytes several times — most of the store is hard-linked
/// into the live Windows installation.
/// </para>
///
/// <para>
/// <b>Analysis only.</b> The verb is <c>/AnalyzeComponentStore</c>, which reports;
/// <c>/StartComponentCleanup</c>, which deletes, exists on the same tool and is never
/// invoked. A test pins the argument list, because that is the difference between a v1
/// that writes nothing and one that does.
/// </para>
///
/// <para>
/// <b>Absolute path, not the search path.</b> The executable is taken from the system
/// directory. Resolving <c>dism.exe</c> through <c>PATH</c> would let a file dropped in
/// the working directory decide what an audit tool runs — on the very machines this
/// tool exists to distrust.
/// </para>
///
/// <para>
/// <b>English output is requested</b> (<c>/English</c>) so the parser faces one set of
/// labels. Without it the output follows the system language and the figures would be
/// read correctly on the developer's machine and nowhere else.
/// </para>
/// </summary>
public sealed class LiveComponentStoreProvider(TimeSpan? timeout = null) : IComponentStoreProvider
{
    /// <summary>Elevation refused, before any work is done.</summary>
    private const int ElevationRequired = 740;

    /// <summary>
    /// Read-only by construction. Kept as a field so a test can assert that no cleanup
    /// verb ever appears here.
    /// </summary>
    public static readonly IReadOnlyList<string> Arguments =
        ["/Online", "/Cleanup-Image", "/AnalyzeComponentStore", "/English"];

    private readonly TimeSpan budget = timeout ?? TimeSpan.FromMinutes(3);

    public ComponentStoreRead Read() => Diagnose().Read;

    /// <summary>
    /// The reading, plus the raw output it came from.
    ///
    /// Exists for <c>rempart diagnose-store</c>, for the same reason
    /// <c>diagnose-wmi</c> and <c>diagnose-tasks</c> exist: a parser that silently
    /// stops recognising its input produces a scan reporting nothing, which looks
    /// exactly like a machine with nothing to report. Confronting the labels with the
    /// real output is the only way to know, and it takes an elevated run.
    /// </summary>
    public ComponentStoreDiagnosis Diagnose()
    {
        var executable = Path.Combine(Environment.SystemDirectory, "Dism.exe");

        if (!File.Exists(executable))
        {
            return Only(ComponentStoreRead.Failed(
                $"Outil de maintenance introuvable : {executable}"));
        }

        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var argument in Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return Only(ComponentStoreRead.Failed("Le processus d'analyse n'a pas démarré."));
            }

            // Both streams are drained while the process runs: reading one to the end
            // first deadlocks as soon as the other fills its pipe buffer.
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit((int)budget.TotalMilliseconds))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Exited between the check and the kill: nothing to stop.
                }

                return Only(ComponentStoreRead.Failed(
                    $"L'analyse du magasin n'a pas répondu en {budget.TotalSeconds:0} s. "
                    + "Une maintenance Windows est peut-être en cours."));
            }

            var text = output.GetAwaiter().GetResult();
            var diagnostic = errors.GetAwaiter().GetResult();

            if (process.ExitCode == ElevationRequired)
            {
                return new ComponentStoreDiagnosis(ComponentStoreRead.Denied(
                    "L'analyse du magasin de composants exige l'élévation. Relancer en "
                    + "administrateur ; sans cela, l'espace récupérable reste inconnu."),
                    text, process.ExitCode);
            }

            if (process.ExitCode != 0)
            {
                return new ComponentStoreDiagnosis(ComponentStoreRead.Failed(
                    $"L'analyse du magasin a échoué (code {process.ExitCode}) : "
                    + Summarise(string.IsNullOrWhiteSpace(diagnostic) ? text : diagnostic)),
                    string.IsNullOrWhiteSpace(text) ? diagnostic : text, process.ExitCode);
            }

            return new ComponentStoreDiagnosis(ComponentStoreParser.Parse(text), text, 0);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            return Only(ComponentStoreRead.Failed($"Analyse du magasin impossible : {ex.Message}"));
        }
    }

    /// <summary>A failure that produced no output worth showing.</summary>
    private static ComponentStoreDiagnosis Only(ComponentStoreRead read) =>
        new(read, string.Empty, -1);

    /// <summary>
    /// Keeps a diagnostic to one readable line: DISM prints a banner and a progress bar
    /// before anything useful, and pasting the lot into a report would bury the reason.
    /// </summary>
    private static string Summarise(string output)
    {
        var meaningful = output
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('[') && !line.StartsWith('='))
            .LastOrDefault();

        return meaningful ?? "aucun message";
    }
}
