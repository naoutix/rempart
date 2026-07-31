using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Reads the <c>hosts</c> file from disk.
///
/// <para>
/// Its location is fixed — <c>%SystemRoot%\System32\drivers\etc\hosts</c>. The scan of the
/// other surfaces continues whatever this one answers, so nothing here throws; what it
/// answers, however, now distinguishes the three states this class used to fold into one.
/// « Pas de fichier hosts » really is « aucune entrée ». <b>« Fichier hosts illisible » never
/// was</b>, and denying read access to it is exactly how a redirection already in place
/// protects itself — the report then said nothing about the surface built to catch it.
/// </para>
/// </summary>
/// <param name="systemRoot">
/// Where Windows lives. A parameter so a test can stage an unreadable file without touching
/// the machine's own; production reads it from the environment as before.
/// </param>
public sealed class LiveHostsFileProvider(string? systemRoot = null) : IHostsFileProvider
{
    public HostsFileRead ReadLines()
    {
        var root = systemRoot
            ?? Environment.GetEnvironmentVariable("SystemRoot")
            ?? @"C:\Windows";

        var path = $@"{root}\System32\drivers\etc\hosts";

        try
        {
            return HostsFileRead.Found(File.ReadAllLines(path));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // An answer, not a failure: a machine with no hosts file resolves through DNS
            // alone, which is what a file holding only comments means too.
            return HostsFileRead.Absent;
        }
        catch (UnauthorizedAccessException)
        {
            // An ACL, so a genuine denial, and now returned as one rather than through the
            // factory that also served the branch below.
            return HostsFileRead.Refused(
                "Fichier hosts illisible : accès refusé. Une redirection posée là "
                + "court-circuiterait la résolution DNS sans apparaître ici.");
        }
        catch (IOException ex)
        {
            // Not a denial, and no longer returned as one — the invariant CONTRIBUTING
            // records. A file held open with no sharing lands here, and it is as ordinary a
            // way to keep a redirection unread as an ACL: what must be said is what happened.
            //
            // These two catches were already separate, and already worded apart; what they
            // shared was the state they returned, which is the only thing HostsFileCollector
            // could branch on. Separating the wording without separating the state is what
            // let the collector keep answering « relancer en administrateur » here.
            return HostsFileRead.Failed(
                $"Fichier hosts illisible : {ex.Message} Une redirection posée là "
                + "court-circuiterait la résolution DNS sans apparaître ici.");
        }
    }
}
