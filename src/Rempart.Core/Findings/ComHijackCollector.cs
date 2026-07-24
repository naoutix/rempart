using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// COM hijacking through a user-side component registration.
///
/// <para>
/// When an application resolves a CLSID, Windows consults
/// <c>HKCU\Software\Classes\CLSID</c> before <c>HKLM</c>. An object registered there
/// therefore runs in place of the expected system component — without administrator
/// rights, since the user's hive belongs to them. This is "COM hijacking": a discreet
/// persistence that no <c>Run</c> key reveals.
/// </para>
///
/// <para>
/// On a healthy machine, this hive holds few registrations. Each is judged on the
/// signature of the library it points to (<see cref="SignatureLadder"/>), and its mere
/// presence on the user side is notable — what makes it a vector is the location being
/// writable without privilege, not the nature of the component.
/// </para>
/// </summary>
public sealed class ComHijackCollector : IFindingCollector
{
    private const string UserClsid = @"HKCU\Software\Classes\CLSID";

    // The two forms of COM server: a DLL loaded into the process, or an executable
    // launched separately. Both execute code, both can be hijacked.
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

        // The very presence of a user-side COM component deserves a look: the location,
        // writable without privilege, is what makes the vector. So we set a Notable
        // floor, without ever lowering a binary already suspicious by its signature.
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
    /// Path of a COM server's binary. A <c>LocalServer32</c> value is a command line —
    /// <c>"C:\…\app.exe" -ToastActivated</c> — from which the executable alone must be
    /// extracted; otherwise the arguments and the closing quote stick to the path, which
    /// then comes out as not found. An <c>InprocServer32</c> is a bare DLL path.
    ///
    /// <para>
    /// A full path is returned as-is; a bare name is assumed to be in System32. Hardcoded,
    /// without touching the disk or <c>System.IO.Path</c>, so that capture and replay
    /// produce the same path whatever the machine.
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
