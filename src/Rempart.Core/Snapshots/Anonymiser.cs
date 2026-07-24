using System.Security.Cryptography;
using System.Text;
using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Replaces machine identifiers with stable digests.
///
/// On by default at capture time: fixtures end up under version control, and a raw
/// snapshot carries hostname, serial number and registered owner. The hash is stable,
/// so two captures of the same machine remain comparable.
/// </summary>
public static class Anonymiser
{
    private const string Prefix = "anon:";

    /// <summary>Value names whose content identifies the machine or its owner.</summary>
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

            // The account name also sneaks into perfectly innocuous values: a Run
            // entry pointing at %LOCALAPPDATA% is stored as a full path, and thus
            // carries someone's first name.
            var scrubbed = IsSensitive(valueName) ? Hash(text) : ScrubProfile(text);

            if (!string.Equals(scrubbed, text, StringComparison.Ordinal))
            {
                snapshot.Registry[key] = read with { Value = read.Value with { Text = scrubbed } };
            }
        }

        snapshot.Signatures = snapshot.Signatures
            .ToDictionary(entry => ScrubProfile(entry.Key), entry => entry.Value);

        // WMI values carry paths: Win32_Service returns the path of every service,
        // and a service installed under a profile names an account there. The
        // anonymiser used to skip them, so those paths leaked into versioned fixtures.
        snapshot.Wmi = snapshot.Wmi.ToDictionary(
            entry => entry.Key,
            entry => entry.Value with
            {
                Instances =
                [
                    .. entry.Value.Instances.Select(instance => new WmiInstance(
                        instance.Properties.ToDictionary(
                            property => property.Key,
                            property => ScrubProfile(property.Value),
                            StringComparer.OrdinalIgnoreCase))),
                ],
            });

        snapshot.Directories = snapshot.Directories.ToDictionary(
            entry => ScrubProfile(entry.Key),
            entry => entry.Value.Select(ScrubProfile).ToList());

        if (snapshot.SystemInfo is { } info)
        {
            snapshot.SystemInfo = info with { MachineName = Hash(info.MachineName) };
        }

        if (snapshot.ScheduledTasks is { } tasks && tasks.Tasks.Count > 0)
        {
            snapshot.ScheduledTasks = tasks with
            {
                Tasks =
                [
                    .. tasks.Tasks.Select(task => task with
                    {
                        Path = ScrubSegments(task.Path),
                        Name = ScrubSegments(task.Name),
                        Author = Depersonalise(task.Author),
                        UserId = Depersonalise(task.UserId),
                        Actions =
                        [
                            .. task.Actions.Select(action => action with
                            {
                                Path = ScrubProfile(action.Path),
                                Arguments = ScrubProfile(action.Arguments),
                            }),
                        ],
                    }),
                ],
            };
        }

        if (snapshot.Drivers is { Count: > 0 } drivers)
        {
            // Driver paths are system paths, but a third-party driver can live under
            // a user profile: scrubbed out of caution, as everywhere else.
            snapshot.Drivers =
            [
                .. drivers.Select(d => d with { Path = ScrubProfile(d.Path) }),
            ];
        }

        if (snapshot.Firewall is { Rules.Count: > 0 } firewall)
        {
            // A rule's application path sometimes carries a user profile — six rules
            // did on the reference machine. The owner SID (LUOwn), however, is not
            // kept at parse time, so there is nothing to scrub there.
            snapshot.Firewall = firewall with
            {
                Rules =
                [
                    .. firewall.Rules.Select(rule => rule.App is { } app
                        ? rule with { App = ScrubProfile(app) }
                        : rule),
                ],
            };
        }

        if (snapshot.Processes is { Count: > 0 } processes)
        {
            // The executable path is a clean path: the account segment is hashed.
            //
            // The command line, however, is emptied — not cleaned. It carries the
            // account name in forms a "\Users\x\" replacement cannot see: a
            // URL-encoded path ("%5CUsers%5Cx%5C"), a secret passed as an argument, or
            // the very command of the session that launched the capture. Claiming to
            // anonymise it would be a lie; a capture that calls itself anonymised must
            // be. A live scan still shows it — only the capture meant to travel loses it.
            snapshot.Processes =
            [
                .. processes.Select(p => p with
                {
                    Path = ScrubProfile(p.Path),
                    CommandLine = "",
                }),
            ];
        }

        if (snapshot.Proxy is { } proxy)
        {
            snapshot.Proxy = proxy with
            {
                WinInet = ScrubScope(proxy.WinInet),
                WinHttp = ScrubScope(proxy.WinHttp),
            };
        }

        if (snapshot.Wifi is { Count: > 0 } wifi)
        {
            // The SSID names a place — home, employer, café. It gets hashed; the
            // profile's security stays readable, as that is what a fixture must exercise.
            snapshot.Wifi = [.. wifi.Select(profile => profile with { Name = Hash(profile.Name) })];
        }

        if (snapshot.BrowserExtensions is { Count: > 0 } extensions)
        {
            // The profile directory name carries Firefox's per-install salt — an
            // installation identifier, masked like the hostname. The extension itself
            // is what the audit is about; it stays readable.
            snapshot.BrowserExtensions =
                [.. extensions.Select(e => e with { Profile = Hash(e.Profile) })];
        }

        snapshot.Anonymised = true;
        return snapshot;
    }

    /// <summary>
    /// Hashes the host of a server and of a PAC, preserving scheme, port and locality:
    /// replaying the collector must yield the same verdict as before anonymisation.
    /// </summary>
    private static ProxyScope ScrubScope(ProxyScope scope) => scope with
    {
        Server = ScrubHostPort(scope.Server),
        AutoConfigUrl = ScrubUrlHost(scope.AutoConfigUrl),
    };

    private static string? ScrubHostPort(string? server)
    {
        if (string.IsNullOrEmpty(server) || IsLocalToken(server))
        {
            return server;
        }

        var colon = server.LastIndexOf(':');
        // A trailing port (digits after the last ":") stays readable.
        return colon > 0 && server[(colon + 1)..].All(char.IsDigit)
            ? Hash(server[..colon]) + server[colon..]
            : Hash(server);
    }

    private static string? ScrubUrlHost(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || IsLocalToken(uri.Host))
        {
            return url;
        }

        return $"{uri.Scheme}://{Hash(uri.Host)}{uri.PathAndQuery}";
    }

    private static bool IsLocalToken(string value) =>
        value.Contains("127.0.0.1", StringComparison.Ordinal)
        || value.Contains("localhost", StringComparison.OrdinalIgnoreCase)
        || value.Contains("[::1]", StringComparison.Ordinal)
        || value is "::1";

    /// <summary>
    /// Hashes what designates a person, leaves the rest readable.
    ///
    /// A scheduled task names its author and the account it runs under. Both are
    /// sometimes harmless — "Microsoft Corporation", <c>S-1-5-18</c> which is the
    /// system account — and sometimes directly identifying: the
    /// <c>MACHINE\user</c> form, or a local account SID.
    ///
    /// Hashing everything would protect just as much but cost fixture readability: a
    /// system task could no longer be told apart from a user task, which is precisely
    /// what we want to be able to judge. The distinction is therefore explicit.
    /// </summary>
    /// <summary>
    /// Profile accounts that designate nobody: they exist identically on every
    /// Windows installation.
    /// </summary>
    private static readonly string[] ImpersonalProfiles =
        ["public", "default", "default user", "all users"];

    /// <summary>
    /// Replaces the account name in a profile path.
    ///
    /// <c>C:\Users\firstname\AppData\...</c> names someone. These paths serve as keys in
    /// the snapshot — verified signatures, enumerated directories — and also show up
    /// in <c>Run</c> registry values.
    ///
    /// Only the account segment is hashed: the rest of the path says which application
    /// starts at boot, and that is exactly what a fixture must preserve.
    /// </summary>
    internal static string ScrubProfile(string path)
    {
        const string Marker = @"\Users\";

        // Every occurrence, not just the first: a command line can carry the same
        // profile path several times — input and output, for instance — and hashing
        // only one would leave the account name readable elsewhere.
        var index = path.IndexOf(Marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return path;
        }

        var builder = new StringBuilder(path.Length);
        var cursor = 0;

        while (index >= 0)
        {
            var start = index + Marker.Length;
            var end = path.IndexOf('\\', start);
            if (end < 0)
            {
                end = path.Length;
            }

            var account = path[start..end];
            builder.Append(path, cursor, start - cursor);

            builder.Append(
                account.Length == 0
                    || account.StartsWith(Prefix, StringComparison.Ordinal)
                    || ImpersonalProfiles.Contains(account, StringComparer.OrdinalIgnoreCase)
                    ? account
                    : Hash(account));

            cursor = end;
            index = path.IndexOf(Marker, end, StringComparison.OrdinalIgnoreCase);
        }

        builder.Append(path, cursor, path.Length - cursor);
        return builder.ToString();
    }

    /// <summary>
    /// Replaces account SIDs buried in a path, leaving the rest untouched.
    ///
    /// Some applications create a per-user task folder and name it after the SID:
    /// <c>\SoftLanding\S-1-5-21-…-1002\…</c>. Hashing the whole path would make the
    /// fixture unreadable — one could no longer tell which application put what —
    /// when only the identifying segment is a problem.
    /// </summary>
    private static string ScrubSegments(string path) =>
        path.Contains("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
            ? string.Join('\\', path.Split('\\').Select(segment =>
                segment.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                    ? Hash(segment)
                    : segment))
            : path;

    private static string? Depersonalise(string? value) => value switch
    {
        null or "" => value,

        // S-1-5-21 prefixes the SIDs of accounts created on the machine or domain:
        // behind each one there is a person. The well-known authorities — S-1-5-18
        // for the system, S-1-5-19 and S-1-5-20 for services — designate nobody
        // and stay readable.
        _ when value.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) => Hash(value),

        // DOMAIN\user form: carries both the machine name and the account name.
        _ when value.Contains('\\') => Hash(value),

        _ => value,
    };

    private static bool IsSensitive(string valueName) =>
        SensitiveValueFragments.Any(fragment =>
            valueName.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    /// <summary>Truncated digest: enough to compare, not enough to identify.</summary>
    public static string Hash(string input)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Prefix + Convert.ToHexStringLower(digest)[..12];
    }
}
