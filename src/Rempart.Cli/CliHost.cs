using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Rules;
using Rempart.Core.Updates;
using System.Reflection;
using static Rempart.Core.Cli.CommandLine;

namespace Rempart.Cli;

/// <summary>
/// What the commands share, and what only the host can answer.
///
/// <para>
/// Everything here reads the machine the binary sits on: <c>AppContext.BaseDirectory</c>,
/// the clock, the console, the assembly. That is exactly why it stays in
/// <c>Rempart.Cli</c> and not in Core — <see cref="Path"/> is legitimate on a host path
/// and forbidden on a captured one, and a helper that joined paths from inside a library
/// replayed on the Linux job would break the fixtures.
/// </para>
///
/// <para>
/// The rule for landing here rather than beside a command: at least two commands call it.
/// A helper used by one command travels with that command, private, so that reading the
/// command shows the whole of it.
/// </para>
/// </summary>
internal static class CliHost
{
    /// <summary>
    /// The reference posture a fleet is held to, carried by the stick beside the binary —
    /// same idea as the update store and the rules folder.
    /// </summary>
    public static string BaselinePath() => Path.Combine(AppContext.BaseDirectory, "baseline.json");

    /// <summary>
    /// The effective catalog of a live scan: the embedded baseline (plus the <c>--rules</c>
    /// rules if any), completed by the store's update when it verifies.
    /// </summary>
    public static CatalogResolution ResolveLiveCatalog(string[] args) =>
        UpdateStore.Resolve(
            StoreDirectory(args),
            RuleCatalog.Load(RulesDirectory(args)),
            PinnedKeys.Verifier());

    /// <summary>
    /// The store travels with the binary: next to the executable by default, so a USB
    /// stick carries its up-to-date data without a companion folder to forget.
    /// </summary>
    public static string StoreDirectory(string[] args) =>
        OptionValue(args, "--store") ?? Path.Combine(AppContext.BaseDirectory, "rempart-data");

    /// <summary>
    /// Where the extra rules come from: <c>--rules</c>, or a <c>rules/</c> folder next to
    /// the binary.
    ///
    /// <para>
    /// Same reasoning as the update store above, and the same stick layout: plug it in, run
    /// it, nothing to remember. Fleet-specific checks travel beside the executable instead
    /// of in a command line nobody types the same way twice.
    /// </para>
    ///
    /// <para>
    /// Picked up, never silently: the header names the folder, and the rule fingerprint
    /// changes — which is what makes two reports comparable or not. The stick seal covers
    /// this folder for the same reason it covers the binary.
    /// </para>
    /// </summary>
    public static string? RulesDirectory(string[] args)
    {
        if (OptionValue(args, "--rules") is { } explicitly)
        {
            return explicitly;
        }

        var beside = Path.Combine(AppContext.BaseDirectory, "rules");
        return Directory.Exists(beside) ? beside : null;
    }

    /// <summary>
    /// The collectors this run wires up.
    ///
    /// <para>
    /// The component store analysis is opt-in: the servicing stack takes tens of seconds to
    /// answer and demands elevation. Adding that to every scan by default would turn a
    /// command that returns in a second into one that appears hung — the same reasoning that
    /// keeps <c>--probe-dns</c> off by default, for a local cost rather than a network one.
    /// </para>
    ///
    /// <para>
    /// This ternary is the whole of the link between the flag and the collector it adds, and
    /// no compiler holds it: dropping the collector from the true branch breaks nothing
    /// visible. The flag stays accepted, stays declared in <c>CommandSurface</c>, stays in the
    /// help, and does nothing — measured, with every test green. Held shut by
    /// <c>FieldCollectorRegistrationTests.Every_opt_in_collector_is_added_by_the_flag_it_names</c>,
    /// which reads this method as text because the Linux job does not compile this project.
    /// </para>
    ///
    /// <para>
    /// Four things about the line below are held, each of them because a looser pattern lets the
    /// matching one-token mutation through, measured green over the whole suite: the flag test
    /// is not negated, the true branch starts from
    /// <c>.. ScanEngine.DefaultCollectors</c> instead of replacing it, that
    /// branch appends exactly the collectors the guard declares opt-in, and no collector is
    /// constructed anywhere else in the method. Negating the test, or appending the collector
    /// to the false branch as well, runs the servicing stack on every scan — the cost the
    /// paragraph above exists to avoid; replacing the default table makes
    /// <c>--analyze-store</c> drop the <c>[inventory]</c> block instead of adding one.
    /// </para>
    ///
    /// <para>
    /// The guard recognises the shape written here and no other, so rewriting this ternary into
    /// an <c>if</c> means updating the guard along with it. That is the price of reading source
    /// rather than types, and it is paid loudly.
    /// </para>
    /// </summary>
    public static IReadOnlyList<ICollector> CollectorsFor(string[] args) =>
        HasFlag(args, "--analyze-store")
            ? [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()]
            : ScanEngine.DefaultCollectors;

    /// <summary>
    /// The report folder for this scan, suffixed if one is already there.
    ///
    /// Two scans of the same machine on the same day are the normal case — before and
    /// after a fix. Overwriting would destroy the "before", which is the half that is
    /// impossible to reproduce.
    /// </summary>
    public static string FreeFolder(string root, string name)
    {
        var candidate = Path.Combine(root, name);

        for (var attempt = 2; Directory.Exists(candidate) && attempt < 100; attempt++)
        {
            candidate = Path.Combine(root, $"{name}-{attempt}");
        }

        return candidate;
    }

    public static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Rempart cible Windows. Utiliser « scan --from <instantané> » pour rejouer hors-ligne.");
        }
    }

    /// <summary>
    /// Version read from the assembly. Hard-coded, it had already diverged twice from
    /// the batch actually shipped: the single source is &lt;Version&gt; in Directory.Build.props.
    /// </summary>
    public static string ToolVersion() =>
        System.Reflection.Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";

    public static string UtcNow() => DateTime.UtcNow.ToString("o");

    /// <summary>
    /// Reads without echo. The passphrase must not remain on screen.
    ///
    /// Shared, against the first sketch of this split which filed it under the seal:
    /// <c>keygen</c>, <c>sign</c> and <c>seal</c> all read a passphrase, so leaving it
    /// beside one of the three would have made the other two reach across for it.
    /// </summary>
    public static string ReadHidden()
    {
        var buffer = new System.Text.StringBuilder();

        while (true)
        {
            var pressed = Console.ReadKey(intercept: true);

            if (pressed.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer.ToString();
            }

            if (pressed.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                {
                    buffer.Length--;
                }

                continue;
            }

            if (!char.IsControl(pressed.KeyChar))
            {
                buffer.Append(pressed.KeyChar);
            }
        }
    }

    public static int Print(string text)
    {
        Console.WriteLine(text);
        return 0;
    }
}
