using System.Text.RegularExpressions;
using Rempart.Core.Collectors;
using Rempart.Core.Engine;

namespace Rempart.Tests.Unit;

/// <summary>
/// Holds the field-collector tables against the collectors that actually exist — the
/// implementations compiled into <c>Rempart.Core</c>, the files that declare them, and, for
/// the ones deliberately left out of the default table, the command-line flag that is meant
/// to add them back.
///
/// <para>
/// The field half of D2, left open when <c>FindingCollectorRegistrationTests</c> closed the
/// finding half twenty lines lower in the same file. A field collector goes missing more
/// quietly than a finding collector: it produces no verdict and no finding, only keys under
/// <c>collectors[]</c>, so an unregistered one costs a paragraph of the report and nothing
/// else notices. Measured on this repository before this file existed: replacing the true
/// branch of <c>CliHost.CollectorsFor</c> with <c>ScanEngine.DefaultCollectors</c> turns
/// <c>--analyze-store</c> into a flag that does nothing whatsoever, and the whole suite stays
/// green — no golden moves, because a collector that never runs writes nothing that could.
/// </para>
///
/// <para>
/// Two tables, two different silences. Emptying <see cref="ScanEngine.DefaultCollectors"/>
/// does fail today, across a dozen renderings, because the fields of the single default
/// collector are printed in the golden console output — that is coverage of the collector,
/// not of the table. What the table alone answers for is the other direction: a field
/// collector written and never registered writes no key, so every reference stays identical
/// to the byte and the suite is green. Reproduced here as well, on a collector added for the
/// experiment and then removed.
/// </para>
///
/// <para>
/// Reflection would do away with both tables, but ADR-001 ships Native AOT without it, so
/// deriving the expectation is this file's job and not the scan path's. The CLI half is read
/// as <em>source</em> rather than as types: <c>Rempart.Cli</c> targets <c>net10.0-windows</c>
/// and the Linux job does not compile it, so a test referencing <c>CliHost</c> would never
/// run in CI — the same technique, for the same reason, as <c>CommandSurfaceTests</c>.
/// <see cref="Path"/> is legitimate here: these are paths on the machine running the test,
/// not Windows paths captured on one machine and replayed on another.
/// </para>
///
/// <para>
/// A guard that reads source can be green because its pattern matches the right thing, or
/// green because its pattern stopped looking — and the two are indistinguishable from the
/// pass. The obvious pattern for the flag half is the second kind: matching
/// <c>HasFlag(...) ? [</c> and any later <c>new X()</c> lets a negated test and a true branch
/// that discards the default table through, both measured green over the whole suite. So what
/// the pattern <em>refuses</em> is asserted here too, against bodies written in this file
/// rather than against <c>CliHost</c> — the real body is well-formed, so no assertion on it
/// can exercise a refusal. That is
/// <c>A_branch_the_flag_does_not_select_yields_no_pair</c> and the two cases beside it.
/// </para>
/// </summary>
public sealed class FieldCollectorRegistrationTests
{
    /// <summary>
    /// A collector kept out of the default registration on purpose, the flag that adds it
    /// back, and why it is not on by default.
    ///
    /// <para>
    /// The escape hatch of the twin guard is a bare <c>string[]</c>: a name can be appended
    /// to it without a line of reason, and nothing then checks that the exemption is still
    /// true. This one cannot be used that way. The collector is a <see cref="Type"/>, so
    /// renaming or deleting it stops the compilation instead of the guard; the reason is a
    /// constructor argument, so it cannot be left out, and every one of the three failures
    /// prints it; and the flag is not a comment but the subject of the third test below. An
    /// entry here does not exempt a collector from being reachable — it claims it is reachable
    /// another way, and that claim is confronted with <c>CliHost</c>.
    /// </para>
    ///
    /// <para>
    /// The first two tests subtract these names before comparing their sets, so their failure
    /// has to say so: a reader shown a balanced set with no mention of the subtraction cannot
    /// tell that a collector was taken out of the reckoning, let alone on what grounds. That is
    /// what <see cref="Exemptions"/> is for, and why it is in all three messages rather than
    /// only in the one that is about the flag.
    /// </para>
    /// </summary>
    private sealed record OptIn(Type Collector, string Flag, string Reason);

    private static readonly OptIn[] OptInCollectors =
    [
        new(typeof(ComponentStoreCollector), "--analyze-store",
            "la pile de maintenance met des dizaines de secondes à répondre et demande "
            + "l'élévation, donc l'analyse du magasin de composants est à la demande"),
    ];

    /// <summary>
    /// An unnegated flag test whose true branch keeps the default table and appends to it —
    /// the whole shape <c>CollectorsFor</c> uses to make a collector opt-in.
    ///
    /// <para>
    /// Every piece of that sentence is load-bearing, and the obvious pattern holds none of it.
    /// Looking for <c>HasFlag(...) ? [</c> followed by any <c>new X()</c> lets two mutations of
    /// a single token walk straight through, both measured green over the whole suite:
    /// <c>[.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()]</c> shortened to
    /// <c>[new ComponentStoreCollector()]</c> — the flag then <em>drops</em> the default
    /// collectors and the report loses its <c>[inventory]</c> block — and
    /// <c>HasFlag(args, …)</c> negated into <c>!HasFlag(args, …)</c> — the component store then
    /// runs on every scan, which is the tens of seconds and the elevation the <c>Reason</c>
    /// above exists to avoid, and <c>--analyze-store</c> becomes the flag that turns it off.
    /// Hence <c>\[\s*\.\.\s*ScanEngine\.DefaultCollectors\s*,</c> spelled out in the true
    /// branch, and the two lookbehinds: no word character before <c>HasFlag</c>, and no <c>!</c>
    /// separated from it by whitespace alone.
    /// </para>
    ///
    /// <para>
    /// What follows the comma is captured whole rather than up to the first constructor, so a
    /// flag appending two collectors reports both. A lazy <c>[^\]]*?new\s+(\w+)\(\)</c> stops at
    /// the first one and would fail a legitimate second with the false message « déclaré ici,
    /// absent de la branche que le drapeau sélectionne » — a red that names a collector sitting
    /// in the very branch it is reported missing from.
    /// </para>
    ///
    /// <para>
    /// Reading source means only the shapes written down here are recognised, so rewriting the
    /// ternary into an <c>if</c> fails this guard. That is the right side to fail on — the
    /// alternative is a pattern that quietly stops matching and reports success. The grammar
    /// itself is pinned by the six cases below — four refusals and two readings — against
    /// bodies written in this file, so that a future loosening of this pattern fails here
    /// rather than in silence.
    /// </para>
    /// </summary>
    private static readonly Regex AppendedBehindAFlag = new(
        """(?<!\w)(?<!!\s*)HasFlag\(args,\s*"(?<flag>--[a-z0-9-]+)"\)\s*\?\s*"""
        + """\[\s*\.\.\s*ScanEngine\.DefaultCollectors\s*,(?<appended>[^\]]*)\]""",
        RegexOptions.Compiled);

    /// <summary>
    /// A collector being built. Deliberately not restricted to names ending in
    /// <c>Collector</c>: anything constructed inside <c>CollectorsFor</c> is wiring, and one
    /// built outside an opt-in branch is what the second assertion of the third test refuses.
    /// </summary>
    private static readonly Regex Constructed = new(
        """new\s+(\w+)\(\)""",
        RegexOptions.Compiled);

    /// <summary>
    /// Reads a <c>CollectorsFor</c> body: the flag-to-collector pairs it appends behind a
    /// flag, and the collectors it builds anywhere else.
    ///
    /// <para>
    /// The second half is what catches the mirror mutation of the negation — appending the
    /// opt-in collector to the <em>false</em> branch as well, which also runs it on every scan
    /// while leaving the true branch intact and the pairs correct. A collector constructed
    /// outside any flag branch is either that, or a default registered here instead of in
    /// <see cref="ScanEngine.DefaultCollectors"/>; both are worth a red.
    /// </para>
    /// </summary>
    private static (HashSet<string> Paired, HashSet<string> Loose) FlagWiring(string body)
    {
        var clauses = AppendedBehindAFlag.Matches(body);

        var paired = clauses
            .SelectMany(clause => Constructed.Matches(clause.Groups["appended"].Value)
                .Select(built => $"{clause.Groups["flag"].Value} → {built.Groups[1].Value}"))
            .ToHashSet(StringComparer.Ordinal);

        var behindAFlag = clauses.Select(clause => clause.Groups["appended"]).ToList();

        var loose = Constructed.Matches(body)
            .Where(built => !behindAFlag.Any(span => built.Index >= span.Index
                && built.Index + built.Length <= span.Index + span.Length))
            .Select(built => built.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        return (paired, loose);
    }

    /// <summary>
    /// Every compiled field collector is registered or declared opt-in, and nothing is
    /// registered that no longer exists.
    ///
    /// <para>
    /// Both directions from one <c>SetEquals</c>, and the second direction is what keeps the
    /// guard honest: were the reflection filter to stop matching — a collector moved behind an
    /// abstract base, the interface renamed — the compiled set would come back empty and the
    /// registered one would have nothing to match, so the assertion fails instead of passing
    /// vacuously. It also catches the opposite mistake to the one this file is about: an
    /// opt-in collector left in the default table as well runs on every scan, flag or no flag,
    /// which for this one means tens of seconds added to a command that returns in one.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_field_collector_compiled_into_the_core_is_registered_or_opt_in()
    {
        var compiled = Compiled();

        Assert.True(compiled.Count > 0,
            "Aucune implémentation d'ICollector trouvée dans Rempart.Core : le filtre de cette "
            + "garde ne voit plus rien, et une garde qui n'inspecte rien passe.");

        var expected = compiled
            .Except(OptInNames(), StringComparer.Ordinal)
            .ToHashSet(StringComparer.Ordinal);

        var registered = Registered();

        Assert.True(expected.SetEquals(registered),
            "Les collecteurs de champs compilés et ceux enregistrés dans "
            + "ScanEngine.DefaultCollectors ont divergé. "
            + $"Compilés, ni enregistrés ni déclarés optionnels, donc jamais exécutés : {Join(expected.Except(registered))}. "
            + $"Enregistrés par défaut sans implémentation compilée, ou enregistrés alors qu'ils sont déclarés optionnels : {Join(registered.Except(expected))}. "
            + $"Retirés du périmètre parce que déclarés optionnels : {Exemptions()}. "
            + "Un collecteur de champs non enregistré ne renseigne aucun champ : son bloc "
            + "disparaît du rapport sans qu'aucune référence ne bouge, et le rapport décrit "
            + "une machine dont une surface entière n'a jamais été lue.");
    }

    /// <summary>
    /// The same claim against the source tree, which the reflection above cannot make.
    ///
    /// <para>
    /// Dropping <c>: ICollector</c> from a collector removes it from the compiled set
    /// <em>and</em> forces its removal from the registration — the collection expression is
    /// typed — so the two shrink together and the guard above stays green while the scan
    /// quietly loses a surface. The files in <c>Collectors/</c> do not move on their own, so
    /// they are the third party that notices.
    /// </para>
    ///
    /// <para>
    /// Swept recursively, unlike the twin's <c>TopDirectoryOnly</c>: a subfolder is the
    /// cheapest place for a collector to be invisible to a guard that only looks at the top,
    /// and recursion costs a single argument. A missing directory throws rather than yielding
    /// an empty set, which is the loud failure wanted — renaming <c>Collectors/</c> must break
    /// this test, not silence it.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_collector_file_in_Collectors_is_registered_or_opt_in()
    {
        var interfaces = Interfaces();

        var onDisk = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("src/Rempart.Core/Collectors"),
                "*Collector.cs", SearchOption.AllDirectories)
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .Where(name => !interfaces.Contains(name))
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(onDisk.Count > 0,
            "Aucun fichier de collecteur de champs dans src/Rempart.Core/Collectors une fois "
            + "les interfaces écartées : le balayage ou l'exclusion a avalé le dossier entier, "
            + "et un balayage vide passe.");

        var expected = onDisk
            .Except(OptInNames(), StringComparer.Ordinal)
            .ToHashSet(StringComparer.Ordinal);

        var registered = Registered();

        Assert.True(expected.SetEquals(registered),
            "Les fichiers de collecteurs de src/Rempart.Core/Collectors et "
            + "ScanEngine.DefaultCollectors ont divergé. "
            + $"Présents sur le disque, ni enregistrés ni déclarés optionnels : {Join(expected.Except(registered))}. "
            + $"Enregistrés sans fichier du même nom : {Join(registered.Except(expected))}. "
            + $"Retirés du périmètre parce que déclarés optionnels : {Exemptions()}.");
    }

    /// <summary>
    /// A collector declared opt-in is really appended by the flag it names, on the branch that
    /// flag selects, and nothing else in the method builds a collector.
    ///
    /// <para>
    /// The link the twin guard never had to hold: for a finding collector, being registered is
    /// the whole of it, whereas a field collector can be reachable only through a word typed
    /// on the command line. That word is held in one place — <c>CliHost.CollectorsFor</c> —
    /// and nothing in the compiler ties it to the collector it is supposed to add. Dropping
    /// the collector from that branch breaks nothing: the flag is still accepted, still
    /// declared in <c>CommandSurface</c>, still documented in the help, and does nothing.
    /// </para>
    ///
    /// <para>
    /// « On the branch that flag selects » is held by the pattern above and not merely claimed
    /// here. The six cases below fail if it ever accepts a negated test, a true branch that
    /// discards the default table or a swapped ternary; if it reads only the first of two
    /// appended collectors; or if it overlooks one appended to the other branch as well.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_opt_in_collector_is_added_by_the_flag_it_names()
    {
        var (paired, loose) = FlagWiring(CollectorsForBody());

        var declared = OptInCollectors
            .Select(entry => $"{entry.Flag} → {entry.Collector.Name}")
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(declared.SetEquals(paired),
            "Le lien entre un drapeau et le collecteur qu'il ajoute a divergé de "
            + "CliHost.CollectorsFor. "
            + $"Déclarés ici, absents de la branche que le drapeau sélectionne : {Join(declared.Except(paired))}. "
            + $"Ajoutés par CollectorsFor sans être déclarés ici : {Join(paired.Except(declared))}. "
            + $"Raisons déclarées : {Exemptions()}. "
            + "Une branche qui ne se lit plus « HasFlag(args, \"--x\") ? [.. "
            + "ScanEngine.DefaultCollectors, new XCollector()] » ne rend aucune paire : le "
            + "drapeau est nié, la table par défaut est écartée, ou le ternaire a été réécrit. "
            + "Un collecteur retiré de cette branche ne casse rien : le drapeau reste accepté "
            + "et documenté, l'utilisateur qui le tape obtient un rapport muet sur la surface "
            + "qu'il venait de demander.");

        Assert.True(loose.Count == 0,
            $"Construits dans CollectorsFor hors de toute branche de drapeau : {Join(loose)}. "
            + "Un collecteur ajouté ailleurs que derrière son drapeau tourne à chaque scan — "
            + "pour le magasin de composants, les dizaines de secondes et l'élévation que "
            + "l'exemption déclarée ici sert précisément à éviter. "
            + $"Exemptions déclarées : {Exemptions()}.");
    }

    /// <summary>
    /// The grammar of the guard above, pinned against bodies written here rather than against
    /// <c>CliHost</c>.
    ///
    /// <para>
    /// A guard that reads source is only as good as what its pattern refuses, and refusal is
    /// exactly what no assertion on the real body can show: the real body is well-formed, so it
    /// exercises the accepting half only. Each case below is a mutation an adversarial reading
    /// of this file measured green against the first draft of the pattern.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("la branche vraie écarte la table par défaut",
        """CollectorsFor(string[] args) => HasFlag(args, "--analyze-store") ? [new ComponentStoreCollector()] : ScanEngine.DefaultCollectors""")]
    [InlineData("le test du drapeau est nié",
        """CollectorsFor(string[] args) => !HasFlag(args, "--analyze-store") ? [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()] : ScanEngine.DefaultCollectors""")]
    [InlineData("le test du drapeau est nié, l'espace en plus",
        """CollectorsFor(string[] args) => ! HasFlag(args, "--analyze-store") ? [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()] : ScanEngine.DefaultCollectors""")]
    [InlineData("les deux branches sont échangées",
        """CollectorsFor(string[] args) => HasFlag(args, "--analyze-store") ? ScanEngine.DefaultCollectors : [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()]""")]
    public void A_branch_the_flag_does_not_select_yields_no_pair(string mutation, string body)
    {
        var (paired, loose) = FlagWiring(body);

        Assert.True(paired.Count == 0,
            $"La forme « {mutation} » a été lue comme un câblage valide : {Join(paired)}. "
            + "La garde du drapeau passerait sur une mutation qui change ce que le drapeau "
            + "fait, ce qui est pire que pas de garde du tout.");

        Assert.True(loose.SetEquals(new[] { "ComponentStoreCollector" }),
            $"La forme « {mutation} » construit un collecteur hors branche de drapeau, et la "
            + $"seconde assertion doit le nommer. Relevés : {Join(loose)}.");
    }

    /// <summary>
    /// Two collectors behind one flag are both read — the false positive the lazy quantifier
    /// of the first draft would have produced, with a message naming the second as missing
    /// from a branch it sits in.
    /// </summary>
    [Fact]
    public void Two_collectors_appended_by_one_flag_are_both_paired()
    {
        var (paired, loose) = FlagWiring(
            """CollectorsFor(string[] args) => HasFlag(args, "--deep") ? [.. ScanEngine.DefaultCollectors, new AlphaCollector(), new BetaCollector()] : ScanEngine.DefaultCollectors""");

        Assert.True(
            paired.SetEquals(new[] { "--deep → AlphaCollector", "--deep → BetaCollector" }),
            "Un drapeau ajoutant deux collecteurs doit rendre les deux paires ; la lecture "
            + $"s'est arrêtée au premier. Relevées : {Join(paired)}.");

        Assert.True(loose.Count == 0,
            $"Aucun de ces deux collecteurs n'est hors branche : {Join(loose)}.");
    }

    /// <summary>
    /// The mirror of the negation: the opt-in collector appended to the false branch as well
    /// runs on every scan, with the true branch and its pair left untouched.
    /// </summary>
    [Fact]
    public void A_collector_appended_to_the_other_branch_too_is_reported_loose()
    {
        var (paired, loose) = FlagWiring(
            """CollectorsFor(string[] args) => HasFlag(args, "--analyze-store") ? [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()] : [.. ScanEngine.DefaultCollectors, new ComponentStoreCollector()]""");

        Assert.True(paired.SetEquals(new[] { "--analyze-store → ComponentStoreCollector" }),
            $"La branche vraie reste bien formée et doit rendre sa paire. Relevées : {Join(paired)}.");

        Assert.True(loose.SetEquals(new[] { "ComponentStoreCollector" }),
            "Le collecteur ajouté aussi hors du drapeau doit être relevé : il tourne alors à "
            + $"chaque scan. Relevés : {Join(loose)}.");
    }

    /// <summary>
    /// The body of <c>CliHost.CollectorsFor</c>, the one place a flag becomes a collector.
    ///
    /// <para>
    /// Sliced out rather than searching the whole file, so that a pair found below can only
    /// come from the method that wires the scan. The slice runs to the semicolon closing the
    /// expression body, and both ends are checked: a method renamed, moved or rewritten fails
    /// here, loudly, instead of yielding a slice that matches nothing and a green test.
    /// </para>
    /// </summary>
    private static string CollectorsForBody()
    {
        const string signature = "CollectorsFor(string[] args)";
        const string anchor = "ScanEngine.DefaultCollectors";

        var source = RepositoryFiles.Read("src/Rempart.Cli/CliHost.cs");
        var start = source.IndexOf(signature, StringComparison.Ordinal);

        Assert.True(start >= 0,
            $"« {signature} » est introuvable dans src/Rempart.Cli/CliHost.cs : la méthode qui "
            + "câble les collecteurs a été renommée ou déplacée, et cette garde ne lit plus "
            + "rien.");

        // The expression body carries no semicolon of its own, so the first one closes it.
        var end = source.IndexOf(';', start);

        Assert.True(end > start,
            $"« {signature} » ne se termine par aucun point-virgule : la méthode n'a plus la "
            + "forme que cette garde sait découper.");

        var body = source[start..end];

        Assert.Contains(anchor, body, StringComparison.Ordinal);

        return body;
    }

    /// <summary>
    /// What the product actually builds, by type name.
    ///
    /// <para>
    /// The instances the registration hands back, never types this guard activates itself —
    /// the twin's reason, and it holds here too: a guard that knew how to construct each
    /// collector would be a third list to keep in step with the other two.
    /// </para>
    /// </summary>
    private static HashSet<string> Registered()
    {
        var collectors = ScanEngine.DefaultCollectors;

        var names = collectors.Select(collector => collector.GetType().Name)
            .ToHashSet(StringComparer.Ordinal);

        // The set comparisons above would swallow a collector registered twice, and twice is
        // not harmless: the machine is read twice, and the report carries the same block
        // under the same name twice, which reads as two collectors rather than one mistake.
        Assert.True(names.Count == collectors.Count,
            $"{collectors.Count} collecteurs de champs enregistrés pour {names.Count} types "
            + "distincts : l'un d'eux est enregistré deux fois, sera exécuté deux fois et "
            + "rendra deux blocs identiques.");

        return names;
    }

    /// <summary>
    /// Every concrete <see cref="ICollector"/> the assembly holds, wherever it lives.
    ///
    /// <para>
    /// The whole of <c>Rempart.Core</c> rather than the <c>Collectors</c> namespace alone:
    /// scoping the search to the namespace would mean that moving a collector elsewhere takes
    /// it out of this guard's sight without failing anything, which is the same silence one
    /// directory over.
    /// </para>
    /// </summary>
    private static HashSet<string> Compiled() =>
        typeof(ICollector).Assembly.GetTypes()
            .Where(type => type is { IsClass: true, IsAbstract: false }
                && typeof(ICollector).IsAssignableFrom(type))
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The names the assembly declares as interfaces.
    ///
    /// <para>
    /// <c>ICollector.cs</c> sits in the swept folder and ends in the same nine characters as
    /// every implementation, and an interface is not something one registers. Recognised by
    /// asking the assembly what the name stands for, rather than by its leading <c>I</c>: a
    /// class named <c>IdentityCollector</c> would not be dropped by mistake, and a second
    /// collector interface would be dropped for a reason instead of by a line added to a list.
    /// </para>
    /// </summary>
    private static HashSet<string> Interfaces() =>
        typeof(ICollector).Assembly.GetTypes()
            .Where(type => type.IsInterface)
            .Select(type => type.Name)
            .ToHashSet(StringComparer.Ordinal);

    private static IEnumerable<string> OptInNames() =>
        OptInCollectors.Select(entry => entry.Collector.Name);

    /// <summary>
    /// What every one of the three failures says it took out of scope, and on whose word.
    ///
    /// <para>
    /// The two set guards subtract <see cref="OptInNames"/> before comparing, so a collector
    /// exempted here is simply absent from their expectation. Printing the subtraction is what
    /// makes their failure readable: without it the reader sees a set that balances and cannot
    /// tell that a collector was removed from the reckoning, still less on what grounds.
    /// </para>
    /// </summary>
    private static string Exemptions() =>
        Join(OptInCollectors.Select(entry =>
            $"{entry.Collector.Name} (ajouté par {entry.Flag}) — {entry.Reason}"));

    private static string Join(IEnumerable<string> names)
    {
        var listed = names.OrderBy(name => name, StringComparer.Ordinal).ToList();
        return listed.Count == 0 ? "aucun" : string.Join(", ", listed);
    }
}
