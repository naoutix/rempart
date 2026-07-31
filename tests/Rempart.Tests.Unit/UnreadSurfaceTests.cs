using System.Reflection;
using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

/// <summary>
/// What the tool answers when <b>nobody looked</b> — on the two wirings where that happens.
///
/// <para>
/// The same question got opposite answers fifteen lines apart in <c>ISystemInfoProvider.cs</c>:
/// an unwired component store said « analyse non effectuée », a sentence that reaches the
/// report, while an unwired DNS answered <c>DnsRead.Found([])</c> — a successful, empty read,
/// indistinguishable from a machine that resolves through nothing. The startup folders next to
/// them carried the argument in writing: « a startup folder nobody enumerated is not a startup
/// folder with nothing in it ». Two of the three could not be right at once (#192).
/// </para>
///
/// <para>
/// <b>The line is « personne n'a regardé » against « j'ai regardé et il n'y a rien »</b>, and
/// not « vide » against « non vide ». The second is a state of the machine and stays silent
/// wherever zero is plausible — no proxy, no Wi-Fi profile, no browser extension, a
/// <c>hosts</c> file with no entry. The first is a hole in the audit, and #187 gave these reads
/// the channel to say it.
/// </para>
///
/// <para>
/// <b>Discovered, not listed.</b> The fallbacks are found by asking <see cref="ProviderSet"/>
/// which of its constructor parameters carry a default — a parameter with one is a surface that
/// works unwired, which is exactly the set at issue — so a provider added tomorrow with an
/// inventing fallback reddens here without anyone remembering this file exists. That is the
/// reproach the audit of 2026-07-29 keeps making, coverage by enumeration, and a hand-kept list
/// of the twenty providers would be one more of them.
/// </para>
///
/// <para>
/// <b>The second wiring is the same hole seen from the other end</b>, and #187 left it open in
/// writing: a block absent from a capture replayed as a successful, empty read. A snapshot that
/// recorded nothing and a provider nobody wired are one surface nobody looked at, so they are
/// judged by one guard rather than by two that could drift apart — which is how the first of
/// them was corrected six times while the second stood.
/// </para>
///
/// <para>
/// <b>What this guard does not reach, written down rather than hoped for.</b> It fixes the
/// status and not the sentence: a fallback answering <see cref="ReadStatus.Failed"/> with a
/// diagnostic that names the wrong surface passes here. It says nothing about whether the
/// diagnostic reaches the report — that is a question about collectors, and the four surfaces
/// this issue moved carry it one test each, below. And it exercises each read on five shapes of
/// argument rather than on all of them; a fallback that answered <c>Found</c> on a sixth string
/// would pass, which is why <see cref="ReadFactoryNamingTests"/> reads the compiled body of the
/// factories these fallbacks call.
/// </para>
/// </summary>
public sealed class UnreadSurfaceTests
{
    /// <summary>No provider was supplied for the surface: the live set minus everything.</summary>
    private const string Unwired = "aucun fournisseur câblé";

    /// <summary>A capture that recorded nothing about the surface, replayed.</summary>
    private const string EmptyCapture = "capture sans le bloc";

    /// <summary>
    /// The surfaces whose read carries no channel at all, and why each is allowed to answer with
    /// a plain value.
    ///
    /// <para>
    /// Both are the judgement <see cref="ProviderStatusChannelTests"/> already records as
    /// « aucun » with the same reasons, and they are legitimate: no proxy is the normal
    /// configuration of a Windows machine, and a desktop without a wireless card has no profile.
    /// A channel here would have to be invented before it could be filled, and a third invention
    /// is what that file exists to make visible.
    /// </para>
    ///
    /// <para>
    /// Named in two places on purpose — here and at the read's own definition — so that an
    /// exemption is an act rather than an omission.
    /// <see cref="An_exemption_names_a_surface_that_still_earns_it"/> holds the other half: a read
    /// on this list that grows a channel stops being covered by it.
    /// </para>
    /// </summary>
    private static readonly (string Surface, string Reason)[] WithoutAChannel =
    [
        ("Proxy", "ProxyConfiguration n'a pas de forme « non lu » : pas de proxy est la "
            + "configuration normale, et la plus fréquente."),
        ("Wifi", "La lecture rend une liste nue : un poste fixe sans carte Wi-Fi n'a aucun "
            + "profil, légitimement."),
    ];

    /// <summary>
    /// The surfaces allowed to stay mute — to settle nothing <em>and</em> report nothing — with
    /// the reason each earns it.
    ///
    /// <para>
    /// One entry, and it is not the defect this issue is about. <c>FirewallState.Unread</c>
    /// answers <see cref="ReadStatus.NotFound"/> with <c>Readable = false</c>, so every query
    /// put to it comes back « inconnu » and the cross-check rule stands down: it claims nothing
    /// about the machine, which is what separates it from the four reads corrected here. Making
    /// it speak would put a gap on every capture taken before the firewall block existed, for a
    /// surface that already answers « je ne sais pas » to everything it is asked.
    /// </para>
    /// </summary>
    private static readonly (string Surface, string Reason)[] Mute =
    [
        ("Firewall", "FirewallState.Unread porte Readable = false : toute question posée à cet "
            + "état rend « inconnu » et la règle de recoupement se retire. Rien n'est affirmé, "
            + "donc rien n'a à être signalé."),
    ];

    /// <summary>
    /// The shapes of argument each read is exercised on.
    ///
    /// <para>
    /// Written to look like what Windows hands these methods — a service key under the two
    /// TCP/IP stacks, a startup folder, a service name, a WMI namespace — because a guard built
    /// on identifiers no machine produces is a guard on a case that never happens, which is the
    /// defect the previous correction shipped. The empty string is there because a caller that
    /// has lost its argument still gets an answer, and that answer must not be « j'ai regardé ».
    /// </para>
    /// </summary>
    private static readonly string[] Texts =
    [
        @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "MpsSvc",
        @"root\cimv2",
        "",
    ];

    /// <summary>The list-shaped arguments, empty and populated: the WMI property list.</summary>
    private static readonly string[][] Lists =
    [
        [],
        ["Name"],
        ["Name", "State", "PathName"],
    ];

    public static TheoryData<string, string> Surfaces()
    {
        var data = new TheoryData<string, string>();

        foreach (var wiring in new[] { Unwired, EmptyCapture })
        {
            foreach (var surface in Fallbacks())
            {
                data.Add(wiring, surface);
            }
        }

        return data;
    }

    /// <summary>
    /// A read nobody performed never comes back as a read that succeeded, and never as a
    /// refusal either.
    ///
    /// <para>
    /// Two forbidden answers and not one. <see cref="ReadStatus.Found"/> is the whole of #192:
    /// it is the only member a rule reads as a state of the machine, so an unwired DNS answering
    /// it is a report that says « rien à signaler » about a surface nobody opened. And
    /// <see cref="ReadStatus.AccessDenied"/> is the invariant CONTRIBUTING records — no
    /// privilege supplies a provider nobody wired, and no console however elevated re-reads a
    /// snapshot, so « relancer en administrateur » is advice that cannot work. That correction
    /// was made one interface at a time in #160, #173, #175 and #177 and never finished; this is
    /// what finishes it, for every fallback at once.
    /// </para>
    ///
    /// <para>
    /// <see cref="ReadStatus.Failed"/> and not merely « something other than the two », because
    /// the third member is a claim on some of these reads and not on others:
    /// <c>DnsRead.Absent</c> documents <see cref="ReadStatus.NotFound"/> as « an answer and not
    /// a hole — what a registry holding no TCP/IP stack says ». Left free, that member is where
    /// the defect walks back in under a different name. A surface that genuinely has nothing to
    /// report says so in <see cref="Mute"/>, in writing, where a reader of the guard sees the
    /// guard shrink.
    /// </para>
    /// </summary>
    [Theory]
    [MemberData(nameof(Surfaces))]
    public void A_surface_nobody_read_answers_a_read_that_did_not_happen(
        string wiring, string surface)
    {
        var provider = Fallback(Wiring(wiring), surface);

        foreach (var method in provider.GetType().GetInterfaces()
            .Single(type => type.Namespace == "Rempart.Core.Providers")
            .GetMethods())
        {
            foreach (var arguments in Arguments(method))
            {
                var call = $"{surface}.{method.Name}({string.Join(", ", arguments)}) "
                    + $"sur « {wiring} »";

                Judge(Invoke(provider, method, arguments), call, surface);
            }
        }
    }

    /// <summary>
    /// Each written exemption still names a surface that earns it — the half that keeps a list
    /// from becoming a way out.
    ///
    /// <para>
    /// A read on <see cref="WithoutAChannel"/> that grows a <c>Status</c> is a read that can now
    /// say « je n'ai pas lu », so its entry stops being an argument and becomes a hole; a
    /// surface on <see cref="Mute"/> that stops answering <see cref="ReadStatus.NotFound"/> is
    /// no longer the state its reason describes. Both are checked against the wiring rather than
    /// against the prose.
    /// </para>
    /// </summary>
    [Fact]
    public void An_exemption_names_a_surface_that_still_earns_it()
    {
        var fallbacks = Fallbacks().ToHashSet(StringComparer.Ordinal);

        foreach (var (surface, reason) in WithoutAChannel)
        {
            Assert.True(fallbacks.Contains(surface),
                $"« {surface} » n'est plus une surface de repli de ProviderSet : {reason}");

            var read = Read(Wiring(Unwired), surface);

            Assert.True(Channel(read) is null,
                $"La lecture de « {surface} » porte désormais un canal ({read.GetType().Name}) : "
                + "l'exemption ci-dessus repose sur le fait qu'elle n'en a pas, et ne tient plus. "
                + $"Raison inscrite : {reason}");
        }

        foreach (var (surface, reason) in Mute)
        {
            Assert.True(fallbacks.Contains(surface),
                $"« {surface} » n'est plus une surface de repli de ProviderSet : {reason}");

            Assert.True(Channel(Read(Wiring(Unwired), surface)) is ReadStatus.NotFound,
                $"« {surface} » ne répond plus « personne n'a regardé, rien à signaler ». "
                + $"L'exemption dit : {reason}");
        }
    }

    // The four reads #192 moved, one test per surface and per wiring: the guard above fixes the
    // status, and only a collector can say whether the sentence reaches the report. Written out
    // because the mapping from a provider to the collector that reads it is a fact about the
    // engine, not a shape reflection can recover.

    [Theory]
    [InlineData(Unwired)]
    [InlineData(EmptyCapture)]
    public void An_unread_dns_surface_reaches_the_report(string wiring)
    {
        var finding = Assert.Single(new DnsResolverCollector().Collect(Wiring(wiring)));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
    }

    [Theory]
    [InlineData(Unwired)]
    [InlineData(EmptyCapture)]
    public void An_unread_hosts_file_reaches_the_report(string wiring)
    {
        var finding = Assert.Single(new HostsFileCollector().Collect(Wiring(wiring)));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
    }

    [Theory]
    [InlineData(Unwired)]
    [InlineData(EmptyCapture)]
    public void An_unread_software_inventory_reaches_the_report(string wiring)
    {
        var finding = Assert.Single(
            new SoftwareInventoryCollector(BloatwareCatalog.Empty).Collect(Wiring(wiring)));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
    }

    [Theory]
    [InlineData(Unwired)]
    [InlineData(EmptyCapture)]
    public void An_unread_browser_profile_reaches_the_report(string wiring)
    {
        var finding = Assert.Single(new BrowserExtensionsCollector().Collect(Wiring(wiring)));

        Assert.Equal(AuditGap.Unreadable, finding.Gap);
    }

    private static ProviderSet Wiring(string name) => name switch
    {
        Unwired => new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider()),
        EmptyCapture => SnapshotProviders.Replaying(new MachineSnapshot()),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Câblage inconnu."),
    };

    /// <summary>
    /// The surfaces that work unwired, asked of <see cref="ProviderSet"/> rather than listed: a
    /// constructor parameter carrying a default is a provider a caller may omit, and therefore a
    /// fallback. The two that carry none — the registry and the system information — have no
    /// fallback to judge, and that is why they are absent rather than excluded by name.
    /// </summary>
    private static IEnumerable<string> Fallbacks()
    {
        var optional = typeof(ProviderSet).GetConstructors().Single().GetParameters()
            .Where(parameter => parameter.HasDefaultValue)
            .Select(parameter => parameter.Name!)
            .ToHashSet(StringComparer.Ordinal);

        var surfaces = typeof(ProviderSet).GetProperties()
            .Where(property => optional.Contains(Parameter(property.Name)))
            .Select(property => property.Name)
            .ToList();

        // A parameter that matched no property means the two names have drifted apart, and a
        // guard that silently covers one surface fewer is the failure mode this whole file is
        // about.
        Assert.Equal(optional.Count, surfaces.Count);

        return surfaces;
    }

    private static string Parameter(string property) =>
        char.ToLowerInvariant(property[0]) + property[1..];

    private static object Fallback(ProviderSet providers, string surface) =>
        typeof(ProviderSet).GetProperty(surface)!.GetValue(providers)!;

    private static object Read(ProviderSet providers, string surface)
    {
        var provider = Fallback(providers, surface);
        var method = provider.GetType().GetInterfaces()
            .Single(type => type.Namespace == "Rempart.Core.Providers")
            .GetMethods()
            .First();

        return Invoke(provider, method, Arguments(method).First())!;
    }

    /// <summary>
    /// Every combination of the shapes above, one row per argument list — so a read is exercised
    /// at several points of its argument space rather than at the one point stand-in values
    /// happen to land on.
    /// </summary>
    private static IEnumerable<object?[]> Arguments(MethodInfo method)
    {
        IEnumerable<object?[]> rows = [[]];

        foreach (var parameter in method.GetParameters())
        {
            var values = Values(parameter.ParameterType);
            rows = rows.SelectMany(row => values.Select(value => (object?[])[.. row, value]))
                .ToList();
        }

        return rows;
    }

    /// <summary>
    /// The values a parameter of a given type is exercised on. Throws rather than skips on a
    /// type it does not know: a provider method taking a number would otherwise leave this guard
    /// silently covering one surface fewer.
    /// </summary>
    private static object?[] Values(Type type) =>
        type == typeof(string) ? [.. Texts]
        : typeof(IReadOnlyList<string>).IsAssignableFrom(type) ? [.. Lists]
        : throw new NotSupportedException(
            $"Aucune forme d'argument connue pour {type.Name} : la garde ne sait pas exercer "
            + "cette lecture, et se taire reviendrait à ne pas la garder.");

    /// <summary>
    /// Calls the read, letting <see cref="SnapshotIncompleteException"/> through as an answer.
    ///
    /// <para>
    /// It is the loudest form of « personne n'a regardé » there is — the replay of a service the
    /// capture never recorded stops the scan rather than inventing a state — so it cannot be
    /// mistaken for a machine that answered. Nothing else is caught: a fallback that throws
    /// anything else is a fallback that fails, and this guard says so by failing.
    /// </para>
    /// </summary>
    private static object? Invoke(object provider, MethodInfo method, object?[] arguments)
    {
        try
        {
            return method.Invoke(provider, arguments);
        }
        catch (TargetInvocationException thrown)
            when (thrown.InnerException is SnapshotIncompleteException)
        {
            return null;
        }
    }

    /// <summary>
    /// The read's own answer about itself, classified the way
    /// <see cref="ProviderStatusChannelTests"/> classifies the channel that carries it —
    /// <c>Status</c> first, then the bespoke booleans, then nothing.
    /// </summary>
    private static ReadStatus? Channel(object? read) => read switch
    {
        null => null,
        ReadStatus bare => bare,
        _ => read.GetType().GetProperty("Status")?.GetValue(read) as ReadStatus?,
    };

    private static void Judge(object? read, string call, string surface)
    {
        if (read is null)
        {
            return;
        }

        var type = read.GetType();

        if (type.GetProperty("Status")?.GetValue(read) is SignatureStatus signature)
        {
            Assert.True(signature is SignatureStatus.Unknown,
                $"{call} rend « {signature} » : une signature que personne n'a vérifiée est "
                + "« inconnue », jamais « non signée ».");
            return;
        }

        if (Channel(read) is { } status)
        {
            var expected = Mute.Any(entry => entry.Surface == surface)
                ? ReadStatus.NotFound
                : ReadStatus.Failed;

            Assert.True(status == expected,
                $"{call} rend « {status} » là où « {expected} » est attendu. Found dit « j'ai "
                + "regardé et voici ce qu'il y a » sur une surface que personne n'a ouverte ; "
                + "AccessDenied envoie son lecteur élever ses droits, ce qui ne câble aucun "
                + "fournisseur et ne relit aucune capture ; NotFound affirme, sur plusieurs de "
                + "ces lectures, que la machine n'a pas la clé. Une surface qui n'a vraiment "
                + "rien à signaler s'inscrit dans Mute, avec sa raison.");

            if (status is ReadStatus.Failed
                && type.GetProperty("Diagnostic") is { } diagnostic)
            {
                Assert.True(diagnostic.GetValue(read) is string { Length: > 0 },
                    $"{call} rend « Failed » sans diagnostic : le canal existe et reste vide, "
                    + "donc le rapport ne dira pas ce qui n'a pas été lu.");
            }

            return;
        }

        if (type.GetProperty("Denied")?.GetValue(read) is bool denied)
        {
            Assert.True(!denied,
                $"{call} rend un refus : personne n'a rien refusé à un fournisseur que "
                + "personne n'a câblé.");

            Assert.True(type.GetProperty("Gaps")?.GetValue(read) is not null,
                $"{call} ne nomme aucun manque : la lecture porte le canal et ne s'en sert pas.");
            return;
        }

        Assert.True(WithoutAChannel.Any(entry => entry.Surface == surface),
            $"{call} rend « {type.Name} », qui ne sait rien dire d'une lecture qui n'a pas eu "
            + "lieu. Une lecture sans canal doit être inscrite dans WithoutAChannel, avec la "
            + "raison pour laquelle zéro y est une réponse et non un trou.");
    }
}
