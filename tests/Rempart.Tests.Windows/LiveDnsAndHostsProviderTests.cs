using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using Rempart.Windows;
using Xunit.Abstractions;

namespace Rempart.Tests.Windows;

/// <summary>
/// The DNS read against the real registry.
///
/// <para>
/// What is left here is the interop half: that the key paths are where Windows actually keeps
/// its interfaces on this machine, and that what the read finds is what the machine resolves
/// with. The splitting, the key path constants and the « no resolver, no interface » rule are
/// judgements and moved to Core with <c>RegistryDnsProvider</c>, where the Linux job
/// exercises them against a fake registry — the same two-step CatalogSignature took.
/// </para>
///
/// <para>
/// And one question that can only be asked here, because it is a fact about Windows and not
/// about the program: whether the stacks the program names are the stacks that keep resolvers.
/// Every test in Core reads a registry a test wrote, so a subtree nobody declared is invisible
/// to all of them — <c>RegistryDnsProviderTests</c> says so in as many words. The real
/// <c>Services</c> hive is the only corpus that can answer, and
/// <see cref="No_service_outside_the_declared_stacks_keeps_a_resolver_per_interface"/> asks it.
/// </para>
///
/// <para>
/// <b>The test that used to be here proved nothing on a machine with no DNS.</b> It walked
/// the interfaces the read returned and asserted inside the loop, so an empty result — the
/// exact symptom of a wrong key path — ran zero assertions and reported green. The read is
/// now confronted with a source that did not come from it: the addresses
/// <see cref="NetworkInterface"/> says this machine resolves with.
/// </para>
/// </summary>
public sealed class LiveDnsProviderTests(ITestOutputHelper output)
{
    private readonly Core.Providers.DnsRead read = new LiveDnsProvider().Read();

    private IReadOnlyList<Core.Providers.DnsInterface> Interfaces => read.Interfaces;

    /// <summary>
    /// The independent half, and the one that refuses to go quiet. Every IPv4 resolver the
    /// operating system says it uses has to appear in what the registry read found; a wrong
    /// key path, a wrong value name or a broken split all put it outside.
    ///
    /// <para>
    /// Subset rather than equality, in that direction only: the registry legitimately holds
    /// resolvers for adapters that are down, and the read returns them. What must never
    /// happen is the reverse — the machine resolving through a server the audit never saw,
    /// which is precisely how a hijacked resolver would stay out of the report.
    /// </para>
    ///
    /// <para>
    /// <b>IPv4 only, and the reason changed with #191 without the line moving.</b> It used to be
    /// « the read walks the v4 stack and nothing else », which was the defect. The read now
    /// walks both, and this confrontation still cannot be made on the v6 side: measured on a
    /// real Windows 11 machine, the resolvers the operating system reports over IPv6 are, in
    /// order of frequency, a DHCPv6 lease — written to <c>Dhcpv6DNSServers</c> as a
    /// <c>REG_BINARY</c>, which this read does not decode — and the <c>fec0:0:0:ffff::1-3</c>
    /// site-local trio, which is built into the resolver and sits in no key at all. Both are
    /// reported by <c>Get-DnsClientServerAddress</c> and neither is in the subtree this read
    /// walks, so demanding them here would redden every machine rather than catch anything.
    /// What <em>is</em> under <c>NameServer</c> on the v6 stack — the statically configured
    /// resolver, which is the hijack lever — is collected, and Core holds that.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_resolver_this_machine_uses_is_found_by_the_read()
    {
        var used = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
            .SelectMany(nic => nic.GetIPProperties().DnsAddresses)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // A machine with no IPv4 resolver at all is a real state — an offline runner, an
        // IPv6-only network — so this says so on the test output instead of failing, the same
        // discipline the WMI tests follow. It is the only silence allowed in this class, and
        // the test below refuses it whatever happens.
        if (used.Count == 0)
        {
            output.WriteLine(
                "Cette machine ne déclare aucun résolveur IPv4 sur une interface active : "
                + "il n'y a rien à confronter à la lecture du registre. Contrôle non exécuté.");
            return;
        }

        var found = Interfaces
            .SelectMany(iface => iface.StaticServers.Concat(iface.DhcpServers))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var invisible = used.Where(address => !found.Contains(address)).ToList();

        Assert.True(invisible.Count == 0,
            $"Cette machine résout via {string.Join(", ", invisible)}, que la lecture du "
            + "registre ne trouve pas. Un résolveur détourné serait absent du rapport, et "
            + "l'audit conclurait « rien à signaler » sur la surface même où le détournement "
            + "se voit.");
    }

    /// <summary>
    /// The shape of what comes back, and the assertion that cannot be skipped: a resolver
    /// carrying a leftover separator is one address where there were two, and it matches
    /// nothing in the well-known list — so the report names a resolver that does not exist
    /// and calls it unrecognised.
    ///
    /// <para>
    /// Written outside a loop over the result on purpose. Its predecessor asserted inside
    /// one, which meant an empty read — the symptom of the defect — ran no assertion at all.
    /// </para>
    /// </summary>
    [Fact]
    public void The_read_returns_interfaces_whose_resolvers_are_single_addresses()
    {
        // The count first, and unconditionally. Moving the assertions out of the loop was
        // meant to stop an empty read from running none of them — but an empty read makes
        // "no malformed resolver" and "every interface has an id" true by vacuity, so the
        // tautology moved rather than went. Pointing the provider at a key that does not
        // exist left this test green while its neighbour reddened, and its neighbour is
        // allowed to fall silent on a machine with no IPv4 resolver. Both green, DNS read
        // entirely broken. Any Windows machine enumerates network interfaces.
        Assert.True(Interfaces.Count > 0,
            "Aucune interface réseau lue : sur une machine Windows allumée ce n'est pas une "
            + "réponse, c'est une clé de registre qui n'est pas celle qu'on croit. Sans "
            + "cette ligne, les deux contrôles ci-dessous seraient vrais par vacuité.");

        var resolvers = Interfaces
            .SelectMany(iface => iface.StaticServers.Concat(iface.DhcpServers))
            .ToList();

        var malformed = resolvers
            .Where(server => server.Any(char.IsWhiteSpace) || server.Contains(',')
                || server.Contains(';'))
            .ToList();

        Assert.True(malformed.Count == 0,
            $"Résolveur(s) portant un séparateur résiduel : {string.Join(" | ", malformed)}. "
            + "Deux adresses collées en une n'existent nulle part, donc le rapport les "
            + "signale comme un résolveur inconnu.");

        Assert.True(Interfaces.All(iface => !string.IsNullOrWhiteSpace(iface.Id)),
            "Interface sans identifiant : la clé énumérée n'est pas celle qu'on croit.");

        // And what the read says about itself, which the count cannot say for it: this runner
        // is refused nothing under either Parameters\Interfaces key, so the read has to come
        // back « lue » and silent. Before #184 there was no field here to assert at all, and a
        // refusal reached the report as the empty list a machine with no adapter returns.
        Assert.Equal(Core.Providers.ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
    }

    /// <summary>
    /// The one question no fake registry can answer: are the stacks the program names the
    /// stacks this machine keeps resolvers on?
    ///
    /// <para>
    /// #191 was a stack that existed and was named nowhere in the repository, and the guard it
    /// produced holds a table against an enum — which cannot find a third subtree, both being
    /// the program's own account of itself. This walks the real <c>Services</c> hive instead
    /// and complains about any service that keeps <c>NameServer</c> or <c>DhcpNameServer</c>
    /// per adapter and is not one of the declared stacks.
    /// </para>
    ///
    /// <para>
    /// <b>What it is worth, stated rather than implied.</b> Its corpus is one machine, so it
    /// proves nothing about the next one; it only reddens where a stack is really there and
    /// really configured. Measured on the machine this was written on: <c>NetBT</c> also keeps
    /// a <c>Parameters\Interfaces</c> subtree, and what it holds is <c>NameServerList</c> —
    /// WINS servers, another protocol and another value name, which is why the match is on the
    /// exact two names this read uses and not on « anything that looks like a name server ».
    /// </para>
    ///
    /// <para>
    /// The declared keys are asserted to exist first, and that is the half that would catch a
    /// path this program guessed: a key that is not there answers « rien » for ever, and
    /// nothing downstream can tell that apart from a machine with nothing configured — the
    /// invariant CONTRIBUTING records about never shipping an unverified key.
    /// </para>
    /// </summary>
    [Fact]
    public void No_service_outside_the_declared_stacks_keeps_a_resolver_per_interface()
    {
        const string Services = @"HKLM\SYSTEM\CurrentControlSet\Services";

        var registry = new LiveRegistryProvider();

        foreach (var (stack, interfacesKey) in Core.Providers.RegistryDnsProvider.Stacks)
        {
            Assert.True(
                registry.ListSubKeys(interfacesKey).Status is Core.Providers.ReadStatus.Found,
                $"La pile « {stack} » est déclarée sur {interfacesKey}, et cette clé ne répond "
                + "pas sur cette machine. Une clé qui n'est pas là rend « rien » pour toujours, "
                + "et rien en aval ne distingue cela d'une machine sans résolveur.");
        }

        var declared = Core.Providers.RegistryDnsProvider.Stacks
            .Select(stack => stack.InterfacesKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var services = registry.ListSubKeys(Services);

        // A walk that enumerated nothing would go green having looked at nothing at all.
        Assert.Equal(Core.Providers.ReadStatus.Found, services.Status);
        Assert.NotEmpty(services.Names);

        var elsewhere = new List<string>();
        var walked = 0;

        foreach (var service in services.Names)
        {
            var interfacesKey = $@"{Services}\{service}\Parameters\Interfaces";

            if (declared.Contains(interfacesKey))
            {
                continue;
            }

            var adapters = registry.ListSubKeys(interfacesKey);

            if (adapters.Status is not Core.Providers.ReadStatus.Found)
            {
                continue;
            }

            walked++;

            foreach (var adapter in adapters.Names)
            {
                var values = registry.ListValues($@"{interfacesKey}\{adapter}");

                if (values.Status is Core.Providers.ReadStatus.Found
                    && (values.Values.ContainsKey("NameServer")
                        || values.Values.ContainsKey("DhcpNameServer")))
                {
                    elsewhere.Add($@"{interfacesKey}\{adapter}");
                }
            }
        }

        output.WriteLine(
            $"{services.Names.Count} services énumérés, dont {walked} hors des piles déclarées "
            + "avec un sous-arbre Parameters\\Interfaces.");

        Assert.True(elsewhere.Count == 0,
            $"Cette machine garde un résolveur DNS par interface hors des piles que Rempart "
            + $"déclare : {string.Join(", ", elsewhere)}. Ou bien c'est une pile à déclarer "
            + "dans RegistryDnsProvider.Stacks, ou bien c'est une valeur homonyme à écarter "
            + "ici — dans les deux cas, un résolveur y est aujourd'hui invisible au rapport.");
    }
}

/// <summary>
/// The hosts file, read from disk.
///
/// <para>
/// Its location is hard-coded — <c>%SystemRoot%\System32\drivers\etc\hosts</c> — and a wrong
/// path fails silently in the worst way for this particular surface: the read returns nothing,
/// the collector reports no redirection, and a machine whose hosts file points a bank at an
/// attacker's address gets a clean report. The old test caught a path so wrong it read no
/// file at all; it could not catch a path pointing at the wrong file.
/// </para>
/// </summary>
public sealed class LiveHostsFileProviderTests
{
    /// <summary>
    /// Refuses to be silent: the file Windows ships is never empty, it carries a comment
    /// header. Nothing about a machine's configuration can make this untrue.
    /// </summary>
    [Fact]
    public void The_real_hosts_file_is_read()
    {
        var read = new LiveHostsFileProvider().ReadLines();

        Assert.Equal(Core.Providers.ReadStatus.Found, read.Status);
        Assert.Null(read.Diagnostic);
        Assert.NotEmpty(read.Lines);
        Assert.Contains(read.Lines, line => line.TrimStart().StartsWith('#'));
    }

    /// <summary>
    /// A path nothing answers at. It stands for the two states this read used to fold into
    /// the empty list Windows' own comment-only file produces — the file is not there, or it
    /// is there and refused.
    ///
    /// <para>
    /// The absence is the one a test can stage without an ACL, and it is the harmless half:
    /// a machine with no hosts file resolves through DNS alone, which is what a file with no
    /// entry means too. What it proves here is that the read <em>separates</em> — nothing
    /// answers, and the status says so instead of the caller inferring it from a count.
    /// </para>
    /// </summary>
    [Fact]
    public void A_hosts_file_that_is_not_there_is_absent_rather_than_empty()
    {
        var read = new LiveHostsFileProvider(@"C:\Rempart\CeCheminNExistePas").ReadLines();

        Assert.Equal(Core.Providers.ReadStatus.NotFound, read.Status);
        Assert.Empty(read.Lines);
    }

    /// <summary>
    /// The failure, staged the one way a non-elevated test can: a file held open with no
    /// sharing, which is what malware protecting its own redirection does as readily as it
    /// sets an ACL. <c>File.ReadAllLines</c> throws <c>IOException</c> there, and the read
    /// must not call that « accès refusé » — the invariant CONTRIBUTING records, paid for
    /// once by two milestones of a mute WMI.
    ///
    /// <para>
    /// This test could only check the <em>sentence</em> until #173, because the channel had a
    /// single speaking state and the state was called <c>AccessDenied</c> whichever exception
    /// arrived. So it passed while <c>HostsFileCollector</c>, which branches on the state and
    /// not on the sentence, answered <see cref="Core.Findings.AuditGap.Refused"/> for exactly
    /// this file and told its reader to re-run as administrator. Asserting the state is what
    /// makes this the guard its name always claimed to be, and it is the one that ties the
    /// <c>catch</c> below to the contract the interface documents.
    /// </para>
    /// </summary>
    [Fact]
    public void A_hosts_file_held_open_fails_without_being_called_a_denial()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"rempart-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(directory, "System32", "drivers", "etc"));
        var path = Path.Combine(directory, "System32", "drivers", "etc", "hosts");
        File.WriteAllText(path, "0.0.0.0 windowsupdate.microsoft.com\n");

        try
        {
            using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);

            var read = new LiveHostsFileProvider(directory).ReadLines();

            Assert.Empty(read.Lines);
            Assert.NotNull(read.Diagnostic);
            Assert.DoesNotContain("accès refusé", read.Diagnostic, StringComparison.Ordinal);

            // The state, not only the wording: this is what the collector reads.
            Assert.Equal(Core.Providers.ReadStatus.Failed, read.Status);
            Assert.NotEqual(Core.Providers.ReadStatus.AccessDenied, read.Status);

            // The category of the failure, and not the framework's own sentence. This branch
            // interpolated ex.Message until #173's review, and the diagnostic is recorded into
            // a capture whose references are compared character for character — so the same
            // held-open file gave a French install and an English one two different captures.
            // The BCL names the file it could not open; a diagnostic that does is carrying it.
            Assert.Contains("erreur d'entrée/sortie", read.Diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(path, read.Diagnostic, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// The confrontation the previous test cannot make: the file that was read is the file
    /// Windows resolves names with, and not merely <em>a</em> file with a comment in it.
    ///
    /// <para>
    /// The location comes from <c>DataBasePath</c> under the TCP/IP parameters, which is
    /// where the stack itself looks and which is configurable. Comparing content rather than
    /// paths, because the two spellings legitimately differ in case and in how
    /// <c>%SystemRoot%</c> was expanded — what matters is that the audit read the bytes the
    /// resolver reads.
    /// </para>
    /// </summary>
    [Fact]
    public void The_file_read_is_the_one_the_TCP_IP_stack_resolves_with()
    {
        using var parameters = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");

        var databasePath = parameters?.GetValue("DataBasePath") as string;

        Assert.False(string.IsNullOrWhiteSpace(databasePath),
            "DataBasePath introuvable sous les paramètres TCP/IP : ce test ne peut plus dire "
            + "où Windows garde son fichier hosts, donc il ne confronte plus rien.");

        var expected = Path.Combine(
            Environment.ExpandEnvironmentVariables(databasePath!), "hosts");

        Assert.True(File.Exists(expected), $"Fichier hosts absent de {expected}.");

        Assert.Equal(File.ReadAllLines(expected), new LiveHostsFileProvider().ReadLines().Lines);
    }
}
