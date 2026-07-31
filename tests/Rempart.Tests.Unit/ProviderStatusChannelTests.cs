using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>
/// What every provider read can say when it did not manage to read.
///
/// <para>
/// The generalisation of DET-WMI-MUET, which was the same defect found twice in one
/// sitting: <c>LiveDriverProvider</c> and <c>LiveProcessProvider</c> both answered with an
/// empty list on a failed read, and an empty list of drivers reads exactly like a clean
/// kernel. The fix gave those two reads a <c>Status</c> and a <c>Diagnostic</c>. What it
/// did not do — what no comment can do — is stop the twentieth provider from being written
/// the same way.
/// </para>
///
/// <para>
/// <b>This does not demand the channel everywhere, and that is deliberate.</b> Phase 2
/// settled the principle and it is a judgement, not a shape: zero drivers or zero
/// processes <em>cannot</em> be true of a machine that is running, so an empty answer there
/// is a failure; zero browser extensions is perfectly true, so an empty answer there is an
/// answer. Requiring a diagnostic channel of every read alike would have added noise
/// exactly where the silence had just been removed. Reflection cannot tell those two apart
/// — only a human can — so what is frozen here is the <em>partition</em>, with the reason
/// on each line that lacks a channel.
/// </para>
///
/// <para>
/// Equality, not a floor: a read that gains a channel fails this test too, and has to be
/// recorded. A list that can only be edited on purpose is the whole mechanism, the same one
/// <c>KnownUndocumented</c> uses in <c>CommandSurfaceTests</c>. Adding a provider without
/// touching this file is what must be impossible.
/// </para>
/// </summary>
public sealed class ProviderStatusChannelTests
{
    /// <summary>
    /// Every read the provider layer offers, and what it can say about its own failure.
    ///
    /// <para>
    /// Written as one line per read rather than per provider, because the gaps are not
    /// uniform inside a provider: <c>IRegistryProvider.ReadValue</c> carried a status for
    /// three milestones while its two enumerating siblings carried none, and the line that
    /// said so is what made the hole nameable.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Ordinal order, because that is the order reflection is sorted into — the reasons
    /// therefore sit on each line rather than under group headings.
    /// </remarks>
    private static readonly string[] Expected =
    [
        // Zéro extension est un état de machine plausible ; le canal sert ici à nommer le
        // profil illisible sans jeter ceux qui ont été lus (DET-EXT-MUET).
        "IBrowserExtensionProvider.Read → statut + diagnostic",
        "IComponentStoreProvider.Read → statut + diagnostic",

        // Une machine sans interface réseau configurée existe : zéro est une réponse. La
        // raison ne couvre plus tout depuis REV-11 : ce provider énumère les interfaces avec
        // ListSubKeys, qui sait désormais dire « refusé », et il jette ce statut faute d'un
        // canal où le poser. Un refus sur Tcpip\Parameters\Interfaces rend donc encore zéro
        // résolveur. Consigné ici plutôt que corrigé au passage — c'est une autre lecture,
        // avec son propre champ d'instantané à ajouter.
        "IDnsProvider.Read → aucun",

        // DET-WMI-MUET même : zéro pilote sur une machine allumée est une panne.
        "IDriverProvider.Enumerate → statut + diagnostic",

        // DET-PLAGE-DYNAMIQUE, fermée. Le canal ne sert pas ici à distinguer « vide » de
        // « refusé » — une plage n'a pas de forme vide — mais « lue sur la machine » de
        // « pas lue, donc c'est la valeur par défaut de Windows ». Mêmes nombres, pas la
        // même affirmation, et c'est exactement ce que la constante en dur ne pouvait pas
        // dire.
        "IDynamicPortRangeProvider.Read → statut + diagnostic",

        // DET-FICHIERS-MUET, fermée — la cinquième et dernière occurrence de la forme, et
        // celle qui était inscrite ici en « aucun » avec la raison « un dossier vide est un
        // dossier vide ; l'appelant sait ce qu'il a demandé ». C'était vrai pour le dossier
        // vide et faux pour le dossier REFUSÉ, qui rendait la même liste nue : « aucun
        // autorun » sur la première surface qu'une persistance utilise. Le canal sépare les
        // deux, et un dossier vide reste muet — c'est l'asymétrie, pas son abandon.
        "IFileSystemProvider.ListFiles → statut + diagnostic",

        // Arrivée ici en « booléen dédié », premier des deux canaux maison : « non lu » ne
        // devient jamais « ouvert » — ni « bloqué », qui était le vrai danger, puisque les
        // défauts Windows appliqués à une lecture ratée décrivent mot pour mot un pare-feu
        // actif (REV-07, fermée). Le booléen répondait à une question et une seule, et
        // l'écart s'est logé dans celle qu'il ne posait pas : « refusé » ou « en panne ». Sa
        // propre documentation employait les deux mots pour le même membre, et
        // ListeningPortsCollector a cru celui qui était faux — une clé universelle absente et
        // un conteneur de règles illisible ressortaient en « relancer en administrateur »,
        // code 3 (#179). Le statut partagé de #177 dit maintenant lequel des deux, et le
        // booléen reste à côté pour qu'une capture antérieure rejoue inchangée.
        "IFirewallProvider.Read → statut + diagnostic",

        // Un fichier hosts sans entrée est l'état par défaut de Windows, et le reste : c'est
        // pourquoi la lecture a le droit de se taire sur zéro ligne. Ce qui était plié dans
        // cette phrase, et qui n'en relevait pas, c'est le REFUS — la technique même qui
        // protège une redirection déjà posée (REV-12, fermée). Diagnostic et pas seulement
        // statut : File.ReadAllLines lève IOException sur un fichier tenu en exclusif, ce
        // qui n'est pas un accès refusé et ne doit pas se présenter comme tel.
        "IHostsFileProvider.ReadLines → statut + diagnostic",

        // DET-PORTS-MUET, fermée. C'est la ligne pour laquelle ce test existe : elle est
        // arrivée ici en « aucun », inscrite au registre à sa première exécution, et le
        // canal a été posé avant qu'une seule capture n'ait figé « aucun port en écoute »
        // sur une lecture ratée. Aucune machine allumée n'écoute sur zéro port — RPC, SMB,
        // le résolveur local — donc zéro ne peut être qu'une panne.
        "IListeningPortProvider.Enumerate → statut + diagnostic",

        // DET-WMI-MUET même : aucune machine n'exécute zéro processus.
        "IProcessProvider.Enumerate → statut + diagnostic",

        // Pas de proxy est la configuration normale, et la plus fréquente.
        "IProxyProvider.Read → aucun",

        // Un test d'existence : le statut EST la donnée.
        "IRegistryProvider.KeyExists → statut, sans donnée",

        // La dégradation voulue tient toujours — ReadValue lève sur une clé absente d'une
        // fixture ancienne là où ces deux-là rendent vide — mais elle portait sur l'ABSENCE,
        // et le refus s'était glissé dans la même liste vide : une clé Run refusée rendait
        // « aucun démarrage automatique » (REV-11, fermée). Les deux réponses sont
        // séparables, et le sont : NotFound pour ce qu'une capture n'a pas énuméré, qui reste
        // muet et rejouable, AccessDenied pour ce qu'on a refusé de lire.
        "IRegistryProvider.ListSubKeys → statut seul",
        "IRegistryProvider.ListValues → statut seul",

        // Statut sans diagnostic, toléré, et pour la même raison sur les trois lectures de
        // cette interface : l'appelant a nommé la clé qu'il lisait, donc « refusé » se suffit.
        // Les énumérations sans argument — pilotes, processus, ports — n'ont pas ce contexte
        // et échouent pour une catégorie entière d'un coup ; celles-ci prennent un chemin.
        // S'y ajoute qu'aucune autre panne n'est avalée ici : le provider n'attrape que les
        // deux exceptions de refus, tout le reste remonte.
        "IRegistryProvider.ReadValue → statut seul",

        // Des manques nommés sur une lecture qui porte déjà un statut, depuis #135. La
        // lecture de `Gaps` posée en #160 ne pouvait pas les voir : elle était écrite dans la
        // branche des booléens maison, donc inatteignable dès qu'un `Status` était présent.
        // Cette ligne annonçait « statut + diagnostic » pour un type qui nomme aussi les
        // dossiers que le parcours a abandonnés — un canal entier tu depuis son arrivée, par
        // la garde même qui existe pour ne pas le rater (#163).
        "IScheduledTaskProvider.Enumerate → statut + diagnostic + manques nommés",

        // PolicyFacts.Denied, second canal maison. Un troisième devrait sauter aux yeux.
        // Le booléen ne portait qu'une seule réponse, et il la déduisait : « zéro fait établi »
        // était rendu comme un refus quel que soit le code de netapi32, et une lecture
        // PARTIELLE — quatre surfaces indépendantes remplissent le même dictionnaire —
        // n'avait aucune trace. Gaps nomme, à côté de chaque fait absent, l'appel qui a
        // échoué et son code ; le booléen ne dit plus « refusé » que là où netapi32 l'a dit
        // (#160).
        "ISecurityPolicyProvider.Read → booléen dédié + manques nommés",

        // Arrivée ici en « statut seul », avec la même raison que les trois lectures du
        // registre — l'appelant a nommé le service, donc « refusé » se suffit. C'était vrai
        // du refus et faux de la PANNE : la lecture rendait AccessDenied pour tout code
        // Win32 autre que « ce service n'existe pas », et pour un SCM qui ne s'ouvre pas ou
        // une requête qui ne répond pas. Un point RPC mort conseillait donc « relancer en
        // administrateur » sur toutes les règles `type: service` à la fois (#147, fermée).
        // Le statut ne peut pas les séparer — ReadStatus n'a pas de membre pour l'échec —
        // c'est le diagnostic qui le fait : nul pour un refus, écrit pour une panne.
        "IServiceStateProvider.Read → statut + diagnostic",

        // SignatureStatus.Unknown tient le rôle du diagnostic : SignatureLadder le rend
        // « non vérifiable », jamais « non signé ». La distinction était perdue une couche
        // plus bas — le catalogue rendait le même null pour « aucun catalogue » et pour
        // « je n'ai pas pu demander » — jusqu'à ce que CatalogOutcome la nomme
        // (DET-CATALOGUE-MUET, fermée).
        "ISignatureProvider.Verify → statut seul",

        // Zéro logiciel installé est faux sur une machine réelle, mais un inventaire vide
        // n'est pas une bonne nouvelle qu'on pourrait prendre pour un verdict : il ne
        // déclenche aucune règle. Moins urgent que les ports. Même réserve que pour le DNS
        // ci-dessus : les quatre ListSubKeys de ce provider savent maintenant dire « refusé »
        // et il n'a pas où le mettre.
        "ISoftwareInventoryProvider.Read → aucun",

        // Pas de forme « vide » : le type rend toujours une machine décrite.
        "ISystemInfoProvider.Read → aucun",

        // Un poste fixe sans carte Wi-Fi n'a aucun profil, légitimement.
        "IWifiProfileProvider.Read → aucun",

        "IWmiProvider.Query → statut + diagnostic",
    ];

    [Fact]
    public void Every_provider_read_declares_what_it_can_say_about_a_failed_read()
    {
        var actual = typeof(ReadStatus).Assembly.GetTypes()
            .Where(type => type.IsInterface
                && type.IsPublic
                && type.Namespace == "Rempart.Core.Providers"
                && type.Name.EndsWith("Provider", StringComparison.Ordinal))
            .SelectMany(type => type.GetMethods()
                .Select(method => $"{type.Name}.{method.Name} → {Channel(method.ReturnType)}"))
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(Expected, actual);
    }

    /// <summary>
    /// What a read type can express about its own failure, from richest to nothing at all.
    ///
    /// <para>
    /// <c>Status</c> is matched by name rather than by type on purpose: <c>FileSignature</c>
    /// carries a <c>SignatureStatus</c> and not a <c>ReadStatus</c>, and it does the same
    /// job — <c>Unknown</c> means « could not verify », which <c>SignatureLadder</c> is
    /// careful never to turn into an accusation.
    /// </para>
    ///
    /// <para>
    /// The bespoke booleans are named here instead of being derived, and naming them is the
    /// point: <c>PolicyFacts.Denied</c> and <c>FirewallState.Readable</c> each invented their
    /// own way to say « je n'ai pas pu lire », so nothing but a list can find them. A third
    /// invention should be visible as an invention.
    /// </para>
    ///
    /// <para>
    /// The firewall has since joined the shared vocabulary and left this branch — it carries a
    /// <c>ReadStatus</c> and is classified on it, the line above says so, and it is the naming
    /// guard rather than this list that now judges its factories. <c>Readable</c> stayed beside
    /// the status because a capture written before #179 records it and nothing else; the
    /// reading below still finds it, which is why the branch is kept rather than deleted with
    /// the one type that no longer needs it.
    /// </para>
    ///
    /// <para>
    /// <c>Gaps</c> is read on its own and appended to whatever the rest gave, rather than
    /// inside one of the branches. Written inside the bespoke-boolean branch, which is how it
    /// arrived in #160, it was unreachable for every read carrying a <c>Status</c> — and
    /// <see cref="ScheduledTaskRead"/> has carried <c>Status</c>, <c>Diagnostic</c> and
    /// <c>Gaps</c> since #135, so this table said « statut + diagnostic » about it and a whole
    /// failure channel was already unnamed on the day the reading was written. A channel added
    /// to a type this classifier already recognises is exactly the change it must not sleep
    /// through, and it slept through that one; the combinations are pinned below so that
    /// folding the reading back into a branch is a red rather than a tidier-looking method
    /// (issue #163).
    /// </para>
    /// </summary>
    private static string Channel(Type returnType)
    {
        if (returnType == typeof(ReadStatus))
        {
            return "statut, sans donnée";
        }

        var status = returnType.GetProperty("Status") is not null;
        var diagnostic = returnType.GetProperty("Diagnostic") is not null;
        var bespoke = returnType.GetProperty("Denied") is not null
            || returnType.GetProperty("Readable") is not null;

        var carried =
            status && diagnostic ? "statut + diagnostic"
            : status ? "statut seul"
            : bespoke ? "booléen dédié"
            : null;

        var gaps = returnType.GetProperty("Gaps") is not null ? "manques nommés" : null;

        return (carried, gaps) switch
        {
            (null, null) => "aucun",
            (null, not null) => gaps,
            (not null, null) => carried,
            _ => $"{carried} + {gaps}",
        };
    }

    /// <summary>
    /// The reading the table above rests on, pinned combination by combination — the same
    /// reason <c>StatusChannelTests.Carries</c> is pinned: a classifier that cannot itself be
    /// wrong is a classifier nobody checks, and this one was wrong.
    ///
    /// <para>
    /// The three rows carrying gaps are what this exists for. Only the last of them was
    /// reachable before, the other two being shadowed by an earlier branch, so adding a
    /// <c>Gaps</c> to <see cref="WmiRead"/> — a whole failure channel on a read the audit
    /// depends on — left the entire unit suite green. Measured, on this branch, before the
    /// reading was moved out of the branch: 954 passing, nothing red.
    /// </para>
    /// </summary>
    [Fact]
    public void Every_combination_of_channels_a_read_can_carry_is_named()
    {
        Assert.Equal("statut, sans donnée", Channel(typeof(ReadStatus)));
        Assert.Equal("aucun", Channel(typeof(NoChannel)));
        Assert.Equal("statut seul", Channel(typeof(StatusOnly)));
        Assert.Equal("statut + diagnostic", Channel(typeof(StatusAndDiagnostic)));
        Assert.Equal("booléen dédié", Channel(typeof(BespokeBoolean)));

        // Gaps beside each of the three, and alone. The first two are the combinations the
        // reading could not reach, and the first is ScheduledTaskRead's own shape.
        Assert.Equal(
            "statut + diagnostic + manques nommés", Channel(typeof(StatusDiagnosticAndGaps)));
        Assert.Equal("statut seul + manques nommés", Channel(typeof(StatusAndGaps)));
        Assert.Equal("booléen dédié + manques nommés", Channel(typeof(BespokeBooleanAndGaps)));
        Assert.Equal("manques nommés", Channel(typeof(GapsOnly)));
    }

    // The shapes a provider read can have, one per combination of channels, standing in for
    // the real records so that a combination nothing carries yet is still pinned.
    private sealed record NoChannel(IReadOnlyList<string> Items);

    private sealed record StatusOnly(ReadStatus Status);

    private sealed record StatusAndDiagnostic(ReadStatus Status, string? Diagnostic);

    private sealed record BespokeBoolean(bool Denied);

    private sealed record StatusAndGaps(
        ReadStatus Status, IReadOnlyDictionary<string, string>? Gaps);

    private sealed record StatusDiagnosticAndGaps(
        ReadStatus Status, string? Diagnostic, IReadOnlyDictionary<string, string>? Gaps);

    private sealed record BespokeBooleanAndGaps(
        bool Readable, IReadOnlyDictionary<string, string>? Gaps);

    private sealed record GapsOnly(IReadOnlyDictionary<string, string>? Gaps);
}
