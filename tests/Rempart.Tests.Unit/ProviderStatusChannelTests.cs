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
    /// uniform inside a provider: <c>IRegistryProvider.ReadValue</c> carries a status and
    /// its two enumerating siblings carry none.
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

        // Une machine sans interface réseau configurée existe : zéro est une réponse.
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

        // FirewallState.Readable, canal maison : « non lu » ne devient jamais « ouvert ».
        "IFirewallProvider.Read → booléen dédié",

        // Un fichier hosts sans entrée est l'état par défaut de Windows.
        "IHostsFileProvider.ReadLines → aucun",

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

        // Dégradation voulue, et déjà payée : ReadValue lève sur une clé absente d'une
        // fixture ancienne là où ces deux-là rendent vide, ce qui est ce qui permet à une
        // capture antérieure d'être rejouée par du code plus récent.
        "IRegistryProvider.ListSubKeys → aucun",
        "IRegistryProvider.ListValues → aucun",

        // Statut sans diagnostic, toléré : l'appelant a nommé la valeur qu'il lisait, donc
        // « refusé » se suffit presque. Les énumérations n'ont pas ce contexte — elles
        // échouent pour une catégorie entière d'un coup.
        "IRegistryProvider.ReadValue → statut seul",

        "IScheduledTaskProvider.Enumerate → statut + diagnostic",

        // PolicyFacts.Denied, second canal maison. Un troisième devrait sauter aux yeux.
        "ISecurityPolicyProvider.Read → booléen dédié",

        "IServiceStateProvider.Read → statut seul",

        // SignatureStatus.Unknown tient le rôle du diagnostic : SignatureLadder le rend
        // « non vérifiable », jamais « non signé ». La distinction était perdue une couche
        // plus bas — le catalogue rendait le même null pour « aucun catalogue » et pour
        // « je n'ai pas pu demander » — jusqu'à ce que CatalogOutcome la nomme
        // (DET-CATALOGUE-MUET, fermée).
        "ISignatureProvider.Verify → statut seul",

        // Zéro logiciel installé est faux sur une machine réelle, mais un inventaire vide
        // n'est pas une bonne nouvelle qu'on pourrait prendre pour un verdict : il ne
        // déclenche aucune règle. Moins urgent que les ports.
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
    /// The two bespoke booleans are named here instead of being derived, and naming them is
    /// the point: <c>PolicyFacts.Denied</c> and <c>FirewallState.Readable</c> each invented
    /// their own way to say « je n'ai pas pu lire », so nothing but a list can find them.
    /// A third invention should be visible as an invention.
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

        if (status && diagnostic)
        {
            return "statut + diagnostic";
        }

        if (status)
        {
            return "statut seul";
        }

        if (returnType.GetProperty("Denied") is not null
            || returnType.GetProperty("Readable") is not null)
        {
            return "booléen dédié";
        }

        return "aucun";
    }
}
