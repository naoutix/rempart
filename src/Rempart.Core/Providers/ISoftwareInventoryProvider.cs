namespace Rempart.Core.Providers;

/// <summary>D'où vient une entrée d'inventaire — chaque source a sa fiabilité et sa sémantique.</summary>
public enum SoftwareSource
{
    /// <summary>Clés de désinstallation classiques (MSI/EXE), au registre.</summary>
    Uninstall,

    /// <summary>Paquet Appx/MSIX (Store, applications modernes).</summary>
    Appx,

    /// <summary>Exécutable autonome enregistré sous <c>App Paths</c>.</summary>
    AppPath,

    /// <summary>Paquet installé par Chocolatey.</summary>
    Chocolatey,
}

/// <summary>
/// Un logiciel installé, quelle que soit sa source.
///
/// <para>
/// Deux drapeaux portent la distinction D6/D7 : un paquet Appx <b>provisionné</b> est stagé
/// pour tous les utilisateurs et <b>revient après une mise à jour de fonctionnalité</b> même
/// si l'utilisateur l'a retiré — c'est le cas qui compte pour le bloatware. Un logiciel
/// classique, lui, survit aux mises à jour sans être provisionné.
/// </para>
/// </summary>
public sealed record InstalledSoftware(
    string Name,
    string? Version,
    string? Publisher,
    SoftwareSource Source,
    bool Provisioned,
    bool SurvivesFeatureUpdate,
    /// <summary>
    /// Identifiant stable pour l'appariement exact du catalogue (M5b) : le
    /// <b>Package Family Name</b> pour un Appx, le <b>nom de clé Uninstall</b> pour une
    /// désinstallation classique. <c>null</c> ailleurs (App Paths, Chocolatey), qui ne
    /// s'apparient alors que par motif de nom/éditeur. Une capture d'avant M5b se relit
    /// avec <c>null</c> — l'exact ne matche pas, le motif reste.
    /// </summary>
    string? Identifier = null);

/// <summary>
/// Énumère les logiciels installés, déjà décodés. Abstrait comme le reste (ADR-001, D5) :
/// le jugement — et le croisement au catalogue bloatware (M5b) — se teste sur une liste
/// donnée, sans machine.
/// </summary>
public interface ISoftwareInventoryProvider
{
    IReadOnlyList<InstalledSoftware> Read();
}
