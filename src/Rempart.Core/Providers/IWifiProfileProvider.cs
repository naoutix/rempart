namespace Rempart.Core.Providers;

/// <summary>
/// Un profil Wi-Fi enregistré : un réseau que la machine sait rejoindre.
///
/// <para>
/// Ce qui compte pour la sécurité : la robustesse du chiffrement, et si la machine s'y
/// connecte <b>automatiquement</b>. Un profil ouvert ou WEP en connexion automatique est
/// un vecteur d'usurpation d'AP (« evil twin ») : la machine rejoint en silence un point
/// d'accès qui se fait passer pour le SSID connu.
/// </para>
/// </summary>
public sealed record WifiProfile(
    string Name,
    string Authentication,
    string Encryption,
    bool AutoConnect);

/// <summary>
/// Énumère les profils Wi-Fi enregistrés, déjà décodés. Abstrait comme le reste
/// (ADR-001, D5) : le jugement se teste sur une liste donnée, sans carte Wi-Fi.
/// </summary>
public interface IWifiProfileProvider
{
    IReadOnlyList<WifiProfile> Read();
}
