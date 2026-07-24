namespace Rempart.Core.Providers;

/// <summary>
/// A saved Wi-Fi profile: a network the machine knows how to join.
///
/// <para>
/// What matters for security: the strength of the encryption, and whether the machine
/// connects <b>automatically</b>. An open or WEP profile with auto-connect is an AP
/// spoofing ("evil twin") vector: the machine silently joins an access point that
/// impersonates the known SSID.
/// </para>
/// </summary>
public sealed record WifiProfile(
    string Name,
    string Authentication,
    string Encryption,
    bool AutoConnect);

/// <summary>
/// Enumerates the saved Wi-Fi profiles, already decoded. Abstracted like the rest
/// (ADR-001, D5): the judgment is tested against a given list, without a Wi-Fi adapter.
/// </summary>
public interface IWifiProfileProvider
{
    IReadOnlyList<WifiProfile> Read();
}
