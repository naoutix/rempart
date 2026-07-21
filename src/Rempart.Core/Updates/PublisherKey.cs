using System.Security.Cryptography;

namespace Rempart.Core.Updates;

/// <summary>
/// La paire de clés d'éditeur : ce qui sort de la génération, et rien de plus.
///
/// <see cref="EncryptedPrivateKey"/> est déjà chiffré par la phrase de passe quand
/// cet objet existe. Il n'y a volontairement aucun moyen d'obtenir la clé privée en
/// clair : le seul usage prévu est de l'écrire sur un support hors ligne.
/// </summary>
public sealed record PublisherKeyPair(
    string EncryptedPrivateKey,
    string PublicKey,
    string KeyId);

/// <summary>
/// Génère la paire de clés qui signera les manifestes.
///
/// <para>
/// Vit dans le binaire parce que celui-ci est autonome et tient sur une clé USB : la
/// génération doit pouvoir se faire sur une machine hors ligne, éventuellement une VM
/// jetable, sans y installer quoi que ce soit. La procédure initiale de l'ADR-002
/// passait par six lignes de PowerShell appelant .NET — elles ne fonctionnent pas sous
/// Windows PowerShell 5.1, qui s'exécute sur .NET Framework et ignore
/// <c>ExportPkcs8PrivateKey</c>. Sur une machine hors ligne, un script qui échoue est
/// un script qu'on ne peut pas déboguer.
/// </para>
/// </summary>
public static class PublisherKey
{
    /// <summary>
    /// Itérations de dérivation de la phrase de passe. Le coût est payé une fois à la
    /// génération et une fois à chaque signature — jamais dans un scan. Le prendre
    /// élevé est donc gratuit ici, et c'est ce qui sépare une clé USB perdue d'une clé
    /// compromise.
    /// </summary>
    private const int Iterations = 600_000;

    /// <summary>
    /// Le chiffrement n'est pas optionnel, et il n'y a pas de variante sans phrase de
    /// passe. Une clé privée en clair sur un support amovible, c'est un support
    /// amovible qui vaut la clé — or ces supports se perdent, se prêtent et se
    /// laissent branchés.
    /// </summary>
    public static PublisherKeyPair Generate(ReadOnlySpan<char> passphrase)
    {
        if (passphrase.Length < 12)
        {
            throw new ArgumentException(
                "Phrase de passe trop courte : 12 caractères au minimum. C'est elle " +
                "qui protège la clé si le support est perdu.");
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var parameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Iterations);

        var spki = key.ExportSubjectPublicKeyInfo();

        return new PublisherKeyPair(
            Convert.ToBase64String(key.ExportEncryptedPkcs8PrivateKey(passphrase, parameters)),
            Convert.ToBase64String(spki),
            ManifestVerifier.KeyId(spki));
    }

    /// <summary>
    /// Relit une clé privée chiffrée. Sert à vérifier immédiatement après génération
    /// que le fichier écrit est réutilisable — une clé qu'on ne peut pas relire ne se
    /// découvre pas le jour où l'on doit publier.
    /// </summary>
    public static string ReadPublicKeyOf(string encryptedPrivateKey, ReadOnlySpan<char> passphrase)
    {
        using var key = Open(encryptedPrivateKey, passphrase);
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>
    /// Ouvre une clé privée chiffrée pour signer. L'appelant en dispose — la clé ne doit
    /// pas séjourner en mémoire plus longtemps que la signature qu'elle produit.
    /// </summary>
    public static ECDsa Open(string encryptedPrivateKey, ReadOnlySpan<char> passphrase)
    {
        var key = ECDsa.Create();
        key.ImportEncryptedPkcs8PrivateKey(
            passphrase, Convert.FromBase64String(encryptedPrivateKey), out _);
        return key;
    }
}
