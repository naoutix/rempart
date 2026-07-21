using System.Text;
using Rempart.Core.Rules;

namespace Rempart.Core.Updates;

/// <summary>
/// Va chercher des octets à une URL. Abstrait pour que l'orchestration réseau se teste
/// sans réseau (ADR-001, D5) — un transport factice sert des octets connus.
/// </summary>
public interface IUpdateTransport
{
    /// <summary>Les octets à cette URL, ou <c>null</c> en cas d'échec — motif dans <paramref name="error"/>.</summary>
    byte[]? Get(string url, out string? error);
}

/// <summary>
/// Ce qu'un téléchargement a rapporté : la prévisualisation, et les octets déjà en main
/// pour l'application — pour ne pas retélécharger ce qu'on vient de vérifier.
/// </summary>
public sealed record RemoteFetch(
    UpdatePreview Preview,
    byte[] ManifestBytes,
    IReadOnlyDictionary<string, byte[]> DatasetBytes);

/// <summary>
/// Télécharge une mise à jour et la prépare — sans jamais faire confiance au transport.
///
/// <para>
/// C'est le point où l'ADR-002 se joue en entier. L'option « confiance dans le
/// transport » a été <b>écartée</b> : HTTPS n'atteste de rien ici. Un manifeste
/// téléchargé passe exactement la même vérification qu'un fichier apporté à la main —
/// signature contre les clés épinglées, empreinte de chaque jeu de données. Un serveur
/// compromis, un intermédiaire, une redirection : aucun ne peut faire accepter des
/// données que l'éditeur n'a pas signées. Le transport n'apporte que la commodité, pas
/// la confiance.
/// </para>
///
/// <para>
/// Le pipeline est celui de <see cref="UpdatePlanner"/>, inchangé : seule la source des
/// octets diffère. C'est ce que le délégué de lecture injecté rendait possible depuis
/// le début.
/// </para>
/// </summary>
public static class RemoteUpdate
{
    public static (RemoteFetch? Fetch, string? Error) Prepare(
        string baseUrl,
        IUpdateTransport transport,
        ManifestVerifier verifier,
        IReadOnlyList<Rule> currentRules)
    {
        var manifestUrl = Join(baseUrl, UpdateStore.ManifestFileName);
        var manifestBytes = transport.Get(manifestUrl, out var error);

        if (manifestBytes is null)
        {
            // Le manifeste injoignable est distinct d'un manifeste refusé : c'est le
            // réseau qui a échoué, pas la confiance. Le dire tel quel.
            return (null, $"Manifeste injoignable ({manifestUrl}) : {error}");
        }

        // Les octets de chaque jeu de données sont retenus au passage : l'application les
        // réutilise sans un second téléchargement, et sans un second aller-retour où le
        // serveur pourrait répondre autre chose que ce qu'on vient de vérifier.
        var cache = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        byte[]? Read(string name)
        {
            var bytes = transport.Get(Join(baseUrl, name), out _);
            if (bytes is not null)
            {
                cache[name] = bytes;
            }

            return bytes;
        }

        var preview = UpdatePlanner.Prepare(
            Encoding.UTF8.GetString(manifestBytes), verifier, Read, currentRules);

        return (new RemoteFetch(preview, manifestBytes, cache), null);
    }

    /// <summary>
    /// Compose l'URL d'une ressource sous la base, sans doubler ni oublier le séparateur.
    /// </summary>
    private static string Join(string baseUrl, string name) =>
        baseUrl.TrimEnd('/') + "/" + name.TrimStart('/');
}
