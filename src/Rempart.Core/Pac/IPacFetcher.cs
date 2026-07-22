namespace Rempart.Core.Pac;

/// <summary>
/// Ce qu'a rendu la récupération d'un PAC : les proxys qu'il nomme, et toujours un résumé
/// lisible — « route vers … », « aucune directive PROXY », « injoignable : … ».
///
/// Une liste vide ne veut pas dire « sûr » : le script peut ne router que vers DIRECT, ou
/// la récupération avoir échoué. Le résumé dit lequel.
/// </summary>
public sealed record PacAnalysis(IReadOnlyList<string> Proxies, string Summary);

/// <summary>
/// Récupère et analyse un script PAC. Abstrait pour que l'enrichissement se teste sans
/// réseau (ADR-001, D5) : un récupérateur factice rend une analyse connue.
/// </summary>
public interface IPacFetcher
{
    PacAnalysis Fetch(string pacUrl);
}
