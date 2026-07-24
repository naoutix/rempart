namespace Rempart.Core.Pac;

/// <summary>
/// What fetching a PAC returned: the proxies it names, and always a readable summary —
/// « route vers … », « aucune directive PROXY », « injoignable : … ».
///
/// An empty list does not mean "safe": the script may route only to DIRECT, or the fetch
/// may have failed. The summary says which.
/// </summary>
public sealed record PacAnalysis(IReadOnlyList<string> Proxies, string Summary);

/// <summary>
/// Fetches and analyses a PAC script. Abstracted so the enrichment can be tested without
/// network access (ADR-001, D5): a fake fetcher returns a known analysis.
/// </summary>
public interface IPacFetcher
{
    PacAnalysis Fetch(string pacUrl);
}
