using System.Text;
using System.Text.Json;

namespace Rempart.Core.Updates;

/// <summary>
/// Raised when the upstream list carries an identifier this repository has not judged.
///
/// <para>
/// Its own type rather than a bare exception, because the caller acts on it: the command
/// prints the list and stops. Every missing identifier is named at once — discovering them
/// one download at a time would be the same list rediscovered as many times.
/// </para>
/// </summary>
public sealed class UnjudgedEntriesException(IReadOnlyList<string> appIds) : Exception(
    $"{appIds.Count} identifiant(s) sans jugement : {string.Join(", ", appIds)}. "
    + "Une entrée sans note d'impact n'entre pas au catalogue : compléter le fichier de "
    + "jugement, puis relancer.")
{
    public IReadOnlyList<string> AppIds { get; } = appIds;
}

/// <summary>
/// Joins the upstream bloatware list with the judgement written in this repository, and
/// produces the catalogue the publisher signs (ADR-006, D18 and D19).
///
/// <para>
/// Upstream supplies facts — an identifier, a removal method, a recommendation — and this
/// repository supplies the judgement: category, risk, and the impact note without which an
/// entry does not get in. The split is the whole point: identifiers are tedious and
/// verifiable, judgement is what distinguishes this catalogue from a debloat list.
/// </para>
///
/// <para>
/// Read with <c>JsonDocument</c> rather than generated types, like
/// <see cref="LolDriversImport"/> and for the same reason: the upstream schema does not
/// belong to this project, so only what is needed is read and a field changing elsewhere
/// breaks nothing.
/// </para>
/// </summary>
public static class Win11DebloatImport
{
    /// <summary>
    /// The upstream list, pinned by commit rather than by branch: a branch is a moving
    /// target, and a dataset a security tool signs should come from a revision someone chose.
    /// Refreshing it is a deliberate edit, and the diff of the produced catalogue says what
    /// moved.
    /// </summary>
    public const string SourceUrl =
        "https://raw.githubusercontent.com/Raphire/Win11Debloat/"
        + "0f30b622214f3a28a0bf4b611941c8318a77dd19/Config/Apps.json";

    /// <summary>Credited in the catalogue file, because MIT asks for attribution.</summary>
    public const string Attribution =
        "Raphire/Win11Debloat (MIT, Copyright (c) 2020 Raphire) — identifiants importés, "
        + "jugement et notes d'impact écrits par Rempart";

    /// <summary>
    /// The local judgement of one upstream identifier. Keyed by <c>appId</c> so it survives
    /// upstream renaming a friendly name, which happens and means nothing.
    /// </summary>
    private sealed record Judgement(
        string Category,
        BloatwareRisk Risk,
        string Impact,
        ImpactProvenance ImpactSource);

    public static BloatwareCatalogFile Transform(string upstreamJson, string judgementJson, string asOfUtc)
    {
        var judgements = ReadJudgements(WithoutByteOrderMark(judgementJson));

        using var upstream = JsonDocument.Parse(WithoutByteOrderMark(upstreamJson));

        if (!upstream.RootElement.TryGetProperty("Apps", out var apps)
            || apps.ValueKind != JsonValueKind.Array)
        {
            // A response of another shape yields zero entries, and zero entries would sign as
            // "no bloatware is known". Refusing beats writing a truncated catalogue that
            // passes for complete -- the same call LolDriversImport's caller makes.
            throw new JsonException(
                "Réponse amont sans tableau « Apps » : la source a probablement changé de forme.");
        }

        var identifiers = new List<string>();

        foreach (var app in apps.EnumerateArray())
        {
            if (!app.TryGetProperty("AppId", out var appId))
            {
                continue;
            }

            // One entry of the upstream list carries an array here, and its two values are
            // not even the same kind of identifier: a package name and a Store product id.
            // Normalising to a list is what keeps that entry from being read as one broken
            // identifier -- or silently skipped.
            switch (appId.ValueKind)
            {
                case JsonValueKind.String when appId.GetString() is { Length: > 0 } single:
                    identifiers.Add(single);
                    break;

                case JsonValueKind.Array:
                    foreach (var element in appId.EnumerateArray())
                    {
                        if (element.ValueKind == JsonValueKind.String
                            && element.GetString() is { Length: > 0 } value)
                        {
                            identifiers.Add(value);
                        }
                    }

                    break;
            }
        }

        var unjudged = identifiers
            .Where(id => !judgements.ContainsKey(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        if (unjudged.Count > 0)
        {
            throw new UnjudgedEntriesException(unjudged);
        }

        var entries = identifiers
            .Distinct(StringComparer.OrdinalIgnoreCase)
            // Ordered so that two imports of the same upstream produce the same file: the
            // output is signed, and a re-run that reordered entries would make every diff
            // unreadable and every signature look like a change.
            .OrderBy(id => id, StringComparer.Ordinal)
            .Select(id => Entry(id, judgements[id]))
            .ToList();

        return new BloatwareCatalogFile(asOfUtc, Attribution, entries);
    }

    private static BloatwareEntry Entry(string appId, Judgement judgement) =>
        new(
            IdOf(appId),
            // The match mode follows the FORM of the value, never what upstream says about
            // removal: a value carrying a publisher hash is a family name, one without is a
            // package name. BloatwareCatalogTests holds the same pairing from the other side.
            appId.Contains('_', StringComparison.Ordinal) ? BloatwareMatch.Pfn : BloatwareMatch.PackageName,
            appId,
            judgement.Category,
            // Deliberately NOT derived from the upstream recommendation: that field says what
            // breaks if you remove the software, this one says why it is catalogued at all.
            // The two are orthogonal, and conflating them would mark the Microsoft Store as
            // security-relevant while leaving a telemetry app as merely unwanted.
            judgement.Risk,
            judgement.Impact,
            judgement.ImpactSource);

    /// <summary>
    /// A stable identifier derived from the upstream one: deterministic, so the same upstream
    /// twice gives the same file, and readable in a report rather than a hash.
    /// </summary>
    private static string IdOf(string appId)
    {
        var builder = new StringBuilder("BLOAT-", appId.Length + 6);

        foreach (var character in appId)
        {
            builder.Append(char.IsLetterOrDigit(character)
                ? char.ToUpperInvariant(character)
                : '-');
        }

        var id = builder.ToString();
        return id.Length <= 60 ? id : id[..60];
    }

    private static Dictionary<string, Judgement> ReadJudgements(string judgementJson)
    {
        using var document = JsonDocument.Parse(judgementJson);

        if (!document.RootElement.TryGetProperty("entries", out var entries)
            || entries.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException(
                "Fichier de jugement sans tableau « entries » : fichier probablement d'un autre type.");
        }

        var result = new Dictionary<string, Judgement>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.EnumerateArray())
        {
            var appId = Text(entry, "appId");
            var category = Text(entry, "category");
            var impact = Text(entry, "impact");

            if (string.IsNullOrWhiteSpace(appId)
                || string.IsNullOrWhiteSpace(category)
                || string.IsNullOrWhiteSpace(impact))
            {
                throw new JsonException(
                    $"Jugement incomplet pour « {appId ?? "(sans identifiant)"} » : "
                    + "identifiant, catégorie et note d'impact sont obligatoires.");
            }

            result[appId] = new Judgement(
                category,
                Enum.TryParse<BloatwareRisk>(Text(entry, "risk"), ignoreCase: true, out var risk)
                    ? risk
                    // Unwanted rather than SecurityRelevant when unreadable: a missing value
                    // must not promote an entry into the category that carries more weight.
                    : BloatwareRisk.Unwanted,
                impact,
                Enum.TryParse<ImpactProvenance>(Text(entry, "impactSource"), ignoreCase: true, out var source)
                    ? source
                    // Same reasoning, and D20's default: unstated provenance is not verified.
                    : ImpactProvenance.Upstream);
        }

        return result;
    }

    /// <summary>
    /// Drops a leading byte-order mark, which <see cref="JsonDocument"/> rejects as an
    /// invalid start of value.
    ///
    /// <para>
    /// Applied to <b>both</b> inputs, and neither is theoretical. The upstream file carries
    /// one — found by running the command rather than by reading the data, since the mark is
    /// invisible in every viewer. And the judgement file is edited on Windows, where a
    /// PowerShell redirection writes UTF-8 <em>with</em> a mark by default; this repository
    /// has already paid once for assuming otherwise about its own scripts.
    /// </para>
    /// </summary>
    private static string WithoutByteOrderMark(string json) =>
        json.Length > 0 && json[0] == '﻿' ? json[1..] : json;

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
