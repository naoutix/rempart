using System.Globalization;

namespace Rempart.Core.Updates;

/// <summary>
/// L'âge des données au moment du scan.
///
/// <see cref="Unknown"/> compte autant que le reste : une date qu'on ne sait pas lire
/// ne doit pas passer pour une donnée fraîche. C'est le même principe que partout
/// ailleurs — une panne ne se déguise pas en résultat favorable.
/// </summary>
public sealed record DataAge(
    string AsOfUtc,
    int Days,
    bool Stale,
    bool Unknown,
    int ThresholdDays);

/// <summary>
/// Calcule depuis combien de temps les données évaluées datent.
///
/// <para>
/// L'ADR-002 (D15) l'exige dans chaque rapport : un binaire vieux de six mois audite
/// avec des règles de six mois, et rien ne le signalait. L'empreinte du catalogue
/// disait <em>quoi</em> ; l'âge dit <em>quand</em>.
/// </para>
///
/// <para>
/// Le seuil d'alerte est provisoire — l'ADR le note « arbitraire tant qu'on n'a pas
/// observé la cadence réelle ». Cent quatre-vingts jours, soit l'ordre des six mois
/// cités par la décision, à revoir une fois la fréquence de publication connue.
/// </para>
/// </summary>
public static class DataFreshness
{
    public const int DefaultThresholdDays = 180;

    public static DataAge At(string asOfUtc, string nowUtc, int thresholdDays = DefaultThresholdDays)
    {
        if (!TryParse(asOfUtc, out var asOf) || !TryParse(nowUtc, out var now))
        {
            // Ni fraîche ni périmée : illisible. Le rapport le dira tel quel plutôt que
            // de laisser croire à une donnée à jour.
            return new DataAge(asOfUtc, 0, Stale: false, Unknown: true, thresholdDays);
        }

        // Un instantané rejoué porte une heure figée, souvent antérieure à la date des
        // données embarquées : l'âge y est négatif et n'a pas de sens. On le plafonne à
        // zéro — « au moins aussi récente que le scan » — plutôt que d'afficher un
        // nombre de jours négatif que personne ne saurait interpréter.
        var days = (int)Math.Floor((now - asOf).TotalDays);
        if (days < 0)
        {
            days = 0;
        }

        return new DataAge(asOfUtc, days, days > thresholdDays, Unknown: false, thresholdDays);
    }

    private static bool TryParse(string value, out DateTimeOffset parsed) =>
        DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out parsed);
}
