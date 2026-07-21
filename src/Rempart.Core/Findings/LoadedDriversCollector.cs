using Rempart.Core.Providers;
using Rempart.Core.Updates;

namespace Rempart.Core.Findings;

/// <summary>
/// Pilotes noyau chargés.
///
/// <para>
/// Un pilote s'exécute dans le noyau : ce qu'il fait n'est arbitré par rien. Deux
/// choses le rendent intéressant à un audit. D'abord sa signature — un pilote noyau non
/// signé n'a rien à faire sur une machine à Secure Boot, et c'est le premier signe
/// d'un chargement forcé. Ensuite son empreinte, confrontée à la liste des pilotes
/// vulnérables connus : un pilote parfaitement signé mais faillible est l'outil même du
/// « BYOVD », où l'on apporte un pilote légitime pour s'en servir de levier.
/// </para>
///
/// <para>
/// Le jugement de signature est celui des autres persistances (<see cref="SignatureLadder"/>) :
/// une même absence de signature ne doit pas être suspecte ici et anodine ailleurs. La
/// confrontation à la liste de blocage vient par-dessus, et ne peut qu'aggraver — un
/// pilote connu vulnérable est suspect même signé.
/// </para>
/// </summary>
public sealed class LoadedDriversCollector(DriverBlocklist blocklist) : IFindingCollector
{
    public string Name => "drivers";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var findings = new List<Finding>();

        foreach (var driver in providers.Drivers.Enumerate())
        {
            var judgement = SignatureLadder.Judge(driver.Path, providers.Signatures);

            var details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["chemin"] = driver.Path,
            };
            SignatureLadder.Describe(judgement.Signature, details);

            var severity = judgement.Severity;
            var reasons = new List<string>(judgement.Reasons);

            // La liste de blocage se juge sur l'empreinte que la vérification de
            // signature vient de calculer — pas de second calcul. Un pilote connu
            // vulnérable est suspect quelle que soit sa signature : c'est justement un
            // pilote signé qu'un attaquant apporte.
            if (blocklist.Match(judgement.Signature.Sha256) is { } blocked)
            {
                severity = FindingSeverity.Suspicious;
                reasons.Insert(0,
                    $"Pilote vulnérable connu ({blocked.Category}) : {blocked.Name}. " +
                    "Signé ou non, il peut servir de levier vers le noyau.");
                details["loldrivers"] = blocked.Category;
            }

            findings.Add(new Finding("driver", driver.Name, driver.Path, severity, reasons, details));
        }

        return findings;
    }
}
