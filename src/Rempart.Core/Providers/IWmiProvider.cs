namespace Rempart.Core.Providers;

/// <summary>
/// Une instance WMI réduite à ses propriétés scalaires, rendues en texte.
///
/// Le moteur de règles compare des chaînes ; typer davantage n'apporterait rien et
/// obligerait chaque règle à connaître le type CIM de la propriété qu'elle interroge.
/// </summary>
public sealed record WmiInstance(IReadOnlyDictionary<string, string> Properties)
{
    public string? Find(string property) =>
        Properties.TryGetValue(property, out var value) ? value : null;
}

public sealed record WmiRead(
    ReadStatus Status,
    IReadOnlyList<WmiInstance> Instances,

    /// <summary>
    /// Raison de l'échec, quand il ne s'agit pas d'un refus d'accès légitime.
    ///
    /// Une première version rendait « accès refusé » pour toute défaillance, ce qui
    /// rendait un bug indiscernable d'un manque de droits — et a effectivement conduit
    /// à un mauvais diagnostic. Une défaillance interne doit se voir.
    /// </summary>
    string? Diagnostic = null)
{
    public static readonly WmiRead AccessDenied = new(ReadStatus.AccessDenied, []);
    public static readonly WmiRead NotFound = new(ReadStatus.NotFound, []);

    public static WmiRead Found(IReadOnlyList<WmiInstance> instances) =>
        new(ReadStatus.Found, instances);

    public static WmiRead Failed(string reason) =>
        new(ReadStatus.AccessDenied, [], reason);
}

/// <summary>
/// Interroge WMI. Reste le seul moyen d'établir certains états que ni le registre ni
/// les API Win32 ne rendent : chiffrement effectif d'un volume, état courant de
/// Defender.
///
/// La plupart de ces espaces de noms exigent l'élévation. Un refus doit se traduire
/// par « non vérifiable », jamais par une non-conformité : le scan n'a pas pu
/// regarder, la machine n'est pas en cause.
/// </summary>
public interface IWmiProvider
{
    /// <param name="namespacePath">Par exemple <c>root\CIMV2\Security\MicrosoftVolumeEncryption</c>.</param>
    /// <param name="className">Classe à énumérer.</param>
    /// <param name="properties">
    /// Propriétés à lire, nommées par l'appelant. Les énumérer demanderait un
    /// SAFEARRAY, que l'interop compatible AOT ne sait pas exprimer — et une règle
    /// sait de toute façon quelle propriété elle interroge.
    /// </param>
    WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties);
}
