namespace Rempart.Core.Rules;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>
/// Comment comparer la valeur observée à celle attendue. Volontairement pauvre :
/// une règle doit rester lisible par quelqu'un qui n'écrit pas de code.
/// </summary>
public enum CheckOperator
{
    /// <summary>Égalité stricte.</summary>
    Equals,

    /// <summary>Différence stricte.</summary>
    NotEquals,

    /// <summary>Valeur numérique supérieure ou égale — planchers de configuration.</summary>
    AtLeast,

    /// <summary>Valeur numérique inférieure ou égale — plafonds, comme un nombre
    /// d'administrateurs locaux.</summary>
    AtMost,

    /// <summary>La valeur existe, quelle qu'elle soit.</summary>
    Exists,

    /// <summary>La valeur n'existe pas.</summary>
    Absent,
}

public enum CheckKind
{
    /// <summary>Valeur de registre.</summary>
    Registry,

    /// <summary>Existence d'une clé de registre.</summary>
    RegistryKey,

    /// <summary>
    /// État ou mode de démarrage d'un service Windows. <c>path</c> porte le nom du
    /// service, <c>value</c> vaut « state » ou « startMode ».
    /// </summary>
    Service,

    /// <summary>
    /// Fait de politique locale — mot de passe, verrouillage, comptes. <c>path</c>
    /// porte le nom du fait, par exemple « password.minLength ».
    /// </summary>
    Policy,

    /// <summary>
    /// Propriété WMI. <c>path</c> porte « espaceDeNoms:Classe », <c>value</c> le nom
    /// de la propriété. Seul moyen d'établir certains états — chiffrement effectif
    /// d'un volume, état courant de Defender — que ni le registre ni les API Win32
    /// ne rendent.
    /// </summary>
    Wmi,
}

public sealed record CheckSpec(
    CheckKind Kind,
    string Path,
    string? ValueName,
    CheckOperator Operator,
    string? Expected,

    /// <summary>
    /// Valeur appliquée par Windows quand la clé est absente.
    ///
    /// Sur le registre Windows, l'absence n'est pas une anomalie : c'est le cas
    /// courant, et le comportement effectif dépend d'un défaut documenté. Traiter
    /// toute absence comme un échec produit des alertes fausses en masse — WDigest
    /// absent signifie « pas de mot de passe en clair », NoAutoUpdate absent signifie
    /// « mises à jour actives ». Les deux sont l'état souhaité.
    ///
    /// Obligatoire pour tout opérateur de comparaison : le chargement échoue sinon.
    /// Renseigner ce champ force l'auteur de la règle à connaître le défaut Windows,
    /// qui est précisément ce qui rend la règle juste.
    /// </summary>
    string? WindowsDefault);

/// <summary>
/// Ce que coûte une remédiation. Inerte en v1 : aucun provider en écriture n'existe
/// avant M9. Renseignée dès maintenant pour que l'information soit écrite au moment
/// où l'on comprend la règle, et non reconstituée un an plus tard.
/// </summary>
public enum Reversibility
{
    Trivial,
    Reinstallable,
    RestorePointOnly,
    Irreversible,
}

/// <summary>
/// Ce que coûte l'application d'une règle, décomposé plutôt que laissé en texte libre.
///
/// Un champ unique « impact » se remplit vite de généralités — « peut avoir des effets
/// de bord » — qui ne permettent aucune décision. Les trois questions ci-dessous sont
/// celles qu'on se pose réellement avant d'appliquer un durcissement sur un parc :
/// qu'est-ce qui cesse de marcher, qui est concerné, comment le savoir à l'avance.
///
/// Les deux premières sont obligatoires. « Rien » est une réponse recevable — mais
/// elle doit être écrite, pas déduite d'un champ vide.
/// </summary>
public sealed record Remediation(
    Reversibility Reversibility,

    /// <summary>Ce qui cesse de fonctionner après application.</summary>
    string Breaks,

    /// <summary>Dans quels cas, et sur quel type de machine.</summary>
    string Affects,

    /// <summary>Comment vérifier avant d'appliquer. Optionnel.</summary>
    string? VerifyBefore);

/// <summary>
/// Conditions sous lesquelles une règle a un sens.
///
/// Sans elles, un contrôle qui ne vaut que dans un contexte précis produit du bruit
/// partout ailleurs — et le bruit disqualifie un outil d'audit plus sûrement qu'un
/// contrôle manquant. Interdire la fusion des règles de pare-feu locales protège une
/// machine sous stratégie de groupe ; sur un poste autonome, la même action supprime
/// les règles créées par les applications sans rien apporter.
///
/// Toutes les conditions renseignées doivent être vraies.
/// </summary>
public sealed record Applicability(
    /// <summary>Exige (ou exclut) une machine jointe à un domaine.</summary>
    bool? DomainJoined = null,

    /// <summary>
    /// Condition portant sur le registre — typiquement l'activation d'une
    /// fonctionnalité dont dépend le contrôle. NLA n'a de sens que si RDP est actif.
    /// </summary>
    CheckSpec? Registry = null)
{
    public bool IsUnconditional => DomainJoined is null && Registry is null;
}

public sealed record Rule(
    string Id,
    string Title,
    Severity Severity,
    string Domain,
    string Rationale,
    IReadOnlyList<string> References,
    CheckSpec Check,
    Remediation? Remediation,
    Applicability? AppliesWhen = null);
