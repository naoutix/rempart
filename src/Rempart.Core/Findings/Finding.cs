namespace Rempart.Core.Findings;

/// <summary>
/// Gravité d'un constat. Distincte de la sévérité d'une règle : celle-ci qualifie un
/// écart de configuration, celle-là ce qu'on a trouvé installé.
/// </summary>
public enum FindingSeverity
{
    /// <summary>Rien d'anormal. Énuméré pour l'inventaire, pas pour alerter.</summary>
    Benign,

    /// <summary>Mérite un coup d'œil : inhabituel sans être suspect.</summary>
    Notable,

    /// <summary>Correspond à une technique connue, ou contredit une attente forte.</summary>
    Suspicious,
}

/// <summary>
/// Ce qu'on a trouvé sur la machine, par opposition à ce qu'on a jugé de sa
/// configuration.
///
/// Une règle compare une valeur à une attente et rend un verdict. La persistance ne
/// s'exprime pas ainsi : dix-sept programmes au démarrage dont trois non signés ne se
/// résument pas à « 3, attendu 0 » — ce qui compte, ce sont lesquels. Un constat porte
/// donc son propre jugement, et le rapport les énumère.
///
/// Les deux ne se mélangent pas dans le score : une configuration à 94 % ne doit pas
/// masquer un binaire non signé lancé au démarrage.
/// </summary>
public sealed record Finding(
    /// <summary>Famille du constat — « autorun », « driver », « wmi-subscription ».</summary>
    string Kind,

    /// <summary>D'où il vient : clé de registre, dossier, nom de tâche.</summary>
    string Source,

    /// <summary>Ce qui s'exécute.</summary>
    string Target,

    FindingSeverity Severity,

    /// <summary>Pourquoi ce constat est signalé. Vide s'il est bénin.</summary>
    IReadOnlyList<string> Reasons,

    /// <summary>Détails observés — éditeur, empreinte, état de signature.</summary>
    IReadOnlyDictionary<string, string> Details);
