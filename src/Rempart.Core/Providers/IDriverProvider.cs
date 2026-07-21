namespace Rempart.Core.Providers;

/// <summary>
/// Un pilote noyau chargé : son nom et le fichier d'où il vient.
///
/// L'empreinte n'est pas ici — elle vient du <see cref="ISignatureProvider"/>, qui la
/// calcule en même temps qu'il vérifie la signature. Un pilote ne porte que ce qui
/// l'identifie ; ce qu'on en juge est calculé ailleurs.
/// </summary>
public sealed record LoadedDriver(string Name, string Path);

/// <summary>
/// Énumère les pilotes noyau actuellement chargés.
///
/// <para>
/// C'est la surface d'un pilote vulnérable réellement en mémoire — le cœur d'une
/// attaque « BYOVD » (bring your own vulnerable driver), où un pilote signé mais
/// faillible est chargé pour obtenir le noyau. Un pilote présent sur le disque mais
/// non chargé n'est pas couvert : il ne s'exécute pas, et l'inventaire dirait le
/// contraire.
/// </para>
///
/// <para>
/// Abstrait comme le reste (ADR-001, D5) : le jugement se teste sur une liste de
/// pilotes donnée, sans exiger d'en charger un vrai.
/// </para>
/// </summary>
public interface IDriverProvider
{
    IReadOnlyList<LoadedDriver> Enumerate();
}
