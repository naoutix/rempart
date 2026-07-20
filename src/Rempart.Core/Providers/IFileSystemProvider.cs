namespace Rempart.Core.Providers;

/// <summary>
/// Liste des fichiers d'un répertoire.
///
/// Abstrait pour la même raison que le registre (ADR-001, D5) : un instantané doit
/// pouvoir être rejoué hors-ligne, et une énumération de dossier fait partie de ce
/// qu'un scan observe.
/// </summary>
public interface IFileSystemProvider
{
    /// <summary>
    /// Fichiers du répertoire, chemins complets. Vide si le répertoire n'existe pas
    /// ou n'est pas lisible — l'énumération des autres emplacements doit se poursuivre.
    /// </summary>
    IReadOnlyList<string> ListFiles(string directory);
}
