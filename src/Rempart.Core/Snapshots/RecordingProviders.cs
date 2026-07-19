using Rempart.Core.Providers;

namespace Rempart.Core.Snapshots;

/// <summary>
/// Enveloppe un provider réel et consigne chaque lecture dans un instantané.
///
/// La capture est donc un sous-produit du scan, pas une liste de clés maintenue à la main :
/// une fixture ne peut pas être incomplète pour les collecteurs qui l'ont produite.
/// </summary>
public sealed class RecordingRegistryProvider(IRegistryProvider inner, MachineSnapshot snapshot)
    : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        var read = inner.ReadValue(keyPath, valueName);
        // Les lectures infructueuses sont consignées aussi : sans elles, le rejeu
        // divergerait sur exactement les cas qu'on cherche à tester.
        snapshot.Registry[SnapshotKeys.Value(keyPath, valueName)] = read;
        return read;
    }

    public ReadStatus KeyExists(string keyPath)
    {
        var status = inner.KeyExists(keyPath);
        snapshot.Registry[SnapshotKeys.Existence(keyPath)] = new RegistryRead(status, null);
        return status;
    }
}

public sealed class RecordingSystemInfoProvider(ISystemInfoProvider inner, MachineSnapshot snapshot)
    : ISystemInfoProvider
{
    public SystemInfo Read()
    {
        var info = inner.Read();
        snapshot.SystemInfo = info;
        return info;
    }
}

/// <summary>
/// Levée quand un rejeu demande une donnée absente de l'instantané. Un échec bruyant
/// est préférable à une valeur par défaut qui ferait passer un test pour la mauvaise raison.
/// </summary>
public sealed class SnapshotIncompleteException(string message) : Exception(message);

public sealed class SnapshotRegistryProvider(MachineSnapshot snapshot) : IRegistryProvider
{
    public RegistryRead ReadValue(string keyPath, string valueName)
    {
        var key = SnapshotKeys.Value(keyPath, valueName);
        return snapshot.Registry.TryGetValue(key, out var read)
            ? read
            : throw new SnapshotIncompleteException(
                $"Lecture non enregistrée dans l'instantané : {key}. " +
                "La fixture a probablement été capturée avec un jeu de collecteurs différent.");
    }

    public ReadStatus KeyExists(string keyPath)
    {
        var key = SnapshotKeys.Existence(keyPath);
        return snapshot.Registry.TryGetValue(key, out var read)
            ? read.Status
            : throw new SnapshotIncompleteException($"Test d'existence non enregistré : {key}.");
    }
}

public sealed class SnapshotSystemInfoProvider(MachineSnapshot snapshot) : ISystemInfoProvider
{
    public SystemInfo Read() =>
        snapshot.SystemInfo
        ?? throw new SnapshotIncompleteException("Aucune information système dans l'instantané.");
}
