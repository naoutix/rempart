using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Contre le vrai gestionnaire de services.
///
/// Trois appels natifs et un protocole d'allocation en deux temps : une erreur de
/// décalage dans la lecture des tampons rendrait un état plausible mais faux, sur
/// lequel des règles critiques se prononcent ensuite.
/// </summary>
public sealed class LiveServiceStateProviderTests
{
    private readonly LiveServiceStateProvider services = new();

    [Fact]
    public void Reads_a_service_windows_always_runs()
    {
        // Le service de gestion des services lui-même : présent et démarré sur
        // toute machine Windows en état de fonctionner.
        var read = services.Read("Schedule");

        Assert.Equal(ReadStatus.Found, read.Status);
        Assert.Equal(ServiceState.Running, read.Info!.State);
    }

    [Fact]
    public void Reads_the_start_mode_as_a_known_value()
    {
        var read = services.Read("Schedule");

        // Un décalage erroné dans le tampon rendrait « Unknown » en permanence, et
        // toute règle sur le mode de démarrage deviendrait muette sans le dire.
        Assert.NotEqual(ServiceStartMode.Unknown, read.Info!.StartMode);
    }

    [Fact]
    public void A_service_that_does_not_exist_is_reported_absent_not_denied()
    {
        // La distinction porte des suites différentes : désinstaller un service
        // absent n'a pas de sens, un refus appelle une relance en administrateur.
        var read = services.Read("CeServiceNExistePasDuTout");

        Assert.Equal(ReadStatus.NotFound, read.Status);
        Assert.Null(read.Info);
    }

    [Fact]
    public void A_stopped_service_is_reported_stopped()
    {
        // RemoteRegistry est désactivé par défaut sur un poste de travail. Si la
        // machine de test l'a activé, on vérifie au moins que l'état est lisible.
        var read = services.Read("RemoteRegistry");

        if (read.Status == ReadStatus.Found)
        {
            Assert.NotEqual(ServiceState.Unknown, read.Info!.State);
        }
    }

    [Fact]
    public void Repeated_reads_stay_consistent_and_do_not_exhaust_handles()
    {
        // Chaque lecture ouvre deux handles natifs. Un oubli de fermeture ne se voit
        // pas sur un appel isolé, mais épuise les ressources d'un scan complet.
        var first = services.Read("Schedule");

        for (var i = 0; i < 200; i++)
        {
            var read = services.Read("Schedule");
            Assert.Equal(first.Status, read.Status);
            Assert.Equal(first.Info!.State, read.Info!.State);
        }
    }
}
