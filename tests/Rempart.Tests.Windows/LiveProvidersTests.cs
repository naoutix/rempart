using Rempart.Core.Providers;
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// The third wiring of the same twenty providers, and the only one the Linux job cannot
/// see: <see cref="LiveProviders.All"/> names Windows types, so its guard has to run here.
///
/// <para>
/// The failure it refuses is the one D2, D2b and the component store all were: a provider
/// added to <see cref="ProviderSet"/> and left out of a wiring. Left out of <em>this</em>
/// one, the scan falls back to the no-op the set supplies by default and reports « aucun
/// fournisseur n'a été fourni à ce scan » — or, for the providers whose fallback is an empty
/// list rather than a denial, nothing at all. Nothing fails to compile: every parameter past
/// the second is optional, which is what makes the omission silent.
/// </para>
///
/// <para>
/// No Windows API is called. Building the set constructs twenty objects and reads nothing,
/// so this test cannot go quiet on a degraded runner the way the WMI ones legitimately do —
/// and it must not, because what it watches is a wiring, not a machine.
/// </para>
/// </summary>
public sealed class LiveProvidersTests
{
    [Fact]
    public void Every_provider_has_a_live_implementation()
    {
        var live = LiveProviders.All();

        var wired = typeof(ProviderSet).GetProperties()
            .Where(property => property.PropertyType.IsInterface)
            .Select(property => (property.Name, Implementation: property.GetValue(live)))
            .ToList();

        // A filter that retains nothing never finds a gap. Without this the guard would go
        // green the day ProviderSet stopped exposing interface-typed properties, which is
        // precisely the refactoring that would need watching.
        Assert.True(wired.Count == 20,
            $"{wired.Count} fournisseur(s) inspecté(s) sur ProviderSet : le filtre ne retient "
            + "presque rien, donc ce garde ne surveille presque rien.");

        var missing = wired
            .Where(entry => entry.Implementation?.GetType().Name
                .StartsWith("Live", StringComparison.Ordinal) != true)
            .Select(entry => $"{entry.Name} → {entry.Implementation?.GetType().Name ?? "null"}")
            .ToList();

        Assert.True(missing.Count == 0,
            "Fournisseur(s) sans implémentation réelle dans le scan de la machine locale : "
            + $"{string.Join(", ", missing)}. Le jeu retombe sur son repli muet, et le rapport "
            + "décrit une surface que personne n'a regardée.");
    }

    // A second test asserting that no two slots hold the same implementation type was
    // written here and deleted: every property of ProviderSet has its own interface type, so
    // the compiler already refuses the swap it claimed to catch. It could not be made to
    // fail by mutation — which is the definition of a guard that watches nothing, and this
    // repository has shipped that shape before.
}
