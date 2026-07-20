using Rempart.Core.Engine;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

public sealed class CheckReaderTests
{
    /// <summary>
    /// L'invariant que le lecteur unifié existe pour tenir.
    ///
    /// Capture et évaluation avaient chacune leur traduction d'un <c>CheckSpec</c> en
    /// appels de provider. Le prochain type de contrôle oublié côté capture aurait
    /// produit des instantanés incomplets — et un échec de rejeu bien plus tard, avec
    /// un message sans rapport avec la cause. Ce test échoue immédiatement à la place.
    /// </summary>
    [Fact]
    public void Capture_and_evaluation_touch_exactly_the_same_keys()
    {
        var rules = RuleCatalog.Load();

        var captured = new MachineSnapshot();
        new ScanEngine([], rules).Prefetch(Recording(captured));

        var evaluated = new MachineSnapshot();
        var registry = new RecordingRegistryProvider(new FakeRegistryProvider(), evaluated);
        foreach (var rule in rules)
        {
            RuleEvaluator.Evaluate(rule, registry, FakeSystemInfoProvider.Default);
        }

        // L'évaluation peut lire moins — une règle hors périmètre n'atteint pas son
        // contrôle principal. Elle ne doit jamais lire davantage : ce serait une clé
        // qu'aucune capture n'enregistrerait.
        Assert.Empty(evaluated.Registry.Keys.Except(captured.Registry.Keys));
    }

    [Fact]
    public void An_absent_value_falls_back_to_the_declared_windows_default()
    {
        var reading = CheckReader.Read(Check(CheckOperator.Equals, "1", "3"), new FakeRegistryProvider());

        Assert.Null(reading.Found);
        Assert.Equal("3", reading.Effective);
        Assert.False(reading.Denied);
    }

    [Fact]
    public void A_present_value_takes_precedence_over_the_default()
    {
        var registry = new FakeRegistryProvider().WithNumber(@"HKLM\SOFTWARE\Test", "Flag", 7);

        var reading = CheckReader.Read(Check(CheckOperator.Equals, "1", "3"), registry);

        Assert.Equal("7", reading.Found);
        Assert.Equal("7", reading.Effective);
    }

    [Fact]
    public void Access_denied_is_carried_rather_than_confused_with_absence()
    {
        var registry = new FakeRegistryProvider().WithAccessDenied(@"HKLM\SOFTWARE\Test", "Flag");

        var reading = CheckReader.Read(Check(CheckOperator.Equals, "1", "3"), registry);

        Assert.True(reading.Denied);
        Assert.Null(reading.Effective);
        Assert.Null(reading.Describe(Check(CheckOperator.Equals, "1", "3")));
    }

    [Fact]
    public void The_description_names_the_default_that_applied()
    {
        // Sans cette mention, on croirait l'outil incapable de lire la clé, alors
        // qu'il rend un verdict fondé sur le comportement réel de la machine.
        var check = Check(CheckOperator.Equals, "1", "3");

        var described = CheckReader.Read(check, new FakeRegistryProvider()).Describe(check);

        Assert.Contains("absent", described!, StringComparison.Ordinal);
        Assert.Contains("3", described!, StringComparison.Ordinal);
    }

    private static RegistryRead Read(FakeRegistryProvider registry, string value) =>
        registry.ReadValue(@"HKLM\SOFTWARE\Test", value);

    private static ProviderSet Recording(MachineSnapshot into) => new(
        new RecordingRegistryProvider(new FakeRegistryProvider(), into),
        new RecordingSystemInfoProvider(new FakeSystemInfoProvider(), into));

    private static CheckSpec Check(CheckOperator op, string expect, string windowsDefault) =>
        new(CheckKind.Registry, @"HKLM\SOFTWARE\Test", "Flag", op, expect, windowsDefault);
}
