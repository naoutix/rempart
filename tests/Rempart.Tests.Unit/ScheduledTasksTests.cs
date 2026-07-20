using Rempart.Core.Findings;
using Rempart.Core.Providers;
using Rempart.Core.Json;
using Rempart.Core.Snapshots;

namespace Rempart.Tests.Unit;

internal sealed class FakeScheduledTaskProvider(ScheduledTaskRead read) : IScheduledTaskProvider
{
    public ScheduledTaskRead Enumerate() => read;
}

internal sealed class FakeSignatureProvider : ISignatureProvider
{
    private readonly Dictionary<string, FileSignature> signatures =
        new(StringComparer.OrdinalIgnoreCase);

    public FakeSignatureProvider With(string path, SignatureStatus status, string? publisher = null)
    {
        signatures[path] = new FileSignature(status, publisher);
        return this;
    }

    public FileSignature Verify(string path) =>
        signatures.TryGetValue(path, out var signature)
            ? signature
            : new FileSignature(SignatureStatus.Unknown);
}

public class ScheduledTasksTests
{
    private static ScheduledTask Task(
        string path, params TaskAction[] actions) =>
        new(path, path, Enabled: true, "ready", "Contoso", "S-1-5-18", null, actions);

    private static TaskAction Exec(string path) => new("exec", path, string.Empty);

    private static IReadOnlyList<Finding> Collect(
        ScheduledTaskRead read, ISignatureProvider signatures) =>
        new ScheduledTasksCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(),
            new FakeSystemInfoProvider(),
            signatures: signatures,
            scheduledTasks: new FakeScheduledTaskProvider(read)));

    [Fact]
    public void Unsigned_action_is_suspicious()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Perso", Exec(@"C:\tools\agent.exe"))]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned));

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("non signé", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Windows livre plusieurs centaines de tâches signées. Si l'une d'elles ressortait
    /// à examiner, le rapport deviendrait illisible et cesserait d'être lu — c'est le
    /// bruit, pas le manque de couverture, qui tue un outil d'audit.
    /// </summary>
    [Fact]
    public void Signed_action_is_benign()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\Microsoft\Windows\Truc", Exec(@"C:\Windows\System32\sc.exe"))]),
            new FakeSignatureProvider().With(@"C:\Windows\System32\sc.exe", SignatureStatus.Valid));

        Assert.Equal(FindingSeverity.Benign, Assert.Single(findings).Severity);
    }

    /// <summary>
    /// La signature est consignée même valide. Ne la noter que lorsqu'elle pose
    /// problème rendrait « vérifiée et bonne » indiscernable de « jamais vérifiée » —
    /// c'est la version silencieuse du défaut qui a rendu WMI inopérant deux lots.
    /// </summary>
    [Fact]
    public void Valid_signature_is_recorded_not_only_failures()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\T", Exec(@"C:\Windows\System32\sc.exe"))]),
            new FakeSignatureProvider().With(
                @"C:\Windows\System32\sc.exe", SignatureStatus.Valid, "Microsoft Corporation"));

        var details = Assert.Single(findings).Details;
        Assert.Equal("Valid", details["signature"]);
        Assert.Equal("Microsoft Corporation", details["éditeur"]);
    }

    /// <summary>
    /// Le planificateur résout <c>sc.exe</c> à l'exécution. Un nom que le provider n'a
    /// pas su résoudre a produit, sur une vraie machine, deux constats « le fichier
    /// visé n'existe pas » portant sur des binaires présents dans System32. Une lacune
    /// de résolution ne doit pas se déguiser en fait sur la machine.
    /// </summary>
    [Fact]
    public void Unresolved_bare_name_is_reported_as_unresolved_not_as_missing_file()
    {
        var findings = Collect(
            ScheduledTaskRead.Found([Task(@"\T", Exec("mystere.exe"))]),
            new FakeSignatureProvider());

        var finding = Assert.Single(findings);
        var reasons = string.Join(" ", finding.Reasons);

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("Chemin non résolu", reasons);
        Assert.DoesNotContain("n'existe pas", reasons);
    }

    /// <summary>
    /// Une tâche sans exécutable — gestionnaire COM — n'a pas de signature à vérifier.
    /// Elle est énumérée en le disant, comme un raccourci du dossier de démarrage.
    /// </summary>
    [Fact]
    public void Com_handler_task_is_listed_without_being_judged()
    {
        var findings = Collect(
            ScheduledTaskRead.Found(
                [Task(@"\NGEN", new TaskAction("ComHandler", string.Empty, string.Empty))]),
            new FakeSignatureProvider());

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
        Assert.Equal("ComHandler", finding.Details["type"]);
        Assert.Contains("aucune signature", finding.Details["note"]);
    }

    /// <summary>
    /// Une tâche désactivée ne s'exécute pas, et le rapport doit le dire — mais le
    /// constat demeure : ce qui est désactivé se réactive.
    /// </summary>
    [Fact]
    public void Disabled_task_keeps_its_severity_and_says_so()
    {
        var task = Task(@"\Perso", Exec(@"C:\tools\agent.exe")) with { Enabled = false };

        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Found([task]),
            new FakeSignatureProvider().With(@"C:\tools\agent.exe", SignatureStatus.Unsigned)));

        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Equal("désactivée", finding.Details["état"]);
        Assert.Contains("désactivée", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Un planificateur illisible n'est pas un planificateur vide. Rendre zéro tâche en
    /// silence ferait passer une panne pour une machine saine.
    /// </summary>
    [Fact]
    public void Failed_enumeration_produces_a_finding_never_silence()
    {
        var finding = Assert.Single(Collect(
            ScheduledTaskRead.Failed("MarshalDirectiveException : bidule"),
            new FakeSignatureProvider()));

        Assert.Equal(FindingSeverity.Notable, finding.Severity);
        Assert.Contains("bidule", string.Join(" ", finding.Reasons));
    }

    /// <summary>
    /// Absent d'une capture antérieure à ce lot : la fixture reste rejouable, et rend
    /// un constat « non énuméré » plutôt qu'un planificateur vide.
    /// </summary>
    [Fact]
    public void Older_snapshot_replays_without_inventing_an_empty_scheduler()
    {
        var read = new SnapshotScheduledTaskProvider(new MachineSnapshot()).Enumerate();

        Assert.Equal(ReadStatus.AccessDenied, read.Status);
        Assert.NotNull(read.Diagnostic);
    }

    [Theory]
    [InlineData("S-1-5-21-2354378594-2253722242-1776815907-1002")]
    [InlineData(@"DESKTOP-3VR09H0\leoar")]
    public void Anonymiser_hashes_accounts_that_designate_a_person(string account)
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            ScheduledTasks = ScheduledTaskRead.Found(
                [Task(@"\T") with { UserId = account, Author = account }]),
        };

        var task = Anonymiser.Apply(snapshot).ScheduledTasks!.Tasks[0];

        Assert.StartsWith("anon:", task.UserId);
        Assert.StartsWith("anon:", task.Author);
    }

    /// <summary>
    /// Le compte système ne désigne personne. Le hacher coûterait la lisibilité des
    /// fixtures sans rien protéger : on ne distinguerait plus une tâche du système
    /// d'une tâche d'utilisateur, ce qui est justement ce qu'on veut juger.
    /// </summary>
    [Fact]
    public void Anonymiser_leaves_well_known_accounts_readable()
    {
        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            ScheduledTasks = ScheduledTaskRead.Found(
                [Task(@"\T") with { UserId = "S-1-5-18", Author = "Microsoft Corporation" }]),
        };

        var task = Anonymiser.Apply(snapshot).ScheduledTasks!.Tasks[0];

        Assert.Equal("S-1-5-18", task.UserId);
        Assert.Equal("Microsoft Corporation", task.Author);
    }

    /// <summary>
    /// Un instantané qui se déclare anonymisé doit l'être. Le nom de compte se glisse
    /// dans les chemins de profil — clés de signatures, répertoires énumérés, valeurs
    /// Run — et une capture partagée en confiance le transmettrait.
    /// </summary>
    [Fact]
    public void Anonymiser_hashes_the_account_name_in_profile_paths()
    {
        const string Path = @"C:\Users\leoar\AppData\Local\Discord\Update.exe";

        var snapshot = new MachineSnapshot
        {
            SystemInfo = FakeSystemInfoProvider.Default,
            Signatures = { [Path] = new FileSignature(SignatureStatus.Valid) },
            Directories = { [@"C:\Users\leoar\Bureau"] = [Path] },
        };

        snapshot.Registry[SnapshotKeys.Value(@"HKCU\Run", "Discord")] =
            RegistryRead.Found(RegistryValue.OfText(Path));

        var result = Anonymiser.Apply(snapshot);

        Assert.DoesNotContain("leoar", RempartJson.Serialise(result), StringComparison.Ordinal);

        // Le reste du chemin survit : c'est lui qui dit quelle application se lance.
        Assert.Contains(result.Signatures.Keys,
            k => k.EndsWith(@"\Discord\Update.exe", StringComparison.Ordinal));
    }

    /// <summary>
    /// Ces profils existent à l'identique sur toute installation de Windows : les
    /// hacher coûterait la lisibilité des fixtures sans rien protéger.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\Public\Desktop\a.exe")]
    [InlineData(@"C:\Users\Default\NTUSER.DAT")]
    public void Anonymiser_leaves_impersonal_profiles_readable(string path) =>
        Assert.Equal(path, Anonymiser.ScrubProfile(path));
}
