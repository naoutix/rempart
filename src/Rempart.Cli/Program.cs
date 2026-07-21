using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Json;
using Rempart.Core.Providers;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;
using System.Reflection;
using Rempart.Windows;

// Analyse d'arguments écrite à la main. L'ADR-001 prévoit System.CommandLine ; l'ajouter
// pour deux commandes serait prématuré. À basculer en M1, quand le nombre de commandes
// le justifiera.



// La console Windows n'est pas en UTF-8 par défaut : sans cela les diagnostics
// accentués sortent illisibles, et ce sont eux qu'il faut lire en priorité.
Console.OutputEncoding = System.Text.Encoding.UTF8;

var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0] : "help";

try
{
    return command switch
    {
        "scan" => Scan(args),
        "capture" => Capture(args),
        "explain" => Explain(args),
        "synthesise" => Synthesise(args),
        "diagnose-wmi" => DiagnoseWmi(),
        "diagnose-tasks" => DiagnoseTasks(),
        "keygen" => Keygen(args),
        "update" => Update(args),
        "version" => Print(ToolVersion()),
        _ => Help(),
    };
}
catch (SnapshotIncompleteException ex)
{
    Console.Error.WriteLine($"Instantané incomplet : {ex.Message}");
    return 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Erreur : {ex.Message}");
    return 1;
}

static int Scan(string[] args)
{
    var snapshotPath = OptionValue(args, "--from");
    var asJson = HasFlag(args, "--json");

    ProviderSet providers;
    string origin;

    if (snapshotPath is not null)
    {
        // Rejeu hors-ligne : le même code de collecte, sans Windows.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(snapshotPath));
        providers = new ProviderSet(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot),
            new SnapshotServiceStateProvider(snapshot),
            new SnapshotSecurityPolicyProvider(snapshot),
            new SnapshotWmiProvider(snapshot),
            new SnapshotSignatureProvider(snapshot),
            new SnapshotFileSystemProvider(snapshot),
            new SnapshotScheduledTaskProvider(snapshot));
        origin = snapshot.CapturedAtUtc;
    }
    else
    {
        RequireWindows();
        providers = new ProviderSet(
            new LiveRegistryProvider(),
            new LiveSystemInfoProvider(),
            new LiveServiceStateProvider(),
            new LiveSecurityPolicyProvider(),
            new Rempart.Windows.Wmi.LiveWmiProvider(),
            new LiveSignatureProvider(),
            new LiveFileSystemProvider(),
            new Rempart.Windows.Tasks.LiveScheduledTaskProvider());
        origin = UtcNow();
    }

    // Le magasin de mises à jour ne s'applique qu'en direct. Un rejeu reproduit un scan
    // passé : y injecter le magasin de cette machine-ci le rendrait non déterministe, et
    // ferait dépendre une fixture d'un état local. En rejeu, seul le socle compte.
    var resolution = snapshotPath is null
        ? ResolveLiveCatalog(args)
        : new CatalogResolution(RuleCatalog.Load(OptionValue(args, "--rules")),
            RuleCatalog.EmbeddedAsOfUtc, null);

    var result = new ScanEngine(ScanEngine.DefaultCollectors, resolution.Rules)
        .Run(providers, ToolVersion(), origin, resolution.AsOfUtc);

    if (asJson)
    {
        Console.WriteLine(RempartJson.Serialise(result));
    }
    else
    {
        WriteHumanReadable(result, resolution.UpdateNote);
    }

    // Un manque de droits n'est pas une erreur d'exécution, mais l'appelant doit
    // pouvoir le détecter sans relire la sortie.
    return result.Collectors.Any(c => c.Status == CollectorStatus.Failed) ? 1
        : result.Collectors.Any(c => c.Status == CollectorStatus.InsufficientPrivileges) ? 3
        : 0;
}

static int Capture(string[] args)
{
    RequireWindows();

    var raw = HasFlag(args, "--raw");
    var snapshot = new MachineSnapshot { CapturedAtUtc = UtcNow() };

    var providers = new ProviderSet(
        new RecordingRegistryProvider(new LiveRegistryProvider(), snapshot),
        new RecordingSystemInfoProvider(new LiveSystemInfoProvider(), snapshot),
        new RecordingServiceStateProvider(new LiveServiceStateProvider(), snapshot),
        new RecordingSecurityPolicyProvider(new LiveSecurityPolicyProvider(), snapshot),
        new RecordingWmiProvider(new Rempart.Windows.Wmi.LiveWmiProvider(), snapshot),
        new RecordingSignatureProvider(new LiveSignatureProvider(), snapshot),
        new RecordingFileSystemProvider(new LiveFileSystemProvider(), snapshot),
        new RecordingScheduledTaskProvider(
            new Rempart.Windows.Tasks.LiveScheduledTaskProvider(), snapshot));

    // Le moteur complet, regles comprises : une fixture doit pouvoir rejouer tout ce
    // que fait un scan, sans quoi elle ne testerait que la moitie du chemin. Le magasin
    // de mises a jour est resolu ici aussi, pour qu'une capture prefetch les cles des
    // regles ajoutees par une mise a jour et reste rejouable.
    var engine = new ScanEngine(
        ScanEngine.DefaultCollectors, ResolveLiveCatalog(args).Rules);
    engine.Run(providers, ToolVersion(), snapshot.CapturedAtUtc);

    // Puis toutes les cles que les regles pourraient lire dans un autre contexte, afin
    // que l'instantane reste rejouable ailleurs que sur la machine qui l'a produit.
    engine.Prefetch(providers);

    // Anonymisation par défaut : les fixtures finissent versionnées.
    if (!raw)
    {
        Anonymiser.Apply(snapshot);
    }

    var suffix = raw ? "raw" : "anon";
    var path = OptionValue(args, "--out")
        ?? $"rempart-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{suffix}.capture.json";

    File.WriteAllText(path, RempartJson.Serialise(snapshot));

    Console.WriteLine($"Instantané écrit : {path}");
    Console.WriteLine($"  lectures enregistrées : {snapshot.Registry.Count} registre, " +
                      $"{snapshot.Services.Count} services");
    Console.WriteLine(raw
        ? "  ATTENTION : capture brute, non anonymisée. Ne pas versionner tel quel."
        : "  anonymisé : hostname, numéros de série et propriétaire remplacés par des empreintes.");

    return 0;
}

/// <summary>
/// Prépare une mise à jour des données depuis un manifeste signé (ADR-002).
///
/// <para>
/// Cette étape vérifie et montre — elle n'applique rien (D14 : « montre ce qui change
/// avant d'appliquer »). Le manifeste et chaque jeu de données sont authentifiés, puis
/// le différentiel affiché. Rien n'est écrit : un refus après lecture ne laisse aucune
/// trace.
/// </para>
///
/// <para>
/// Depuis un fichier local, pas encore du réseau : c'est le flux de la clé USB (D11),
/// et la seule moitié qui se teste sans hébergement. La couche réseau produira ce même
/// fichier, et se branchera ici sans rien changer à la vérification.
/// </para>
/// </summary>
static int Update(string[] args)
{
    var manifestPath = OptionValue(args, "--from");

    if (manifestPath is null)
    {
        Console.Error.WriteLine(
            "Indiquer le manifeste : rempart update --from <fichier>. Le téléchargement " +
            "réseau n'est pas encore disponible ; produire le fichier sur une machine " +
            "connectée, puis l'apporter.");
        return 1;
    }

    if (!File.Exists(manifestPath))
    {
        Console.Error.WriteLine($"Manifeste introuvable : {manifestPath}");
        return 1;
    }

    // Les jeux de données vivent à côté du manifeste : c'est ce qu'a produit la
    // machine connectée, transporté d'un bloc. Le séparateur final est ajouté pour que
    // le garde-fou distingue « dans ce dossier » d'« un dossier frère au nom voisin ».
    var directory = (Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? ".")
        .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

    byte[]? ReadDataset(string name)
    {
        // Empêche un manifeste de faire lire un fichier hors de son dossier : un nom
        // comme « ..\\.. » ne doit pas devenir un chemin arbitraire.
        var full = Path.GetFullPath(Path.Combine(directory, name));
        if (!full.StartsWith(directory, StringComparison.OrdinalIgnoreCase)
            || !File.Exists(full))
        {
            return null;
        }

        return File.ReadAllBytes(full);
    }

    var preview = UpdatePlanner.Prepare(
        File.ReadAllText(manifestPath),
        PinnedKeys.Verifier(),
        ReadDataset,
        RuleCatalog.Load(OptionValue(args, "--rules")));

    if (!preview.Trusted)
    {
        // Chaque motif de refus a sa réaction propre : ne pas les confondre.
        Console.Error.WriteLine($"Manifeste refusé ({preview.Status}) : {preview.Explanation}");
        return 1;
    }

    Console.WriteLine($"Manifeste de confiance. {preview.Explanation}");
    Console.WriteLine();

    var blocked = false;
    foreach (var dataset in preview.Datasets)
    {
        WriteDataset(dataset);
        blocked |= !dataset.Verified;
    }

    if (preview.Datasets.Count == 0)
    {
        Console.WriteLine("Le manifeste ne décrit aucun jeu de données.");
        return 0;
    }

    Console.WriteLine();
    if (blocked)
    {
        Console.Error.WriteLine(
            "Au moins un jeu de données n'a pas pu être vérifié : rien ne serait appliqué. " +
            "On ne pose pas la moitié d'une mise à jour.");
        return 1;
    }

    if (!HasFlag(args, "--apply"))
    {
        Console.WriteLine(
            "Tout est vérifié. Rien n'a été écrit — relancer avec --apply pour poser cette " +
            "mise à jour, que les prochains scans utiliseront.");
        return 0;
    }

    // Appliquer modifie ce que les scans évalueront : on le confirme, sauf --yes. Sans
    // console, refuser plutôt qu'appliquer une mise à jour que personne n'a validée.
    if (!HasFlag(args, "--yes"))
    {
        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine(
                "Application non confirmée : ajouter --yes, ou lancer depuis une console.");
            return 1;
        }

        Console.Write("Appliquer cette mise à jour ? [o/N] ");
        var answer = Console.ReadLine()?.Trim();
        if (!string.Equals(answer, "o", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(answer, "oui", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Annulé. Rien n'a été écrit.");
            return 0;
        }
    }

    var storeDir = StoreDirectory(args);
    UpdateStore.Apply(manifestPath, storeDir, preview.Datasets.Select(d => d.Name));

    Console.WriteLine($"Mise à jour posée dans {storeDir}.");
    Console.WriteLine(
        "Les prochains scans la vérifieront de nouveau avant de l'utiliser, et " +
        "l'afficheront dans leur en-tête.");
    return 0;
}

/// <summary>
/// Le catalogue effectif d'un scan en direct : socle embarqué (plus les règles
/// <c>--rules</c> s'il y en a), complété par la mise à jour du magasin si elle vérifie.
/// </summary>
static CatalogResolution ResolveLiveCatalog(string[] args) =>
    UpdateStore.Resolve(
        StoreDirectory(args),
        RuleCatalog.Load(OptionValue(args, "--rules")),
        PinnedKeys.Verifier());

/// <summary>
/// Le magasin voyage avec le binaire : à côté de l'exécutable par défaut, pour qu'une
/// clé USB emporte ses données à jour sans dossier compagnon à ne pas oublier.
/// </summary>
static string StoreDirectory(string[] args) =>
    OptionValue(args, "--store") ?? Path.Combine(AppContext.BaseDirectory, "rempart-data");

static void WriteDataset(DatasetPreview dataset)
{
    if (!dataset.Verified)
    {
        Console.WriteLine($"  ✗ {dataset.Name} ({dataset.Version}) — {dataset.Problem}");
        return;
    }

    var diff = dataset.Diff!;
    if (diff.ChangesNothing)
    {
        Console.WriteLine($"  = {dataset.Name} ({dataset.Version}) — rien ne change " +
                          $"({diff.Unchanged} contrôles identiques)");
        return;
    }

    Console.WriteLine($"  ✓ {dataset.Name} ({dataset.Version}) — " +
                      $"{diff.Added.Count} ajouté(s), {diff.Modified.Count} modifié(s), " +
                      $"{diff.Unchanged} inchangé(s)");

    foreach (var id in diff.Added)
    {
        Console.WriteLine($"      + {id}");
    }

    foreach (var change in diff.Modified)
    {
        Console.WriteLine($"      ~ {change.Id}  ({change.Before} → {change.After})");
    }
}

/// <summary>
/// Vérifie que WMI répond réellement — destiné à la CI, exécuté contre le binaire
/// Native AOT.
///
/// Existe parce qu'un bug d'interop COM a rendu WMI inopérant dans le binaire publié
/// sans que rien ne le signale : les contrôles rendaient « non vérifiable », le scan
/// sortait en 0, et le job de publication le déclarait sain. Les tests, eux, ne
/// s'exécutaient qu'en JIT, où le bug n'apparaît pas.
///
/// Interroge un espace de noms présent sur toute machine Windows et disponible sans
/// élévation : un échec ici dénonce l'interop, pas l'environnement.
/// </summary>
static int DiagnoseWmi()
{
    RequireWindows();

    const string Namespace = @"root\CIMV2";
    const string Class = "Win32_OperatingSystem";
    const string Property = "Caption";

    var read = new Rempart.Windows.Wmi.LiveWmiProvider().Query(Namespace, Class, [Property]);
    var value = read.Instances.Count > 0 ? read.Instances[0].Find(Property) : null;

    Console.WriteLine($"{Namespace}:{Class} -> {read.Status}, {read.Instances.Count} instance(s)");
    if (read.Diagnostic is { } diagnostic)
    {
        Console.WriteLine($"  défaillance : {diagnostic}");
    }

    if (read.Status != ReadStatus.Found || string.IsNullOrWhiteSpace(value))
    {
        Console.Error.WriteLine(
            "WMI ne répond pas. Sur un espace de noms accessible sans élévation, " +
            "c'est l'interop COM qui est en cause, pas l'environnement.");
        return 1;
    }

    Console.WriteLine($"  {Property} = {value}");
    return 0;
}

/// <summary>
/// Génère la paire de clés qui signera les manifestes de mise à jour.
///
/// <para>
/// À lancer sur une machine hors ligne — une VM jetable suffit quand on n'en a
/// qu'une (ADR-002, D16). C'est précisément pour ce genre d'usage que le livrable est
/// un exécutable autonome : on copie <c>rempart.exe</c> sur une clé, on génère
/// là-bas, rien à installer.
/// </para>
///
/// <para>
/// La clé privée n'est jamais écrite en clair et il n'existe pas d'option pour le
/// faire. Un support amovible se perd ; la phrase de passe est ce qui sépare alors
/// une clé perdue d'une clé compromise.
/// </para>
/// </summary>
static int Keygen(string[] args)
{
    var path = OptionValue(args, "--out") ?? "cle-privee-rempart.txt";

    if (File.Exists(path))
    {
        // Écraser une clé privée existante la détruit sans recours : il n'y a pas de
        // copie ailleurs, c'est tout l'intérêt du dispositif.
        Console.Error.WriteLine($"{path} existe déjà. Refus d'écraser une clé privée.");
        return 1;
    }

    if (Console.IsInputRedirected)
    {
        // Sans console, la phrase de passe viendrait d'un tube — donc d'un historique,
        // d'un script ou d'un journal. Refuser plutôt que produire une clé dont la
        // protection est déjà connue de quelqu'un d'autre.
        Console.Error.WriteLine(
            "Cette commande exige une console interactive : la phrase de passe ne doit " +
            "pas transiter par un tube ni par un argument.");
        return 1;
    }

    Console.WriteLine("Phrase de passe (12 caractères minimum, non affichée) :");
    var passphrase = ReadHidden();

    Console.WriteLine("Confirmer :");
    if (!string.Equals(passphrase, ReadHidden(), StringComparison.Ordinal))
    {
        Console.Error.WriteLine("Les deux saisies diffèrent. Rien n'a été écrit.");
        return 1;
    }

    PublisherKeyPair pair;
    try
    {
        pair = PublisherKey.Generate(passphrase);
    }
    catch (ArgumentException ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    // Relecture immédiate : une clé qu'on ne sait pas rouvrir ne doit pas se
    // découvrir le jour où l'on doit publier, sur une machine qu'on aura détruite.
    if (PublisherKey.ReadPublicKeyOf(pair.EncryptedPrivateKey, passphrase) != pair.PublicKey)
    {
        Console.Error.WriteLine("La clé générée ne se relit pas. Rien n'a été écrit.");
        return 1;
    }

    File.WriteAllText(path, pair.EncryptedPrivateKey);

    Console.WriteLine();
    Console.WriteLine($"Clé privée chiffrée écrite dans {path}.");
    Console.WriteLine("  Elle ne doit pas revenir sur la machine de développement.");
    Console.WriteLine("  La phrase de passe ne voyage pas sur le même support.");
    Console.WriteLine();
    Console.WriteLine("À reporter dans ManifestVerifier, publiables l'une comme l'autre :");
    Console.WriteLine();
    Console.WriteLine($"  empreinte     {pair.KeyId}");
    Console.WriteLine($"  clé publique  {pair.PublicKey}");
    Console.WriteLine();
    Console.WriteLine("Sauvegarde papier de la clé privée chiffrée — elle tient en une ligne,");
    Console.WriteLine("et c'est la meilleure protection contre la perte du support :");
    Console.WriteLine();
    Console.WriteLine($"  {pair.EncryptedPrivateKey}");

    return 0;
}

/// <summary>Lit sans écho. La phrase de passe ne doit pas rester à l'écran.</summary>
static string ReadHidden()
{
    var buffer = new System.Text.StringBuilder();

    while (true)
    {
        var pressed = Console.ReadKey(intercept: true);

        if (pressed.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            return buffer.ToString();
        }

        if (pressed.Key == ConsoleKey.Backspace)
        {
            if (buffer.Length > 0)
            {
                buffer.Length--;
            }

            continue;
        }

        if (!char.IsControl(pressed.KeyChar))
        {
            buffer.Append(pressed.KeyChar);
        }
    }
}

/// <summary>
/// Vérifie que le planificateur de tâches répond depuis le binaire publié.
///
/// Même raison d'être que <c>diagnose-wmi</c>, et même risque exactement : l'interop
/// COM du planificateur est générée à la compilation, ses interfaces dérivent
/// d'<c>IDispatch</c>, et un décalage d'un seul emplacement de table virtuelle est
/// invisible en JIT comme à la compilation.
///
/// Un scan qui ne trouverait aucune tâche produirait un rapport d'apparence saine.
/// C'est précisément ce qui s'est produit avec WMI pendant deux lots, et la raison
/// pour laquelle cette commande existe avant que le problème ne se pose.
///
/// Toute machine Windows porte des dizaines de tâches ; l'énumération de base ne
/// demande pas l'élévation. Un échec ici dénonce l'interop, pas l'environnement.
/// </summary>
static int DiagnoseTasks()
{
    RequireWindows();

    var read = new Rempart.Windows.Tasks.LiveScheduledTaskProvider().Enumerate();

    Console.WriteLine($"planificateur -> {read.Status}, {read.Tasks.Count} tâche(s)");

    if (read.Diagnostic is { } diagnostic)
    {
        Console.WriteLine($"  défaillance : {diagnostic}");
    }

    // Un Windows sans aucune tâche n'existe pas : zéro dénonce l'énumération, pas la
    // machine. Le seuil reste bas — un runner de CI en porte moins qu'un poste réel.
    if (read.Status != ReadStatus.Found || read.Tasks.Count == 0)
    {
        Console.Error.WriteLine(
            "Le planificateur ne rend aucune tâche. Toute installation de Windows en " +
            "porte : c'est l'interop COM qui est en cause, pas l'environnement.");
        return 1;
    }

    // La définition XML est lue par un appel distinct de l'énumération. Compter les
    // tâches ne prouve donc pas qu'on sait les lire.
    var withAction = read.Tasks.Count(t => t.Actions.Count > 0);
    Console.WriteLine($"  dont {withAction} avec au moins une action lue");

    if (withAction == 0)
    {
        Console.Error.WriteLine(
            "Aucune définition lisible : l'énumération répond mais get_Xml non. " +
            "Un scan rendrait des tâches sans jamais juger ce qu'elles lancent.");
        return 1;
    }

    Console.WriteLine($"  exemple : {read.Tasks[0].Path}");
    return 0;
}

/// <summary>
/// Fabrique une fixture synthétique à partir d'une capture réelle.
///
/// Les fixtures étaient régénérées par un script jetable qui reparsait le YAML en
/// expressions régulières : une seconde implémentation du chargeur, ni versionnée ni
/// testée, et que personne d'autre ne pouvait rejouer. Ici ce sont les règles chargées
/// par le moteur qui pilotent la substitution.
/// </summary>
static int Synthesise(string[] args)
{
    var sourcePath = OptionValue(args, "--from")
        ?? throw new ArgumentException("« synthesise » exige --from <capture>.");
    var outPath = OptionValue(args, "--out")
        ?? throw new ArgumentException("« synthesise » exige --out <fichier>.");

    var profile = OptionValue(args, "--profile") switch
    {
        "hardened" or null => SyntheticProfile.Hardened,
        "defaults" => SyntheticProfile.WindowsDefaults,
        var other => throw new ArgumentException(
            $"Profil inconnu « {other} ». Attendu : hardened, defaults."),
    };

    var deny = OptionValues(args, "--deny");

    var built = SyntheticSnapshot.Build(
        RempartJson.DeserialiseSnapshot(File.ReadAllText(sourcePath)),
        RuleCatalog.Load(OptionValue(args, "--rules")),
        profile,
        machineName: OptionValue(args, "--name") ?? "anon:synthetic",
        domainJoined: HasFlag(args, "--domain-joined"),
        elevated: !HasFlag(args, "--not-elevated"),
        denyPathFragments: deny);

    File.WriteAllText(outPath, RempartJson.Serialise(built));

    Console.WriteLine($"Fixture écrite : {outPath}");
    Console.WriteLine($"  profil               : {profile}");
    Console.WriteLine($"  lectures             : {built.Registry.Count}");
    Console.WriteLine($"  jointe à un domaine  : {built.SystemInfo?.IsDomainJoined}");
    if (deny.Count > 0)
    {
        Console.WriteLine($"  accès refusé sur     : {string.Join(", ", deny)}");
    }

    return 0;
}

/// <summary>
/// Rend l'âge des données en une ligne. Une date illisible est dite telle, jamais
/// tue : « inconnu » ne doit pas se lire comme « à jour ».
/// </summary>
static string DescribeAge(DataAge age)
{
    if (age.Unknown)
    {
        return "date de référence illisible — impossible d'en juger l'ancienneté";
    }

    var asOf = age.AsOfUtc.Length >= 10 ? age.AsOfUtc[..10] : age.AsOfUtc;

    var summary = age.Days == 0
        ? $"catalogue au {asOf}, à jour"
        : $"catalogue au {asOf}, {age.Days} jour{(age.Days > 1 ? "s" : "")}";

    if (age.Stale)
    {
        summary += $" — au-delà de {age.ThresholdDays} j, envisager « rempart update »";
    }

    return summary;
}

/// <summary>
/// Ce qu'on vient chercher d'abord : les problèmes. L'inventaire ferme le rapport —
/// c'est du contexte, et vingt-trois lignes de contexte avant le premier constat
/// font qu'on ne lit plus le constat.
/// </summary>
static void WriteHumanReadable(ScanResult result, string? updateNote = null)
{
    Console.WriteLine($"Rempart {result.ToolVersion} — scan du {result.StartedAtUtc}");
    Console.WriteLine($"règles : {result.RulesFingerprint}");
    Console.WriteLine($"données : {DescribeAge(result.DataAge)}");

    // La provenance des données — appliquée ou refusée — se dit toujours, jamais en
    // silence (ADR-002, D14 et D17).
    if (updateNote is { } note)
    {
        Console.WriteLine($"mise à jour : {note}");
    }

    if (result.Score is { } score)
    {
        WritePosture(result, score);
    }

    WriteFindings(result.Findings);

    Console.WriteLine();
    foreach (var collector in result.Collectors)
    {
        Console.WriteLine($"[{collector.Name}] {collector.Status}");

        foreach (var (key, value) in collector.Fields)
        {
            Console.WriteLine($"  {key,-32} {value ?? "—"}");
        }

        foreach (var diagnostic in collector.Diagnostics)
        {
            Console.WriteLine($"  ! {diagnostic}");
        }
    }
}

/// <summary>
/// Les constats ne se melangent pas au score : une configuration a 94 % ne doit pas
/// masquer un binaire non signe lance au demarrage.
/// </summary>
static void WriteFindings(IReadOnlyList<Finding> findings)
{
    if (findings.Count == 0)
    {
        return;
    }

    var flagged = findings.Where(f => f.Severity != FindingSeverity.Benign).ToList();

    Console.WriteLine();
    var byKind = string.Join(", ", findings
        .GroupBy(f => f.Kind)
        .OrderBy(g => g.Key, StringComparer.Ordinal)
        .Select(g => $"{g.Count()} {g.Key}"));

    Console.WriteLine($"[constats] {byKind} — {flagged.Count} à examiner");

    foreach (var finding in flagged.OrderByDescending(f => f.Severity))
    {
        Console.WriteLine();
        Console.WriteLine($"  {finding.Severity.ToString().ToUpperInvariant(),-11} {finding.Source}");
        Console.WriteLine($"              {finding.Target}");

        foreach (var reason in finding.Reasons)
        {
            Console.WriteLine($"              → {reason}");
        }

        if (finding.Details.TryGetValue("éditeur", out var publisher))
        {
            Console.WriteLine($"              éditeur : {publisher}");
        }
    }
}

static void WritePosture(ScanResult result, ScoreCard score)
{
    // Les règles satisfaites ne sont pas listées, seulement comptées : un rapport qui
    // noie trois problèmes dans cent lignes vertes ne sera pas lu.
    var failures = result.Verdicts
        .Where(v => v.Status == VerdictStatus.Fail)
        .OrderByDescending(v => v.Severity)
        .ToList();

    if (failures.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("[posture] à corriger");
        foreach (var verdict in failures)
        {
            Console.WriteLine(
                $"  {verdict.Severity.ToString().ToUpperInvariant(),-8} " +
                $"{verdict.RuleId}  {verdict.Title}");
            Console.WriteLine($"           observé : {verdict.Observed ?? "absent"}" +
                              (verdict.Expected is null ? "" : $"   attendu : {verdict.Expected}"));
        }
    }

    var unknown = result.Verdicts.Where(v => v.Status == VerdictStatus.Unknown).ToList();
    if (unknown.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("[posture] non vérifiable — accès refusé");
        foreach (var verdict in unknown)
        {
            Console.WriteLine($"  {verdict.RuleId}  {verdict.Title}");
        }
    }

    Console.WriteLine();
    Console.WriteLine("[score] par domaine");
    foreach (var domain in score.Domains)
    {
        var value = domain.Score is { } s ? $"{s,3} %" : "  n/d";
        Console.WriteLine(
            $"  {domain.Domain,-18} {value}   " +
            $"conformes {domain.Passed}, échecs {domain.Failed}, non vérifiés {domain.Unknown}" +
            (domain.NotApplicable > 0 ? $", hors périmètre {domain.NotApplicable}" : string.Empty));
    }

    Console.WriteLine();
    Console.WriteLine($"  {"GLOBAL",-18} {(score.Overall is { } o ? $"{o,3} %" : "  n/d")}");

    if (score.IsPartial)
    {
        Console.WriteLine();
        Console.WriteLine(
            $"  Score partiel : {score.TotalUnknown} contrôle(s) non vérifiable(s) sans élévation.");
        Console.WriteLine(
            "  Les contrôles non vérifiés sont exclus du calcul, jamais comptés comme conformes.");
    }

    if (failures.Count > 0 || unknown.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("  « rempart explain <ID> » détaille une règle et ce que coûte sa correction.");
    }
}

/// <summary>
/// Rend accessible ce que le scan ne peut pas afficher : la justification, les
/// références, et le coût réel d'une correction. Sans cette commande, ces informations
/// n'existaient que dans les fichiers YAML — écrites, mais hors de portée à l'usage.
/// </summary>
static int Explain(string[] args)
{
    var id = args.Length > 1 && !args[1].StartsWith('-') ? args[1] : null;
    var rules = RuleCatalog.Load(OptionValue(args, "--rules"));

    if (id is null)
    {
        Console.WriteLine($"{rules.Count} contrôles :");
        foreach (var group in rules.GroupBy(r => r.Domain).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            Console.WriteLine();
            Console.WriteLine($"  {group.Key}");
            foreach (var rule in group)
            {
                Console.WriteLine($"    {rule.Id,-14} {rule.Severity,-8} {rule.Title}");
            }
        }

        return 0;
    }

    var found = rules.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));
    if (found is null)
    {
        Console.Error.WriteLine($"Règle inconnue : {id}. « rempart explain » liste les contrôles.");
        return 1;
    }

    Console.WriteLine($"{found.Id} — {found.Title}");
    Console.WriteLine($"  sévérité   {found.Severity}");
    Console.WriteLine($"  domaine    {found.Domain}");
    if (found.References.Count > 0)
    {
        Console.WriteLine($"  références {string.Join(", ", found.References)}");
    }

    Console.WriteLine();
    Console.WriteLine("Pourquoi");
    WriteWrapped(found.Rationale);

    Console.WriteLine();
    Console.WriteLine("Ce qui est vérifié");
    Console.WriteLine($"  {found.Check.Path}");
    if (found.Check.ValueName is { } value)
    {
        Console.WriteLine($"  valeur « {value} » {found.Check.Operator} {found.Check.Expected}");
    }
    else
    {
        Console.WriteLine($"  la clé doit être {found.Check.Operator}");
    }

    if (found.Check.WindowsDefault is { } fallback)
    {
        Console.WriteLine($"  si la valeur est absente, Windows applique : {fallback}");
    }

    if (found.Remediation is not { } remediation)
    {
        Console.WriteLine();
        Console.WriteLine("Correction");
        Console.WriteLine("  Aucune remédiation décrite pour cette règle.");
        return 0;
    }

    Console.WriteLine();
    Console.WriteLine($"Correction — réversibilité : {remediation.Reversibility}");
    Console.WriteLine("  Ce qui cesse de fonctionner");
    WriteWrapped(remediation.Breaks, "    ");
    Console.WriteLine("  Qui est concerné");
    WriteWrapped(remediation.Affects, "    ");

    if (remediation.VerifyBefore is { } verify)
    {
        Console.WriteLine("  À vérifier avant d'appliquer");
        WriteWrapped(verify, "    ");
    }

    Console.WriteLine();
    Console.WriteLine("  La v1 n'applique aucune correction : elle constate et documente.");

    return 0;
}

static void WriteWrapped(string text, string indent = "  ")
{
    var words = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
    var line = new System.Text.StringBuilder(indent);

    foreach (var word in words)
    {
        if (line.Length + word.Length + 1 > 88)
        {
            Console.WriteLine(line.ToString());
            line.Clear().Append(indent);
        }

        line.Append(word).Append(' ');
    }

    if (line.Length > indent.Length)
    {
        Console.WriteLine(line.ToString().TrimEnd());
    }
}

static void RequireWindows()
{
    if (!OperatingSystem.IsWindows())
    {
        throw new PlatformNotSupportedException(
            "Rempart cible Windows. Utiliser « scan --from <instantané> » pour rejouer hors-ligne.");
    }
}

/// <summary>
/// Version lue sur l'assembly. Écrite en dur, elle avait déjà divergé deux fois du
/// lot réellement livré : la source unique est &lt;Version&gt; dans Directory.Build.props.
/// </summary>
static string ToolVersion() =>
    System.Reflection.Assembly.GetEntryAssembly()
        ?.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
        ?.InformationalVersion.Split('+')[0]
    ?? "0.0.0";

static string UtcNow() => DateTime.UtcNow.ToString("o");

static string? OptionValue(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static bool HasFlag(string[] args, string name) => Array.IndexOf(args, name) >= 0;

/// <summary>Toutes les occurrences d'une option répétable.</summary>
static IReadOnlyList<string> OptionValues(string[] args, string name)
{
    var values = new List<string>();
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] == name)
        {
            values.Add(args[i + 1]);
        }
    }

    return values;
}

static int Print(string text)
{
    Console.WriteLine(text);
    return 0;
}

static int Help() => Print(
    """
    Rempart — audit de postes Windows

      rempart scan [--json] [--from <instantané>] [--rules <dossier>]
          Analyse la machine locale, ou rejoue un instantané hors-ligne.

      rempart capture [--out <fichier>] [--raw]
          Enregistre l'état brut de la machine, rejouable en test.
          Anonymisé par défaut ; --raw conserve les identifiants.

      rempart explain [<ID>] [--rules <dossier>]
          Liste les contrôles, ou détaille une règle : justification,
          références, et ce que coûte sa correction.

      --rules <dossier>
          Charge des règles YAML supplémentaires, en plus des règles
          embarquées. Itérer sans recompiler, ou porter des contrôles
          propres à un parc. Les identifiants doivent rester uniques.

      rempart synthesise --from <capture> --out <fichier>
                         [--profile hardened|defaults] [--name <nom>]
                         [--domain-joined] [--not-elevated] [--deny <fragment>]
          Fabrique une fixture de test à partir d'une capture réelle.

      rempart diagnose-wmi
          Vérifie que WMI répond. Destiné à la CI, contre le binaire AOT.

      rempart diagnose-tasks
          Vérifie que le planificateur de tâches répond. Même usage.

      rempart keygen [--out <fichier>]
          Génère la paire de clés d'éditeur, pour signer les manifestes.
          À lancer sur une machine hors ligne — voir ADR-002. La clé privée
          est chiffrée par une phrase de passe, sans option contraire.

      rempart update --from <manifeste> [--apply] [--yes] [--store <dossier>]
          Vérifie un manifeste signé et ses jeux de données, puis montre ce
          qui changerait. Sans --apply, n'écrit rien. Avec --apply, pose la
          mise à jour dans le magasin (après confirmation, ou --yes) ; les
          scans suivants la vérifient de nouveau avant de l'utiliser.
          Les jeux de données sont attendus à côté du manifeste.

      rempart version

    Codes de sortie : 0 succès · 1 échec · 2 instantané incomplet · 3 droits insuffisants
    """);
