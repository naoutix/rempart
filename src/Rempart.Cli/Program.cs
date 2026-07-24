using Rempart.Core.Collectors;
using Rempart.Core.Engine;
using Rempart.Core.Findings;
using Rempart.Core.Dns;
using Rempart.Core.Json;
using Rempart.Core.Pac;
using Rempart.Core.Providers;
using Rempart.Core.Reputation;
using Rempart.Core.Rules;
using Rempart.Core.Snapshots;
using Rempart.Core.Updates;
using System.Reflection;
using Rempart.Windows;

// Hand-written argument parsing. ADR-001 plans for System.CommandLine; adding it for
// two commands would be premature. To be switched in M1, once the number of commands
// justifies it.



// The Windows console is not UTF-8 by default: without this, accented diagnostics
// come out garbled, and they are exactly what needs to be read first.
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
        "fetch-loldrivers" => FetchLoldrivers(args),
        "sign" => Sign(args),
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
        // Offline replay: the same collection code, without Windows.
        var snapshot = RempartJson.DeserialiseSnapshot(File.ReadAllText(snapshotPath));
        providers = new ProviderSet(
            new SnapshotRegistryProvider(snapshot),
            new SnapshotSystemInfoProvider(snapshot),
            services: new SnapshotServiceStateProvider(snapshot),
            policy: new SnapshotSecurityPolicyProvider(snapshot),
            wmi: new SnapshotWmiProvider(snapshot),
            signatures: new SnapshotSignatureProvider(snapshot),
            files: new SnapshotFileSystemProvider(snapshot),
            scheduledTasks: new SnapshotScheduledTaskProvider(snapshot),
            drivers: new SnapshotDriverProvider(snapshot),
            processes: new SnapshotProcessProvider(snapshot),
            listeningPorts: new SnapshotListeningPortProvider(snapshot),
            firewall: new SnapshotFirewallProvider(snapshot),
            dns: new SnapshotDnsProvider(snapshot),
            hostsFile: new SnapshotHostsFileProvider(snapshot),
            proxy: new SnapshotProxyProvider(snapshot),
            wifi: new SnapshotWifiProfileProvider(snapshot),
            softwareInventory: new SnapshotSoftwareInventoryProvider(snapshot));
        origin = snapshot.CapturedAtUtc;
    }
    else
    {
        RequireWindows();
        providers = new ProviderSet(
            new LiveRegistryProvider(),
            new LiveSystemInfoProvider(),
            services: new LiveServiceStateProvider(),
            policy: new LiveSecurityPolicyProvider(),
            wmi: new Rempart.Windows.Wmi.LiveWmiProvider(),
            signatures: new LiveSignatureProvider(),
            files: new LiveFileSystemProvider(),
            scheduledTasks: new Rempart.Windows.Tasks.LiveScheduledTaskProvider(),
            drivers: new LiveDriverProvider(),
            processes: new LiveProcessProvider(),
            listeningPorts: new LiveListeningPortProvider(),
            firewall: new LiveFirewallProvider(),
            dns: new LiveDnsProvider(),
            hostsFile: new LiveHostsFileProvider(),
            proxy: new LiveProxyProvider(),
            wifi: new LiveWifiProfileProvider(),
            softwareInventory: new LiveSoftwareInventoryProvider());
        origin = UtcNow();
    }

    // The update store only applies to live scans. A replay reproduces a past scan:
    // injecting this machine's store would make it non-deterministic, and make a
    // fixture depend on local state. On replay, only the embedded baseline counts.
    var resolution = snapshotPath is null
        ? ResolveLiveCatalog(args)
        : new CatalogResolution(RuleCatalog.Load(OptionValue(args, "--rules")),
            DriverBlocklist.Empty, BloatwareCatalog.Embedded, RuleCatalog.EmbeddedAsOfUtc, null);

    var result = new ScanEngine(ScanEngine.DefaultCollectors, resolution.Rules)
        .Run(providers, ToolVersion(), origin, resolution.AsOfUtc,
            ScanEngine.DefaultFindingCollectors(resolution.Blocklist, resolution.Catalog));

    // VirusTotal enrichment — the scan's only network call, never on by default
    // (ADR-001, D9) and never on replay: that is a past snapshot, not the current
    // machine. The key comes from --virustotal-key or the environment.
    var virusTotalKey = OptionValue(args, "--virustotal-key")
        ?? Environment.GetEnvironmentVariable("REMPART_VT_KEY");

    if (snapshotPath is null && !string.IsNullOrWhiteSpace(virusTotalKey))
    {
        var flagged = result.Findings.Count(f => f.Severity != FindingSeverity.Benign
            && f.Details.ContainsKey("sha256"));

        Console.Error.WriteLine($"Consultation VirusTotal de {flagged} constat(s) signalé(s)…");

        using var reputation = new VirusTotalReputation(virusTotalKey);
        result = result with
        {
            Findings = [.. FindingEnrichment.WithReputation(result.Findings, reputation)],
        };
    }

    // PAC script retrieval — the scan's second possible network call, explicit opt-in
    // (--fetch-pac) and never on replay: a past snapshot must not trigger traffic.
    // Only fetches for flagged proxy findings that carry a URL.
    if (snapshotPath is null && HasFlag(args, "--fetch-pac"))
    {
        var withPac = result.Findings.Count(f => f.Severity != FindingSeverity.Benign
            && f.Details.ContainsKey("pac") && f.Details["pac"].Length > 0);

        Console.Error.WriteLine($"Récupération de {withPac} script(s) PAC signalé(s)…");

        using var fetcher = new LivePacFetcher();
        result = result with
        {
            Findings = [.. PacEnrichment.WithRouting(result.Findings, fetcher)],
        };
    }

    // Active DoH/DoT probe — the other opt-in network call, never by default nor on
    // replay. Measures encrypted-resolver latency and separates the finding (encrypted
    // DNS blocked) from the advice (the fastest one), which stays out of the score.
    if (snapshotPath is null && HasFlag(args, "--probe-dns"))
    {
        Console.Error.WriteLine("Sonde des résolveurs DNS chiffrés (DoH/DoT)…");

        using var probe = new LiveDnsProbe();
        var (report, probeFindings) = DnsProbeAnalysis.Analyse(probe.Probe());
        result = result with
        {
            Findings = [.. result.Findings, .. probeFindings],
            DnsProbe = report,
        };
    }

    if (asJson)
    {
        Console.WriteLine(RempartJson.Serialise(result));
    }
    else
    {
        WriteHumanReadable(result, resolution.UpdateNote);
    }

    // Missing privileges are not an execution error, but the caller must be able
    // to detect them without re-reading the output.
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
        services: new RecordingServiceStateProvider(new LiveServiceStateProvider(), snapshot),
        policy: new RecordingSecurityPolicyProvider(new LiveSecurityPolicyProvider(), snapshot),
        wmi: new RecordingWmiProvider(new Rempart.Windows.Wmi.LiveWmiProvider(), snapshot),
        signatures: new RecordingSignatureProvider(new LiveSignatureProvider(), snapshot),
        files: new RecordingFileSystemProvider(new LiveFileSystemProvider(), snapshot),
        scheduledTasks: new RecordingScheduledTaskProvider(
            new Rempart.Windows.Tasks.LiveScheduledTaskProvider(), snapshot),
        drivers: new RecordingDriverProvider(new LiveDriverProvider(), snapshot),
        processes: new RecordingProcessProvider(new LiveProcessProvider(), snapshot),
        listeningPorts: new RecordingListeningPortProvider(new LiveListeningPortProvider(), snapshot),
        firewall: new RecordingFirewallProvider(new LiveFirewallProvider(), snapshot),
        dns: new RecordingDnsProvider(new LiveDnsProvider(), snapshot),
        hostsFile: new RecordingHostsFileProvider(new LiveHostsFileProvider(), snapshot),
        proxy: new RecordingProxyProvider(new LiveProxyProvider(), snapshot),
        wifi: new RecordingWifiProfileProvider(new LiveWifiProfileProvider(), snapshot),
        softwareInventory: new RecordingSoftwareInventoryProvider(
            new LiveSoftwareInventoryProvider(), snapshot));

    // The full engine, rules included: a fixture must be able to replay everything a
    // scan does, otherwise it would only test half the path. The update store is
    // resolved here too, so a capture prefetches the keys of rules added by an update
    // and stays replayable.
    var engine = new ScanEngine(
        ScanEngine.DefaultCollectors, ResolveLiveCatalog(args).Rules);
    engine.Run(providers, ToolVersion(), snapshot.CapturedAtUtc);

    // Then every key the rules could read in another context, so the snapshot stays
    // replayable elsewhere than on the machine that produced it.
    engine.Prefetch(providers);

    // Anonymised by default: fixtures end up under version control.
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
/// Downloads the official LOLDrivers list and prepares it in the format that <c>sign</c>
/// then <c>update</c> know how to process.
///
/// <para>
/// The tool fetches the data; the publisher signs it. This is the publishing side,
/// online: the only place where we reach out to the network to produce a dataset,
/// never to apply one. The audited machines' trust does not rest on this download
/// but on the signature that follows — loldrivers.io is the upstream source the
/// publisher chooses, and their signature vouches for it.
/// </para>
/// </summary>
static int FetchLoldrivers(string[] args)
{
    var outPath = OptionValue(args, "--out") ?? "loldrivers.json";

    Console.WriteLine($"Téléchargement depuis {LolDriversImport.SourceUrl} …");

    using var transport = new HttpTransport(TimeSpan.FromSeconds(120));
    var raw = transport.Get(LolDriversImport.SourceUrl, out var error);

    if (raw is null)
    {
        Console.Error.WriteLine($"Téléchargement impossible : {error}");
        return 1;
    }

    DriverBlocklistFile blocklist;
    try
    {
        blocklist = LolDriversImport.Transform(
            System.Text.Encoding.UTF8.GetString(raw), UtcNow());
    }
    catch (System.Text.Json.JsonException ex)
    {
        // The source may have changed shape: say so rather than write a truncated
        // list that would pass for complete.
        Console.Error.WriteLine(
            $"La réponse n'a pas la forme attendue : {ex.Message} La source a pu changer.");
        return 1;
    }

    File.WriteAllText(outPath, RempartJson.SerialiseCompact(blocklist));

    Console.WriteLine();
    Console.WriteLine($"Écrit dans {outPath} — {blocklist.Drivers.Count} pilotes.");
    Console.WriteLine(
        "Rien n'est signé : c'est ton geste. Sur une machine hors ligne, avec ta clé :");
    Console.WriteLine($"  rempart sign --key <clé privée> --data {Path.GetDirectoryName(Path.GetFullPath(outPath))}");
    Console.WriteLine("  puis  rempart update --from <…\\manifest.json> --apply");
    return 0;
}

/// <summary>
/// Signs a manifest — the publication act of ADR-002.
///
/// <para>
/// The counterpart of <c>keygen</c>: run on the same offline machine, with the
/// encrypted private key that never leaves it (D16). Gathers the datasets of a
/// directory, computes their digests, and signs the lot. The resulting manifest is
/// exactly what <c>update</c> will know how to verify.
/// </para>
/// </summary>
static int Sign(string[] args)
{
    var keyPath = OptionValue(args, "--key");
    var dataDir = OptionValue(args, "--data") ?? ".";

    if (keyPath is null || !File.Exists(keyPath))
    {
        Console.Error.WriteLine(
            "Indiquer la clé privée chiffrée : rempart sign --key <fichier> --data <dossier>.");
        return 1;
    }

    if (!Directory.Exists(dataDir))
    {
        Console.Error.WriteLine($"Dossier de données introuvable : {dataDir}");
        return 1;
    }

    var outPath = OptionValue(args, "--out")
        ?? Path.Combine(dataDir, UpdateStore.ManifestFileName);

    // Neither the private key nor the produced manifest must sign themselves as
    // datasets: exclude both from the enumeration.
    var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Path.GetFullPath(keyPath), Path.GetFullPath(outPath),
    };

    var datasets = Directory
        .EnumerateFiles(dataDir, "*", SearchOption.TopDirectoryOnly)
        .Where(f => !excluded.Contains(Path.GetFullPath(f)))
        .OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal)
        .ToList();

    if (datasets.Count == 0)
    {
        Console.Error.WriteLine(
            $"Aucun jeu de données à signer dans {dataDir}. Y placer les fichiers d'abord.");
        return 1;
    }

    if (Console.IsInputRedirected)
    {
        Console.Error.WriteLine(
            "Cette commande exige une console : la phrase de passe ne doit pas transiter " +
            "par un tube ni par un argument.");
        return 1;
    }

    Console.WriteLine("Phrase de passe de la clé privée (non affichée) :");
    var passphrase = ReadHidden();

    // Kind forced for all files, or guessed from the extension: a publisher usually
    // signs a single kind at a time (a rules update, or a drivers update).
    var kind = OptionValue(args, "--kind");

    var entries = datasets
        .Select(f => ManifestSigner.Describe(Path.GetFileName(f), File.ReadAllBytes(f), kind))
        .ToList();

    var payload = new ManifestPayload(
        1, OptionValue(args, "--published") ?? UtcNow(), entries);

    SignedManifest signed;
    try
    {
        using var key = PublisherKey.Open(File.ReadAllText(keyPath).Trim(), passphrase);
        signed = ManifestSigner.Sign(payload, key);
    }
    catch (System.Security.Cryptography.CryptographicException)
    {
        // Wrong passphrase, or corrupted key file: not telling the two apart gives
        // an attacker nothing and avoids confirming that a phrase came close.
        Console.Error.WriteLine("Clé illisible : phrase de passe erronée, ou fichier abîmé.");
        return 1;
    }

    File.WriteAllText(outPath, RempartJson.Serialise(signed));

    Console.WriteLine();
    Console.WriteLine($"Manifeste signé écrit dans {outPath}.");
    Console.WriteLine($"  signé par {signed.Signatures[0].KeyId}, {entries.Count} jeu(x) de données");
    foreach (var entry in entries)
    {
        Console.WriteLine($"    {entry.Name}  ({entry.SizeBytes} octets, {entry.Sha256[..12]})");
    }

    Console.WriteLine();
    Console.WriteLine(
        "Apporter ce manifeste et les jeux de données sur la machine cible, côte à côte, " +
        "puis : rempart update --from <manifeste> --apply");
    return 0;
}

/// <summary>
/// Prepares a signed data update (ADR-002).
///
/// <para>
/// Verifies and shows — applies nothing without <c>--apply</c> (D14). The manifest and
/// every dataset are authenticated, the diff displayed. From a local file
/// (<c>--from</c>, the USB-stick flow) or from the network (<c>--url</c>): the
/// verification is exactly the same, because <b>the transport is never trusted</b>,
/// only the signature is.
/// </para>
/// </summary>
static int Update(string[] args)
{
    var manifestPath = OptionValue(args, "--from");
    var url = OptionValue(args, "--url");

    if ((manifestPath is null) == (url is null))
    {
        Console.Error.WriteLine(
            "Indiquer soit --from <fichier>, soit --url <base>, mais pas les deux ni aucun.");
        return 1;
    }

    var current = RuleCatalog.Load(OptionValue(args, "--rules"));

    // Each source produces the same thing: a preview, and the means to apply it.
    // The rest — display, confirmation, writing — is shared.
    UpdatePreview preview;
    Action applyToStore;

    if (url is not null)
    {
        using var transport = new HttpTransport();
        var (fetch, error) = RemoteUpdate.Prepare(url, transport, PinnedKeys.Verifier(), current);

        if (fetch is null)
        {
            Console.Error.WriteLine(error);
            return 1;
        }

        preview = fetch.Preview;
        applyToStore = () =>
            UpdateStore.Write(StoreDirectory(args), fetch.ManifestBytes, fetch.DatasetBytes);
    }
    else
    {
        if (!File.Exists(manifestPath))
        {
            Console.Error.WriteLine($"Manifeste introuvable : {manifestPath}");
            return 1;
        }

        // Datasets live next to the manifest. The trailing separator distinguishes
        // "inside this directory" from "a sibling directory with a similar name".
        var directory = (Path.GetDirectoryName(Path.GetFullPath(manifestPath!)) ?? ".")
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

        byte[]? ReadDataset(string name)
        {
            // A name like "..\\.." must not become an arbitrary path.
            var full = Path.GetFullPath(Path.Combine(directory, name));
            return full.StartsWith(directory, StringComparison.OrdinalIgnoreCase)
                && File.Exists(full)
                ? File.ReadAllBytes(full)
                : null;
        }

        preview = UpdatePlanner.Prepare(
            File.ReadAllText(manifestPath!), PinnedKeys.Verifier(), ReadDataset, current);

        applyToStore = () => UpdateStore.Apply(
            manifestPath!, StoreDirectory(args), preview.Datasets.Select(d => d.Name));
    }

    return ReportAndMaybeApply(args, preview, applyToStore);
}

/// <summary>
/// Displays the preview, then, given <c>--apply</c> and confirmation, writes to the
/// store. Shared by both sources — verification has already happened, identically.
/// </summary>
static int ReportAndMaybeApply(string[] args, UpdatePreview preview, Action applyToStore)
{
    if (!preview.Trusted)
    {
        // Each rejection reason gets its own response: do not conflate them.
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

    // Applying changes what future scans will evaluate: confirm it, unless --yes.
    // Without a console, refuse rather than apply an update nobody validated.
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

    applyToStore();

    Console.WriteLine($"Mise à jour posée dans {StoreDirectory(args)}.");
    Console.WriteLine(
        "Les prochains scans la vérifieront de nouveau avant de l'utiliser, et " +
        "l'afficheront dans leur en-tête.");
    return 0;
}

/// <summary>
/// The effective catalog of a live scan: the embedded baseline (plus the <c>--rules</c>
/// rules if any), completed by the store's update when it verifies.
/// </summary>
static CatalogResolution ResolveLiveCatalog(string[] args) =>
    UpdateStore.Resolve(
        StoreDirectory(args),
        RuleCatalog.Load(OptionValue(args, "--rules")),
        PinnedKeys.Verifier());

/// <summary>
/// The store travels with the binary: next to the executable by default, so a USB
/// stick carries its up-to-date data without a companion folder to forget.
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

    // A driver list has no diff: it replaces the previous one. Report its entry
    // count, the only measure that means anything.
    if (dataset.Kind == DatasetKind.Drivers)
    {
        Console.WriteLine($"  ✓ {dataset.Name} ({dataset.Version}) — " +
                          $"{dataset.DriverCount} pilote(s) vulnérable(s) surveillé(s)");
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
/// Verifies that WMI actually responds — intended for CI, run against the Native AOT
/// binary.
///
/// Exists because a COM interop bug left WMI inoperative in the published binary
/// with nothing reporting it: checks came back "unverifiable", the scan exited
/// with 0, and the publish job declared it healthy. The tests, for their part, only
/// ran under JIT, where the bug does not show.
///
/// Queries a namespace present on every Windows machine and available without
/// elevation: a failure here indicts the interop, not the environment.
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
/// Generates the key pair that will sign update manifests.
///
/// <para>
/// Run it on an offline machine — a disposable VM is enough when that is all you
/// have (ADR-002, D16). This is precisely the kind of use the standalone executable
/// deliverable exists for: copy <c>rempart.exe</c> onto a USB stick, generate
/// there, nothing to install.
/// </para>
///
/// <para>
/// The private key is never written in cleartext and no option exists to do so. A
/// removable drive gets lost; the passphrase is then what separates a lost key
/// from a compromised one.
/// </para>
/// </summary>
static int Keygen(string[] args)
{
    var path = OptionValue(args, "--out") ?? "cle-privee-rempart.txt";

    if (File.Exists(path))
    {
        // Overwriting an existing private key destroys it beyond recovery: there is
        // no copy anywhere else, which is the whole point of the scheme.
        Console.Error.WriteLine($"{path} existe déjà. Refus d'écraser une clé privée.");
        return 1;
    }

    if (Console.IsInputRedirected)
    {
        // Without a console, the passphrase would come from a pipe — hence from a
        // history, a script, or a log. Refuse rather than produce a key whose
        // protection is already known to someone else.
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

    // Immediate read-back: a key that cannot be reopened must not be discovered
    // on publication day, on a machine that will have been destroyed by then.
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

/// <summary>Reads without echo. The passphrase must not remain on screen.</summary>
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
/// Verifies that the Task Scheduler responds from the published binary.
///
/// Same reason to exist as <c>diagnose-wmi</c>, and exactly the same risk: the
/// scheduler's COM interop is generated at compile time, its interfaces derive
/// from <c>IDispatch</c>, and an offset of a single vtable slot is invisible
/// under JIT as at compile time.
///
/// A scan that found no tasks would produce a healthy-looking report. That is
/// precisely what happened with WMI for two batches, and the reason this command
/// exists before the problem arises.
///
/// Every Windows machine carries dozens of tasks; basic enumeration does not
/// require elevation. A failure here indicts the interop, not the environment.
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

    // A Windows with no tasks at all does not exist: zero indicts the enumeration, not
    // the machine. The bar stays low — a CI runner carries fewer than a real machine.
    if (read.Status != ReadStatus.Found || read.Tasks.Count == 0)
    {
        Console.Error.WriteLine(
            "Le planificateur ne rend aucune tâche. Toute installation de Windows en " +
            "porte : c'est l'interop COM qui est en cause, pas l'environnement.");
        return 1;
    }

    // The XML definition is read by a call separate from the enumeration. Counting
    // tasks therefore proves nothing about being able to read them.
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
/// Builds a synthetic fixture from a real capture.
///
/// Fixtures used to be regenerated by a throwaway script that re-parsed the YAML
/// with regular expressions: a second implementation of the loader, neither
/// versioned nor tested, that nobody else could replay. Here the rules loaded by
/// the engine drive the substitution.
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
/// Renders the data age in one line. An unreadable date is stated as such, never
/// silenced: "unknown" must not read as "up to date".
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
/// What the reader comes for first: the problems. The inventory closes the report —
/// it is context, and twenty-three lines of context before the first finding mean
/// the finding never gets read.
/// </summary>
static void WriteHumanReadable(ScanResult result, string? updateNote = null)
{
    Console.WriteLine($"Rempart {result.ToolVersion} — scan du {result.StartedAtUtc}");
    Console.WriteLine($"règles : {result.RulesFingerprint}");
    Console.WriteLine($"données : {DescribeAge(result.DataAge)}");

    // Data provenance — applied or rejected — is always stated, never silent
    // (ADR-002, D14 and D17).
    if (updateNote is { } note)
    {
        Console.WriteLine($"mise à jour : {note}");
    }

    if (result.Score is { } score)
    {
        WritePosture(result, score);
    }

    WriteFindings(result.Findings);

    if (result.DnsProbe is { } probe)
    {
        WriteDnsProbe(probe);
    }

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
/// Active DoH/DoT probe: advice, not a finding. Shown separately, outside the score,
/// and clearly presented as a one-off measurement and a suggestion.
/// </summary>
static void WriteDnsProbe(Rempart.Core.Dns.DnsProbeReport probe)
{
    Console.WriteLine();
    Console.WriteLine("[résolveurs chiffrés] latence mesurée (ponctuelle, depuis ce réseau) :");

    foreach (var result in probe.Results)
    {
        var state = result.Reachable ? $"{result.LatencyMs} ms" : $"bloqué ({result.Error})";
        Console.WriteLine($"  {result.Resolver,-12} {result.Protocol,-4} {state}");
    }

    if (probe.RecommendedResolver is { } resolver)
    {
        Console.WriteLine(
            $"  → suggestion : {resolver} en {probe.RecommendedProtocol} "
            + $"({probe.RecommendedLatencyMs} ms) est le plus rapide joignable.");
    }
    else
    {
        Console.WriteLine("  → aucun résolveur chiffré joignable — voir le constat ci-dessus.");
    }
}

/// <summary>
/// Findings do not blend into the score: a configuration at 94 % must not mask an
/// unsigned binary launched at startup.
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

        if (finding.Details.TryGetValue("virustotal", out var virusTotal))
        {
            Console.WriteLine($"              virustotal : {virusTotal}");
        }
    }
}

static void WritePosture(ScanResult result, ScoreCard score)
{
    // Satisfied rules are not listed, only counted: a report that drowns three
    // problems in a hundred green lines will not be read.
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
/// Surfaces what the scan cannot display: the rationale, the references, and the
/// real cost of a fix. Without this command, that information only existed in the
/// YAML files — written down, but out of reach in practice.
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
/// Version read from the assembly. Hard-coded, it had already diverged twice from
/// the batch actually shipped: the single source is &lt;Version&gt; in Directory.Build.props.
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

/// <summary>All occurrences of a repeatable option.</summary>
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
                   [--virustotal-key <clé>] [--fetch-pac] [--probe-dns]
          Analyse la machine locale, ou rejoue un instantané hors-ligne.
          Trois appels réseau, tous opt-in et jamais en rejeu :
          --virustotal-key (ou REMPART_VT_KEY) enrichit les constats signalés
          de leur réputation VirusTotal ; --fetch-pac récupère et analyse le
          script PAC d'un proxy signalé ; --probe-dns mesure la latence des
          résolveurs chiffrés (DoH/DoT) et recommande le plus rapide.

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

      rempart fetch-loldrivers [--out <fichier>]
          Télécharge la liste officielle LOLDrivers et la prépare à signer.
          L'outil va chercher la donnée ; toi seul la signes ensuite.

      rempart sign --key <clé privée> --data <dossier> [--out <manifeste>]
                   [--kind rules|drivers] [--published <date ISO>]
          Signe un manifeste sur les jeux de données d'un dossier. À lancer
          hors ligne avec la clé privée, pendant de keygen. Le type est deviné
          à l'extension (.yaml = règles, sinon pilotes), ou imposé par --kind.

      rempart update (--from <manifeste> | --url <base>) [--apply] [--yes]
                     [--store <dossier>]
          Vérifie un manifeste signé et ses jeux de données, puis montre ce
          qui changerait. --from lit un fichier local (flux clé USB) ; --url
          télécharge <base>/manifest.json et ses jeux de données. Le transport
          n'est jamais de confiance : seule la signature l'est. Sans --apply,
          n'écrit rien ; avec, pose la mise à jour après confirmation (ou --yes).

      rempart version

    Codes de sortie : 0 succès · 1 échec · 2 instantané incomplet · 3 droits insuffisants
    """);
