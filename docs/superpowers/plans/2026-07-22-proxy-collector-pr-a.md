# Collecteur proxy passif (PR-A) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter un collecteur de constats `proxy` qui relève la configuration proxy/PAC de la machine (WinINET par utilisateur, proxy imposé par GPO, proxy machine WinHTTP) et la juge sur l'échelle bénin/notable/suspect, sans aucun appel réseau.

**Architecture:** Un `IProxyProvider` rend une `ProxyConfiguration` **déjà décodée** (jamais du registre brut), sur le modèle exact d'`IDnsProvider`/`DnsInterface`. Le blob binaire WinHTTP est lu via `IRegistryProvider` (qui surface un `REG_BINARY` en hex) puis décodé par une fonction pure Core testable sans Windows. Le snapshot n'enregistre que le record décodé, donc le rejeu reste texte/JSON et ne repasse jamais par le registre.

**Tech Stack:** C# / .NET 10, xUnit, Native AOT (sérialisation par source-gen), pas de nouvelle dépendance.

## Global Constraints

- **Aucun appel réseau** dans PR-A : le PAC n'est pas récupéré, seule son URL est jugée (schéma + localité de l'hôte). L'appel réseau opt-in est PR-B.
- **AOT-compatible** : pas de réflexion. La sérialisation passe par `RempartJsonContext` (source-gen) ; les nouveaux records sont atteints via `MachineSnapshot`.
- **`Unknown`/absent n'est jamais une invention** : un provider proxy absent rend `ProxyConfiguration.Empty` (rien configuré), jamais un faux proxy — comme `EmptyDns`.
- **Ne pas crier au loup** : un proxy/PAC imposé par stratégie de groupe (`PolicyImposed`) s'inventorie en bénin ; ce qui compte est un proxy/PAC posé sans contrainte.
- **Aucun collecteur n'appelle Windows directement** (ADR-001, D5) : tout passe par les providers.
- **Le décodeur ne lève jamais** sur entrée malformée : un blob tronqué/corrompu dégrade en scope désactivé, il ne plante pas le scan.
- Tests cross-platform → `Rempart.Tests.Unit` (référence Core seul). Tests machine réelle → `Rempart.Tests.Windows` (référence Windows, net10.0-windows).
- Branche de travail : `feat/proxy-pac-collector` (déjà créée). Commits fréquents, un par tâche.

---

## File Structure

| Fichier | Rôle |
|---|---|
| `src/Rempart.Core/Providers/IProxyProvider.cs` | *(créer)* interface + records `ProxyScope`/`ProxyConfiguration` |
| `src/Rempart.Core/Providers/WinHttpSettingsDecoder.cs` | *(créer)* décodeur pur du blob WinHTTP (octets → `ProxyScope`) |
| `src/Rempart.Core/Findings/ProxyCollector.cs` | *(créer)* le jugement bénin/notable/suspect |
| `src/Rempart.Windows/LiveProxyProvider.cs` | *(créer)* lecture registre (WinINET+GPO+WinHTTP hex) → décodeur |
| `src/Rempart.Core/Providers/ISystemInfoProvider.cs` | *(modifier)* `ProviderSet` gagne `Proxy` + `EmptyProxy` |
| `src/Rempart.Core/Snapshots/MachineSnapshot.cs` | *(modifier)* propriété `ProxyConfiguration? Proxy` |
| `src/Rempart.Core/Snapshots/RecordingProviders.cs` | *(modifier)* `RecordingProxyProvider` + `SnapshotProxyProvider` |
| `src/Rempart.Core/Snapshots/Anonymiser.cs` | *(modifier)* hache l'hôte d'un serveur/PAC proxy identifiant |
| `src/Rempart.Core/Engine/ScanEngine.cs` | *(modifier)* enregistre `ProxyCollector` |
| `src/Rempart.Cli/Program.cs` | *(modifier)* câble Live/Recording/Snapshot proxy (3 emplacements) |
| `tests/Rempart.Tests.Unit/ProxyTests.cs` | *(créer)* décodeur + collecteur + provider absent + intégration moteur |
| `tests/Rempart.Tests.Unit/FixtureReplayTests.cs` | *(modifier)* câble `SnapshotProxyProvider` dans `Replay` |
| `tests/Rempart.Tests.Windows/LiveProxyProviderTests.cs` | *(créer)* fumée machine réelle |

---

## Task 1 : Interface, modèle de données, défaut `EmptyProxy`

**Files:**
- Create: `src/Rempart.Core/Providers/IProxyProvider.cs`
- Modify: `src/Rempart.Core/Providers/ISystemInfoProvider.cs` (constructeur `ProviderSet` ~L32-46, propriétés ~L92, section des no-op ~L98)
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs`

**Interfaces:**
- Produces: `ProxyScope(bool Enabled, string? Server, string? AutoConfigUrl, IReadOnlyList<string> Bypass)` avec `ProxyScope.Disabled` ; `ProxyConfiguration(ProxyScope WinInet, ProxyScope WinHttp, bool PolicyImposed)` avec `ProxyConfiguration.Empty` ; `interface IProxyProvider { ProxyConfiguration Read(); }` ; `ProviderSet.Proxy` (type `IProxyProvider`, défaut `EmptyProxy.Instance`).

- [ ] **Step 1 : Écrire le test qui échoue**

Créer `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
using Rempart.Core.Findings;
using Rempart.Core.Providers;

namespace Rempart.Tests.Unit;

/// <summary>Un fournisseur proxy simulé, sur le modèle de FakeDnsProvider.</summary>
internal sealed class FakeProxyProvider(ProxyConfiguration config) : IProxyProvider
{
    public ProxyConfiguration Read() => config;
}

public class ProxyProviderSetTests
{
    /// <summary>Absent, aucun proxy n'est inventé : la config est vide, comme EmptyDns.</summary>
    [Fact]
    public void An_absent_proxy_provider_yields_an_empty_configuration()
    {
        var providers = new ProviderSet(new FakeRegistryProvider(), new FakeSystemInfoProvider());

        var config = providers.Proxy.Read();

        Assert.False(config.WinInet.Enabled);
        Assert.Null(config.WinInet.Server);
        Assert.False(config.WinHttp.Enabled);
        Assert.False(config.PolicyImposed);
    }
}
```

- [ ] **Step 2 : Lancer le test, vérifier qu'il ne compile pas / échoue**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyProviderSetTests`
Expected : échec de compilation — `IProxyProvider`, `ProxyConfiguration`, `ProviderSet.Proxy` n'existent pas.

- [ ] **Step 3 : Créer l'interface et les records**

Créer `src/Rempart.Core/Providers/IProxyProvider.cs` :

```csharp
namespace Rempart.Core.Providers;

/// <summary>
/// Configuration proxy d'une portée (par utilisateur WinINET, ou machine WinHTTP).
///
/// <para>
/// Distincte du DNS mais de même esprit : un proxy imposé par stratégie de groupe est le
/// cas d'entreprise attendu, un proxy ou un PAC posé sans contrainte est un choix — ou une
/// greffe. Un AutoConfigURL (PAC) réécrit tout le routage de la machine, technique de
/// détournement connue.
/// </para>
/// </summary>
public sealed record ProxyScope(
    bool Enabled,
    string? Server,
    string? AutoConfigUrl,
    IReadOnlyList<string> Bypass)
{
    public static readonly ProxyScope Disabled = new(false, null, null, []);
}

/// <summary>Toutes les portées proxy de la machine, déjà décodées.</summary>
public sealed record ProxyConfiguration(
    ProxyScope WinInet,
    ProxyScope WinHttp,
    bool PolicyImposed)
{
    public static readonly ProxyConfiguration Empty =
        new(ProxyScope.Disabled, ProxyScope.Disabled, false);
}

/// <summary>
/// Rend la configuration proxy déjà décodée. Abstrait comme le reste (ADR-001, D5) : le
/// jugement se teste sur une config donnée, sans registre ni machine.
/// </summary>
public interface IProxyProvider
{
    ProxyConfiguration Read();
}
```

- [ ] **Step 4 : Câbler `ProviderSet`**

Dans `src/Rempart.Core/Providers/ISystemInfoProvider.cs`, ajouter le paramètre au constructeur `ProviderSet` (après `hostsFile`, ~L46) :

```csharp
    IDnsProvider? dns = null,
    IHostsFileProvider? hostsFile = null,
    IProxyProvider? proxy = null)
```

Ajouter la propriété après `HostsFile` (~L95) :

```csharp
    /// <summary>Absent, aucune configuration proxy n'est inventée — config vide.</summary>
    public IProxyProvider Proxy { get; } = proxy ?? EmptyProxy.Instance;
```

Ajouter le no-op après `EmptyDns` (~L103) :

```csharp
internal sealed class EmptyProxy : IProxyProvider
{
    public static readonly EmptyProxy Instance = new();

    public ProxyConfiguration Read() => ProxyConfiguration.Empty;
}
```

- [ ] **Step 5 : Lancer le test, vérifier qu'il passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyProviderSetTests`
Expected : PASS.

- [ ] **Step 6 : Commit**

```bash
git add src/Rempart.Core/Providers/IProxyProvider.cs src/Rempart.Core/Providers/ISystemInfoProvider.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : IProxyProvider et modèle de configuration décodée

ProviderSet gagne Proxy, défaut EmptyProxy — absent, aucun proxy inventé.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 2 : `ProxyCollector` — l'échelle de jugement

**Files:**
- Create: `src/Rempart.Core/Findings/ProxyCollector.cs`
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs` (ajouter une classe)

**Interfaces:**
- Consumes: `ProviderSet.Proxy` (Task 1), `FakeProxyProvider` (Task 1), `Finding`/`FindingSeverity` (`Rempart.Core.Findings`), `IFindingCollector`.
- Produces: `ProxyCollector : IFindingCollector`, `Name => "proxy"`.

**Rappel de l'échelle :**

| Situation | Gravité |
|---|---|
| Rien configuré | *(rien émis)* |
| Serveur → boucle locale | Bénin |
| Serveur → externe, imposé GPO | Bénin |
| Serveur → externe, non imposé | Notable |
| PAC `https://`, ou PAC local/file | Notable |
| PAC `http://` externe (ou IP), non imposé | Suspect |
| PAC imposé GPO | Bénin |

Un constat par portée configurée ; sa gravité est le maximum du signal serveur et du signal PAC.

- [ ] **Step 1 : Écrire les tests qui échouent**

Ajouter à `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
public class ProxyCollectorTests
{
    private static IReadOnlyList<Finding> Collect(ProxyConfiguration config) =>
        new ProxyCollector().Collect(new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            proxy: new FakeProxyProvider(config)));

    private static ProxyConfiguration WinInet(
        bool enabled = false, string? server = null, string? pac = null, bool policy = false) =>
        new(new ProxyScope(enabled, server, pac, []), ProxyScope.Disabled, policy);

    [Fact]
    public void Nothing_configured_yields_no_finding() =>
        Assert.Empty(Collect(ProxyConfiguration.Empty));

    [Fact]
    public void A_loopback_proxy_is_benign()
    {
        var finding = Assert.Single(Collect(WinInet(enabled: true, server: "127.0.0.1:8080")));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void An_external_proxy_imposed_by_policy_is_benign()
    {
        var finding = Assert.Single(
            Collect(WinInet(enabled: true, server: "proxy.corp:8080", policy: true)));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void An_external_proxy_not_imposed_is_notable()
    {
        var finding = Assert.Single(Collect(WinInet(enabled: true, server: "proxy.corp:8080")));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    [Fact]
    public void An_https_pac_is_notable()
    {
        var finding = Assert.Single(Collect(WinInet(pac: "https://wpad.example/proxy.pac")));
        Assert.Equal(FindingSeverity.Notable, finding.Severity);
    }

    [Fact]
    public void An_http_external_pac_not_imposed_is_suspicious()
    {
        var finding = Assert.Single(Collect(WinInet(pac: "http://198.51.100.7/p.pac")));
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
        Assert.Contains("PAC", string.Join(" ", finding.Reasons));
    }

    [Fact]
    public void An_http_external_pac_imposed_by_policy_is_benign()
    {
        var finding = Assert.Single(
            Collect(WinInet(pac: "http://wpad.corp/p.pac", policy: true)));
        Assert.Equal(FindingSeverity.Benign, finding.Severity);
    }

    [Fact]
    public void A_disabled_proxy_with_a_malicious_pac_is_still_judged_on_the_pac()
    {
        // AutoConfigURL s'applique même quand ProxyEnable vaut 0 : le PAC est jugé seul.
        var finding = Assert.Single(Collect(WinInet(enabled: false, pac: "http://198.51.100.7/p.pac")));
        Assert.Equal(FindingSeverity.Suspicious, finding.Severity);
    }

    [Fact]
    public void Winhttp_and_wininet_are_two_findings()
    {
        var config = new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp:8080", null, []),
            new ProxyScope(true, "10.0.0.9:3128", null, []),
            PolicyImposed: false);
        Assert.Equal(2, Collect(config).Count);
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyCollectorTests`
Expected : échec de compilation — `ProxyCollector` n'existe pas.

- [ ] **Step 3 : Implémenter le collecteur**

Créer `src/Rempart.Core/Findings/ProxyCollector.cs` :

```csharp
using Rempart.Core.Providers;

namespace Rempart.Core.Findings;

/// <summary>
/// Configuration proxy et PAC de la machine, par portée.
///
/// <para>
/// Un proxy imposé par stratégie de groupe est le cas d'entreprise attendu : inventorié,
/// pas alarmé. Un proxy posé sans contrainte intercepte le trafic ; un AutoConfigURL (PAC)
/// réécrit tout le routage, et un PAC http hébergé hors du contrôle de la machine est la
/// forme même d'un détournement. Aucun appel réseau : seule l'URL est jugée, jamais son
/// contenu (ce sera un enrichissement opt-in, cf. PR-B).
/// </para>
/// </summary>
public sealed class ProxyCollector : IFindingCollector
{
    public string Name => "proxy";

    public IReadOnlyList<Finding> Collect(ProviderSet providers)
    {
        var config = providers.Proxy.Read();
        var findings = new List<Finding>();

        Judge(findings, "WinINET", config.WinInet, config.PolicyImposed);
        Judge(findings, "WinHTTP", config.WinHttp, config.PolicyImposed);

        return findings;
    }

    private static void Judge(
        List<Finding> findings, string scope, ProxyScope proxy, bool policyImposed)
    {
        var hasServer = proxy.Enabled && !string.IsNullOrWhiteSpace(proxy.Server);
        var hasPac = !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl);

        if (!hasServer && !hasPac)
        {
            return;
        }

        var severity = FindingSeverity.Benign;
        var reasons = new List<string>();

        if (hasServer && !ServerIsLocal(proxy.Server!) && !policyImposed)
        {
            severity = FindingSeverity.Notable;
            reasons.Add(
                $"Proxy {proxy.Server} non imposé par stratégie — un serveur posé sans "
                + "contrainte intercepte le trafic.");
        }

        if (hasPac)
        {
            var pacSeverity = JudgePac(proxy.AutoConfigUrl!, policyImposed);
            if (pacSeverity > severity)
            {
                severity = pacSeverity;
            }

            if (pacSeverity == FindingSeverity.Suspicious)
            {
                reasons.Add(
                    $"PAC {proxy.AutoConfigUrl} en http externe non imposé — un script de "
                    + "configuration en clair, altérable et hébergé hors du contrôle de la "
                    + "machine, peut réécrire tout le routage.");
            }
            else if (pacSeverity == FindingSeverity.Notable)
            {
                reasons.Add(
                    $"PAC {proxy.AutoConfigUrl} — un script de configuration réécrit le "
                    + "routage ; à connaître.");
            }
        }

        var origin = policyImposed ? "imposé GPO"
            : hasServer && ServerIsLocal(proxy.Server!) ? "local"
            : "utilisateur";

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["portée"] = scope,
            ["origine"] = origin,
        };
        if (hasServer)
        {
            details["serveur"] = proxy.Server!;
        }
        if (hasPac)
        {
            details["pac"] = proxy.AutoConfigUrl!;
        }
        if (proxy.Bypass.Count > 0)
        {
            details["exclusions"] = string.Join(", ", proxy.Bypass);
        }

        findings.Add(new Finding(
            "proxy", scope, proxy.AutoConfigUrl ?? proxy.Server ?? scope, severity, reasons, details));
    }

    private static bool ServerIsLocal(string server) =>
        server.Contains("127.0.0.1", StringComparison.Ordinal)
        || server.Contains("localhost", StringComparison.OrdinalIgnoreCase)
        || server.Contains("[::1]", StringComparison.Ordinal);

    private static FindingSeverity JudgePac(string url, bool policyImposed)
    {
        // Un PAC imposé par stratégie est le cas d'entreprise attendu.
        if (policyImposed)
        {
            return FindingSeverity.Benign;
        }

        // http en clair vers un hôte externe : altérable en transit, hors du contrôle de
        // la machine — la forme d'un détournement. https, ou un PAC local/file, reste à
        // signaler sans être suspect.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            && !IsLocalHost(uri.Host))
        {
            return FindingSeverity.Suspicious;
        }

        return FindingSeverity.Notable;
    }

    private static bool IsLocalHost(string host) =>
        host.Length == 0
        || host.StartsWith("127.", StringComparison.Ordinal)
        || host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        || host is "::1";
}
```

- [ ] **Step 4 : Lancer, vérifier que tout passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyCollectorTests`
Expected : PASS (9 tests).

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Core/Findings/ProxyCollector.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : ProxyCollector, échelle bénin/notable/suspect

Un proxy/PAC imposé par GPO est inventorié en bénin ; un proxy externe
non imposé est notable ; un PAC http externe non imposé est suspect. Le
PAC est jugé sur sa seule URL, sans appel réseau.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 3 : `WinHttpSettingsDecoder` — décodeur pur du blob

**Files:**
- Create: `src/Rempart.Core/Providers/WinHttpSettingsDecoder.cs`
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs` (ajouter une classe)

**Interfaces:**
- Consumes: `ProxyScope` (Task 1).
- Produces: `static ProxyScope WinHttpSettingsDecoder.Decode(byte[] blob)`.

**Format du blob** (`HKLM\…\Connections\WinHttpSettings`, posé par `netsh winhttp set proxy`) — en-tête de 12 octets puis chaînes ASCII préfixées de leur longueur, en little-endian :

```
[0..4)   version (DWORD LE)
[4..8)   compteur (DWORD LE)
[8..12)  drapeaux (DWORD LE) : bit 0x1 = accès direct, bit 0x2 = proxy configuré
[12..16) longueur du serveur (DWORD LE)
[16..)   serveur (ASCII)
[..+4)   longueur du bypass (DWORD LE)
[..)     bypass (ASCII)
```

> ⚠️ **Les valeurs de drapeaux et l'agencement sont à confirmer empiriquement** (mes faits plateforme se sont déjà révélés faux). Le test ci-dessous construit des blobs *selon ce format* et vérifie le décodage. La **confrontation à un vrai blob** est faite en Task 4 (vérification manuelle `netsh`). Si le blob réel diffère, ajuster `Decode` **et** le constructeur de blob du test pour coller aux octets observés — la réalité tranche.

- [ ] **Step 1 : Écrire les tests qui échouent**

Ajouter à `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
using System.Buffers.Binary;
using System.Text;

public class WinHttpSettingsDecoderTests
{
    /// <summary>Construit un blob au format WinHttpSettings (en-tête + chaînes préfixées).</summary>
    private static byte[] BuildBlob(uint flags, string server, string bypass)
    {
        var serverBytes = Encoding.ASCII.GetBytes(server);
        var bypassBytes = Encoding.ASCII.GetBytes(bypass);
        var blob = new byte[12 + 4 + serverBytes.Length + 4 + bypassBytes.Length];
        var span = blob.AsSpan();

        BinaryPrimitives.WriteUInt32LittleEndian(span[0..], 0x18);   // version
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..], 0x01);   // compteur
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], flags);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)serverBytes.Length);
        serverBytes.CopyTo(span[16..]);
        var offset = 16 + serverBytes.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], (uint)bypassBytes.Length);
        bypassBytes.CopyTo(span[(offset + 4)..]);
        return blob;
    }

    [Fact]
    public void Decodes_a_configured_proxy_with_bypass()
    {
        var scope = WinHttpSettingsDecoder.Decode(
            BuildBlob(0x2, "proxy.corp:8080", "*.local;<local>"));

        Assert.True(scope.Enabled);
        Assert.Equal("proxy.corp:8080", scope.Server);
        Assert.Equal(["*.local", "<local>"], scope.Bypass);
    }

    [Fact]
    public void A_direct_access_blob_is_disabled()
    {
        var scope = WinHttpSettingsDecoder.Decode(BuildBlob(0x1, "", ""));

        Assert.False(scope.Enabled);
        Assert.Null(scope.Server);
    }

    [Fact]
    public void An_empty_blob_is_disabled_and_does_not_throw() =>
        Assert.False(WinHttpSettingsDecoder.Decode([]).Enabled);

    [Fact]
    public void A_truncated_blob_is_disabled_and_does_not_throw()
    {
        // En-tête annonçant un serveur de 400 octets sur un blob qui n'en a que 16.
        var blob = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan()[8..], 0x2);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan()[12..], 400);

        var scope = WinHttpSettingsDecoder.Decode(blob);

        Assert.Null(scope.Server);
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run : `dotnet test tests/Rempart.Tests.Unit --filter WinHttpSettingsDecoderTests`
Expected : échec de compilation — `WinHttpSettingsDecoder` n'existe pas.

- [ ] **Step 3 : Implémenter le décodeur**

Créer `src/Rempart.Core/Providers/WinHttpSettingsDecoder.cs` :

```csharp
using System.Buffers.Binary;
using System.Text;

namespace Rempart.Core.Providers;

/// <summary>
/// Décode le blob binaire <c>WinHttpSettings</c> — le proxy machine posé par
/// <c>netsh winhttp set proxy</c>. En-tête de 12 octets (version, compteur, drapeaux),
/// puis serveur et bypass en chaînes ASCII préfixées de leur longueur, little-endian.
///
/// <para>
/// Pur, testable sans Windows : la couche Windows lui passe les octets lus au registre.
/// Ne lève jamais — un blob tronqué ou corrompu rend un scope désactivé plutôt qu'une
/// exception qui emporterait le scan.
/// </para>
/// </summary>
public static class WinHttpSettingsDecoder
{
    private const uint ProxyConfiguredFlag = 0x2;
    private const int HeaderLength = 12;

    public static ProxyScope Decode(byte[] blob)
    {
        if (blob.Length < HeaderLength + 4)
        {
            return ProxyScope.Disabled;
        }

        var flags = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan()[8..]);
        var offset = HeaderLength;

        var server = ReadPrefixedAscii(blob, ref offset);
        var bypass = ReadPrefixedAscii(blob, ref offset);

        var configured = (flags & ProxyConfiguredFlag) != 0 && server.Length > 0;
        if (!configured)
        {
            return ProxyScope.Disabled;
        }

        return new ProxyScope(
            Enabled: true,
            Server: server,
            AutoConfigUrl: null,   // WinHTTP ne porte pas de PAC.
            Bypass: bypass.Length == 0
                ? []
                : bypass.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// Lit une chaîne préfixée de sa longueur. Rend la chaîne vide sans lever si le blob
    /// est trop court pour la longueur annoncée — un blob corrompu ne doit pas planter.
    /// </summary>
    private static string ReadPrefixedAscii(byte[] blob, ref int offset)
    {
        if (offset + 4 > blob.Length)
        {
            offset = blob.Length;
            return string.Empty;
        }

        var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan()[offset..]);
        offset += 4;

        if (length < 0 || offset + length > blob.Length)
        {
            offset = blob.Length;
            return string.Empty;
        }

        var text = Encoding.ASCII.GetString(blob, offset, length);
        offset += length;
        return text;
    }
}
```

- [ ] **Step 4 : Lancer, vérifier que tout passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter WinHttpSettingsDecoderTests`
Expected : PASS (4 tests).

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Core/Providers/WinHttpSettingsDecoder.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : décodeur du blob WinHttpSettings

Fonction pure Core, testable sans Windows. En-tête 12 octets puis chaînes
préfixées ; ne lève jamais sur blob tronqué. Le format des drapeaux reste
à confirmer contre un vrai blob (voir tâche LiveProxyProvider).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 4 : `LiveProxyProvider` — lecture registre + confrontation au réel

**Files:**
- Create: `src/Rempart.Windows/LiveProxyProvider.cs`
- Test: `tests/Rempart.Tests.Windows/LiveProxyProviderTests.cs`

**Interfaces:**
- Consumes: `IRegistryProvider`, `LiveRegistryProvider` (Windows), `WinHttpSettingsDecoder.Decode` (Task 3), `ProxyConfiguration`/`ProxyScope` (Task 1).
- Produces: `LiveProxyProvider : IProxyProvider` avec `LiveProxyProvider()` et `LiveProxyProvider(IRegistryProvider)`.

- [ ] **Step 1 : Implémenter le provider**

Créer `src/Rempart.Windows/LiveProxyProvider.cs` :

```csharp
using Rempart.Core.Providers;

namespace Rempart.Windows;

/// <summary>
/// Lit la configuration proxy depuis le registre — par utilisateur (WinINET), imposée par
/// stratégie de groupe, et machine (WinHTTP).
///
/// <para>
/// Tout passe par <see cref="IRegistryProvider"/>, y compris le blob binaire WinHTTP :
/// <c>LiveRegistryProvider</c> surface un <c>REG_BINARY</c> en chaîne hexadécimale, qu'on
/// reconvertit en octets pour le décodeur. Aucun accès direct au registre, donc rejouable
/// et sans couplage à l'OS au-delà de cette lecture.
/// </para>
/// </summary>
public sealed class LiveProxyProvider : IProxyProvider
{
    private const string WinInetKey =
        @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private const string WinHttpKey =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

    private static readonly string[] PolicyKeys =
    [
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        @"HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    ];

    private readonly IRegistryProvider registry;

    public LiveProxyProvider()
        : this(new LiveRegistryProvider())
    {
    }

    public LiveProxyProvider(IRegistryProvider registry) => this.registry = registry;

    public ProxyConfiguration Read() =>
        new(ReadWinInet(), ReadWinHttp(), ReadPolicyImposed());

    private ProxyScope ReadWinInet()
    {
        var enabled = registry.ReadValue(WinInetKey, "ProxyEnable").Value?.Number == 1;
        var server = Text(registry.ReadValue(WinInetKey, "ProxyServer"));
        var pac = Text(registry.ReadValue(WinInetKey, "AutoConfigURL"));
        var bypass = Split(Text(registry.ReadValue(WinInetKey, "ProxyOverride")));
        return new ProxyScope(enabled, server, pac, bypass);
    }

    private ProxyScope ReadWinHttp()
    {
        if (Text(registry.ReadValue(WinHttpKey, "WinHttpSettings")) is not { Length: > 0 } hex)
        {
            return ProxyScope.Disabled;
        }

        byte[] blob;
        try
        {
            blob = Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return ProxyScope.Disabled;
        }

        return WinHttpSettingsDecoder.Decode(blob);
    }

    private bool ReadPolicyImposed() =>
        PolicyKeys.Any(key =>
            Text(registry.ReadValue(key, "ProxyServer")) is { Length: > 0 }
            || Text(registry.ReadValue(key, "AutoConfigURL")) is { Length: > 0 });

    private static string? Text(RegistryRead read) =>
        read.Status == ReadStatus.Found ? read.Value?.Text : null;

    private static IReadOnlyList<string> Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
```

- [ ] **Step 2 : Écrire le test de fumée Windows**

Créer `tests/Rempart.Tests.Windows/LiveProxyProviderTests.cs` :

```csharp
using Rempart.Windows;

namespace Rempart.Tests.Windows;

/// <summary>
/// Test machine réelle, sur le modèle de LiveDnsAndHostsProviderTests : on ne connaît pas
/// la config proxy du runner, on vérifie qu'elle se lit sans lever et reste cohérente.
/// </summary>
public sealed class LiveProxyProviderTests
{
    [Fact]
    public void Reads_the_current_machine_without_throwing()
    {
        var config = new LiveProxyProvider().Read();

        // Cohérence interne : un scope activé porte un serveur ou est décodé désactivé.
        Assert.NotNull(config);
        if (config.WinHttp.Enabled)
        {
            Assert.False(string.IsNullOrEmpty(config.WinHttp.Server));
        }
    }
}
```

- [ ] **Step 3 : Lancer les tests Windows**

Run : `dotnet test tests/Rempart.Tests.Windows --filter LiveProxyProviderTests`
Expected : PASS (sur une machine Windows ; en CI c'est le job `test-windows`).

- [ ] **Step 4 : Confronter le décodeur à un vrai blob (vérification manuelle)**

Sur une machine Windows, dans un PowerShell élevé :

```powershell
netsh winhttp set proxy proxy-server="proxy.test:8080" bypass-list="*.local;<local>"
$b = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections').WinHttpSettings
-join ($b | ForEach-Object { $_.ToString('x2') })   # blob en hex
netsh winhttp show proxy                             # la vérité de référence
netsh winhttp reset proxy                            # remettre en l'état
```

Vérifier que `WinHttpSettingsDecoder.Decode(Convert.FromHexString(hex))` rend `Server = "proxy.test:8080"` et `Bypass = ["*.local", "<local>"]`. **Si l'agencement diffère** (drapeaux, offsets), ajuster `Decode` et `BuildBlob` (Task 3) pour coller aux octets réels, relancer les tests du décodeur, recommit Task 3. Consigner le vrai format en commentaire du décodeur.

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Windows/LiveProxyProvider.cs tests/Rempart.Tests.Windows/LiveProxyProviderTests.cs
git commit -F- <<'EOF'
Proxy : LiveProxyProvider, lecture registre WinINET + GPO + WinHTTP

Tout via IRegistryProvider, y compris le blob WinHTTP lu en hex puis
décodé. Format du blob confronté à un vrai netsh set proxy.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 5 : Câblage snapshot (capture & rejeu)

**Files:**
- Modify: `src/Rempart.Core/Snapshots/MachineSnapshot.cs` (après `HostsFile`, ~L76)
- Modify: `src/Rempart.Core/Snapshots/RecordingProviders.cs` (après `SnapshotHostsFileProvider`, ~L271)
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs` (ajouter une classe)

**Interfaces:**
- Consumes: `MachineSnapshot`, `IProxyProvider`, `ProxyConfiguration` (Task 1), `RempartJson` (`Rempart.Core.Json`).
- Produces: `MachineSnapshot.Proxy` (type `ProxyConfiguration?`), `RecordingProxyProvider(IProxyProvider, MachineSnapshot)`, `SnapshotProxyProvider(MachineSnapshot)`.

- [ ] **Step 1 : Écrire les tests qui échouent**

Ajouter à `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
using Rempart.Core.Json;
using Rempart.Core.Snapshots;

public class ProxySnapshotTests
{
    [Fact]
    public void Recording_then_replaying_round_trips_the_configuration()
    {
        var snapshot = new MachineSnapshot { CapturedAtUtc = "2026-01-01T00:00:00.0000000Z" };
        var config = new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp:8080", "http://wpad.corp/p.pac", ["*.local"]),
            ProxyScope.Disabled, PolicyImposed: false);

        new RecordingProxyProvider(new FakeProxyProvider(config), snapshot).Read();

        // Passe par la sérialisation réelle : garde-fou AOT sur les nouveaux records.
        var round = RempartJson.DeserialiseSnapshot(RempartJson.Serialise(snapshot));
        var replayed = new SnapshotProxyProvider(round).Read();

        Assert.Equal(config, replayed);
    }

    [Fact]
    public void A_snapshot_without_a_proxy_section_replays_an_empty_configuration()
    {
        // Rétrocompat : une fixture d'avant ce lot n'a pas de section proxy.
        var replayed = new SnapshotProxyProvider(new MachineSnapshot()).Read();

        Assert.Equal(ProxyConfiguration.Empty, replayed);
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxySnapshotTests`
Expected : échec de compilation — `MachineSnapshot.Proxy`, `RecordingProxyProvider`, `SnapshotProxyProvider` absents.

- [ ] **Step 3 : Ajouter la propriété au snapshot**

Dans `src/Rempart.Core/Snapshots/MachineSnapshot.cs`, après la propriété `HostsFile` (~L76) :

```csharp
    /// <summary>Configuration proxy décodée, ou null si l'instantané précède sa collecte.</summary>
    public ProxyConfiguration? Proxy { get; set; }
```

- [ ] **Step 4 : Ajouter les providers d'enregistrement et de rejeu**

Dans `src/Rempart.Core/Snapshots/RecordingProviders.cs`, après `SnapshotHostsFileProvider` (~L271) :

```csharp
public sealed class RecordingProxyProvider(IProxyProvider inner, MachineSnapshot snapshot) : IProxyProvider
{
    public ProxyConfiguration Read() => snapshot.Proxy ??= inner.Read();
}

public sealed class SnapshotProxyProvider(MachineSnapshot snapshot) : IProxyProvider
{
    // Absent d'une capture antérieure : config vide, la fixture reste rejouable et
    // produit simplement aucun constat proxy.
    public ProxyConfiguration Read() => snapshot.Proxy ?? ProxyConfiguration.Empty;
}
```

- [ ] **Step 5 : Lancer, vérifier que tout passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxySnapshotTests`
Expected : PASS (2 tests). Un échec de sérialisation signalerait un souci de source-gen — dans ce cas, ajouter `[JsonSerializable(typeof(ProxyConfiguration))]` à `RempartJsonContext` dans `src/Rempart.Core/Json/RempartJson.cs` et relancer.

- [ ] **Step 6 : Commit**

```bash
git add src/Rempart.Core/Snapshots/MachineSnapshot.cs src/Rempart.Core/Snapshots/RecordingProviders.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : câblage capture et rejeu du snapshot

MachineSnapshot.Proxy porte la config décodée ; Recording/Snapshot
providers l'enregistrent et la rejouent. Une capture antérieure sans
section proxy rejoue une config vide.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 6 : Anonymisation du serveur proxy

**Files:**
- Modify: `src/Rempart.Core/Snapshots/Anonymiser.cs` (dans `Apply`, après le bloc `Processes` ~L149 ; ajouter deux helpers privés)
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs` (ajouter une classe)

**Interfaces:**
- Consumes: `MachineSnapshot.Proxy` (Task 5), `Anonymiser.Apply`, `Anonymiser.Hash` (public).
- Produces: comportement d'anonymisation sur `snapshot.Proxy` (aucune nouvelle API publique).

**Principe :** un hôte de proxy/PAC identifie une infrastructure → on le hache. Mais on **préserve les propriétés jugées** (schéma http/https, localité) pour que le rejeu du collecteur rende la même gravité : un `http://` externe reste un `http://` externe une fois l'hôte haché.

- [ ] **Step 1 : Écrire les tests qui échouent**

Ajouter à `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
public class ProxyAnonymisationTests
{
    private static ProxyConfiguration Anonymise(ProxyConfiguration config)
    {
        var snapshot = new MachineSnapshot { SystemInfo = FakeSystemInfoProvider.Default, Proxy = config };
        return Anonymiser.Apply(snapshot).Proxy!;
    }

    [Fact]
    public void An_external_proxy_host_is_hashed()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(true, "proxy.corp.example:8080", null, []),
            ProxyScope.Disabled, false));

        Assert.DoesNotContain("corp.example", result.WinInet.Server);
        Assert.Contains("anon:", result.WinInet.Server);
        Assert.EndsWith(":8080", result.WinInet.Server);   // le port reste lisible
    }

    [Fact]
    public void A_loopback_proxy_is_left_readable()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(true, "127.0.0.1:8888", null, []),
            ProxyScope.Disabled, false));

        Assert.Equal("127.0.0.1:8888", result.WinInet.Server);
    }

    [Fact]
    public void A_pac_url_keeps_its_scheme_but_hides_its_host()
    {
        var result = Anonymise(new ProxyConfiguration(
            new ProxyScope(false, null, "http://wpad.corp.example/proxy.pac", []),
            ProxyScope.Disabled, false));

        Assert.StartsWith("http://anon:", result.WinInet.AutoConfigUrl);
        Assert.EndsWith("/proxy.pac", result.WinInet.AutoConfigUrl);
        Assert.DoesNotContain("corp.example", result.WinInet.AutoConfigUrl);
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyAnonymisationTests`
Expected : FAIL — l'anonymiseur ne touche pas encore `snapshot.Proxy`.

- [ ] **Step 3 : Anonymiser le proxy dans `Apply`**

Dans `src/Rempart.Core/Snapshots/Anonymiser.cs`, à la fin de `Apply` juste avant `snapshot.Anonymised = true;` (~L151) :

```csharp
        if (snapshot.Proxy is { } proxy)
        {
            snapshot.Proxy = proxy with
            {
                WinInet = ScrubScope(proxy.WinInet),
                WinHttp = ScrubScope(proxy.WinHttp),
            };
        }
```

Ajouter ces helpers privés dans la classe (après `ScrubProfile`, avant `Hash`) :

```csharp
    /// <summary>
    /// Hache l'hôte d'un serveur et d'un PAC, en préservant schéma, port et localité :
    /// le rejeu du collecteur doit rendre le même verdict qu'avant anonymisation.
    /// </summary>
    private static ProxyScope ScrubScope(ProxyScope scope) => scope with
    {
        Server = ScrubHostPort(scope.Server),
        AutoConfigUrl = ScrubUrlHost(scope.AutoConfigUrl),
    };

    private static string? ScrubHostPort(string? server)
    {
        if (string.IsNullOrEmpty(server) || IsLocalToken(server))
        {
            return server;
        }

        var colon = server.LastIndexOf(':');
        // Un port en fin de chaîne (chiffres après le dernier « : ») reste lisible.
        return colon > 0 && server[(colon + 1)..].All(char.IsDigit)
            ? Hash(server[..colon]) + server[colon..]
            : Hash(server);
    }

    private static string? ScrubUrlHost(string? url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || IsLocalToken(uri.Host))
        {
            return url;
        }

        return $"{uri.Scheme}://{Hash(uri.Host)}{uri.PathAndQuery}";
    }

    private static bool IsLocalToken(string value) =>
        value.Contains("127.0.0.1", StringComparison.Ordinal)
        || value.Contains("localhost", StringComparison.OrdinalIgnoreCase)
        || value.Contains("[::1]", StringComparison.Ordinal)
        || value is "::1";
```

- [ ] **Step 4 : Lancer, vérifier que tout passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyAnonymisationTests`
Expected : PASS (3 tests).

- [ ] **Step 5 : Commit**

```bash
git add src/Rempart.Core/Snapshots/Anonymiser.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : anonymiser l'hôte d'un serveur/PAC identifiant

L'hôte est haché, schéma port et localité préservés — le rejeu rend le
même verdict, l'infra n'est plus identifiable dans une fixture versionnée.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Task 7 : Enregistrement moteur, câblage CLI, intégration bout-en-bout

**Files:**
- Modify: `src/Rempart.Core/Engine/ScanEngine.cs` (liste `DefaultFindingCollectors` ~L45-60)
- Modify: `src/Rempart.Cli/Program.cs` (bloc rejeu ~L66-80, bloc live ~L86-100, bloc capture ~L159-174)
- Modify: `tests/Rempart.Tests.Unit/FixtureReplayTests.cs` (helper `Replay`, `ProviderSet` ~L164-178)
- Test: `tests/Rempart.Tests.Unit/ProxyTests.cs` (ajouter un test d'intégration)

**Interfaces:**
- Consumes: `ProxyCollector` (Task 2), `LiveProxyProvider` (Task 4), `RecordingProxyProvider`/`SnapshotProxyProvider` (Task 5), `ScanEngine.DefaultFindingCollectors`, `DriverBlocklist.Empty`.

- [ ] **Step 1 : Écrire le test d'intégration moteur qui échoue**

Ajouter à `tests/Rempart.Tests.Unit/ProxyTests.cs` :

```csharp
using Rempart.Core.Engine;
using Rempart.Core.Updates;

public class ProxyEngineIntegrationTests
{
    [Fact]
    public void The_engine_surfaces_a_suspicious_pac_finding()
    {
        var providers = new ProviderSet(
            new FakeRegistryProvider(), new FakeSystemInfoProvider(),
            proxy: new FakeProxyProvider(new ProxyConfiguration(
                new ProxyScope(false, null, "http://198.51.100.7/p.pac", []),
                ProxyScope.Disabled, PolicyImposed: false)));

        var result = new ScanEngine(ScanEngine.DefaultCollectors, [])
            .Run(providers, "test", "2026-01-01T00:00:00.0000000Z", null,
                ScanEngine.DefaultFindingCollectors(DriverBlocklist.Empty));

        var proxy = Assert.Single(result.Findings, f => f.Kind == "proxy");
        Assert.Equal(FindingSeverity.Suspicious, proxy.Severity);
    }
}
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyEngineIntegrationTests`
Expected : FAIL — aucun constat `proxy` (collecteur pas encore enregistré).

- [ ] **Step 3 : Enregistrer le collecteur**

Dans `src/Rempart.Core/Engine/ScanEngine.cs`, ajouter à la liste `DefaultFindingCollectors` après `new HostsFileCollector(),` (~L59) :

```csharp
        new ProxyCollector(),
```

- [ ] **Step 4 : Lancer, vérifier que l'intégration passe**

Run : `dotnet test tests/Rempart.Tests.Unit --filter ProxyEngineIntegrationTests`
Expected : PASS.

- [ ] **Step 5 : Câbler le CLI (les trois emplacements)**

Dans `src/Rempart.Cli/Program.cs` :

Bloc rejeu — après `hostsFile: new SnapshotHostsFileProvider(snapshot));` (~L80), transformer la fin de l'appel en :

```csharp
            hostsFile: new SnapshotHostsFileProvider(snapshot),
            proxy: new SnapshotProxyProvider(snapshot));
```

Bloc live — après `hostsFile: new LiveHostsFileProvider());` (~L100) :

```csharp
            hostsFile: new LiveHostsFileProvider(),
            proxy: new Rempart.Windows.LiveProxyProvider());
```

Bloc capture — après `hostsFile: new RecordingHostsFileProvider(new LiveHostsFileProvider(), snapshot));` (~L174) :

```csharp
        hostsFile: new RecordingHostsFileProvider(new LiveHostsFileProvider(), snapshot),
        proxy: new RecordingProxyProvider(new Rempart.Windows.LiveProxyProvider(), snapshot));
```

- [ ] **Step 6 : Câbler le rejeu des tests de fixtures**

Dans `tests/Rempart.Tests.Unit/FixtureReplayTests.cs`, helper `Replay`, ajouter à la fin du `ProviderSet` (~L177-178) :

```csharp
            dns: new SnapshotDnsProvider(snapshot),
            hostsFile: new SnapshotHostsFileProvider(snapshot),
            proxy: new SnapshotProxyProvider(snapshot));
```

- [ ] **Step 7 : Lancer la suite complète**

Run : `dotnet test`
Expected : PASS, tous projets. Les références de rejeu (`*.expected.json`) sont **inchangées** : aucune fixture ne porte de données proxy, donc aucun nouveau constat. Si une référence diffère, c'est un bug — investiguer avant de régénérer.

- [ ] **Step 8 : Vérifier la compatibilité AOT**

Run : `dotnet build src/Rempart.Cli -c Release`
Expected : build vert, aucun avertissement de trim/AOT sur les nouveaux types (le garde-fou `IsAotCompatible` les attraperait).

- [ ] **Step 9 : Commit**

```bash
git add src/Rempart.Core/Engine/ScanEngine.cs src/Rempart.Cli/Program.cs tests/Rempart.Tests.Unit/FixtureReplayTests.cs tests/Rempart.Tests.Unit/ProxyTests.cs
git commit -F- <<'EOF'
Proxy : enregistrer le collecteur et le câbler au scan

ProxyCollector rejoint les collecteurs de constats ; live, capture et
rejeu câblent le provider proxy. Les références de rejeu restent
inchangées, aucune fixture ne portant de données proxy.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015pMTMoTkBxZBaRBWxW6FMq
EOF
```

---

## Vérification finale (avant PR)

- [ ] `./scripts/verify.ps1` — workflows, tests, publication AOT, binaire isolé (le garde-fou complet du dépôt).
- [ ] Sur une machine réelle avec un PAC http externe posé à la main (`HKCU\…\Internet Settings\AutoConfigURL`), `rempart scan` remonte un constat `proxy` **suspect** ; un proxy `127.0.0.1` reste **bénin**. C'est le critère de sortie PR-A.
- [ ] `gh pr create` puis, une fois les 5 checks verts, `gh pr merge --squash` (l'auto-merge du dépôt est activé : `gh pr merge <n> --squash --auto`).

## Couverture du spec

| Exigence du spec | Tâche |
|---|---|
| `IProxyProvider` rend une config décodée | 1 |
| `ProviderSet` défaut `EmptyProxy` (absent → vide) | 1 |
| Échelle bénin/notable/suspect, tolérance GPO | 2 |
| PAC jugé sur l'URL seule, sans réseau | 2 |
| Décodage WinHTTP pur, ne lève jamais | 3 |
| Blob lu en hex via `IRegistryProvider` | 4 |
| WinINET + GPO + WinHTTP | 4 |
| Confrontation du format à un vrai blob | 4 |
| Snapshot capture/rejeu, rétrocompat | 5 |
| Anonymisation de l'hôte proxy | 6 |
| Enregistrement moteur + câblage CLI | 7 |
| Références de rejeu inchangées | 7 |

**PR-B (hors périmètre)** — récupération opt-in du PAC : suivra dans son propre spec/plan.
