# Design — Collecteur proxy & PAC (M4 réseau)

> État : design validé le 2026-07-22. Deux PR, un seul design.
> **PR-A** — collecteur proxy passif (WinINET + GPO + WinHTTP). ✅ livrée (#52).
> **PR-B** — récupération et analyse opt-in du PAC (`--fetch-pac`). ✅ livrée.

## Contexte

M4 (réseau) a déjà livré : ports en écoute, croisement pare-feu, résolveurs DNS et
fichier `hosts`. Restent deux cases : le test actif DoH/DoT, et le proxy/PAC. Ce
design couvre le proxy/PAC.

Le proxy est un vecteur de détournement de trafic classique. Un `AutoConfigURL` (PAC)
malveillant réécrit silencieusement le routage de toute la machine — technique connue
des maliciels bancaires. Un serveur proxy posé sans contrainte intercepte le trafic.
L'audit doit distinguer ces cas de la configuration d'entreprise légitime (proxy imposé
par stratégie de groupe) sans crier au loup.

## Principe directeur

Comme `DnsResolverCollector` distingue un résolveur reçu du DHCP (subi, inventorié) d'un
résolveur posé statiquement (choix, jugé) : un proxy **imposé par stratégie de groupe**
est le cas d'entreprise attendu, on l'inventorie sans alarmer. Ce qui compte, c'est un
proxy ou un PAC **posé sans y être contraint**.

## Contrainte technique déterminante

`WinHttpSettings` est un blob binaire (`REG_BINARY`). Vérification faite dans le code :
`LiveRegistryProvider.Convert` (ligne 111) **surface déjà un `REG_BINARY` en chaîne
hexadécimale minuscule** (`RegistryValue` de `Kind="Binary"`, hex dans `Text`). Le blob
est donc lisible **à travers `IRegistryProvider.ReadValue`**, sans accès direct au
registre ni extension de l'abstraction.

**Décision (A2) :** `IProxyProvider` rend une configuration **déjà décodée** (comme
`IDnsProvider` rend des `DnsInterface`, pas du registre brut). Le décodage du blob WinHTTP
vit dans la couche logique (décodeur pur, testable sans Windows), et le snapshot
n'enregistre que le record décodé. Deux bénéfices :

- Le rejeu reste 100 % texte/JSON et passe par `SnapshotProxyProvider` (qui rend
  `snapshot.Proxy`), **jamais** par le registre du snapshot — donc aucun risque de
  `SnapshotIncompleteException` sur une fixture ancienne, contrairement à un collecteur
  qui relirait le registre au rejeu.
- `LiveProxyProvider` ne dépend que de `IRegistryProvider` → il se teste avec le
  `FakeRegistryProvider` existant, sans machine Windows.

---

# PR-A — Collecteur proxy passif

## Modèle de données

```csharp
// Core/Providers/IProxyProvider.cs
public sealed record ProxyScope(
    bool Enabled,
    string? Server,            // "host:port" ou "http=…;https=…"
    string? AutoConfigUrl,     // le PAC — WinINET seulement, WinHTTP ne fait pas de PAC
    IReadOnlyList<string> Bypass);

public sealed record ProxyConfiguration(
    ProxyScope WinInet,        // par utilisateur, HKCU
    ProxyScope WinHttp,        // machine, blob binaire décodé
    bool PolicyImposed);       // une clé proxy sous …\Policies\… est présente

public interface IProxyProvider { ProxyConfiguration Read(); }
```

## Répartition des responsabilités

- **`LiveProxyProvider`** (`Rempart.Windows`) : lit tout via `IRegistryProvider` (comme
  `LiveDnsProvider`) — chaînes WinINET + GPO, **et** le blob WinHTTP récupéré en hex puis
  décodé (`Convert.FromHexString` → octets → décodeur). Aucun accès direct au registre.
  - WinINET : `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` —
    `ProxyEnable`, `ProxyServer`, `AutoConfigURL`, `ProxyOverride`.
  - GPO : présence d'une valeur `ProxyServer` ou `AutoConfigURL` sous
    `…\Policies\Microsoft\Windows\CurrentVersion\Internet Settings` (HKLM et/ou HKCU)
    → `PolicyImposed`.
  - WinHTTP : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings`.

- **`WinHttpSettingsDecoder`** (`Rempart.Core`, décodeur pur, testable sans Windows) :
  le blob est un petit en-tête
  (version, drapeaux) suivi de chaînes **préfixées par leur longueur** (serveur, bypass).
  ⚠️ Les offsets exacts ne sont PAS présumés depuis la mémoire — ils seront **épinglés
  contre un blob réel capturé** et recoupés avec `netsh winhttp show proxy` pendant
  l'implémentation. Le décodeur est isolé, testé unitairement, et ne lève jamais sur
  entrée malformée (un blob tronqué ou corrompu dégrade en `ProxyScope` désactivé, pas en
  exception qui planterait le scan).

- **`ProxyCollector`** (`Core/Findings`) : transforme le `ProxyConfiguration` décodé en
  `Finding`s selon l'échelle ci-dessous.

Le `ProviderSet` gagne `IProxyProvider Proxy` avec un défaut `EmptyProxy` (config toute
vide → aucune invention de proxy), exactement comme `EmptyDns`.

## Échelle de jugement

Un constat par portée configurée (WinINET, WinHTTP). Rien d'émis si tout est par défaut
(silence, pas de bruit d'inventaire vide).

| Situation | Gravité | Raison |
|---|---|---|
| Aucun proxy, aucun PAC | *(rien émis)* | Défaut Windows |
| Proxy → boucle locale (`127.*`, `localhost`, `::1`) | **Bénin** | Outil local délibéré (filtre, Fiddler) — cf. résolveur local toléré |
| Proxy → hôte externe, imposé GPO | **Bénin** | Piloté par stratégie, attendu |
| Proxy → hôte externe, non imposé | **Notable** | Un proxy non contraint intercepte le trafic |
| `AutoConfigURL` en `https://`, ou PAC local | **Notable** | Un PAC réécrit tout le routage — à connaître |
| `AutoConfigURL` en `http://` externe (ou IP littérale), non imposé | **Suspect** | Détournement connu : PAC en clair, altérable, hébergé hors du contrôle de la machine |

`Details` portés par chaque constat : portée (`WinINET`/`WinHTTP`), serveur, URL du PAC,
origine (`imposé GPO` / `local`), bypass.

**Ce que PR-A ne fait pas :** elle ne récupère pas le PAC. Le classement « suspect »
repose uniquement sur l'URL (schéma + localité de l'hôte), donc reste passif et
rejouable. L'inspection du contenu du script est PR-B.

## Câblage

| Fichier | Changement |
|---|---|
| `Providers/IProxyProvider.cs` | *(nouveau)* interface + records |
| `Providers/ISystemInfoProvider.cs` | `ProviderSet` gagne `IProxyProvider Proxy` + `EmptyProxy` |
| `Findings/ProxyCollector.cs` | *(nouveau)* le jugement |
| `Providers/WinHttpSettingsDecoder.cs` | *(nouveau)* décodeur pur du blob (Core, testable sans Windows) |
| `Windows/LiveProxyProvider.cs` | *(nouveau)* WinINET+GPO+WinHTTP, tout via `IRegistryProvider` |
| `Snapshots/RecordingProviders.cs` | enregistre le `ProxyConfiguration` décodé |
| `Snapshots/MachineSnapshot.cs` + `Json/RempartJson.cs` | section `proxy` (source-gen, AOT) |
| `Snapshots/Anonymiser.cs` | masque un serveur proxy identifiant |
| `Engine/ScanEngine.cs` | enregistre `ProxyCollector` |
| `Cli/Program.cs` | branche `LiveProxyProvider` sur le scan live |

## Fixtures & tests

Alignement sur le pattern réel du dépôt : les collecteurs de constats réseau (DNS, hosts,
ports) ne sont **pas** injectés dans les fixtures synthétiques (`SyntheticSnapshot.Build`
ne porte aucune donnée réseau). Ils sont couverts par des **tests unitaires à provider
simulé** pour l'échelle de jugement, et par les **captures locales réelles** (hors dépôt)
pour la matière. Le proxy suit ce pattern — pas de fixture synthétique proxy à fabriquer.

- `WinHttpSettingsDecoder` : vecteurs = **blobs hex réels capturés** (`netsh winhttp set
  proxy …` puis lecture du registre) → `ProxyScope` attendu ; blob tronqué/vide → scope
  désactivé, **jamais** d'exception (un registre corrompu ne doit pas planter le scan).
- `ProxyCollector` : chaque ligne de l'échelle → gravité attendue, via un
  `FakeProxyProvider`.
- `LiveProxyProvider` : test de fumée Windows-only (`Rempart.Tests.Windows`, comme
  `LiveDnsProvider`) — lit la machine courante sans lever, config cohérente. Il reste
  mince : ne dépend que de `IRegistryProvider` et délègue tout le décodage au décodeur
  Core. Vérification manuelle documentée : capturer un vrai blob (`netsh winhttp set
  proxy …`), confirmer que le décodeur en tire le même serveur/bypass que
  `netsh winhttp show proxy`.
- Round-trip snapshot : un `ProxyConfiguration` enregistré puis rejoué rend la config
  identique ; un snapshot sans section `proxy` rejoue une config vide (rétrocompat).
- Intégration moteur : `ScanEngine.Run` avec un `FakeProxyProvider` posant un PAC http
  externe fait apparaître un constat *suspect* dans `result.Findings`.
- Invariant d'anonymisation : un serveur proxy externe est haché dans les captures
  versionnées (test `Anonymiser`).
- La suite complète reste verte : les références de rejeu existantes sont **inchangées**
  (aucune donnée proxy dans les fixtures → aucun nouveau constat).

## Critère de sortie PR-A

Sur une machine réelle, `rempart scan` remonte le proxy configuré au bon niveau — un PAC
http externe posé à la main ressort *suspect*, un proxy local reste *bénin*, un proxy
imposé par GPO reste *bénin*.

---

# PR-B — Récupération et analyse du PAC (opt-in) ✅ livrée

Nature distincte : appel réseau actif. Suit le précédent VirusTotal (`--virustotal-key`).

Tel que livré :

- Flag `--fetch-pac`, jamais par défaut, jamais en rejeu (garde-fou `snapshotPath is null`,
  jumeau de celui de VirusTotal).
- `LivePacFetcher` réutilise le patron `HttpClient` de `VirusTotalReputation` (AOT, timeout,
  erreurs typées — un 404/timeout n'est jamais « sain »).
- `PacDirectiveExtractor` (pur, `[GeneratedRegex]`, testable sans réseau) extrait
  **statiquement** les directives `PROXY`/`SOCKS`/`HTTPS host:port` du script — **jamais
  d'exécution JS** : embarquer un moteur pour évaluer un script hostile serait le contraire
  de l'objectif.
- `PacEnrichment` greffe le routage sur les constats proxy signalés (comme
  `FindingEnrichment` greffe la réputation) : une route externe hisse à suspect, une route
  locale ou une récupération en échec n'aggrave rien. Un constat bénin (proxy imposé GPO)
  n'est jamais récupéré.
- Abstraction dédiée `IPacFetcher`/`PacAnalysis` plutôt que réutiliser
  `IReputationSource` : la sémantique diffère (des points de routage, pas une empreinte).
