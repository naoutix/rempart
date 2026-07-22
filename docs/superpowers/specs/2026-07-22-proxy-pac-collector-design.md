# Design — Collecteur proxy & PAC (M4 réseau)

> État : design validé le 2026-07-22. Deux PR, un seul design.
> **PR-A** livre le collecteur proxy passif (WinINET + GPO + WinHTTP).
> **PR-B** ajoute la récupération et l'analyse du PAC, opt-in.

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

`IRegistryProvider` / `RegistryValue` ne portent que du texte et du nombre — pas d'octets
bruts. Or `WinHttpSettings` est un blob binaire (`REG_BINARY`).

**Décision (A2) :** ne PAS étendre `IRegistryProvider` au binaire. Un tel changement
transverse toucherait le provider, l'impl live, l'enregistrement snapshot, la
sérialisation et **toutes les fixtures existantes** — précisément le genre de changement
qui a déjà cassé le rejeu des fixtures anciennes.

À la place, `IProxyProvider` rend une configuration **déjà décodée** (comme `IDnsProvider`
rend des `DnsInterface`, pas du registre brut). Le décodage du blob WinHTTP vit
entièrement dans la couche `Rempart.Windows`. Le snapshot n'enregistre que le record
décodé → le rejeu reste 100 % texte/JSON, aucun support binaire ajouté, aucune fixture
existante touchée.

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

- **`LiveProxyProvider`** (`Rempart.Windows`) : lit les chaînes WinINET + GPO via
  `IRegistryProvider` (comme `LiveDnsProvider`), et lit le blob WinHTTP en **accès direct**
  (`RegistryKey.GetValue` rend un `byte[]`, hors du `IRegistryProvider` texte-only), puis
  le passe au décodeur.
  - WinINET : `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` —
    `ProxyEnable`, `ProxyServer`, `AutoConfigURL`, `ProxyOverride`.
  - GPO : présence d'une clé proxy sous `…\Policies\…\Internet Settings` (HKLM et/ou HKCU)
    → `PolicyImposed`.
  - WinHTTP : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings`.

- **`WinHttpSettingsDecoder`** (`Rempart.Windows`) : le blob est un petit en-tête
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
| `Windows/LiveProxyProvider.cs` | *(nouveau)* WinINET+GPO + WinHTTP direct |
| `Windows/WinHttpSettingsDecoder.cs` | *(nouveau)* décodeur du blob |
| `Snapshots/RecordingProviders.cs` | enregistre le `ProxyConfiguration` décodé |
| `Snapshots/MachineSnapshot.cs` + `Json/RempartJson.cs` | section `proxy` (source-gen, AOT) |
| `Snapshots/Anonymiser.cs` | masque un serveur proxy identifiant |
| `Engine/ScanEngine.cs` | enregistre `ProxyCollector` |
| `Cli/Program.cs` | branche `LiveProxyProvider` sur le scan live |

## Fixtures

Synthétiques versionnées, étendues avec une section `proxy` :

- *défaut* → aucun proxy → aucun constat
- *proxy local* → `127.0.0.1:8080` → bénin
- *proxy GPO externe* → imposé → bénin
- *proxy externe non imposé* → notable
- *PAC http externe* → suspect
- + un blob WinHTTP réel capturé (hors dépôt s'il identifie une machine, sinon synthétisé)
  pour le test du décodeur

## Tests

- `WinHttpSettingsDecoder` : blob → `ProxyScope` attendu ; blob tronqué/vide → dégradation
  propre (pas d'exception)
- `ProxyCollector` : chaque ligne de l'échelle → gravité attendue
- Rejeu déterministe : la fixture proxy rejouée rend la sortie de référence
- Invariant : les fixtures versionnées avec proxy restent anonymisées
- Le décodeur ne lève jamais sur entrée malformée

## Critère de sortie PR-A

Sur une machine réelle, `rempart scan` remonte le proxy configuré au bon niveau — un PAC
http externe posé à la main ressort *suspect*, un proxy local reste *bénin*, un proxy
imposé par GPO reste *bénin*.

---

# PR-B — Récupération et analyse du PAC (opt-in) *(esquisse)*

Nature distincte : appel réseau actif. Suit le précédent VirusTotal (`--virustotal-key`).

- Flag explicite (p. ex. `--fetch-pac`), jamais par défaut, jamais en rejeu.
- Réutilise le patron `HttpClient` de `VirusTotalReputation` (AOT, timeout, erreurs
  typées — chaque code de réponse a sa lecture, aucune ne se déguise en « sain »).
- Télécharge le script PAC référencé par `AutoConfigURL`, en extrait les directives de
  routage (`PROXY`/`SOCKS host:port`), et hisse la gravité si le PAC route vers un hôte
  externe inattendu.
- Greffé en enrichissement sur le constat proxy de PR-A (comme `FindingEnrichment` greffe
  la réputation VirusTotal), pas un collecteur séparé.

Détail à trancher au moment de PR-B : réutiliser `IReputationSource`/`FindingEnrichment`
ou une abstraction dédiée. Hors périmètre de ce design.
