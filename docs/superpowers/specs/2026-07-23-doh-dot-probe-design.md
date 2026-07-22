# Design — Test actif DoH/DoT (M4 réseau)

> État : design validé le 2026-07-23 (sections 1-3 approuvées en brainstorming).
> Dernier morceau de M4 avec le proxy/PAC, le Wi-Fi et le DNS/hosts livrés.

## Contexte

M4 a livré l'inventaire réseau passif (ports, pare-feu, DNS, hosts, proxy, Wi-Fi). Reste
le seul volet **actif** : mesurer la joignabilité et la latence des résolveurs DNS
**chiffrés** (DoH, DoT), et recommander le plus rapide. La ROADMAP l'assume comme une
exception explicite au « constater sans conseiller » — d'où le soin apporté ci-dessous à
séparer le **constat** de l'**avis**.

## Principes

- **Test actif, opt-in explicite** (`--probe-dns`), jamais par défaut, **jamais en rejeu**
  (garde-fou `snapshotPath is null`, jumeau de `--virustotal-key` et `--fetch-pac`). Un
  instantané passé ne doit pas déclencher de trafic.
- **Enrichissement post-scan, pas un collecteur** : comme VirusTotal et le fetch PAC. Donc
  **aucune plomberie snapshot** — un avis de latence n'a pas à être figé dans une fixture.
- **Constat ≠ avis.** Une observation de sécurité (le DNS chiffré est-il bloqué ?) entre
  dans les `Findings` et le flux normal. Le classement/recommandation est un **avis
  séparé**, hors du score, clairement étiqueté — il ne se déguise pas en verdict.
- **Mesure honnête.** Latence ponctuelle, depuis ce réseau et cet emplacement ; médiane de
  plusieurs échantillons ; jamais présentée comme une vérité absolue.

## Les deux mécaniques

Un **unique paquet de requête DNS au format wire** (RFC 1035) sert les deux protocoles —
c'est le cœur testable et réutilisé :

- **DoT (DNS over TLS)** : `TcpClient` → `résolveur:853`, `SslStream` (TLS, validation du
  certificat sur le nom d'hôte), envoi du paquet wire préfixé de sa longueur sur 2 octets
  (comme le DNS/TCP), lecture de la réponse, chronométré.
- **DoH (DNS over HTTPS)** : `HttpClient` POST sur `https://<hôte>/dns-query`,
  `content-type: application/dns-message`, corps = le **même** paquet wire (RFC 8484),
  chronométré.

Le même `DnsWireFormat.BuildQuery(name)` alimente les deux ; `DnsWireFormat.IsValidResponse`
confirme qu'une réponse est bien une réponse DNS au même identifiant. AOT-safe (aucune
réflexion, construction d'octets à la main).

⚠️ Le format wire est la partie novatrice/risquée (comme le blob WinHTTP) : **construit et
vérifié contre un vrai résolveur** pendant l'implémentation, pas de mémoire.

## Résolveurs sondés

Jeu fixe de résolveurs vie-privée répandus, chacun exposant DoH `/dns-query` en
`application/dns-message` **et** DoT sur 853 :

| Résolveur | Hôte (DoH + SNI DoT) |
|---|---|
| Cloudflare | `cloudflare-dns.com` |
| Google | `dns.google` |
| Quad9 | `dns.quad9.net` |

La liste ne prétend pas à l'exhaustivité — elle couvre les choix légitimes les plus
fréquents, comme la liste de résolveurs bien connus du collecteur DNS.

## Mesure

Pour chaque couple (résolveur × protocole), soit 3 × 2 = 6 sondes :

- **3 échantillons**, un timeout court par tentative (~3 s), un échantillon de chauffe
  écarté (première connexion TLS/HTTP plus lente), puis la **médiane** (robuste à un pic).
- Échec/timeout → `Reachable = false`, pas de latence, message d'erreur conservé.
- Borné : plafond global de temps, quelques secondes au total.

```csharp
public enum DnsProbeProtocol { DoH, DoT }

public sealed record DnsProbeResult(
    string Resolver, DnsProbeProtocol Protocol, bool Reachable, int? LatencyMs, string? Error);

public interface IDnsProbe
{
    IReadOnlyList<DnsProbeResult> Probe();   // les 6 sondes
}
```

## Ce qu'on en conclut

`DnsProbeAnalysis` (pur) transforme les 6 résultats en (a) des constats et (b) un avis.

| Résultat | Nature | Sortie |
|---|---|---|
| **Aucun** résolveur chiffré joignable (DoH *et* DoT partout en échec) | **Constat** | `Finding` `dns-encrypted`, **Suspect** : le réseau force le DNS en clair, interceptable |
| Un protocole entièrement bloqué (p. ex. tous les 853 filtrés, DoH passe) | Constat mineur | `Finding` `dns-encrypted`, **Notable** : on nomme le protocole filtré |
| ≥1 chiffré joignable en DoH et DoT | rien d'alarmant | pas de `Finding` |
| Le couple (résolveur, protocole) le plus rapide | **Avis** | section conseil, **hors score** |

L'avis :

```csharp
public sealed record DnsProbeReport(
    IReadOnlyList<DnsProbeResult> Results,
    string? RecommendedResolver,     // le plus rapide joignable, ou null si aucun
    DnsProbeProtocol? RecommendedProtocol,
    int? RecommendedLatencyMs);
```

## Composants & câblage

Nouveau dossier `src/Rempart.Core/Dns/` :

| Fichier | Rôle |
|---|---|
| `IDnsProbe.cs` | interface + `DnsProbeResult`/`DnsProbeProtocol` + liste des résolveurs |
| `DnsWireFormat.cs` | *pur* : `BuildQuery(name)` → octets ; `IsValidResponse(query, response)` |
| `DnsProbeAnalysis.cs` | *pur* : résultats → `DnsProbeReport` + `IReadOnlyList<Finding>` |
| `LiveDnsProbe.cs` | DoH (HttpClient) + DoT (TcpClient+SslStream), médiane, timing |

Câblage :

- `ScanResult` gagne `DnsProbeReport? DnsProbe` (défaut `null` = non sondé), sérialisé par
  source-gen (atteint via `ScanResult` ; à enregistrer explicitement si besoin).
- `Program.cs` : après le bloc `--fetch-pac`, un bloc `--probe-dns`
  (`snapshotPath is null && HasFlag(args, "--probe-dns")`) qui lance `LiveDnsProbe`, ajoute
  les constats aux `Findings`, et pose l'avis dans `result.DnsProbe`.
- Sortie humaine : une section « Résolveurs chiffrés » imprimant les latences et la reco,
  clairement hors du score. En `--json`, le champ `dnsProbe`.

**Aucune** modification des collecteurs, du snapshot, du rejeu ou des fixtures.

## Tests

- `DnsWireFormatTests` (unit, pur) : `BuildQuery` produit un en-tête DNS valide (QDCOUNT=1,
  RD posé, question encodée en labels) ; `IsValidResponse` accepte une réponse au bon
  identifiant, rejette un identifiant différent / un paquet tronqué (sans lever).
- `DnsProbeAnalysisTests` (unit, `FakeDnsProbe`) : classement par latence, reco du plus
  rapide, constat Suspect si tout est bloqué, Notable si un protocole est filtré, aucun
  constat si tout passe.
- La sonde **live** (réseau réel, flaky) n'est **pas** testée en unitaire (précédent
  VirusTotal). Le format wire DoT/DoH est **vérifié contre un vrai résolveur** pendant
  l'implémentation, documenté dans le décodeur.
- Zéro impact fixtures/rejeu (live-only) — les références existantes restent inchangées.

## Critère de sortie

Sur une machine réelle, `rempart scan --probe-dns` mesure les latences DoH/DoT vers les
trois résolveurs, recommande le plus rapide joignable dans une section hors score, et — si
le réseau bloque le DNS chiffré — le relève comme un constat. `rempart scan` sans le flag
ne déclenche aucun trafic ; un rejeu ne sonde jamais.
