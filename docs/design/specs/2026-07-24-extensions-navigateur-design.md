# Design — Extensions navigateur (M5c)

> État : design validé le 2026-07-24. Dernier sous-lot de M5 (logiciels & bloatware).
> Indépendant de M5a/M5b : pas d'enrichissement croisé, le jugement est porté par les
> permissions elles-mêmes.

## Contexte

Une extension de navigateur est du code tiers qui tourne dans la session de l'outil le
plus exposé de la machine. Les permissions déclarées disent exactement ce qu'elle peut
faire : lire toutes les pages, les cookies, parler à un binaire natif. L'inventaire
énumère chaque extension **avec ses permissions effectives** et juge chacune — même
philosophie que les constats logiciels : bénin par défaut, escalade motivée.

## Sources (vérifiées sur machine réelle le 2026-07-24, sauf Firefox)

| Navigateur | Racine | Vérifié |
|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | oui — 1 profil, 10 entrées |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | oui — 3 profils, 42/24/37 entrées |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` | absent (dégrade à vide) |
| Chromium | `%LOCALAPPDATA%\Chromium\User Data` | absent (dégrade à vide) |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json` | **absent de cette machine** — format d'après la documentation du fichier, à confirmer sur une machine qui l'a |

Profils Chromium : dossiers `Default` et `Profile N` sous la racine.

### Ce que la machine réelle a appris (et qui contredit la documentation courante)

- **`extensions.settings` vit dans `Secure Preferences`**, pas dans `Preferences`
  (0 entrée dans Preferences sur les 4 profils inspectés). Lire les deux, fusionner.
- **`state` n'existe plus** sur Chrome/Edge récents : l'état se lit dans
  `disable_reasons` — liste vide ou absente = activée, non vide = désactivée
  (observé : `[2]`, `[8192]`). Garder `state == 0` comme signal legacy pour les
  captures anciennes.
- **`from_webstore` est inutilisable comme signal « hors magasin »** : sur Edge, les
  extensions du magasin Microsoft portent `from_webstore: false`. S'en servir
  marquerait Suspicious toutes les extensions de chaque Edge. Le signal fiable est
  **`location`** : `2` (external_pref), `3` (external_registry) et `4` (unpacked)
  sont les vecteurs de sideload ; `1` (magasin), `10` (stratégie d'entreprise) non.
- **Les extensions composants** (`location` 5/6, chemin absolu vers l'installation du
  navigateur) sont livrées par l'éditeur du navigateur : les inclure produirait des
  faux positifs sur toute machine. Écartées par le critère « chemin relatif au profil ».
- **Des entrées fantômes existent** (synchronisation) : 42 ids en settings pour 5
  dossiers d'extensions réels sur un profil Edge. Une entrée n'est retenue que si son
  `manifest.json` existe sous `Extensions\<chemin relatif>`.
- **Permissions effectives** : `granted_permissions.{api, explicit_host,
  scriptable_host}` dans les settings — préférées au manifeste (elles reflètent ce qui
  est accordé, y compris les optionnelles acceptées). Le manifeste
  (`permissions` + `host_permissions`) ne sert que de repli quand les settings
  manquent.
- Les noms `__MSG_clé__` se résolvent dans
  `_locales/<default_locale>/messages.json` (clé insensible à la casse) ; à défaut,
  le nom brut est conservé.

### Firefox (à confirmer sur machine réelle)

`extensions.json` : `addons[]` filtrés sur `type == "extension"` et
`location == "app-profile"` (installées par l'utilisateur). Champs : `id`,
`defaultLocale.name`, `version`, `active`, `signedState` (2 = signée par
addons.mozilla.org), `userPermissions.{permissions, origins}`.

## Modèle

```csharp
public sealed record BrowserExtension(
    string Browser,                       // Chrome | Edge | Brave | Chromium | Firefox
    string Profile,                       // nom du dossier de profil — jamais un chemin
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Permissions,    // permissions d'API accordées
    IReadOnlyList<string> HostAccess,     // motifs d'hôtes accordés
    bool Enabled,
    bool FromStore);                      // false = sideload (location 2/3/4, ou non signée Firefox)

public interface IBrowserExtensionProvider
{
    IReadOnlyList<BrowserExtension> Read();
}
```

`Profile` est un nom de dossier (`Default`, `Profile 1`, `abcd1234.default-release`),
jamais un chemin : aucun nom d'utilisateur Windows ne doit entrer dans une capture.
L'anonymisation hache tout de même `Profile` — le sel du dossier Firefox identifie une
installation.

## Jugement

Le principe anti-bruit d'abord : un gestionnaire de mots de passe légitime cumule
`<all_urls>` + `nativeMessaging` — le marquer Suspicious disqualifierait le rapport
sur la moitié des machines. La provenance décide du palier, les permissions motivent.

| Constat | Sévérité |
|---|---|
| Sideload (`location` 2/3/4, ou Firefox non signée) | **Suspicious** — vecteur classique d'extension malveillante, quoi qu'elle déclare |
| Magasin + accès large (`<all_urls>`, `*://*/*`, `http(s)://*/*`) | **Notable** — peut lire et modifier toutes les pages |
| Magasin + permission forte (`debugger`, `nativeMessaging`, `proxy`) sans accès large | **Notable** |
| Le reste | **Benign** — inventaire |

L'état désactivé ne change pas la sévérité (une extension sideloadée désactivée reste
un constat) ; il figure dans les détails. Détails par constat : `navigateur`, `profil`,
`id`, `version`, `permissions`, `accès`, `état`, `magasin`.

## Composants (patron A2, comme M5a)

| Fichier | Rôle |
|---|---|
| `Providers/IBrowserExtensionProvider.cs` | interface + `BrowserExtension` |
| `Browsers/ChromiumExtensions.cs` | *pur* : parse manifeste, Secure Preferences, messages.json (testable sans fichier) |
| `Browsers/FirefoxExtensions.cs` | *pur* : parse `extensions.json` |
| `Findings/BrowserExtensionsCollector.cs` | un constat `browser-extension` par extension |
| `Windows/LiveBrowserExtensionProvider.cs` | énumère racines/profils, lit les fichiers, appelle les parseurs |
| snapshot + `ProviderSet` + `ScanEngine` + `Program.cs` | câblage rejouable habituel (patron Wi-Fi) |

Un fichier illisible ou un JSON malformé écarte l'entrée ou le profil concerné, jamais
le collecteur entier : rapport partiel plutôt que pas de rapport.

## Limites documentées

- **Utilisateur courant uniquement** : les profils lus sont ceux de `%LOCALAPPDATA%` /
  `%APPDATA%` de l'utilisateur qui lance le scan — même périmètre que le proxy WinINET.
- Opera/Vivaldi : dispositions différentes, hors périmètre, à ajouter sur demande.
- Extensions poussées par stratégie (`location` 10) : non marquées sideload — c'est
  l'administrateur ; le détail `magasin` les distingue.
- Firefox : parseur livré testé sur fixtures fabriquées ; la validation sur machine
  réelle attendra une machine avec Firefox (consigné ici, pas caché).

## Fait quand

- Constats vérifiés sur cette machine contre le contenu réel de
  `chrome://extensions` / `edge://extensions` (ids et états comparés à la main sur les
  fichiers, faute d'UI scriptable).
- Fixtures synthétiques rejouées, capture → rejeu → même sortie.
- Aucun faux « Suspicious » sur les extensions composants ou du magasin Edge.
