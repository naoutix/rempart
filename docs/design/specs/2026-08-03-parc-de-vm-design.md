# Design — Le parc de VM : mesurer un défaut au lieu de le supposer (1.x)

> État : proposé le 2026-08-03. Débloque `DET-WINDEFAULT`, `DET-TLS`, `DET-IPV6`
> (partie règles), et alimente #213/#214/#215/#216.

## Contexte

`DEBT.md` range cinq dettes dans une phase à part — *« ce qui attend des machines, pas
du code »*. Elles n'avancent pas d'une ligne écrite au clavier : il faut observer
plusieurs builds de Windows. Le parc est ce que ces cinq dettes attendent.

[ADR-006](../../adr/ADR-006-catalogue-bloatware-importe.md) l'avait déjà écarté pour le
catalogue bloatware — une VM Microsoft ne porte aucun logiciel constructeur, donc elle ne
ferme pas ce critère-là — en notant qu'il *« sert en revanche très bien les dettes
suspendues à “les défauts varient selon la build” »*. C'est cet emploi-là, et pas l'autre.

## 1. La question, qui n'est pas celle qu'on croit

`survey` (#213) sait dire que des machines ne sont pas d'accord sur un champ. Ce n'est
pas la question. La question est **de quoi ce défaut dépend** :

- de la **build** — 26100 contre 17763 ;
- de l'**édition** — Pro contre Enterprise, à build égale ;
- de la **famille** — client contre serveur, à build égale.

Un parc rassemblé au hasard répond « ces six machines diffèrent » et laisse le lecteur
deviner laquelle des trois causes agit. D'où une matrice, et non une liste : **chaque
paire ne fait varier qu'une chose.**

| Machine | Build | Famille | Édition | Ce que sa paire isole |
|---|---|---|---|---|
| Poste de développement | 26200 | client | Pro | — *(déjà capturé)* |
| Windows 11 Enterprise 25H2 | 26200 | client | Enterprise | l'**édition**, contre le poste |
| Windows 11 Enterprise LTSC 2024 | 26100 | client | LTSC | la **build**, contre 25H2 |
| Windows Server 2025 | 26100 | serveur | Datacenter | la **famille**, contre LTSC 2024 |
| Windows Server 2019 | 17763 | serveur | — | la **build**, sur sept ans |
| Windows 11 23H2 | 22631 | client | — | la **build**, côté client |
| Windows 10 22H2 | 19045 | client | — | la **génération** |

Les quatre premières lignes suffisent à séparer les trois causes. Les deux dernières
étendent la portée, et arrivent par un autre chemin — voir §2.

Numéros de build relevés le 2026-08-03 sur la [page de publication Windows 11 de
Microsoft](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information)
et non de mémoire : 25H2 = 26200, 24H2 = 26100, 23H2 = 22631, **LTSC 2024 = 26100**.
C'est cette dernière égalité qui rend la matrice possible — sans elle, aucun couple
client/serveur ne partagerait une build.

## 2. Provenance : deux sources, et elles ne se valent pas

Vérifié sur l'Evaluation Center le 2026-08-03 : Microsoft ne distribue que la version
**courante** d'un produit client. Sont disponibles Windows 11 Enterprise 25H2, Windows 11
Enterprise LTSC 2024, et les Windows Server 2025 / 2022 / 2019 / 2016. **Windows 10 n'est
plus proposé du tout, et Windows 11 23H2 non plus.**

Ces deux-là n'entrent donc que par UUP dump, qui reconstruit un ISO à partir des paquets
que Microsoft sert encore. **C'est un choix assumé, pas un détail d'intendance** : un ISO
signé par Microsoft et un ISO reconstruit ne portent pas la même autorité comme source
d'une mesure, et ce dépôt refuse ailleurs qu'une déduction ressemble à une observation.

**Décision.** La provenance est portée par le nom de la fixture, où elle est visible dans
chaque nom de test : `lab/win11-23h2-22631-uup`. Un défaut établi uniquement sur des
captures suffixées `-uup` est un défaut à confirmer, et le nom suffit à le voir sans
ouvrir un fichier.

## 3. Les VM restent hors ligne

`tests/fixtures/local/README.md` explique pourquoi une capture réelle ne se versionne pas.
Ici, le point est différent et il est méthodologique : **une VM connectée n'est plus une
mesure de la build, mais de la build plus les correctifs du jour.** Windows Update modifie
des valeurs que ce parc existe pour observer. La capture se prend sur l'image fraîchement
installée, réseau désactivé, avant tout redémarrage inutile.

Conséquence pratique : le binaire entre par `Copy-VMFile` et la capture ressort en
montant le VHDX après extinction. Aucune des deux étapes ne demande de réseau invité.

## 4. Pourquoi ces captures-là se versionnent

C'est une entorse à la règle de `tests/fixtures/local/`, et elle demande à être justifiée
plutôt que constatée. Cette règle refuse les captures réelles parce qu'une capture
cartographie les faiblesses d'une machine **rattachée à une identité publique**.

Une image installée depuis un ISO Microsoft n'a ni couche constructeur, ni compte
personnel, ni identité à rattacher. Ses « faiblesses » sont les défauts de Microsoft,
c'est-à-dire une information publique — et c'est précisément ce qu'on cherche à publier.
Le motif du refus ne s'applique pas.

Elles vont donc dans `tests/fixtures/lab/`, versionnées, rejouées à chaque PR comme les
synthétiques. Le garde-fou d'anonymisation les couvre depuis #228 : il nommait
`synthetic/`, il nomme désormais `local/` comme seule exception.

**Ce que ça change.** `DET-WINDEFAULT` cesse de se fermer sur une parole et se ferme sur
des preuves que n'importe qui peut rejouer, y compris quelqu'un qui n'a aucune de ces six
machines.

## 5. Ce que le parc ne prouve pas

À écrire ici pour que personne ne l'attende du parc :

- **Le bloatware OEM.** Aucune VM n'en porte. Tranché par ADR-006, D21.
- **Le matériel.** SMART, températures, firmware réel : hors de portée d'une VM,
  `ARCHITECTURE.md` le dit déjà.
- **Le domaine.** La seule règle portant `appliesWhen: domainJoined`
  (`rules/security/firewall.yaml`) reste non applicable partout dans le parc.
- **Un défaut « de Windows 11 ».** LTSC 2024 est un 26100 client, pas un 26100 grand
  public. Une différence LTSC/grand public reste possible et n'est pas mesurée ici.

## 6. Après le parc

1. `survey` répond sur six machines au lieu d'une, et sa phrase « une seule valeur sur
   toutes les machines vues » cesse d'être vraie et trompeuse à la fois (#213).
2. Les seize valeurs SCHANNEL collectées depuis #223 ont enfin des défauts observés par
   build : `DET-TLS` se ferme, et les règles TLS (#215) deviennent écrivables.
3. Même chose pour le durcissement IPv6 (#216).
4. Les ~60 `windowsDefault` validés sur une machine se confrontent à cinq autres. Ceux
   qui tombent sont le vrai produit du lot.

Rien de tout cela ne demande de code nouveau : les commandes existent, il leur manquait
des machines.
