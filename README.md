# Rempart

Security audit for Windows workstations. A single executable, no installation, runs
from a USB stick.

`rempart scan` reads the machine and prints a scored report covering four areas:

- **Hardening posture** — 82 checks across 13 domains (Defender, attack surface
  reduction, BitLocker, firewall, local accounts, LSA protection, logging, legacy
  protocols, privacy, …), mapped to CIS and ASD Essential Eight references.
- **Persistence surfaces** — autoruns, scheduled tasks, loaded kernel drivers
  (matched against the LOLDrivers list), WMI event subscriptions, running processes,
  Winlogon/AppInit extension points, LSA packages, unquoted service paths, and
  user-level COM hijacking. Every reported binary is hashed and its Authenticode
  signature verified, including catalog signatures.
- **Network exposure** — listening ports resolved to their owning binary and
  cross-checked against firewall rules (a port that is open but blocked is not
  reported as exposed), DNS resolvers, the hosts file, proxy and PAC configuration,
  and saved Wi-Fi profiles.
- **Software inventory** — installed software from four sources (Uninstall registry,
  Appx/MSIX, App Paths, Chocolatey), cross-checked against a signed bloatware
  catalog; browser extensions (Chrome, Edge, Brave, Firefox) with the permissions
  they were actually granted, sideloads flagged.

The scan is read-only and works offline. The only two features that touch the
network — VirusTotal lookups and active DoH/DoT probing — are opt-in flags, never
defaults.

## What it looks like

Abridged output on a stock Windows 11 machine (report language is currently French —
see [Output language](#output-language)):

```text
Rempart 0.3.0 — scan du 2026-07-23T14:03:14Z
règles : 82:c3e6e3029b12
données : catalogue au 2026-07-21, 2 jours

[posture] à corriger
  HIGH     WIN-ASR-001  ASR — abus de pilotes signés vulnérables non bloqué
           observé : absent (défaut Windows : 0)   attendu : 1
  HIGH     WIN-LEG-003  LLMNR activé
           observé : absent (défaut Windows : 1)   attendu : 0
  HIGH     WIN-LOG-001  Journalisation des blocs de script PowerShell inactive
           observé : absent (défaut Windows : 0)   attendu : 1
  …

[score] par domaine
  asr                  0 %   conformes 0, échecs 18, non vérifiés 0
  defender            92 %   conformes 12, échecs 2, non vérifiés 0
  firewall           100 %   conformes 6, échecs 0, non vérifiés 0, hors périmètre 1
  …
  GLOBAL              58 %

[constats] 8 autorun, 188 driver, 32 listening-port, 196 scheduled-task,
           220 software, … — 17 à examiner

  NOTABLE     UDP 0.0.0.0:5353
              C:\Program Files\Google\Chrome\Application\chrome.exe
              → Service joignable depuis un réseau public : écoute sur toutes les
                interfaces et autorisé en entrée par le pare-feu sur le profil Public.

  NOTABLE     Appx  Microsoft.XboxGamingOverlay
              → Superposition de jeu Xbox. Désinstallable ; revient à la mise à jour
                de fonctionnalité si provisionné.
```

Key French terms in the output: *règles* = rules · *données* = data freshness ·
*à corriger* = to fix · *conformes / échecs / non vérifiés / hors périmètre* =
compliant / failing / unverified / out of scope · *constats* = findings ·
*à examiner* = worth reviewing.

Every rule can explain itself — why it exists, what fixing it breaks, and how to
check beforehand:

```text
> rempart explain WIN-LEG-003

WIN-LEG-003 — LLMNR activé
  sévérité   High
  références CIS-18.5.4.2, ASD-E8

Pourquoi
  LLMNR diffuse les résolutions de noms échouées sur tout le réseau local. N'importe
  quelle machine peut y répondre et capturer une authentification NTLM…

Correction — réversibilité : Trivial
  Ce qui cesse de fonctionner
    La résolution des noms de machines locales non déclarés au DNS.
  À vérifier avant d'appliquer
    Vérifier que les machines à joindre par leur nom sont bien résolues par le DNS.
```

## Quick start

Runs on 64-bit Windows; the rule set is written against Windows 11 defaults.
There is no packaged release yet — build from source with the
[.NET SDK 10](docs/BUILD.md):

```bash
git clone https://github.com/naoutix/rempart
dotnet run --project src/Rempart.Cli -- scan   # fastest way to try it
```

Producing the single self-contained `rempart.exe` is a Native AOT publish, which
additionally needs the C++ Build Tools ([BUILD.md](docs/BUILD.md)):

```bash
dotnet publish src/Rempart.Cli -c Release
# → src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe
```

Then:

```text
rempart scan             # audit the machine; run elevated for the full view
rempart explain <ID>     # why a rule exists and what fixing it costs
```

A non-elevated scan works but leaves some checks unverified (BitLocker, account
policy, LSA); unverified checks are excluded from the score, never counted as
compliant.

## Commands

| Command | What it does |
|---|---|
| `rempart scan [--json]` | Audit the machine and print the scored report. |
| `rempart scan --from <capture>` | Replay a snapshot without the machine. |
| `rempart explain [<ID>]` | List all checks, or detail one: rationale, references, cost of fixing. |
| `rempart capture [--raw]` | Record a replayable snapshot, anonymized by default. |
| `rempart update …` | Verify and apply a signed data update (see below). |

Opt-in network flags for `scan`: `--virustotal-key` (hash lookups),
`--probe-dns` (DoH/DoT latency test), `--fetch-pac` (retrieve the PAC script,
analyzed statically, never executed).

## What it is not

Rempart audits; it does not fix, clean, or protect. It is not an antivirus, not a
network scanner (it audits the machine it runs on), and not a "PC optimizer".
Remediation is planned as a later milestone, strictly after the audit has proven
itself; today the only thing the tool ever writes is its own data store, on
`update --apply`.

## Updating the data

Rules and the vulnerable-driver list age — the latter changes weekly. The binary
embeds a complete baseline; a signed update corrects or extends it, never removes
from it ([ADR-002](docs/adr/ADR-002-mise-a-jour-des-donnees.md), French).

Trust comes from the signature, never from the transport. A dataset — downloaded,
carried on a USB stick, served by a public repository — is accepted if and only if
it is signed by a key pinned in the binary. `update --url` and `update --from` run
the exact same verification, and every later `scan` re-verifies the store before
using it.

| Command | Where | What it does |
|---|---|---|
| `rempart keygen` | offline, once | Generate the publisher key pair (private key encrypted). |
| `rempart fetch-loldrivers` | online | Download the official LOLDrivers list, ready to sign. |
| `rempart sign --key … --data …` | offline | Sign a dataset (rules or drivers). |
| `rempart update --from <manifest> \| --url <base>` | on the audited machine | Verify, preview, and `--apply`. |

## Status

In development. The read-only audit described above is implemented and tested
(447 tests); packaged reports (HTML), fleet comparison, and remediation are
planned. [ROADMAP.md](docs/ROADMAP.md) (French) tracks milestones and records
what was deliberately deferred or discarded, with reasons.

## Output language

Rule texts — titles, rationales, remediation notes, i.e. what `scan` and `explain`
print — are currently written in French. Translating the rule set is on the
roadmap. Code, code comments, and the technical documentation are in English;
dated internal records (ADRs, design specs, roadmap) remain in French.

## Developing

```bash
dotnet test                                   # 447 tests (52 require Windows), ~10 s
dotnet run --project src/Rempart.Cli -- scan  # scan the local machine
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project invariants, how to add a
rule, the test layout, and the known build pitfalls.

## Documentation map

| | |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Invariants, adding a rule, tests, workflow |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagrams, rule format, test strategy |
| [BUILD.md](docs/BUILD.md) | Prerequisites, AOT publish, build pitfalls |
| [ROADMAP.md](docs/ROADMAP.md) (French) | Milestones, including what was deferred and why |
| [DEBT.md](docs/DEBT.md) (French) | Technical debt register |
| [ADRs](docs/adr/) (French) | Decision records: stack, update channel, firewall via registry, … |
| [docs/design/](docs/design/) (French) | Design specs and implementation plans, per milestone |
| [rules/security/](rules/security/) | The 82 checks, as YAML |

## License

[MIT](LICENSE). Provided without warranty: the tool inspects — and will eventually
modify — system configuration. Whoever runs it is responsible for how it is used.
