# Rempart

Security audit for Windows workstations. One executable, no installation, runs from
a USB stick.

`rempart scan` reads the machine and prints a scored report covering four areas:

- **Hardening posture** — 82 checks across 13 domains (Defender, attack surface
  reduction, BitLocker, firewall, local accounts, LSA protection, logging, legacy
  protocols, privacy, …), mapped to CIS and ASD Essential Eight references.
- **Persistence surfaces** — autoruns, scheduled tasks, loaded kernel drivers
  (matched against the LOLDrivers list), WMI event subscriptions, running processes,
  Winlogon/AppInit extension points, LSA packages, unquoted service paths, and
  user-level COM hijacking. Every reported binary is hashed and its Authenticode
  signature verified, catalog signatures included.
- **Network exposure** — listening ports resolved to the binary that owns them and
  cross-checked against firewall rules (a port that is open but blocked is not
  reported as exposed), DNS resolvers, the hosts file, proxy and PAC configuration,
  and saved Wi-Fi profiles.
- **Software inventory** — installed software from four sources (Uninstall registry,
  Appx/MSIX, App Paths, Chocolatey), checked against a signed 123-entry bloatware
  catalog; browser extensions (Chrome, Edge, Brave, Firefox) with the permissions
  they were actually granted; sideloads flagged.

The scan is read-only and works offline. Three scan features can reach the network —
VirusTotal hash lookups, DoH/DoT probing, and fetching a proxy's PAC script — and all
three are opt-in flags, never defaults. Outside the scan, only `update --url` and the
publisher-side commands `fetch-loldrivers` and `fetch-bloatware` go online, and none
of them trusts the transport: a dataset is accepted on its signature alone.

## What it looks like

Abridged output on a stock Windows 11 machine (report language is currently French —
see [Output language](#output-language)):

```text
Rempart 1.0.0 — scan du 2026-07-28T18:28:45Z
règles : 82:c3e6e3029b12
données : catalogue au 2026-07-21, 7 jours

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

[constats] 8 autorun, 189 driver, 52 listening-port, 196 scheduled-task,
           186 software, … — 27 à examiner

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

Runs on 64-bit Windows; the rule set targets Windows 11 defaults.

**The current release is [v1.0.0](https://github.com/naoutix/rempart/releases)** —
stable, not a candidate: the sealed archive has been run on a machine other than the
one that built it, on a different Windows feature update, with nothing pre-installed.

A release archive is the stick layout: `rempart.exe` plus a `rempart-integrity.json`
signed by the publisher key. The 82 rules are compiled into the binary, so there is
no companion folder to copy. (A `rules/` directory next to the executable adds
fleet-specific checks of your own; it never replaces the shipped ones.) Before
trusting the binary, verify the archive — from a copy you already trust:

```text
rempart seal --dir <dir> --check
```

Or build from source. This needs the **.NET SDK 10.0.302 or later**, pinned by
`global.json` — an older 10.0 SDK stops with `A compatible .NET SDK was not found`
([BUILD.md](docs/BUILD.md)):

```bash
git clone https://github.com/naoutix/rempart
dotnet run --project src/Rempart.Cli -- scan   # fastest way to try it
```

Producing the single self-contained `rempart.exe` is a Native AOT publish, which
also needs the C++ Build Tools ([BUILD.md](docs/BUILD.md)):

```bash
dotnet publish src/Rempart.Cli -c Release
# → src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe
```

Then:

```text
rempart scan             # audit the machine; run elevated for the full view
rempart explain <ID>     # why a rule exists and what fixing it costs
```

A non-elevated scan works, but some checks come back unverified (BitLocker, account
policy, LSA). Unverified checks are excluded from the score — never counted as
compliant.

## Commands

| Command | What it does |
|---|---|
| `rempart scan [--json]` | Audit the machine and print the scored report. |
| `rempart scan --report [dir]` | Also write `rapport.html`, `.md` and `.json` to `<dir>/<machine>-<date>/`. |
| `rempart scan --from <capture>` | Replay a snapshot without the machine. |
| `rempart report --from <rapport.json>` | Re-render the HTML, Markdown and JSON without scanning again — `--format` narrows it to one. Runs anywhere. |
| `rempart diff <a.json> <b.json>` | Compare two scans: what regressed, what the audit stopped seeing. Exits `4` on a regression. |
| `rempart index [dir]` | Build the fleet page from a folder of reports, worst first. |
| `rempart explain [<ID>]` | List all checks, or detail one: rationale, references, cost of fixing. |
| `rempart capture [--raw]` | Record a replayable snapshot, anonymized by default. |
| `rempart synthesise --from <capture> --out <file>` | Turn a real capture into a versioned test fixture — `--profile hardened\|defaults`, `--domain-joined`, `--not-elevated`, and `--compromised` to plant fabricated signs of intrusion. |
| `rempart seal --dir … ` | Seal the USB stick, or `--check` that it is still what it was. |
| `rempart version` | Print the version the binary was built as. |
| `rempart update …` | Verify and apply a signed data update (see below). |

Five `diagnose-*` commands (`diagnose-wmi`, `-tasks`, `-drivers`, `-processes`,
`-store`) exist for CI, not for users. Each checks that one system interface still
answers **from the published binary**, where COM interop behaves differently than
under the JIT. Four run on every build; `diagnose-store` needs elevation and is run
by hand.

The HTML report is a single self-contained file — inline styles and script, no
external references, light and dark theme. The JSON is the complete artifact; the
other two formats summarize it.

`scan` has four opt-in flags: `--virustotal-key` (hash lookups), `--probe-dns`
(DoH/DoT latency test), `--fetch-pac` (retrieves the PAC script — analyzed
statically, never executed), and `--analyze-store` (measures reclaimable space in
the component store). The first three reach the network; the last is local but slow,
needs elevation, and deletes nothing.

## Exit codes

When a scan runs from a scheduler or a script, the exit code is all the caller sees.
The mapping is a pure function of the result (`src/Rempart.Core/Cli/ExitCodes.cs`),
and `rempart help` prints the same six lines because it derives them from that source.

| Code | Meaning |
|---|---|
| `0` | Complete audit — everything requested was checked |
| `1` | The run failed: a collector broke, or a file could not be written |
| `2` | A replayed snapshot lacks data the rules need |
| `3` | A **surface** was denied — re-run elevated |
| `4` | `diff` found a control that used to pass and no longer does |
| `5` | The scan finished, but some **rules** have no answer — the score covers less of the machine than it appears to |

**Non-zero is the normal outcome, not the edge case.** All four versioned fixtures
exit non-zero. `compromised-win11` exits `5`: `WIN-ENC-001` (BitLocker) is
unverifiable even from an elevated console when the machine has no volume-encryption
WMI class. The three others exit `3` — `restricted-access` was captured without
elevation, and all three predate the collection of drivers, processes and listening
ports, so their replay reports three surfaces it never looked at rather than passing
for a full audit. Treat anything but `0` as failure and you will alert on healthy
machines; treat `3` or `5` as success and you will hide that part of the audit never
ran. CI accepts `0`, `3` and `5` from a scan, and nothing else.

## What it is not

Rempart audits. It does not fix, clean, or protect. It is not an antivirus, not a
network scanner (it audits the machine it runs on), and not a "PC optimizer".
Remediation is planned as a later milestone, strictly after the audit has proven
itself. Today the only thing the tool ever writes is its own data store, on
`update --apply`.

## Updating the data

Rules and the vulnerable-driver list age — the driver list changes weekly. The
binary embeds a complete baseline; a signed update corrects or extends it, and never
removes anything from it
([ADR-002](docs/adr/ADR-002-mise-a-jour-des-donnees.md), French).

Trust comes from the signature, never from the transport. A dataset — downloaded,
carried on a USB stick, served from a public repository — is accepted if and only if
it is signed by a key pinned in the binary. `update --url` and `update --from` run
the exact same verification, and every later `scan` re-verifies the store before
using it.

| Command | Where | What it does |
|---|---|---|
| `rempart keygen` | offline, once | Generate the publisher key pair (private key encrypted). |
| `rempart fetch-loldrivers` | online | Download the official LOLDrivers list, ready to sign. |
| `rempart fetch-bloatware` | online | Download the upstream bloatware list and join it with the local judgement file, ready to sign. |
| `rempart sign --key … --data …` | offline | Sign a dataset (rules, drivers or bloatware). |
| `rempart update --from <manifest> \| --url <base>` | on the audited machine | Verify, preview, and `--apply`. |

## Status

**v1.0.0 — the read-only audit is complete**: 827 tests, three report formats, a
signed integrity seal for the stick, and fleet comparison. It is a stable release
rather than a candidate because the sealed archive has been run on a machine other
than the one that built it — this project's own release condition.

Remediation — writing to the machine — is a later milestone and has not started.
[ROADMAP.md](docs/ROADMAP.md) (French) records what was deferred and why. One
deferral worth knowing about: **TLS and IPv6 hardening rules are not shipped**,
because their effective defaults vary by Windows build, and a guessed default would
raise findings on machines that are configured correctly.

## Output language

Rule texts — titles, rationales, remediation notes; everything `scan` and `explain`
print — are currently written in French. Translating them is on the roadmap. Code,
code comments and the technical documentation are in English; dated internal records
(ADRs, design specs, roadmap) stay in French.

## Developing

```bash
dotnet test                                   # 827 tests (78 require Windows), ~12 s
dotnet run --project src/Rempart.Cli -- scan  # scan the local machine
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project invariants, how to add a
rule, the test layout, and the known build pitfalls.

## Documentation map

| | |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Invariants, adding a rule or a command, tests, workflow |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, and what counts as one here |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | How disagreement is expected to go |
| [CHANGELOG.md](CHANGELOG.md) | What changed between releases |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagrams, rule format, exit codes, test strategy |
| [BUILD.md](docs/BUILD.md) | Prerequisites, AOT publish, build pitfalls |
| [ROADMAP.md](docs/ROADMAP.md) (French) | Milestones, including what was deferred and why |
| [DEBT.md](docs/DEBT.md) (French) | Technical debt register |
| [ADRs](docs/adr/) (French) | Decision records: stack, update channel, firewall via registry, … |
| [docs/design/](docs/design/) (French) | Design specs and implementation plans, per milestone |
| [rules/security/](rules/security/) | The 82 checks, as YAML |

## License

[MIT](LICENSE). Provided without warranty: the tool inspects — and will eventually
modify — system configuration. Whoever runs it is responsible for how it is used.
