# Contributing

## Getting started

```bash
dotnet test                                   # 564 tests (56 require Windows), ~10 s
dotnet run --project src/Rempart.Cli -- scan  # scan the local machine
```

Prerequisites: [.NET SDK 10](docs/BUILD.md). The C++ Build Tools are only needed
for the Native AOT publish step.

## Language policy

- **English**: code, code comments, commit messages, README, CONTRIBUTING,
  ARCHITECTURE, BUILD.
- **French**: ADRs, design specs, ROADMAP, DEBT — dated internal records are not
  rewritten.
- **French, for now**: rule texts in `rules/security/` (titles, rationales), which
  are what `scan` and `explain` print. Their translation is tracked in the roadmap.

## Project invariants

These rules are enforced by tests where possible. Each one exists because its
violation caused a real bug.

- **No collector calls Windows directly.** Everything goes through the providers
  (`IRegistryProvider`, `IServiceStateProvider`, `IWmiProvider`, …). This is what
  makes a scan replayable offline, and therefore testable without a Windows VM.
- **`Unknown` is never `Fail`.** A check that could not be read is excluded from
  the score, and a fully unreadable domain scores `n/a`, not zero. "Could not
  verify" and "verified bad" call for different actions.
- **Never translate a failure into "access denied".** A catch-all handler once
  converted a WMI interop bug into what looked like missing privileges; WMI was
  silently broken in the published binary for two milestones. Failures must
  surface as failures.
- **`CheckSpec` is translated into reads in exactly one place** —
  [`CheckReader`](src/Rempart.Core/Rules/CheckReader.cs). Evaluation and capture
  both go through it, and a test locks the invariant. Without it, a new check
  type forgotten on the capture side would produce silently incomplete snapshots.
- **Never ship a rule that was not verified on a real machine.** A guessed
  registry value or WMI property name returns `Unknown` forever, and nothing
  distinguishes that from missing privileges. Two rules were removed for this
  reason; the explanation is recorded in the rule file, where each rule used to be.

## Adding a check

Edit a YAML file in [`rules/security/`](rules/security/), then:

```powershell
./scripts/regenerate-fixtures.ps1   # if the rule reads keys absent from fixtures
dotnet test                         # fails once while it rewrites the golden
                                    #   references — review the diff, then commit
```

To iterate without recompiling:

```powershell
rempart scan --rules ./my-rules
```

The full format is described in [ARCHITECTURE.md](docs/ARCHITECTURE.md). Three
fields need particular care:

- **`windowsDefault` (mandatory).** On the Windows registry, an absent key is the
  common case: behavior then follows a documented default, which is often the
  desired state. An early version treated every absent key as a failure and
  reported three false `CRITICAL` findings on a healthy machine. This field is
  what decides correctness.
- **`appliesWhen`.** Several checks only make sense in context — domain-joined
  machine, RDP enabled. Everywhere else they are noise, and noise gets an audit
  tool ignored.
- **`breaks` / `affects` / `verifyBefore`.** The three questions to answer before
  applying a hardening change: what stops working, who is affected, how to check
  in advance. "Nothing" is an acceptable answer, but it must be written down.

## Tests

| Project | Scope | Runs on |
|---|---|---|
| `Rempart.Tests.Unit` | Engine, rules, fixture replay | Anywhere, no Windows needed |
| `Rempart.Tests.Windows` | Real registry, services, WMI, full scan | Windows only |

Fixtures in `tests/fixtures/synthetic/` are versioned and fabricated. Captures of
real machines go to `tests/fixtures/local/`, which is excluded from the
repository: the repo is public, and a real capture maps the weaknesses of an
identifiable machine. Local captures are replayed when present — real machines
carry the cases nobody would think to fabricate.

Some tests worth knowing about before touching the engine:

- *No rule fails on a hardened machine* — catches unsatisfiable rules.
- *Evaluation never reads a key that capture does not record.*
- *No rule targets a protected component* — Edge, Store, Windows Update.
- *Versioned fixtures are anonymized.*

## Build pitfalls

All of these were hit during development; details are in
[BUILD.md](docs/BUILD.md).

| Symptom | Cause |
|---|---|
| `MSB3073 ... code 123` after several minutes of AOT publish | `vswhere.exe` missing from `PATH` — the message blames `link.exe` |
| `winget` fails with `0x8a15000f` | Elevated terminal: separate source cache. Run from a normal PowerShell |
| "An application control policy has blocked this file" (`0x800711C7`) | Smart App Control blocking freshly compiled assemblies — see [BUILD.md](docs/BUILD.md#smart-app-control) |
| A test fails on a fixture after adding a rule | Run `./scripts/regenerate-fixtures.ps1` |
| `verify.ps1` stops without a diagnostic | PowerShell 5.1: native stderr becomes terminating under `$ErrorActionPreference = 'Stop'` |
| Code compiles but fails at AOT publish | The `IsAotCompatible` guard catches most cases at build time — what remains is COM interop |

On a machine where Smart App Control is active, CI is the reference: its runners
do not apply that policy, and they run `rempart diagnose-wmi` and
`rempart diagnose-tasks` against the published binary — COM interop behaves
differently under AOT than under the JIT, and that step is where such bugs are
observable.

## Workflow

`main` is protected: pull request required, all five checks green, linear
history, and the rule applies to administrators — otherwise it would enforce
nothing.

```bash
git checkout -b feat/…
./scripts/verify.ps1        # workflow syntax, tests, AOT publish, isolated binary
gh pr create
gh pr merge --squash --delete-branch
```

`verify.ps1` replays locally what CI runs; `-SkipPublish` skips the AOT step for
a faster loop.

The roadmap also records what was tried and discarded, with reasons — check
[ROADMAP.md](docs/ROADMAP.md) (French) before reimplementing something that
looks missing.
