# Contributing

## Getting started

```bash
dotnet test                                   # the whole suite, a few seconds
dotnet run --project src/Rempart.Cli -- scan  # scan the local machine
```

Most of the suite needs no Windows machine; `Rempart.Tests.Windows` does, and CI runs
the two as separate jobs. **No test count here, deliberately.** The line used to carry
one, and it had drifted by several hundred without anything noticing — which is what a
documented figure does when nothing measures it.

Holding it was the other option, and the repository has the precedent: the line
count of `Program.cs` is written into the documentation, and a test reddens on any
passage that miscounts it. That figure is read from a file in the checkout, it is the
same on every machine, and it is a budget — a number a decision chose, so changing it
means something. A test count is none of the three. It cannot be read from a checkout,
only by running the suite; it would move on nearly every pull request, in the
direction the project wants; and a workstation does not print the same number as CI
anyway, because real captures in `tests/fixtures/local/` add three tests each and that
folder is gitignored, so the difference never shows in a diff. A guard for it would
either hold a number nobody can reproduce or redden every time someone writes a test.

The figures that *are* written down here — the size of the rule catalog, below — are
the ones a test can measure, and `ShippedRulesTests` measures them against the catalog
on every run.

Prerequisites: **.NET SDK 10.0.302 or later** — `winget install
Microsoft.DotNet.SDK.10`. `global.json` pins that floor with
`rollForward: latestFeature`, so anything from 10.0.302 up to the end of 10.0 works
and a .NET 11 SDK does not. An older 10.0 SDK — including 10.0.100, the GA build —
stops every `dotnet` command with `A compatible .NET SDK was not found`, naming the
version it wanted; [BUILD.md](docs/BUILD.md) explains the range. The C++ Build Tools
are only needed for the Native AOT publish step.

## Language policy

- **English**: code, code comments, commit messages, README, CONTRIBUTING,
  ARCHITECTURE, BUILD.
- **French**: ADRs, design specs, ROADMAP, DEBT — dated internal records are not
  rewritten.
- **French, for now**: rule texts in `rules/security/` (titles, rationales), which
  are what `scan` and `explain` print. Their translation is tracked in the roadmap.

## Project invariants

Each of these exists because breaking it caused a real bug. They are enforced by
tests where possible.

- **No collector calls Windows directly.** Everything goes through the providers
  (`IRegistryProvider`, `IServiceStateProvider`, `IWmiProvider`, …). This is what
  makes a scan replayable offline, and therefore testable without a Windows VM.
- **`Unknown` is never `Fail`.** A check that could not be read is excluded from
  the score, and a fully unreadable domain scores `n/d` — *non déterminé*, the
  report language is French — never zero. "Could not verify" and "verified bad"
  call for different actions, and the exit code says so too: `5` for the first,
  not `1`.
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

- **`windowsDefault` — mandatory wherever an absent key would decide the verdict.**
  The loader demands it for every comparison operator (`equals`, `notEquals`,
  `atLeast`, `atMost`) on a registry check, and refuses the file without it. It does
  **not** demand it of a `service`, `policy` or `wmi` check, whose state is directly
  observable — there is no "value Windows applies when the key is absent". 19
  of the 82 shipped rules legitimately carry none. Where it does apply, this field
  decides correctness: on the Windows registry an absent key is the common case, and
  behavior then follows a documented default which is often the desired state. An
  early version treated every absence as a failure and reported three false
  `CRITICAL` findings on a healthy machine.
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
real machines go to `tests/fixtures/local/`, which is excluded from the repository:
the repo is public, and a real capture maps the weaknesses of an identifiable
machine. Local captures are replayed when present — real machines carry the cases
nobody would think to fabricate.

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

On a machine where Smart App Control is active, CI is the reference: its runners do
not apply that policy, and they run `rempart diagnose-wmi` and `rempart
diagnose-tasks` against the published binary — COM interop behaves differently
under AOT than under the JIT, and that step is where such bugs show up.

## Workflow

`main` is protected: pull request required, all five checks green, linear history,
and the rule applies to administrators — otherwise it would enforce nothing.

```bash
git checkout -b feat/…
./scripts/verify.ps1        # workflow syntax, tests, AOT publish, isolated binary
gh pr create
gh pr merge --squash --delete-branch
```

`verify.ps1` replays locally what CI runs; `-SkipPublish` skips the AOT step for a
faster loop. `-Coverage` collects line coverage for `Rempart.Core` and prints the
same summary CI prints — off by default, because a workstation replays captures CI
does not have, so the two figures are not comparable.

The roadmap also records what was tried and discarded, with reasons — check
[ROADMAP.md](docs/ROADMAP.md) (French) before reimplementing something that looks
missing.
