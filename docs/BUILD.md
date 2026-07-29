# Building Rempart

## Prerequisites

| | |
|---|---|
| .NET SDK 10.0.302 → 10.0.x (a .NET 11 SDK is refused) | `winget install Microsoft.DotNet.SDK.10` |
| C++ Build Tools | Required **only** for the Native AOT publish (see below) |

`global.json` pins the SDK to **10.0.302** with `rollForward: latestFeature`:
anything from that version up to the end of 10.0 is accepted, a .NET 11 SDK is not.
An older 10.0 SDK stops every command with `A compatible .NET SDK was not found`,
naming the version it wanted. The file itself explains why the range is neither
tighter nor looser.

Package versions live in `Directory.Packages.props`, not in the `.csproj` files: a
`PackageReference` here carries no `Version` attribute, and adding one is an error
(`NU1008`).

Adding a package is therefore two edits: `<PackageVersion Include="X" Version="…" />`
in `Directory.Packages.props`, and a bare `<PackageReference Include="X" />` in the
project. Anything that is not a version — `PrivateAssets`, `IncludeAssets` — stays
on the `PackageReference`: central management moves the version and nothing else,
and metadata written in the central file is silently ignored.

Two test suites, two regimes:

| Project | Scope | Runs on |
|---|---|---|
| `Rempart.Tests.Unit` | `Rempart.Core` alone, snapshot replay | Anywhere, no Windows needed |
| `Rempart.Tests.Windows` | Real registry, system APIs, end-to-end scan | Windows only |

```bash
dotnet test                              # both
dotnet test tests/Rempart.Tests.Unit     # the portable part
```

## Publishing the binary

```bash
dotnet publish src/Rempart.Cli -c Release
# → src/Rempart.Cli/bin/Release/net10.0-windows/win-x64/publish/rempart.exe
```

Native AOT needs the MSVC linker, which ships with the "Desktop development with
C++" workload:

```powershell
winget install Microsoft.VisualStudio.BuildTools --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" --accept-package-agreements --accept-source-agreements
```

Run this from a **normal** PowerShell, not an elevated one: winget triggers its own
elevation, and the elevated context uses a separate source cache that often fails
with `0x8a15000f: Data required by the source is missing`.

### `vswhere.exe` must be on the PATH

The AOT compiler targets invoke `vswhere.exe` without an absolute path, and the
Visual Studio installer does not add it to `PATH`. The result is a late failure —
after several minutes of compilation — with `MSB3073 ... code 123`, even though
`link.exe` was found.

```powershell
$env:PATH += ";${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
```

Or permanently, through the user environment variables.

## Smart App Control

On a machine where Smart App Control is active, freshly compiled assemblies can be
**refused at load time**:

```
System.IO.FileLoadException: An application control policy has blocked this
file. (0x800711C7)
```

The refusal is logged in `Microsoft-Windows-CodeIntegrity/Operational`, event 3077:
*did not meet the Enterprise signing level requirements*.

Checking the protection state:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
    -Name VerifiedAndReputablePolicyState   # 0 off · 1 on · 2 evaluation
```

**This behavior is not predictable locally.** Smart App Control submits each file
hash to Microsoft's reputation service; some files pass, others do not, and neither
recompiling nor waiting is a reliable workaround.

### Disabling it: the trade-off

An earlier version of this document claimed Smart App Control could only be
re-enabled by reinstalling Windows. That is wrong: per the
[Microsoft FAQ](https://support.microsoft.com/en-us/windows/smart-app-control-frequently-asked-questions-285ea03d-fa88-4d56-882e-6698afdb7003),
recent updates allow re-enabling it without a clean install.

Observed on a development machine: disabling takes effect **without a reboot**, and
`VerifiedAndReputablePolicyState` drops to `0` while `SAC_PreviousState` is kept —
Windows records the previous state.

The trade-off is real, but not irreversible:

- **keep it on** — freshly compiled binaries will be blocked unpredictably; CI
  validates in your place;
- **turn it off** — the development machine becomes less protected than the
  machines this tool prepares;
- **sign the code** — the only fix that satisfies both. An EV certificate has
  immediate reputation. Left open in ADR-001, to be settled when the tool is
  distributed.

Practical consequences:

- **CI is the reference** on a machine protected by Smart App Control. Its runners
  do not apply that policy, and they run the four diagnostics — `rempart
  diagnose-wmi`, `diagnose-tasks`, `diagnose-drivers` and `diagnose-processes` —
  against the published binary, because a COM interop bug does not show under the
  JIT. `scripts/verify.ps1` replays the same four, from the same list, and a test
  holds that list against the workflow.
- `verify.ps1` reads the code-integrity log and distinguishes this refusal from a
  test failure — the xUnit message, on its own, looks like a regression.

## Replaying CI locally

```powershell
./scripts/verify.ps1              # everything
./scripts/verify.ps1 -SkipPublish # skip the AOT step, for a fast loop
./scripts/verify.ps1 -Coverage    # add the two coverage summaries CI publishes
```

The script validates workflow syntax, runs both test suites, publishes with AOT,
then copies the binary into a temporary directory and exercises it **alone**:
`version`, a real `scan`, `capture`, a replay of that capture, and the four
`diagnose-*` commands the `publish-aot` job runs. It applies the `vswhere.exe`
`PATH` fix by itself.

`-Coverage` collects line coverage for `Rempart.Core` and `Rempart.Windows` and
prints the same two summaries CI prints, through the same
`scripts/coverage-summary.ps1` — a second summariser would drift from the first
(see `DET-SCRIPTS` in [DEBT.md](DEBT.md)). It is off by default: instrumentation
slows the very loop this script exists to shorten, and the local figure is not
comparable to the CI one anyway, since a workstation also replays the captures in
`tests/fixtures/local/`, which is gitignored.

`act` would replay the workflows more faithfully, in containers, but requires
Docker — heavy on a machine one is trying to keep clean. This script runs the same
commands directly, which covers most of the risk.

Workflow syntax validation uses
[`actionlint`](https://github.com/rhysd/actionlint), which is optional — the script
says so and continues without it:

```powershell
winget install rhysd.actionlint
```

It is worth installing: an invalid workflow fails at startup, **with no job and no
log to consult**. One caveat: CI pins actionlint to **1.7.12 by image digest**
(`.github/workflows/ci.yml`), and Dependabot does not refresh that pin — its
Actions parser skips anything starting with `docker://`. `winget` installs the
current release, so a local run and the job can disagree on a new rule. The job is
the reference.

## Verifying the deliverable

The binary must work **alone**, outside its build directory — that is the promise
the USB stick relies on:

```powershell
Copy-Item ...\publish\rempart.exe $env:TEMP\test\
cd $env:TEMP\test
.\rempart.exe scan
.\rempart.exe capture --out t.json
.\rempart.exe scan --from t.json
```

`scan` returns `0`, `3` or `5` here, and all three mean the binary ran end to end:
`3` says a collector was denied for want of rights, `5` says every collector read
fine and some rules still came back unverifiable. `WIN-ENC-001` (BitLocker) does
that even from an elevated console when the WMI class is absent, so `5` is the
ordinary case, not the edge one. CI and `scripts/verify.ps1` accept exactly that
set. Anything else is a failure.

Expected size: about 11.4 MB. It grows with the audited surfaces and the embedded
data — 11.1 MB before the bloatware catalogue went from 5 entries to 123, 10.9 MB
at M7, 9.4 MB before the reports of M6, 2.6 MB at milestone M0. The `.pdb` files in
the `publish` directory are debug symbols and are not needed at run time.

## Cutting a release

`release.yml` runs on a tag and stops at a **draft**: the publisher key is
deliberately not available to the build, so the seal is added by hand before
publishing. Three preconditions — forgetting any of them fails the job rather than
producing a wrong archive:

1. The whole of `ci.yml` passes. `release.yml` calls it and waits on it, so a tag
   pushed onto a commit that does not build, or whose tests fail, produces nothing.
   Starting the run from the Actions page works the same way, and the tag typed
   there must be the ref the run starts on: the checks run on the commit that
   triggered the run, and that is the commit the job publishes.
2. `<Version>` in `Directory.Build.props` matches the tag.
3. `CHANGELOG.md` carries a `## <version>` section — the workflow reads it for the
   release notes.

The artifact CI attaches is named `rempart-<version>-win-x64-unsealed.zip`. Sealing
it is what turns it into a release: `rempart seal --dir <folder> --key <private
key>`, from the offline machine that holds the key (ADR-002, D16).
