# Building Rempart

## Prerequisites

| | |
|---|---|
| .NET SDK 10 | `winget install Microsoft.DotNet.SDK.10` |
| C++ Build Tools | Required **only** for the Native AOT publish (see below) |

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

The AOT compiler targets invoke `vswhere.exe` without an absolute path. The Visual
Studio installer does not add it to `PATH`, which produces a late failure — after
several minutes of compilation — with `MSB3073 ... code 123`, even though `link.exe`
was found.

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

An earlier version of this document claimed it could only be re-enabled by
reinstalling Windows. That is wrong: per the
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
  immediate reputation. Left open in ADR-001.

Practical consequences:

- **CI is the reference** on a machine protected by Smart App Control. Its runners
  do not apply that policy, and they run `rempart diagnose-wmi` and
  `rempart diagnose-tasks` against the published binary: a COM interop bug does not
  show under the JIT.
- `verify.ps1` reads the code-integrity log and distinguishes this refusal from a
  test failure — the xUnit message, on its own, looks like a regression.
- Code signing is the only durable fix. Left open in ADR-001, to be settled when
  the tool is distributed.

## Replaying CI locally

```powershell
./scripts/verify.ps1              # everything
./scripts/verify.ps1 -SkipPublish # skip the AOT step, for a fast loop
```

The script validates workflow syntax, runs the tests, publishes with AOT, and checks
that the binary works **alone** in a temporary directory. It applies the `vswhere.exe`
`PATH` fix by itself.

`act` would replay the workflows more faithfully, in containers, but requires
Docker — heavy on a machine one is trying to keep clean. This script runs the same
commands directly, which covers most of the risk.

Workflow syntax validation uses [`actionlint`](https://github.com/rhysd/actionlint),
which is optional — the script says so and continues without it:

```powershell
winget install rhysd.actionlint
```

It is worth installing: an invalid workflow fails at startup, **with no job and no
log to consult**.

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

Expected size: about 9.4 MB (it grows with the audited surfaces; 2.6 MB at
milestone M0). The `.pdb` files in the `publish` directory are debug symbols and are
not needed at run time.
