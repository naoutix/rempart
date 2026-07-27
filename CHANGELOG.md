# Changelog

Versions before 1.0.0-rc.1 were built from source only; this is the first packaged
release. The milestone-by-milestone account of how the tool got here, including what was
tried and rejected, lives in [docs/ROADMAP.md](docs/ROADMAP.md) — this file records what
changed between releases.

## Unreleased

### Structure

- **`Program.cs` is 29 lines.** It was 1 881 at its worst, growing by half a milestone at a
  time. The dispatch is now an explicit table, each of the 17 commands is its own class,
  and the helpers that touch the host sit in `CliHost`. Nothing changed in what the tool
  does: every command's output and exit code was captured before and after and compared —
  63 invocations, byte for byte identical, including the error paths.
- **Ten guards watch the table**, all verified by mutation rather than merely green. Two of
  them exist only because review showed the first version compared the dispatch table to
  another hand-written list instead of to the command classes that actually exist —
  the same list, written twice, cannot check itself.

### Tests and tooling

- **The CLI layer has tests.** It had none: 1 872 lines that every command passes through,
  watched only by CI asserting an exit code. The two pure surfaces now live in
  `Rempart.Core/Cli/` and are covered on the Linux job — the exit-code contract (5 codes)
  and the argument parser (6 primitives), 44 tests between them. No command was moved.
- **`rempart index` renders through `ConsoleReport.Fleet`**, like `scan` and `diff` before
  it, with a golden test. Output verified identical byte for byte before and after.
- **Three golden references for `rempart diff`**, covering a regression, a correction, a
  control that went blind, one that came back, a scope change, findings that disappeared
  and were retargeted — and a capture compared with itself, which freezes what the tool
  says when nothing moved.
- **`rempart help` lists all five exit codes.** It stopped at 3 and never mentioned 4
  (regression), from the day that code was introduced; the help now derives its own text
  from the contract, so it cannot drift again.
- **Code coverage is measured** on the Linux job and summarised in the run — Rempart.Core
  only, deliberately without a threshold. Six reasons in `docs/DEBT.md` (DET-COUVERTURE).
  The summary states which figure it is: a workstation holding real captures in
  `tests/fixtures/local/` measures a different one, and the two are not comparable.

Three real defects were **frozen by tests rather than fixed here**, each recorded in
`docs/DEBT.md`: a scan exits 0 when controls could not be verified (DET-SORTIE-PARTIELLE),
`rempart diff --report --baseline b.json a.json` writes into a folder named `--baseline`
(DET-ARITE-REPORT), and `rempart explain --rules <dir> <ID>` lists everything instead of
explaining the rule (DET-EXPLAIN-POSITIONNEL). Each changes what an existing command line
does, so each gets its own change.

## 1.0.0-rc.1 — 2026-07-26

First packaged release of the read-only audit, and a release **candidate** on purpose:
the code is complete and tested, but the stick has not yet run on a machine other than
the one it was built on. That was the exit criterion this project set for M6, so calling
this 1.0.0 would claim something not yet observed.

### The audit

- **Posture** — 82 rules across 8 domains, mapped to CIS and Essential Eight: Defender,
  the 17 workstation-applicable ASR rules, firewall across its three profiles, logging,
  network hardening, privacy, encryption, legacy protocols. Every rule declares the
  Windows default it compares against, because on the registry an absent key is the
  common case and the effective behaviour depends on a documented default — treating
  absence as failure raised three false CRITICALs on a healthy machine.
- **Persistence** — autoruns, permanent WMI subscriptions, Startup folders, scheduled
  tasks, loaded drivers checked against LOLDrivers, running processes, Winlogon and
  AppInit, LSA packages, COM hijacking, unquoted service paths. Each enumerated item
  carries its own verdict rather than folding into a score: a configuration at 94 % must
  not hide an unsigned binary launched at boot.
- **Network** — listening ports with their bind address, owning binary and signature,
  crossed with the firewall rule that actually admits them; DNS resolvers and the hosts
  file; proxy and PAC; saved Wi-Fi profiles judged on their security.
- **Software** — inventory from four authoritative sources, browser extensions with their
  effective permissions, and a signed bloatware catalogue.

### Reporting and fleet

- `rempart scan --report` writes a self-contained HTML report (single file, light and dark
  theme, no external resource), Markdown for a ticket, and JSON as the complete data.
- `rempart report --from` re-renders from the JSON without rescanning, and without
  needing Windows.
- `rempart diff` compares two scans; `rempart index` builds a fleet page ordered by what
  is left to do. Transient facts — consumed `RunOnce` entries, self-deleting tasks,
  ephemeral high ports — are marked at the source so a second scan does not report
  movement as change.
- `rempart seal` produces an integrity manifest signed by the publisher key. An added
  file is reported as loudly as a modified one: dropping a DLL beside the executable is
  the vector, not editing a listed file.

### Deliberately opt-in

Three features touch the network and none is ever a default: VirusTotal enrichment
(`--virustotal-key`), active DoH/DoT probing (`--probe-dns`), and fetching the PAC script
(`--fetch-pac`). A replay never performs them.

### Known limitations at this release

- **TLS/SCHANNEL and IPv6 rules are not shipped.** Their effective defaults vary by
  Windows build, and a guessed default would produce false findings. IPv6 also has code
  left: listening ports are collected over `AF_INET` only. **Fixed after this release** —
  IPv6 listeners are collected as of 2026-07-26; only the hardening rules remain deferred.
- **Two exit criteria are unmet**, both needing a machine rather than code: the bloatware
  catalogue validated on a real OEM machine, and the stick run on a third-party machine
  without installing anything.
- The full register of known debt, with impact and effort, is in
  [docs/DEBT.md](docs/DEBT.md).

### Verifying what you downloaded

The published archive carries `rempart-integrity.json`, signed by the publisher key. Check it
from a copy you already trust rather than from the stick under test — a binary that
verifies itself proves little:

```text
rempart seal --dir <dossier> --check
```
