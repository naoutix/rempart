# Changelog

Versions before 1.0.0-rc.1 were built from source only; this is the first packaged
release. The milestone-by-milestone account of how the tool got here, including what was
tried and rejected, lives in [docs/ROADMAP.md](docs/ROADMAP.md) — this file records what
changed between releases.

## Unreleased

### Two command lines now do what they read like

The two defects the previous batches froze rather than fixed are closed. Both were held
back for the same reason and released for it too: each changes what an existing command
line does, so neither could ride along with a pass whose whole claim was that it changed
nothing.

- **`rempart diff --report --baseline b.json a.json` no longer files the comparison into a
  folder named `--baseline`** (`DET-ARITE-REPORT`). `--report` was read by `OptionalValue`
  on `scan` and by `OptionValue` on `diff` — one spelling, two readers, and the second
  takes whatever follows it. `diff` now reads it the way `scan` always did, and the
  declared arity follows the reader. Measured on the built binary: the three files moved
  from `--baseline\` to the current folder, `--report ./sortie` still writes to `./sortie`,
  and the comparison itself is byte-for-byte identical — `Positional` was never wrong, and
  `--baseline b.json` was already naming the "before" report. The scope of the defect was
  the output folder, not the choice of files.
- **`rempart explain --rules <dir> WIN-CRED-001` explains the rule instead of listing the
  catalog** (`DET-EXPLAIN-POSITIONNEL`). The identifier was read at index 1, where an
  option had been written, so `explain` found none and did what an argument-less `explain`
  legitimately does: list everything. Nothing failed, which is why it lasted. It goes
  through `Positional` now — 110 lines of catalog became the 28 lines of the rule asked
  for. `WordAt` is unchanged and still reads the command word at index 0, the one fixed
  index that is a fact rather than an assumption: nothing can precede it.
- **The guards now watch the cause, not the symptom** — and it took two attempts to find
  the cause. Nothing related a declared arity to the reader a command actually calls, so a
  guard was added comparing the two per command. Review then showed that guard goes green
  on the very defect it was written for: reverting `DiffCommand` *and* the surface together
  restores `--report` swallowing `--baseline`, both files internally consistent, whole suite
  passing. The defect was never a command disagreeing with its own declaration — it was two
  commands disagreeing with **each other** about the same word. A third guard now holds one
  spelling to one arity everywhere, and reverting the pair reddens it.
- A reader typing `--report` should not have to remember which command they are in to know
  whether the next token gets swallowed.

### An unreadable file is no longer accused, and zero exposed ports is no longer good news

The two silences the previous batch found and deliberately froze are now closed. They are
the same defect on opposite sides: one hid a breakdown, the other invented an accusation.

- **A signature that could not be verified comes back "non vérifiable", never "non signé"**
  (`DET-CATALOGUE-MUET`). The catalog lookup answered `int?` and its `null` meant two
  different things — "no catalog references this file", which is an answer, and "the store
  could not be asked", which is not: a context `wintrust` refused, a hash that would not
  compute, a file another process held open. Both became `Unsigned`, and the ladder turns
  `Unsigned` into a **`Suspicious`** finding. A driver locked by the process holding it was
  therefore blamed for it, on precisely the machines that are hardest to audit, and under a
  header comment promising the opposite. A named `CatalogOutcome` separates the four cases
  and the two that mean "nobody answered" map to `Unknown`, which the ladder reports as a
  stated gap. **Measured on this machine: 303 signatures, 0 verdicts moved** — a file that
  opens fine goes down exactly the same path as before, so the change bites only where a
  read actually fails.
- **Listening ports gained a status channel** (`DET-PORTS-MUET`, fourth occurrence of
  `DET-WMI-MUET`). `Enumerate` returned a bare list, so a failed read looked like a machine
  exposing no service — and no machine that is switched on listens on zero ports: the RPC
  endpoint mapper, SMB, the local resolver. The report nonetheless concluded "aucun port en
  écoute", which reads as good news on the one surface that says what the network can
  reach. The status is **beside** the list and never in its place: turning the
  `listeningPorts` array into an object would have made every existing capture unreadable,
  including the real ones kept outside the repository. A capture written before this change
  replays as the success it was — verified on one, 54 endpoints, no finding invented.
- **Four tables, four ways to fail.** IPv4 and IPv6, TCP and UDP are separate calls, so the
  read also reports itself *partial*: the endpoints that were read stay in the report and
  the silent table is named beside them. Dropping the IPv4 ports because the IPv6 table
  refused would only have moved the silence one protocol over. A new Windows test refuses to
  skip and pins the whole read as complete — asking one table with a wrong address family
  leaves three of the four old tests green and reddens only that one.

### The anonymiser washes what identifies a machine, not just who owns it

- **Hardware identity is now scrubbed** — manufacturer, model, family, mainboard, BIOS
  version and release date. A board model plus a firmware version plus its build date
  narrows a machine down about as far as a serial number does, and nothing reads them
  back: no shipped rule touches that key, the inventory only prints what it finds. The
  scope is the registry **key**, not the value name — `ProductName` under
  `CurrentVersion` is "Windows 11 Pro" and stays readable, because the whole OS-version
  derivation rests on it.
- **Scheduled tasks outside `\Microsoft\` lose their path and name.** A third-party task
  label is an inventory line: it names the product that installed it, sometimes with an
  install GUID or a per-user folder on top. The criterion is the folder and not the
  author, deliberately — a task that *borrows* Microsoft's folder is exactly what an
  intrusion does, and hashing by author would have hidden the impostor while scrubbing its
  innocent neighbours.
- **What stays readable, and why**: the executable a task launches, and the paths of every
  verified signature. They are the object of the audit — the signature ladder judges them
  and the report exists to name the binary that runs — and the collector reads their
  *shape* to tell a resolved path from a bare name, so a digest would invent a "chemin non
  résolu" finding on every third-party task.
- **`Anonymiser.Hash` is idempotent.** "Anonymised" now means "stays anonymised": a value
  already reduced to a digest crosses a second pass unchanged, instead of becoming a
  digest of a digest.
- **`synthesise` runs the anonymiser instead of declaring its output anonymised.** The
  builder used to set the flag and stop there, trusting the source capture for fields the
  anonymiser did not know about — which is how eleven task paths, a mainboard model and a
  BIOS date reached a public repository. The flag is now produced, not asserted.
- `Versioned_fixtures_are_anonymised` checked a boolean and a machine-name prefix, so it
  could see none of this. It now fails on any hardware value or any third-party task label
  left in the clear, and it was verified to fail on the fixtures as they stood before the
  fix.
- **No intrusion marker was damaged**: the four fixtures were regenerated with identical
  verdicts and identical findings — the compromised one still renders exactly seven
  `Suspicious` and three `Notable` — and the four comparison references came back
  character for character identical.

### A scan that could not see everything says so in its exit code

- **New exit code `5` — *audit partiel***, returned by `rempart scan` when one or more
  rules came back `Unknown`. Until now the code answered for the *collectors* only: a
  machine where every collector read fine while controls stayed unverifiable for want of
  elevation exited `0`, and to a scheduler or a fleet script that is indistinguishable
  from a machine that was fully checked. The console and the reports have always said the
  score was partial; the exit code — the one channel of the caller who reads nothing else
  — was the one staying silent.
- **`5` is deliberately not `3`.** `3` says a *collector* was refused; `5` says every
  collector read fine and *rules* still have no answer. Precedence is `1 > 3 > 5 > 0`,
  ordered by what the caller can act on: a breakdown does not repair itself by re-running
  elevated, a refused collector does, and an unevaluable rule is the weakest of the three
  signals without being nothing.
- **Measured on the four versioned fixtures.** `restricted-access` — which scores **100 %
  with four controls it never managed to look at**, the case the debt entry was written
  about — goes from `0` to `5`. `hardened-win11` stays at `0`. `default-win11` and
  `compromised-win11` move to `5`, both on an unreadable `WIN-ENC-001`. No report
  changed: the exit code is not rendered anywhere.
- The three exit-code guards — both CI workflows **and `scripts/verify.ps1`**, the gate
  CONTRIBUTING puts before every pull request — now accept `0`, `3` or `5` from the real
  scan they run. What those steps prove is that the binary runs a scan end to end, not that
  the machine running it is well configured. That tolerance belongs there and nowhere else:
  for an auditor, `5` is a result to act on.
- **`5` is not a symptom of a non-elevated runner, and assuming so is the trap.** Elevation
  is the usual remedy, not the only one: two of the four versioned fixtures were captured
  *elevated* and still exit `5`, because `WIN-ENC-001` (BitLocker) has no volume-encryption
  WMI class to ask. Narrowing the accepted set back to `{0, 3}` after elevating a runner
  would redden a correct build.

### The audit is now tested against a compromised machine

- **A fourth versioned fixture, deliberately dirty** — `synthesise --compromised` plants a
  single coherent intrusion: an unsigned autorun in `%TEMP%`, a fileless WMI subscription,
  a scheduled task launching an unsigned binary, an unsigned loaded driver, a process
  running from `%TEMP%`, a command port the intrusion opened a firewall rule for, a
  hijacked DNS resolver, a sideloaded extension. **Every suspicious item is paired with a
  benign twin the collector must not flag** — signed `svchost.exe` against the one in
  `%TEMP%`, `ntfs.sys` against the planted driver. A fixture where everything is
  suspicious proves the tool alerts, not that it discriminates.
- Until now the only flagged findings in the entire versioned corpus were two *absences*,
  and the autoruns collector — the first place anyone looks — produced nothing at all.
- **What it revealed goes past coverage.** A machine carrying an active implant, a
  reachable command port and a hijacked resolver scores **52 %** — identical, domain by
  domain, to a merely unhardened clean machine. Intended (findings do not enter the score)
  but never demonstrated end to end before.
- **Three judgement defects found and recorded, not silently fixed**: a listening port
  blocked by a firewall rule drops to benign with no reason given, while a *disabled*
  scheduled task keeps its severity — two opposite doctrines for "the mitigation is one
  click away"; the C2 command line never reaches the console rendering; and WMI
  subscriptions are the one persistence collector that checks no signature.

### Windows layer

- **`diagnose-drivers` and `diagnose-processes`**, on the `diagnose-wmi` model, run against
  the published AOT binary in CI. Each checks more than a count: drivers verify a path
  resolves to a file, processes verify the enumeration finds itself. Zero drivers or zero
  processes on a running machine is a breakdown, never an answer.
- **`CatalogSignature`'s judgement moved into Core** (`AuthenticodeVerdict`), so the part
  that decides a binary is sound is now tested **on the Linux job**. Proven neutral on 459
  real System32 files. The remaining interop is held by probed Windows tests, plus one that
  refuses to skip: no catalog covering any System32 binary is a dead subsystem, not a quiet
  machine, and it would turn every catalog-signed binary into "suspicious".
- Two more silences found and frozen: `CatalogSignature` returned the same `null` for "no
  catalog" and "could not ask", so an unreadable file was **accused** (`DET-CATALOGUE-MUET`);
  and listening ports had no status channel (`DET-PORTS-MUET`) — the fourth occurrence of
  DET-WMI-MUET, found by the new reflection guard *before* it did harm. Both are closed in
  this same Unreleased section, above.

### Fixed

- **The `fixtures-anonymised` CI job ran no tests and exited 0.** Its filter named a test
  renamed long ago, so the guard whose whole purpose is keeping a real machine's capture
  out of a public repository had been green while checking nothing. The assertion itself
  always ran inside the main test job, so nothing was exposed — what was lost was the
  dedicated guard. A test now checks that every test name a CI job filters on exists.

### Structure

- **`Program.cs` is 29 lines.** It was 1 881 at its worst, growing by half a milestone at a
  time. The dispatch is now an explicit table, each of the 17 commands is its own class,
  and the helpers that touch the host sit in `CliHost`. Nothing changed in what the tool
  does: every command's output and exit code was captured before and after and compared —
  63 invocations, byte for byte identical, including the error paths.
- **Thirteen guards watch the table**, all verified by mutation rather than merely green. Two of
  them exist only because review showed the first version compared the dispatch table to
  another hand-written list instead of to the command classes that actually exist —
  the same list, written twice, cannot check itself.

### Tests and tooling

- **The CLI layer has tests.** It had none: 1 872 lines that every command passes through,
  watched only by CI asserting an exit code. The two pure surfaces now live in
  `Rempart.Core/Cli/` and are covered on the Linux job — the exit-code contract (6 codes)
  and the argument parser (6 primitives), 55 tests between them. No command was moved.
- **`rempart index` renders through `ConsoleReport.Fleet`**, like `scan` and `diff` before
  it, with a golden test. Output verified identical byte for byte before and after.
- **Three golden references for `rempart diff`**, covering a regression, a correction, a
  control that went blind, one that came back, a scope change, findings that disappeared
  and were retargeted — and a capture compared with itself, which freezes what the tool
  says when nothing moved.
- **`rempart help` lists all six exit codes.** It stopped at 3 and never mentioned 4
  (regression), from the day that code was introduced; the help now derives its own text
  from the contract, so it cannot drift again — code 5 above reached it without anyone
  having to remember.
- **Code coverage is measured** on the Linux job and summarised in the run — Rempart.Core
  only, deliberately without a threshold. Six reasons in `docs/DEBT.md` (DET-COUVERTURE).
  The summary states which figure it is: a workstation holding real captures in
  `tests/fixtures/local/` measures a different one, and the two are not comparable.

Two real defects were **frozen by tests rather than fixed** in this batch, each recorded in
`docs/DEBT.md`: `rempart diff --report --baseline b.json a.json` wrote into a folder named
`--baseline` (DET-ARITE-REPORT), and `rempart explain --rules <dir> <ID>` listed everything
instead of explaining the rule (DET-EXPLAIN-POSITIONNEL). Each changes what an existing
command line does, so each got its own change — as the exit code above did. Both are closed
in this same Unreleased section, at the top: the frozen assertions were inverted rather than
deleted, so the fix is visible in a diff, which was the whole point of freezing them.

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
