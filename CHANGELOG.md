# Changelog

Versions before 1.0.0-rc.1 were built from source only; this is the first packaged
release. The milestone-by-milestone account of how the tool got here, including what was
tried and rejected, lives in [docs/ROADMAP.md](docs/ROADMAP.md) — this file records what
changed between releases.

## 1.2.0 — 2026-08-02

**In short.** `diff` compares two points; this release reads a series.

- **`rempart drift [dir]`** reads a folder of reports as one trajectory per machine: the
  slope of the score, how long a control has been failing, which controls keep falling back
  after being repaired, and when the series stopped being fed. That last one is how a
  scheduled audit that quietly stopped running three months ago becomes visible.
- **`rempart baseline <rapport.json>`** promotes a report to the reference `diff` compares
  against, and refuses a truncated file, a report of another machine, or one produced by
  another catalog instead of installing it. Until now the reference was put in place by a
  copy, and a copy cannot refuse.
- **A scheduled task definition** is shipped in `tools/scheduled-task/`, imported by hand.
  The tool does not create it, and will not: registering a task changes the machine's
  configuration, which is what v1 promises not to do.
- **No new exit code.** A drift run answers `4` when a control that used to pass still
  fails, `5` when the series went stale or the last scan left controls unevaluable.

**Upgrading** is replacing the executable. Nothing in a report changed shape, so the reports
already on a stick are the series this release reads.

## 1.1.0 — 2026-08-01

**In short.** This release is about what the audit can see, and about what it says when it
cannot see.

- **Three DNS surfaces are now read** that were outside the audit entirely: the IPv6 stack, the
  resolver list above the adapters, and the name resolution policy table. All three are places
  a resolver can be redirected without touching the per-adapter settings the tool inspected.
- **A refused read no longer looks like a clean answer.** Where the tool handed back an empty
  list — no autorun, no resolver, no scheduled task — it now says it could not look, and the
  exit code says so too.
- **Fewer wrong instructions.** Surfaces that failed for reasons no privilege repairs stopped
  telling you to re-run as administrator.
- **One breaking change:** a mistyped command word — `rempart scna`, `rempart -scan` — exits
  `6` instead of `0`. A scheduled job that relied on the old behaviour will start reporting
  failure, which is the point: it was reporting success for a run that did something else.

**Upgrading** is replacing the executable. A capture written by 1.0.0 still replays; its exit
code can differ, because a refusal the tool used to swallow now reaches the exit code.

---

The rest of this section is the record: the 33 findings of the
[2026-07-29 review](docs/revues/2026-07-29-revue-complete.md) and the nine rounds that followed
them, in fifty-two pull requests of one issue each. Every round re-read the previous round's
fixes adversarially, and what a review refuted became the next round's finding; eleven of the
last eighteen fixes were refuted that way before merging.

What the review charged the repository with was fixing a class of defect in one place and
leaving the layer next to it, so the entries below are grouped by the mechanism that replaced a
hand-maintained list rather than by file.

### A refused read stops looking like a clean answer

- **The firewall.** An unreadable firewall reported the Windows defaults — enabled, inbound
  blocked — so an unsigned binary listening on `0.0.0.0` came back `Benign` with the claim
  "blocked inbound". It now says it could not read, and no port is called blocked on that basis.
- **Scheduled tasks.** A walk refused in one folder was handed over as complete. It now keeps
  the tasks it read and names the folders it gave up on, and every COM result in the walk is
  recorded by construction rather than by four hand-written branches.
- **Registry enumeration and the `hosts` file.** `ListValues` and `ListSubKeys` returned an
  empty result for a denial exactly as for a missing key, so a deny ACL on a `Run` key printed
  "no autorun" and one on `HKCU\…\CLSID` printed "no COM hijack". Both now carry a status, and
  an unreadable `hosts` file is no longer indistinguishable from an empty one.
- **The exit code hears them.** A refusal seen by a *finding* collector never reached
  `ForScan`: three refused surfaces could exit `0`. Three versioned fixtures now exit `3`
  instead of `0` or `5` — their captures predate the collection of drivers, processes and
  listening ports, and replaying them genuinely hears "denied" on those surfaces.

### A failure stops borrowing the meaning of a denial

- An unrecognised WMI `HRESULT` is reported as a failure naming its code, instead of advising
  an elevation the user already had.
- A manifest with a missing field is refused rather than throwing outside the `try` — fifty
  bytes written into `rempart-data/`, a folder the seal deliberately excludes, could otherwise
  kill every later scan.
- `--fetch-pac` no longer destroys a completed scan over a `file://` or `ftp://` proxy URL,
  which WinINET accepts as a legitimate value.
- WMI enumeration gains the timeout DISM and netsh already had, `NetUserEnum` no longer leaks
  its buffer on `ERROR_MORE_DATA`, and `WinVerifyTrust` revocation returns to the opt-in
  network regime ADR-001 describes.

### What is written by hand is now held against what is on disk

- A finding collector missing from the registration table produced nothing and moved no golden.
  A guard confronts the table with the compiled implementations and with the files on disk.
- A multi-document rule file silently lost everything after the first `---`, and `.yml` files
  were ignored in a mixed folder. Both are read; a rule file that is not read now says so.
- The Markdown report escapes every machine-chosen value, held by a sweep over the whole
  document rather than by an assertion per interpolation site. Rule identifiers, finding
  sources and detail values lose their code spans as a result.
- An autorun whose executable is an interpreter has its command line judged:
  `powershell.exe -enc <base64>` was `Benign`, with no reason, and vanished from every report.
- The debt register's count of unverified impact notes said 113 of 116 where the catalogue
  carried 120 of 123. All four hand-written copies of that count are now held against the
  catalogue itself.

### The neighbours the fixes uncovered

Every fix above was adversarially reviewed, and six defects of the same shape were found in
the layer next door — none of them a line of the review itself.

- **A service read that failed stopped asking for an elevation that cannot help.** Every Win32
  code other than "service does not exist" mapped to a denial, which is the invariant
  CONTRIBUTING records, broken one interface over from where WMI had just been fixed. The
  reason now reaches the JSON report; the three human renderings still title it "accès refusé"
  either way (#159).
- **A WMI enumeration that broke in mid-walk** kept what it had read instead of handing a
  truncated inventory over as complete.
- **A dataset with a null element, and one with a duplicated identifier,** are refused rather
  than throwing out of the loader. A fifty-byte write into `rempart-data/` — a folder the seal
  deliberately excludes — could otherwise end every later scan.
- **An unreadable update store refuses the update** instead of ending the scan, and says so
  rather than reading as "no update available".
- **A failing `--virustotal` lookup no longer costs the report**, including when the key itself
  cannot be installed in a request header.
- **A flag can no longer promise a collector it does not add.** `--analyze-store` could become
  an inert flag, and the collector could be made to run on every scan, without a test noticing.

### What the neighbours' own review then found

A third round, on the six fixes above. Five were refuted by their review — one of them at the
root — and repaired before merging.

- **A failure that elevation cannot repair now has a word of its own.** Every unverifiable
  control was titled "accès refusé" and never printed the reason the provider had already
  written; `AuditGap` had no value for it, and the exit code said `3`, "re-run elevated". There
  is now a third value, the three renderings print the reason where there is one, and the code
  is `5` — which CI already accepted, so no contract moved. Which of the two a gap is, is
  **stated by the collector** and no longer inferred: inferring it from the presence of a
  reason turned a refused startup folder — the ordinary non-elevated case — into "elevation
  will not help".
- **An elevated scan is no longer told to elevate.** Two committed references carried the
  advice on captures whose `isElevated` was already true.
- **A WMI enumeration that times out keeps what it read**, and a provider that fails to load is
  no longer reported as an absence.
- **A security-policy read that established nothing** no longer claims it was denied, and a
  partial read is no longer indistinguishable from a complete one.
- **A scan can no longer lose its driver blocklist and bloatware catalogue in silence**: the
  parameter that carried them was optional, and dropping it at the call site compiled.
- **Five guards that would have stopped guarding** — four compatibility assertions written on
  the presence of a JSON key rather than its value, and two reflection sweeps that only saw
  `const` fields.

### A command line that was not understood stops exiting `0`

Three spellings of one defect, found a round apart each, and all three the same thing to a
scheduler: a success reported for a run that did something other than what was asked.

- `rempart scan --replay capture.json` scanned the local machine. The replay option is
  `--from`; `--replay` does not exist, and nothing read it or complained. Unknown options are
  now refused against what the command declares — `CommandSurface.Unknown` returns the
  complement of the declared set, so an option added tomorrow is refused until it is declared.
- `rempart scna --from t.json` printed the usage text and exited `0`. **This is a contract
  change, and the only one in this release**: a mistyped command word now exits `6`, and the
  message lists the words that exist rather than leaving the speller to guess.
- `rempart -scan --from t.json` did the same and had survived both fixes above — the parser
  returned "no command word" on the leading dash, and the fallback exempted it without looking.
  The spellings that ask for help without naming a command are now declared rather than
  guessed, and a line that names no command and asks for nothing is refused.

### "Attempted and failed" gets a word of its own

The invariant CONTRIBUTING records first — a failure never borrows the meaning of a denial —
had no vocabulary to be kept with. Each entry below is a surface that told the user to re-run
as administrator where no privilege would have helped.

- `ReadStatus` gains `Failed`. A startup folder held open by another process, and a `hosts`
  file that could not be read, stop coming back as "accès refusé".
- The issue listed eight factories named `Failed` carrying the status of a denial; a guard
  written by construction found **twelve**, plus a fallback inheriting from one of them. Only
  one produced a false verdict, and it is the one that mattered: replaying a capture taken
  before scheduled tasks were collected exited `3`, "re-run elevated" — and no console,
  however elevated, re-reads a snapshot.
- The firewall's contract used two words for one member, which the issue recorded as a
  contradiction of prose with nothing measured downstream. That part was wrong: a universal
  key the machine does not have, and a rule container whose values do not parse, both came out
  as denials.
- The guard holding all of this now reads the compiled body instead of three sample arguments.
  Four deliberately faulty factories had been planted in `Rempart.Core` — branching on a count,
  on a path, on a threshold, on an absent diagnostic — and the whole suite stayed green.

### The DNS surface, read from four levels it did not know about

Six rounds on one surface, because each fix's review found the next hole in it.

- **A refused read returned zero resolvers.** `IDnsProvider.Read` and
  `ISoftwareInventoryProvider.Read` returned a bare list, so a deny ACL on
  `Tcpip\Parameters\Interfaces` gave the same empty answer as a machine with no interface
  configured — on the surface a hijack sits on. Both carry a status now, and a refusal on one
  adapter no longer removes that adapter, and its static resolver, from the inventory.
- **The IPv6 stack was not read at all**: `Tcpip6` appeared nowhere in the repository. Both
  stacks are walked from a table keyed on `DnsStack`, and the tests are theories over its
  members, so a stack declared tomorrow is exercised without this file being opened.
- **An unwired read answered `Found([])`** — a successful, empty read, which every rule
  downstream takes for a state of the machine. Six fallbacks answered the wrong side of
  "nobody looked" against "I looked and there was nothing"; the second stays silent wherever
  zero is a plausible answer, and every test pinning that is untouched.
- **A repointed resolver came out as two unrelated lines.** Windows binds both stacks of an
  adapter under one GUID, so a dual-stack card carried two findings under one source and
  `rempart diff` refused to fold them into one "le même emplacement lance autre chose" — on
  the command written to detect drift, for the hijack that collector exists to catch.
- **The level above the adapters** carries the same two value names and was read on neither
  stack. Measured on a real machine: what Windows writes there is a copy of the connected
  adapter's own values, so collecting it would repeat an inventory line. It stays unread, now
  with a reason, and the half that could not be settled says so instead of guessing.
- **The name resolution policy table (NRPT)** points a namespace's queries at servers of its
  own without touching the per-adapter configuration this tool inspects. Both stores are
  enumerated now, and a rule is **signalled rather than judged**: the finding says which names,
  which servers and which store, then says what this audit did not establish. The `NameServer`
  policy value beside it is documented as *not read by the resolver of this build* — measured
  in `dnsrslvr.dll` and `dnsapi.dll`, against a Microsoft help text that claims the opposite.

### Build and release

- The release tag is bound to a step's `env:` and validated before use, instead of being
  interpolated into a PowerShell body on the one job carrying `contents: write` and `GH_TOKEN`.
- A tag must now point at a commit that passed CI, `ci.yml` declares `permissions:`, the key is
  no longer publishable without its licence, and `verify.ps1` stops printing `ok` for a tool it
  never ran.

## 1.0.0 — 2026-07-28

**The exit criterion this project set for itself is met, and that is the only reason this is
not another candidate.** The sealed archive of `1.0.0-rc.2` was run on a machine other than
the one that built it — a different Windows feature update, no toolchain, nothing installed —
and the snapshot it produced replays here in full: 82 rules evaluated, none unreadable, no
collector refused, exit code `0`.

Two candidates preceded this. rc.1 was built and never published. rc.2 was published, and
running it elsewhere is what closed the last criterion.

### The bloatware catalogue went from 5 entries to 123

The catalogue was the other thing standing between this and a stable release, and it was
stuck for a reason that turned out to be a category error: M5 asked a **data** question in the
shape of a test. One OEM machine validates one vendor; a VM from a Microsoft ISO carries no
vendor software at all. [ADR-006](docs/adr/ADR-006-catalogue-bloatware-importe.md) splits it —
the mechanism was already demonstrated, the coverage is data, and data is maintained.

- **116 entries imported** from [Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat)
  (MIT, pinned by commit), **7 written here** for ASUS, Acer, MSI and Razer, which no
  maintained list carries identifiers for.
- **Upstream supplies identifiers, this repository supplies judgement.** Category, risk and the
  impact note are joined at fetch time, and an identifier nobody has judged **fails the
  command by name** rather than shipping without a note or vanishing.
- **26 identifiers are judged and deliberately not catalogued.** The upstream list is what a
  debloat tool offers to remove, which is not what an audit should call bloatware: Windows
  Terminal, the Store, Notepad, the Xbox identity provider. Cataloguing those would have put a
  finding on nearly every machine audited.
- **Every impact note declares its provenance.** 3 of 123 are `Verified` — confronted with
  software actually installed — and 120 are `Upstream`. That ratio is registered as debt
  (`DET-NOTES-AMONT`) rather than hidden: the field exists so the number is readable.
- Measured on the third-party capture: **10 catalogue entries matched real installed
  software**, which corroborates the identifiers. It does not promote their notes to
  `Verified` — matching proves the identifier, not what removing the software costs.

### Known limitations at this release

- **TLS/SCHANNEL and IPv6 hardening rules are not shipped.** Their effective defaults vary by
  Windows build, and a guessed default would raise findings on machines that are already
  correctly configured.
- **120 of the 123 impact notes were written from a third-party description**, not from
  observing the software run. The report says which is which.
- The full register of known debt, with impact and effort, is in
  [docs/DEBT.md](docs/DEBT.md).

## 1.0.0-rc.2 — 2026-07-28

### The stick shipped the rules the binary already contains, and could not run at all

A first build of this tag was published and **withdrawn within the hour**, downloaded by
nobody. It could not run a single command that resolves the rule catalogue — `scan`,
`explain` and `capture` all stopped on the same error, naming all 82 shipped identifiers as
duplicates. `version`, `help` and `seal --check` worked, which is why the archive looked
fine to everything that checked it.

- **Three deliberate decisions, never executed together.** The 82 rules are compiled into the
  binary, so the stick needs no companion folder. A `rules/` directory found beside the
  executable is read as an **external** catalogue, for fleet-specific checks. And an
  identifier present in both is refused rather than silently redefined. Each is right on its
  own; `release.yml` copied the repository's `rules/` into the archive, which handed the
  binary its own catalogue as a third-party supplement, and the third decision fired on all
  82. **The guard was not wrong — it was the only thing in the chain doing its job.**
- **The release workflow no longer copies `rules/`.** The comment that told it to has been
  replaced by the reason not to: the folder is a supplement, and shipping a copy of what is
  already embedded is the one thing it must never contain.
- **Nothing caught it because nothing ran the artifact in the shape it ships.** The workflow
  scanned from the *publish* directory, before assembly; `verify.ps1` copied `rempart.exe`
  alone into a sandbox. Both proved that a binary with no neighbours can scan — true, and not
  the claim anyone needed. The scan step now runs from the assembled staging folder and is
  followed by an `explain`, which resolves the catalogue without needing a machine.
- **`verify.ps1` builds the shipped layout** instead of the executable alone, from a
  `$stickContents` list declared by name — the same shape as `$aotDiagnostics`, and for the
  same reason: a guard reads it.
- **A new parity guard, verified by mutation in both directions.** `BuildChainParityTests`
  now holds what `release.yml` puts in the stick against what `verify.ps1` runs, and requires
  equality rather than inclusion. Re-adding the `Copy-Item "rules"` line reddens it; removing
  it greens it again. Written before the fix and confirmed failing on the defect first.
- **Measured on the published archive, not reasoned about**: it was downloaded, unzipped and
  run, and it reproduced the user's error character for character. The same layout without
  `rules/` runs `scan` (exit `5`, the ordinary partial audit), `explain` and `capture` from a
  folder holding three files.
- **What this does not close, stated rather than implied.** The per-commit jobs still do not
  assemble a stick: `ci.yml` runs the binary from its publish directory, as it always has.
  A change that added the same wrong item to *both* `release.yml` and `$stickContents` would
  satisfy the parity guard and reach a tag. It could not reach a **release** — the job now
  runs the stick before drafting and fails there — so what is lost in that case is the speed
  of the feedback, not the protection. Assembling a third stick in `ci.yml` would put the
  layout in a third file and give the guard a third list to reconcile, which is the trade
  this repository has already declined once, for `verify.ps1` itself (DET-SCRIPTS).

The rest of this section describes the twenty-one commits this release packages, unchanged.

---

Still a **candidate**, and for the one reason the first one was: the stick has not been run
on a machine other than the one it was built on. That criterion needs a machine rather than
code, so no amount of work in this section could have closed it — and calling this 1.0.0
would claim something still not observed.

What did move, in twenty-one commits: **five silences closed**, all the same shape — a
refused read coming back indistinguishable from a clean answer, on drivers, processes,
browser profiles, listening ports and startup folders. Two command lines now do what they
read like. A scan that could not evaluate everything says so in its exit code. The
anonymiser earns its flag instead of asserting it, which is what took a mainboard model and
eleven third-party task paths out of a public repository. The audit is tested against a
deliberately compromised fixture for the first time. And `Program.cs` went from 1 881 lines
to 29.

**rc.1 was drafted and never published**, so this is the first archive to leave the
repository. Nothing in it was withdrawn: it is superseded by the fixes listed below, several
of which change what the report says on exactly the machines that are hardest to audit.

### A startup folder the scan could not open no longer reports as an empty one

The fifth and last occurrence of the shape phase 2 closed four times — mute drivers and
processes, mute browser profiles, mute listening tables, mute catalog. It was found while
writing the `LiveFileSystemProvider` tests and left standing on purpose, because fixing it
changes what a snapshot stores and that is a decision, not the side effect of a test batch.

- **`IFileSystemProvider.ListFiles` gained a status channel** (`DET-FICHIERS-MUET`). It
  returned a bare list, so a startup folder the scan was **refused** came back exactly like
  an **empty** one and the report concluded « aucun autorun » about the first place a
  persistence is dropped. The refusal is now a `Notable` finding naming the folder, the way
  the four sibling collectors already name theirs.
- **Three states, because three facts exist.** A listed folder that is empty stays silent —
  an empty startup folder is the ordinary state of most machines, unlike zero drivers or
  zero listening ports, which cannot be true of a running one. A folder that is not on disk
  stays silent too, but is recorded as its own state rather than as an empty listing: « I
  listed this folder and it was empty » is a claim, and about a folder that is not there the
  scan never made it. Only a refusal speaks. The collector therefore tests for
  `AccessDenied` where its four siblings test for "anything but `Found`", and the deviation
  is commented where it sits — testing "anything but `Found`" here would put a finding on
  nearly every scan.
- **No `Partial` factory, unlike the port read, and the difference is the argument.** A port
  `Enumerate` spans four tables behind one call and can come back half-read. `ListFiles`
  takes the directory as a parameter: one call is one directory, and `Directory.GetFiles`
  either returns the whole listing or throws. The partiality is real all the same, one level
  up — a refused machine folder must not cost the files of the user folder that answered —
  so the collector adds its finding instead of returning it, and a test pins exactly that.
- **The status sits beside the listing, never in its place.** Two maps keyed like
  `directories` itself, so the JSON stays an array of paths: turning it into an object would
  have made every existing capture unreadable, the real ones kept outside the repository
  included. Keyed per directory because the read is — the machine folder can be refused
  while the user folder answers, and one status for the whole map would have to lie about
  one of them. A capture written before this change replays as the success it was.
- **A leak closed on the way past.** The diagnostic quotes the directory it failed on, so a
  user's startup folder writes an account name into it. The anonymiser now scrubs that
  **value** and not only the map keys; without it a capture calling itself anonymised would
  have carried the name out through the one field it had never had a way into.
- **The four versioned fixtures and their twelve references did not move a byte**, checked
  rather than hoped: the synthetic captures record no enumerated registry key for
  `Shell Folders`, so no startup folder is resolved and `ListFiles` is never called on them.
- Verified on the published AOT binary: a real capture carries both new fields, and the same
  capture with one folder marked refused prints a `NOTABLE` naming it where it used to print
  nothing at all.


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

### The build chain is pinned, and CI and the local script can no longer drift apart

- **`global.json` pins the SDK** to 10.0.302 with `rollForward: latestFeature` — a floor at
  the version this is developed with, a ceiling at the end of 10.0. Without it, whichever
  SDK a machine happened to carry compiled the binary a user is asked to run as
  Administrator, and "it builds on my machine" was evidence of nothing.
- **Package versions moved to `Directory.Packages.props`**, so the test tooling is declared
  once instead of in three project files.
- **actionlint is pinned by image digest**, not by tag. Worth knowing: Dependabot will never
  refresh that pin — its Actions parser skips anything starting with `docker://` — so the
  refresh was already manual and the tag merely also allowed silent movement.
- **`scripts/verify.ps1` is held against the workflows by a test.** This repository had just
  paid for the divergence: both workflows moved to accepting exit code `5` and the local
  script stayed at `{0, 3}`, which would have rejected every correct build. It also claimed
  to replay CI while running none of the four `diagnose-*` commands the publish job runs.
  Both fixed; a guard now fails if a workflow accepts a code the script refuses.
- **Coverage of `Rempart.Windows` was wrong, not merely missing.** It reported 35.5 %; 751
  of 1 677 lines were COM stubs the interface generator emits into `obj/`, covered at 4.7 %,
  and nine of the twelve worst "files" were generator output. The real figure is 60.6 %, and
  its worst-covered list names two of the providers the register flags.
- A trap nobody knew they were maintaining: two PowerShell scripts had no UTF-8 BOM and were
  surviving only because every non-ASCII character happened to sit in a single-quoted
  string. Under Windows PowerShell 5.1 an em dash in a double-quoted string decodes to
  something ending in `U+201D` — a closing quote — and the file stops parsing. CI never sees
  it; the maintainer's own shell does.

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
  this same release, above.

### Fixed

- **The `fixtures-anonymised` CI job ran no tests and exited 0.** Its filter named a test
  renamed long ago, so the guard whose whole purpose is keeping a real machine's capture
  out of a public repository had been green while checking nothing. The assertion itself
  always ran inside the main test job, so nothing was exposed — what was lost was the
  dedicated guard. A test now checks that every test name a CI job filters on exists.

### Structure

- **`Program.cs` is 29 lines.** It was 1 881 at its worst, growing by half a milestone at a
  time. The dispatch is now an explicit table, each of the 19 commands is its own class,
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
  and the argument parser (6 primitives), 56 tests between them. No command was moved.
- **`rempart index` renders through `ConsoleReport.Fleet`**, like `scan` and `diff` before
  it, with a golden test. Output verified identical byte for byte before and after.
- **Golden references for `rempart diff`** — three at first, four once the compromised
  fixture existed — covering a regression, a correction, a
  control that went blind, one that came back, a scope change, findings that disappeared
  and were retargeted — and a capture compared with itself, which freezes what the tool
  says when nothing moved.
- **`rempart help` lists all six exit codes.** It stopped at 3 and never mentioned 4
  (regression), from the day that code was introduced; the help now derives its own text
  from the contract, so it cannot drift again — code 5 above reached it without anyone
  having to remember.
- **Code coverage is measured on both jobs** and summarised in the run — `Rempart.Core` on
  the Linux job, `Rempart.Windows` on the Windows one, the only job that can compile it,
  through the same `scripts/coverage-summary.ps1` one parameter apart. Deliberately without
  a threshold: the six reasons in `docs/DEBT.md` (DET-COUVERTURE) are untouched by the
  widening, because what moved is the perimeter *seen*, not what is *enforced*.
  `Rempart.Cli` stays unmeasured and the entry says why. The summary states which figure it
  is: a workstation holding real captures in `tests/fixtures/local/` measures a different
  one, and the two are not comparable.

Two real defects were **frozen by tests rather than fixed** in this batch, each recorded in
`docs/DEBT.md`: `rempart diff --report --baseline b.json a.json` wrote into a folder named
`--baseline` (DET-ARITE-REPORT), and `rempart explain --rules <dir> <ID>` listed everything
instead of explaining the rule (DET-EXPLAIN-POSITIONNEL). Each changes what an existing
command line does, so each got its own change — as the exit code above did. Both are closed
in this same release, under "Two command lines now do what they read like": the
frozen assertions were inverted rather than deleted, so the fix is visible in a diff, which
was the whole point of freezing them.

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
