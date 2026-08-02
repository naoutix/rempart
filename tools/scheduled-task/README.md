# The scheduled task, and why the tool does not create it

Drift monitoring needs a trigger. **That trigger will not be created by `rempart`.**

Creating a scheduled task means changing the machine's configuration — the one thing v1
promises not to do. The only thing the tool writes is its own update store, and only when
asked. Triggering on a schedule is the Windows scheduler's job, not the auditor's; slipping
a system write into a read-only release would move this milestone into the write perimeter
of [ADR-007](../../docs/adr/ADR-007-perimetre-v2-et-ecriture.md), with everything that
implies — a plan, a read-back check, and a way to undo.

So this folder ships the definition, and you import it.

## Import it

Edit two lines of `rempart-derive.xml` first — `Command` and `WorkingDirectory`, both naming
the folder `rempart.exe` sits in — then:

```
schtasks /Create /XML tools\scheduled-task\rempart-derive.xml /TN "Rempart\Weekly audit"
```

Remove it the same way, with `schtasks /Delete /TN "Rempart\Weekly audit"`.

**Keep the file as UTF-16.** `schtasks` refuses any other encoding, and it refuses it before
reading a single element: an UTF-8 copy answers `impossible de changer d'encodage` at line 1,
column 40 — the encoding declaration. This is measured, not quoted from documentation; the
first version of this file was UTF-8 and imported nowhere. Most editors will offer to
"fix" the encoding, and a test pins the byte order mark so that offer cannot be accepted
quietly.

## What it runs, and where the reports land

The task runs `rempart scan --report`, which writes `rapport.html`, `.md` and `.json` into
`<binaire>/reports/<machine>-<date>/`. Two runs on one day do not overwrite each other: the
second takes a suffix, because the "before" of a fix is the half you cannot redo.

Nothing prunes that folder. Read the series it accumulates with:

```
rempart drift
```

which names the window it covers, how many reports it read, and what they weigh on disk —
the numbers you need to decide when to delete something, since the tool will not decide it
for you.

## Before you import it

**The account.** `LogonType` is `InteractiveToken`: the task runs as the user who registers
it, when that user is logged on. A machine nobody logs into will produce no series. To audit
a machine that sits at a login screen, register it under a service account and switch to
`Password` or `S4U` yourself — that is a decision about credentials, and this file will not
make it for you.

**It does not ask for elevation.** `RunLevel` is `LeastPrivilege`, and that is a decision
rather than a default. An elevated task would read more of the machine; it would also mean
this repository shipped a file that runs a binary as administrator on a schedule. Raise it
to `HighestAvailable` yourself if you want the fuller picture, knowing what you are granting.

**A non-elevated run exits `5`, and that is the ordinary case.** Code 5 means the scan
finished and some controls could not be evaluated — BitLocker's state, for one, comes back
unverifiable without elevation. It is not a failure and it is not a machine in trouble. An
orchestrator should treat `0`, `3` and `5` from the scan as a run that happened, and keep
its attention for `1`.

**What `rempart drift` answers is a different question**, and that is the one worth wiring
an alert to: `4` when a control that used to pass still fails, `5` when the series stopped
being fed or the last scan left controls unevaluable.

## What keeps this file honest

`ScheduledTaskDefinitionTests` reads the command line out of the XML and puts it through the
same door a typed line goes through. A file a user imports and forgets is exactly where a
renamed option would fail weeks later, on someone else's machine, at an hour nobody watches.
It also pins `RunLevel`, so the decision above cannot be relaxed by accident.
