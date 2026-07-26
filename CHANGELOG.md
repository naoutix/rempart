# Changelog

Versions before 1.0.0-rc.1 were built from source only; this is the first packaged
release. The milestone-by-milestone account of how the tool got here, including what was
tried and rejected, lives in [docs/ROADMAP.md](docs/ROADMAP.md) — this file records what
changed between releases.

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
  left: listening ports are collected over `AF_INET` only.
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
