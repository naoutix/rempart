# Security policy

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/naoutix/rempart/security/advisories/new).**
It is enabled on this repository, so a report reaches the maintainer without becoming
public first. Please do not open a public issue for a security problem.

What helps, roughly in order of usefulness:

- the version — `rempart version`, or the tag of the release you downloaded;
- what the tool did versus what it should have done;
- a scan snapshot if one reproduces it (`rempart capture` is anonymised by default:
  hostname, serial numbers and registered owner are replaced by fingerprints);
- whether the machine was scanned elevated.

Expect an acknowledgement within **7 days**, and an assessment within **30**. This is a
personal project, not a staffed product: those are honest targets, not a contractual SLA.

## What counts as a vulnerability here

Rempart reads a Windows machine and writes a report. It has no write providers yet, no
service, and no network listener, so the interesting failures are about **what it claims**
and **what it exposes**, not about remote compromise:

- **A false negative.** The tool reports a machine as compliant when it is not, or stays
  silent about a persistence surface it claims to cover. An audit that reassures wrongly is
  worse than no audit.
- **A report that leaks.** The HTML report embeds strings chosen by the audited machine —
  command lines, paths, extension names. An escaping failure there turns a formatting bug
  into a vulnerability, which is why it is the one place in the project covered by a test
  that plants markup in every field.
- **A capture that is not anonymised.** `rempart capture` must not carry an identifier it
  claims to have replaced.
- **A seal that verifies when it should not.** `rempart seal --check` accepting a modified
  or added file, or accepting a manifest signed by an unknown key.
- **Anything that makes the tool write to a machine.** The audit is read-only by design;
  a path that modifies state is a bug of the most serious kind here.

## What does not count

- A rule that produces a false positive on a specific machine. That is a rule bug — open a
  normal issue, they are taken seriously, but they are not security reports.
- Requiring elevation to read something. A refused read maps to "not verifiable", never to
  compliance; that is the intended behaviour.
- The two opt-in network features (VirusTotal enrichment, DoH/DoT probing) reaching the
  network when explicitly enabled by their flags.

## Supported versions

Only the latest release is supported. The project is at `1.0.0-rc.1`; there is no
maintenance branch and no backporting.

## Signature and provenance

Release binaries are built by GitHub Actions from the tagged commit, and each release
archive carries a `rempart-integrity.json` signed by the publisher key. Verify it from a
copy you already trust rather than from the stick under test — a binary that verifies
itself proves little:

```text
rempart seal --dir <folder> --check
```
