# Security policy

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/naoutix/rempart/security/advisories/new).**
It is enabled on this repository, so a report reaches the maintainer without
becoming public first. Please do not open a public issue for a security problem.

What helps, roughly in order of usefulness:

- the version — `rempart version`, or the tag of the release you downloaded;
- what the tool did versus what it should have done;
- a scan snapshot if one reproduces it — `rempart capture` is anonymised by
  default (hostname, serial numbers, registered owner, hardware identity,
  scheduled-task names outside `\Microsoft\`, Wi-Fi and browser profile names,
  user folder paths are all replaced by stable fingerprints; `--raw` keeps them);
- whether the machine was scanned elevated.

Expect an acknowledgement within **7 days**, and an assessment within **30**. This
is a personal project, not a staffed product: those are honest targets, not a
contractual SLA.

## What counts as a vulnerability here

Rempart reads a Windows machine and writes a report. It has no write providers yet,
no service, and no network listener, so the interesting failures are about **what it
claims** and **what it exposes**, not remote compromise:

- **A false negative.** The tool reports a machine as compliant when it is not, or
  stays silent about a persistence surface it claims to cover. An audit that
  reassures wrongly is worse than no audit.
- **A report that leaks.** The HTML report embeds strings chosen by the audited
  machine — command lines, paths, extension names. An escaping failure there turns
  a formatting bug into a vulnerability, which is why it is the one place in the
  project covered by a test that plants markup in every field.
- **A capture that is not anonymised.** `rempart capture` must not carry an
  identifier it claims to have replaced.
- **A seal that verifies when it should not.** `rempart seal --check` accepting a
  modified or added file, or a manifest signed by an unknown key.
- **A signed dataset that is accepted when it should not be.** `rempart update`
  trusts the signature and never the transport: a manifest or dataset that passes
  verification while altered, or one signed by a key that is not pinned, puts
  chosen rules or a chosen driver catalogue into the audit. Same defect as a seal
  that verifies wrongly, on the other command.
- **Anything that makes the tool write to a machine.** The audit is read-only by
  design; a path that modifies state is the most serious kind of bug here.

## What does not count

- A rule that produces a false positive on a specific machine. That is a rule bug —
  open a normal issue. They are taken seriously, but they are not security reports.
- Requiring elevation to read something. A denied read maps to "not verifiable",
  never to compliance; that is the intended behaviour.
- The opt-in network features reaching the network when explicitly enabled:
  VirusTotal enrichment (`--virustotal-key`, or the `REMPART_VT_KEY` environment
  variable), DoH/DoT probing (`--probe-dns`), PAC retrieval (`--fetch-pac`), and
  the commands that are online by nature — `fetch-loldrivers`, `fetch-bloatware`
  and `update --url`. None of them fires on a replay.

## Supported versions

Only the latest release is supported. The project is at `1.1.0`; there is no
maintenance branch and no backporting.

## Signature and provenance

Release binaries are built by GitHub Actions from the tagged commit. CI stops at a
**draft**, and the archive it attaches is named `-unsealed`: the publisher key is
deliberately not available to the build, so the seal is added by hand before
publishing. Every **published** archive carries a `rempart-integrity.json` signed by
that key — an archive still named `-unsealed` is not a release.

Verify it from a copy you already trust, not from the stick under test — a binary
that verifies itself proves little:

```text
rempart seal --dir <folder> --check
```
