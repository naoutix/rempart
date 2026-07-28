<!--
Keep what applies, delete the rest. The prompts below are the questions this repository has
learned to ask, each of them the hard way — they are not a form to fill in for its own sake.
-->

## What changes, and why

<!-- What the reader of a `git log` in six months needs, not a restatement of the diff. -->

## How it was verified

<!--
`./scripts/verify.ps1` replays CI locally. Paste what it printed, or say plainly which parts
you skipped — a claim of "tested" with nothing behind it is worse than an honest gap.
-->

- [ ] `./scripts/verify.ps1` green
- [ ] Behaviour that changed is covered by a test that **fails without the change**

## If this touches an audit surface

- [ ] A read that can be **refused** is distinguishable from one that found nothing — an empty
      list must never look like a clean answer
- [ ] No `windowsDefault` was guessed; anything unobserved says so rather than asserting
- [ ] A capture written before this change still replays (fields are added **beside** data,
      never in place of it)

## If this changes what ships

- [ ] `CHANGELOG.md` says what changed and what was measured
- [ ] `docs/DEBT.md` records anything knowingly left open
- [ ] The documentation describes the code as it is now, not as it is planned to be
