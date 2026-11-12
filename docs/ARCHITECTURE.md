# Architecture

## The one idea

**QA.JP.AI owns the judging layer. Inspectors are pluggable.**

An inspector (a *checker*) produces evidence. It may be code in this repository,
another project's audit method, or another vendor's model. The judging layer
(`src/core`) decides what a set of evidence means and validates the result, no
matter who produced it. Independence lives in the judging layer: the rules, the
verdict contracts, the coverage ledger and the validator are public and the same
for everyone.

```
            entrances                     inspectors                 judging layer (src/core)
  ┌───────────────────────────┐   ┌──────────────────────────┐   ┌──────────────────────────────┐
  │ A. URL of a deployed site │──▶│ URL checkers (src/url)   │──▶│ rule registry                │
  │    passive for anyone,    │   │  passive / active        │   │ records: three verdicts      │
  │    active for the owner   │   └──────────────────────────┘   │ stable fingerprints          │
  ├───────────────────────────┤   ┌──────────────────────────┐   │ coverage ledger              │
  │ B. Source code, before    │──▶│ repo checkers (planned)  │──▶│ validator                    │
  │    deployment (planned)   │   │  local checks, audit     │   │ summary and grade            │
  └───────────────────────────┘   │  skills, other vendors   │   └──────────────┬───────────────┘
                                  └──────────────────────────┘                  │ Assessment (JSON)
                                                                                ▼
                                                              reports, badges, re-verification
```

## Two entrances, one result format

| | A. URL | B. Source code (planned) |
|---|---|---|
| When | After deployment | Before deployment: the QA stage |
| Sees | What the site actually exposes | Why it is exposed, and what is not visible from outside |
| Ownership | Must be verified for details and active checks | Implicit: the owner runs it on their own code |
| Good at | Leaked keys, exposed files, transport | Access rules, auth logic, injection, AI-specific risks |

A defender only wins by finding a problem before an attacker does. Entrance B is
where that happens most cheaply, so the core is built for both from the start:
both entrances emit the same `Assessment`, and one assessment can later combine
evidence from both.

## Core objects

| Object | File | What it is |
|---|---|---|
| Rule registry | `core/rules.ts` | The machine-readable list of what is checked: id, maximum severity, which layers can answer it |
| Record | `core/records.ts` | One issue, with a verdict and a stable fingerprint |
| Coverage ledger | `core/coverage.ts` | For every rule: examined, partly examined, not examined (and why), or failed |
| Assessment | `core/assessment.ts` | Records + ledger + versions. The only input to reports |
| Validator | `core/validate.ts` | Checks any assessment for consistency. Zero dependencies, treats input as untrusted |
| Checker | `core/checker.ts` | The inspector interface |

### Three verdicts

| Verdict | Meaning | Severity |
|---|---|---|
| `confirmed` | Evidence was observed | Yes |
| `needs_validation` | A concrete concern this layer cannot decide. Names the missing fact; handed to the owner | No |
| `rejected` | A candidate that verification disproved. Kept so it is not raised again | No |

"Not enough evidence" is neither a finding nor silence. Example: a site that
talks to Supabase from the browser. Whether row-level security is on cannot be
seen from outside and must not be tested without consent, so the URL layer emits
`needs_validation` with one precise thing for the owner to check.

### Fingerprints

`fp_` + a hash of (layer, rule, code, stable key). The key identifies the issue
without volatile detail (no offsets, no ports) and without secret material. The
same issue keeps its fingerprint across runs, which is what makes re-runs
additive and lets a certificate be bound to a version.

### Coverage ledger

Exactly one unit per rule, always. A rule that was not examined is `not_run`
with a reason. It is never reported as passed. A check that crashed is `error`.
A check with known limits is `partial` with a note. Every summary states its
coverage, so a grade can only be read together with what was examined.

## Invariants

Each of these is enforced by the validator or by a test, not by convention.

1. Only `confirmed` records carry a severity, and never one above the rule's maximum.
2. A record can exist only for a rule the ledger says was examined.
3. A public-tier assessment contains no active check and no record from one.
4. The public summary is computed from passive checks only, even when derived
   from an owner-tier assessment.
5. The detailed report refuses to render without a valid ownership proof.
6. Evidence never contains a full secret or fetched file contents.
7. A failed checker is recorded as an error, never as "nothing found".
8. Reports are derived from the assessment and nothing else.

## Adding a checker

1. Implement `Checker<Ctx>`: an id, a layer, `passive` or `active`, the rules it
   answers, and `run()`.
2. Build records with the `RecordFactory` passed to `run()`. Supply a stable `key`.
3. Return one coverage entry per rule, stating honestly how far the check got.
4. Add Japanese text for any new code in `src/i18n/ja.ts`.
5. Register it (for the URL layer: `URL_CHECKERS` in `src/url/scan.ts`).

A checker never decides grades, never writes report text, and never needs to
know who will read the result.

## Layout

```
src/core/        judging layer (no network, no I/O)
src/url/         entrance A: fetch guard, context loading, checkers
src/ownership/   proof of ownership: mailbox, verification file, DNS
src/i18n/ja.ts   every string a person reads
src/report.ts    public summary and owner report, derived from an Assessment
src/cli.ts       command line
```

## Not built yet

- Entrance B (source code), including adapters for external audit methods and
  cross-vendor verification.
- Combining several runs into one assessment.
- Certificates, the public registry and revocation.
- The web service: UI, login-link mail, rate limiting, audit log.
