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
  │ B. Source code, before    │──▶│ repo checkers (src/repo) │──▶│ validator                    │
  │    deployment             │   │  local checks; later:    │   │ summary and grade            │
  └───────────────────────────┘   │  skills, other vendors   │   └──────────────┬───────────────┘
                                  └──────────────────────────┘                  │ Assessment (JSON)
                                                                                ▼
                                                              reports, badges, re-verification
```

## Two entrances, one result format

| | A. URL | B. Source code |
|---|---|---|
| When | After deployment | Before deployment: the QA stage |
| Sees | What the site actually exposes | Why it is exposed, and what is not visible from outside |
| Ownership | Must be verified for details and active checks | Implicit: the owner runs it on their own code |
| Good at | Leaked keys, exposed files, transport | Access rules, auth logic, injection, AI-specific risks |

A defender only wins by finding a problem before an attacker does. Entrance B is
where that happens most cheaply, so the core is built for both from the start:
both entrances emit the same `Assessment`, and one assessment can later combine
evidence from both.

### Entrance B in practice

- `src/repo/load.ts` reads the folder into memory once: symbolic links are
  never followed, files are opened with `O_NOFOLLOW`, and size, count, total
  and depth are capped. Everything skipped is counted in `RepoLoadStats`, and a
  checker reading files must report `some_files_not_read` when anything was.
- Checkers see only that in-memory `RepoContext`. None touches the file system,
  runs code or uses the network.
- Text from the project is treated like text from a hostile site: SQL and
  Firebase rules are blanked (comments, strings, function bodies) in one linear
  pass before any pattern runs, and every pattern is bounded.
- Tests, fixtures and documents are not evidence that a service is used, and a
  key-shaped value in a test becomes `needs_validation`, not a leak.
- Key detection is shared with entrance A (`src/detect/secrets.ts`), so a key
  has the same fingerprint wherever it is found.

### Handing off to an AI coding tool

`src/handoff.ts` renders an assessment for an AI rather than a person. It keeps
apart what carries different weight: confirmed records (to be passed on
unchanged), needs_validation records (to be asked, not answered), and every
coverage unit that is not `checked` (for the AI to review, labelled as its own
judgement). The AI is another inspector; its findings are never merged into
the scanner's verdicts. Every string taken from the project goes through
`cleanText()` (`src/text.ts`) first.

### Fixing, and confirming the fix

`src/fixrequest.ts` renders the fix request (`check --fix-request`): every
confirmed record, P0 first, with its fingerprint as an ID, steps per problem
code (`fixSteps` in `src/i18n/ja.ts`), the conditions the AI must keep, owner
questions to ask, and the re-check command pinned to this version
(`src/invocation.ts`).

`src/core/compare.ts` compares a re-check with an earlier assessment of the same
target. Records are matched by fingerprint; "new" is judged per verdict. A
confirmed record that is gone is *fixed* only if all of these hold, and
otherwise *gone but not verified* with the first reason that failed:

| Condition | Reason when it fails |
|---|---|
| same engine and rules version | `tool_changed` |
| its rule was examined this time | `rule_not_examined` |
| examined at least as fully as before (`checked` > `partial` > `partial` with unread files or limits) | `coverage_reduced` |
| the place it was in was read in full this time: the file (repo layer), or the served text (URL layer, see below). Always a lookup in what the check read, never a file-system or network call with a path from the earlier result | `file_not_read` |
| no new record of the same rule and code family (`rls.*`, `secret.*` …), of either verdict, in the same file (repo layer) or anywhere on the site (URL layer) | `similar_finding_present` |

The last condition catches renaming a variable to another public prefix and
rewriting a confirmed problem into an undecidable one (RLS made to look dynamic)
without listing evasions one by one. It can also hold back a genuine fix when an
unrelated new item of the same kind appears in the same file; that errs on the
side of not claiming a fix.

What remains is always the current check's own records. The earlier result is
untrusted input: it is validated, and editing it can at most invent a "fixed"
item that never existed, never hide one that is still there.

#### The same for a published site

A verified owner fixes a site with an AI coding tool too, so the URL layer
uses the same two modules. `renderFixRequest()` words the request for a site:
the AI works in the project the site is built from, never on the published
files; it is given no command, because it cannot check the site itself; the
owner publishes the fix and checks the site again. Steps per problem code are
`urlFixSteps` in `src/i18n/ja.ts`. DNS and hosting settings are named as the
owner's to change.

`inspectOwner()` returns the assessment together with what the check read, and
`servedTextReader()` (`src/url/compare.ts`) turns that into the `wasRead` of
the comparison. A key that was in a script is *fixed* only when the check can
say it is not simply somewhere unread:

- the page and every script it references were read in full, so the key is in
  none of them, whatever the build calls its output now; or
- something was left unread, and a text with the same address was read in full
  again.

Built assets are renamed on every build, so "the same file" means nothing on a
site: a new record of the same kind anywhere on the site holds the old one
back. A key swapped for another, or SPF added in a form that still allows
every sender, is therefore *gone but not verified*, with the new record listed
beside it.

Known limit: scripts a page loads later at runtime are not read by this layer,
so a key moved into one reads as fixed. The R02 coverage note says so on every
result; closing it means reading the build manifest (see "Not built yet").

The engine keeps no earlier result for a site. The service that offers the
re-check keeps it, and decides which earlier result to compare with.

`test/case-site.ts` is the case site: one small service with the six problems
QA.JP.AI was started from, and the same site after a correct fix. Its
scoreboard (`test/case-site.test.ts`, `evals/case-site/`) is how the free
check is measured: a change to a checker moves a line of it, on purpose.

`src/baseline.ts` keeps the earlier result in the user's cache folder, one file
per project (named by a hash of its real path), directory 0700 and file 0600,
written by create-then-rename; a linked folder or file is refused. Nothing is
written into the project. Comparing never replaces the saved result, so repeated
re-checks during one round of fixes all compare with the state before it.

## Core objects

| Object | File | What it is |
|---|---|---|
| Rule registry | `core/rules.ts` | The machine-readable list of what is checked: id, maximum severity, which layers can answer it, and whether its findings may be disclosed before ownership is verified |
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
without volatile detail (no offsets, no ports, no build hashes in file names)
and without secret material. The
same issue keeps its fingerprint across runs, which is what makes re-runs
additive and lets a certificate be bound to a version.

### Coverage ledger

Exactly one unit per rule, always. A rule that was not examined is `not_run`
with a reason. It is never reported as passed. A check that crashed is `error`.
A check with known limits is `partial` with a note, and the note says which
limit applied: only statically referenced scripts, some content unreadable, the
match cap reached, some probes unanswered. When a rule is covered by both a
passive and an active check, the unit keeps the passive result alongside, and
the public view is built from that. Every summary states its coverage, so a
grade can only be read together with what was examined.

## Invariants

Each of these is enforced by the validator or by a test, not by convention.

1. Only `confirmed` records carry a severity, and never one above the rule's maximum.
2. A record can exist only for a rule the ledger says was examined.
3. A public-tier assessment contains no active check and no record from one.
4. The public summary is computed from passive checks under rules marked for
   public disclosure (basic configuration) and nothing else, even when derived
   from an owner-tier assessment. It is identical for two sites that differ
   only in owner-disclosure findings.
5. The detailed report refuses to render without a valid ownership proof for the
   assessed host, presented again at render time.
6. Evidence never contains a full secret or fetched file contents.
7. A check that failed, or content that could not be read, is recorded as such —
   never as "nothing found". A failed check is shown next to the grade.
8. Reports are derived from the assessment and nothing else.
9. An owner-tier scan never touches a host its proof does not cover, including
   by redirect.
10. Work done on text from the target is linear in its size and bounded in output.
11. The public coverage view is identical whether or not owner-only checks ran.
12. A problem is reported as fixed only by a comparison made by the same tool
    version, under coverage at least as full, with its file read; what remains
    comes from the current check alone.

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
src/detect/      detection shared by both entrances (privileged keys, placeholders)
src/url/         entrance A: fetch guard, context loading, checkers
src/repo/        entrance B: safe folder loading, .gitignore matching, checkers
src/ownership/   proof of ownership: mailbox, verification file, DNS
src/i18n/ja.ts   every string a person reads
src/report.ts    public summary, owner report and local report, derived from an Assessment
src/handoff.ts   the same assessment as a hand-off for an AI coding tool
src/fixrequest.ts  the fix request to paste into an AI coding tool
src/recheck.ts   the re-check report (comparison) for people
src/url/compare.ts  what a site check must have read before a problem counts as fixed
src/baseline.ts  the saved earlier result, in the user's cache folder
src/invocation.ts  how text written by the tool names the command to run again
src/text.ts      cleaning of text taken from the thing being checked
integrations/    files people copy into their projects (CC0)
scripts/build.mjs  bundles the command for npx
src/cli.ts       command line
```

## Not built yet

- Entrance B beyond R01 and R02, including adapters for external audit methods
  and cross-vendor verification.
- Recording the AI's own review as structured data (today it is prose in the
  AI's report, kept apart from the assessment).
- Combining several runs into one assessment.
- Certificates, the public registry and revocation.
- URL checkers for R03, R04 and R06 (the registry says this layer can answer
  them; the case site scores them "not examined"), and scripts loaded at
  runtime for R02.

The web service (UI, login-link mail, rate limiting, audit log) is a separate
repository, `qa-url-ai-scanner`. It holds no check logic.
