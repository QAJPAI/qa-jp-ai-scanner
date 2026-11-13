# qa-jp-ai-scanner

The QA.JP.AI scanner for AI-generated web apps.

Many small businesses want their own site or tool, build it with AI, and cannot
tell whether it is safe to put online. This scanner is meant to tell them, for
free, before an attacker finds out first.

**QA.JP.AI owns the judging layer; inspectors are pluggable.** The rules, the
verdict contracts, the coverage ledger and the validator are public and the same
for every inspector. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

There are two entrances. Both produce the same result format.

| Entrance | Status |
|---|---|
| A. URL of a deployed site | Built: R01 hint, R02, R11, R14 |
| B. Source code, before deployment | Built: R01, R02 |

## Rules for AI coding tools (free)

[`rules/security-rules.ja.md`](rules/security-rules.ja.md) is the 15 rules
written as instructions for an AI coding tool, in Japanese. A person with no
programming background pastes it into their project's `AGENTS.md` or
`CLAUDE.md`; from then on their AI follows it while building, and reports a
pre-release check in the same three verdicts the scanner uses.

Preventing a problem while the app is being written is cheaper than finding it
afterwards. Using the file is not certification. Its effect has not been
measured yet.

The file is dedicated to the public domain under CC0 1.0, so it can be copied
into any project, open or closed, with no conditions and no attribution.

## Results

Every result has three parts, and none is shown without the others. All three
are shown in full to a verified owner. An unverified requester sees the grade
and counts for basic configuration, the coverage totals, and one sentence that
is the same for every site: whether serious problems exist is shown after
ownership is verified.

- **Problems found** (`confirmed`): evidence was observed. Graded P0 / P1 / P2.
- **Items for the owner to check** (`needs_validation`): a concrete concern that
  cannot be decided from outside. Not graded. Example: a site that connects to
  Supabase from the browser is asked to confirm row-level security is on.
- **Coverage**: for each of the 15 rules, whether it was examined, partly
  examined, or not examined and why. A rule that was not examined is never
  reported as passed.

## Entrance B: source code, before deployment

```sh
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check .              # Japanese report
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check . --for-ai     # hand-off for an AI coding tool
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check . --json       # the assessment, for tools
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check . --fail-on P0 # exit code 3 if a P0 is found (CI)
```

### Fix, then let the tool confirm the fix

```sh
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check . --fix-request  # text to paste into an AI; saves this result
# … the AI fixes the code …
npx --yes github:QAJPAI/qa-jp-ai-scanner#v0.7.0 check . --compare      # what is confirmed fixed
```

`--fix-request` lists every problem, most serious first, with concrete steps
for an AI coding tool and the conditions it must keep (explain and ask before
changing files, never print key values, add a new migration rather than edit an
applied one, ask the owner who may read or write the data).

`--compare` matches problems by fingerprint and sorts them into *confirmed
fixed*, *still present*, *gone but not verified*, and *new*. "It is gone" is
not "it is fixed": a problem counts as fixed only when the same tool version
examined its rule at least as fully as before, read the file it was in, and
found nothing new of the same kind in that file. Deleting, renaming or moving
the file, moving a key into a test folder, swapping one public prefix for
another, or making RLS merely look dynamic all show as *not verified*, with the
reason. What remains always comes from the current check alone, so an edited
saved result cannot hide a problem. Each fixed item also says what the tool
cannot see: whether a leaked key was re-issued, and whether a rule fixed in
code has reached production.

The saved result goes to the user's cache folder (`$XDG_CACHE_HOME` or
`~/.cache`, `%LOCALAPPDATA%` on Windows), one file per project, readable by its
owner only. Nothing is written into the project. `--since <file>` compares with
any earlier `--json` result instead.

From a clone: `npm install`, then `npx tsx src/cli.ts check ./my-app`.

### Inside AI coding tools

Someone with no programming background should be able to say
「公開前チェックをしてください」 and get a sound result. [`integrations/`](integrations/README.ja.md)
holds what makes that work (Japanese, CC0):

- a Claude Code skill, and the same steps in the rules file for tools that read
  `AGENTS.md` (Cursor, Codex, Windsurf …);
- the AI runs `check --for-ai` and receives a hand-off in three parts: what the
  tool confirmed (pass on unchanged), what only the owner can decide (ask, do
  not answer), and what the tool did not examine (review it, and label the
  result as the AI's own judgement);
- text taken from the project is cleaned of control and reordering characters
  and marked as data, so a file or policy name cannot pass itself off as an
  instruction.

Reads the project's files and nothing else: no code is run, nothing is sent
anywhere, and symbolic links are never followed, so nothing outside the folder
is read. Whoever runs it holds the code, so the full report is shown without
further proof.

| ID | What it finds | Verdict |
|---|---|---|
| R01 | Supabase: a table in `public` whose migrations never enable RLS; a policy of `using (true)` for update, delete or all | confirmed, P0 |
| R01 | Supabase: a public read or open insert policy (may be intended); RLS switched inside a function the replay cannot follow; Supabase used but no table definitions in the code | needs_validation |
| R01 | Firebase: rules with no condition or `if true` (any write, or reads of everything); test mode | confirmed, P0 |
| R01 | Firebase: public read of one path; "any signed-in user"; Firebase used but no rules in the code | needs_validation |
| R02 | A key written into a file that will be committed | confirmed (P0, or P1 for Stripe test keys and AWS key IDs) |
| R02 | A secret under a variable name the build copies into browser code (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_` …), found in an env file or in code | confirmed, P0 |
| R02 | An env file holding secrets that `.gitignore` does not exclude | confirmed, P0 |
| R02 | A key-shaped value in a test or fixture (fake is fine, real must be revoked) | needs_validation |

R01 is always `partial` with the note `code_only`: settings changed in a
dashboard are invisible to a code check. A project that uses neither Supabase
nor Firebase gets R01 `not_run` / `not_applicable`, never "passed". Rules that
only a deployed site can answer (R11, R14) are `not_run` /
`requires_deployed_site`.

Placeholders in documentation and templates (`sk_live_xxxx…`,
`sk-proj-your-key-here`, `AKIAIOSFODNN7EXAMPLE`) are not findings. The cost of
that filter is measured: about 1 to 2 real keys in 100,000 would be dismissed by
chance (`test/placeholder.test.ts` fails if this rises).

## Entrance A: URL

Anyone can run a passive check on a URL and get a grade and counts. What the
problems are, where they are, and how to fix them is shown only to someone who
has proved they own the site.

Code and identifiers are English. Everything a user reads is Japanese
(`src/i18n/ja.ts`).

## Design rules

| Rule | How the code enforces it |
|---|---|
| Unverified requesters learn nothing about serious problems | The public view reports basic configuration only (transport and response headers: what any browser's developer tools show). For every other rule it carries nothing, not even a count, so it is identical for a site with a leaked key and a site without one. `scanPublic()` returns that view and nothing else; `renderOwnerReport()` requires the ownership proof again and checks it against the assessed host |
| Unverified scans are passive | Only the page and the same-site scripts it references are fetched. For an https site there is one more request, to its http:// address, to see whether it redirects. Active checkers run only with an `OwnershipProof`, and the public summary does not reveal that they ran |
| Detect, never exploit | A detected key is never sent anywhere. Evidence keeps a 6-character prefix and a length. File probes keep a boolean and a count, not contents |
| The scanner cannot be aimed at internal networks | `src/url/net/guard.ts` refuses loopback, private, link-local and metadata addresses and every IPv6 range that embeds IPv4, at connect time (covers DNS rebinding) and on every redirect hop, plus non-standard ports. Error messages are the same for every cause |
| A hostile page cannot stall or crash the scanner | Text from the target is scanned in linear time with bounded matches; one deadline covers every request of a scan |
| A result is about one site | A redirect to a different site is refused, for both tiers; an owner's proof must cover the host actually reached |
| An error page is not graded | A non-2xx page stops the scan |
| Details are unlocked by ownership, not by contact details | The only way to obtain an `OwnershipProof` is one of the three verification methods |
| A result can be checked by someone else | `--json` emits the full assessment for a verified owner; `validate` checks any assessment for consistency |

## Ownership verification

| Method | For whom | Module |
|---|---|---|
| A. Mailbox on the site's own domain | Businesses with a domain mailbox | `ownership/email.ts` |
| B. Verification file placed by the owner's AI coding tool | Sites on platform subdomains; owners who use free mail | `ownership/file.ts` |
| C. DNS TXT record | People comfortable with DNS | `ownership/dns.ts` |

Method A requires a mailbox directly on the site's registrable domain
(`info@example.jp`, not `info@mail.example.jp`). It refuses free and carrier
mail and sites on shared hosting domains, and accepts only admin mailboxes
(`admin@`, `administrator@`, `webmaster@`, `hostmaster@`, `postmaster@`) on
large shared domains such as `ac.jp` and `go.jp`. Its proof covers the one host
that was asked for.

What method A establishes is that the person can read mail at the site's own
domain. In a small business that is the owner. In a larger organisation it is
any member. A service built on this engine should therefore notify the domain's
admin address whenever a detailed report is unlocked, and keep an audit log.

## Rules implemented (rules v0.1.0)

| ID | What | Severity | Tier |
|---|---|---|---|
| R01 | Direct browser connection to Supabase or Firebase detected: asks the owner to confirm the access rules | Not graded (`needs_validation`) | public |
| R02 | Privileged keys shipped to the browser (Supabase service_role / secret, OpenAI, Anthropic, Stripe, AWS, GitHub, Slack, SendGrid, private keys) | P0 (Stripe test key, AWS key ID: P1) | public |
| R14 | HTTPS, HSTS, CSP, nosniff, clickjacking protection, cookie attributes | No HTTPS: P1. Others: P2 | public |
| R11 | Exposed `.env`, `.git`, source maps | `.env`: P0. `.git`: P1. Source maps: P2 | owner |

P0 = any one fails the check. P1 = serious. P2 = should improve.

Keys that are public by design are not findings: Supabase anon / publishable
keys, Firebase web API keys, Stripe publishable keys.

## Use

```sh
npm install
npm test
npm run typecheck

# Public summary
npm run scan -- https://example.jp

# Show the ownership token, the prompt to paste into an AI coding tool, and the DNS record
QA_JP_AI_SECRET=... npm run scan -- token https://example.jp --account acct-1

# Verify, then show the detailed report
QA_JP_AI_SECRET=... npm run scan -- https://example.jp --account acct-1 --verify file

# Machine-readable assessment (verified owner), and checking one
QA_JP_AI_SECRET=... npm run scan -- https://example.jp --account acct-1 --verify file --json > assessment.json
npm run scan -- validate assessment.json
```

Only check sites you own or have permission to check.

## Known limits

- Script discovery reads the HTML only. Chunks loaded later at runtime are not seen.
- Method A decides eligibility and issues the proof; sending the login link is the service layer's job and is not built yet. `issueEmailProofAfterLinkClick()` trusts its caller to have confirmed the click.
- The lower-level `scan()` returns every detail at either tier. It is not exported from the package entry point; a service must use `scanPublic()` for unverified requesters.
- `.env` files that start with more than 8 KB of comments, and source maps not referenced from a script, are not found.
- No web UI, rate limiting or audit log yet. These are required before any public deployment.
- Source-code check: it does not run git, so it cannot see keys that were committed in the past and later deleted. It replays SQL far enough to judge RLS and policies, and is not a SQL parser: views (which bypass RLS by default), storage buckets and `security definer` functions are not yet checked. The `.gitignore` matcher covers what env-file rules use in practice, not every corner of git's syntax.
- A grade of A means nothing was found in the checks that ran. It does not mean the site is safe.

## Acknowledgements

This project builds on the published work of others and says so.

- **[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)**
  (MIT, Copyright (c) 2025-2026 Cloudflare, Inc.) — the source of several ideas in
  the judging layer: three distinct verdicts, a coverage ledger, stable
  fingerprints, and machine-validated records. Those ideas are implemented here
  independently; this repository contains no code or text from it. It is also the
  reference for the planned source-code entrance. When its files are incorporated,
  they will be kept in a separate directory together with its original license.
- **CodeRabbit** — its public descriptions of a sandboxed, evidence-filtered review
  pipeline informed the design.

Improvements made here that are useful upstream will be offered back.

## License

Copyright (C) 2026 iQi

The scanner (everything except `rules/`) is AGPL-3.0-or-later. See `LICENSE`.

`rules/` is CC0-1.0: public domain, no conditions. See `rules/LICENSE`. The
AGPL does not apply to it.

Anyone may use, study, change and redistribute this checker. If you run a
modified version as a network service, you must offer the source of that
version to the people who use the service.

## Contact

Questions and security reports: qa@email.jp.ai
